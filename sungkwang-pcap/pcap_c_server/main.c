/*!
 * @mainpage AI 기반 웹 접근제어 탐지 엔진
 *
 * @section overview 프로젝트 개요 
 * 미러링 패킷을 분석하여 유해 사이트 접근을 탐지합니다.
 *
 * @section architecture 시스템 구성
 * - 탐지 엔진 : 패킷 수집 및 접근 제어
 * - 웹 서버 : 관리자 페이지와 API 제공
 * - DB 서버 : 정책 및 로그 저장
 *
 * @section build 빌드 방법
 * @code{.sh}
 * make
 * @endcode
 *
 */

/*!
 * @file main.c
 * @brief 탐지엔진 초기화 및 실행 흐름 관리
 * @detail 
 * 디테일한 설명을 여기에 쓰시면 됩니다.
 *
 *
 */


#include "pcap_project.h"

// 디바이스와 핸들을 하나로 묶어 관리
typedef struct Device {
  pcap_if_t *dev;
  pcap_t *handle;
} Device;

// 이곳은 전역변수 세팅하는곳으로 시작하자마자 데이터세그먼트영역에
// 메모리올리는것(extern로 헤더에 다른파일에서도 쓰겠다고 명시되어있음)
// AuthRecord whitelist[256] = {0};
// pthread_mutex_t lock = PTHREAD_MUTEX_INITIALIZER;
// pthread_cond_t cond = PTHREAD_COND_INITIALIZER;
// volatile sig_atomic_t keep_running = 1;
// int server_fd = -1;
// pcap_t *handle = NULL;  // 추후에 그냥 여기쓸거 구조체변수를 전역으로 빼볼생각 (코드정리)
//                         // 지금 devices[0].handle를 시그널함수에 가져다 못쓰기때문에(main함수에서
//                         // 구조체변수로만들어진놈이라 stack영역으로 지역변수임)
// uint8_t latest_mac_cache[256][6] = {0};
// SharedLogQueue log_queue = {0};
// AIQueue ai_queue = {0};

// // 여기서 전역변수 정의해서 메모리에올림이제 다른곳에서 그냥 변수쓰면됨
// // 더블 버퍼링기법을 활용
// DoubleBufferManager black_manager = {0};
// DoubleBufferManager white_manager = {0};

//이제 메인스택에 선언후 다 이 메모리를 포인터로써 써먹는 구조로 개편
//시그널 핸들러에서 안전한 종료 처리를 위해 오직 하나의 포인터만 전역으로
EngineContext *g_ctx = NULL;

/*!
 * @brief 시그널 핸들링 함수
 * @param[in] sig 발생한 시그널 번호
 *
 */
 void handle_sigint(int sig) {
    if (!g_ctx) return;
    
    printf("\n[Main] 종료 신호 감지! 스레드들을 깨웁니다...\n");
    g_ctx->keep_running = 0; // 깃발 내리기

    // 1. 자고 있는 만료 스레드 강제 기상 (비상벨)
    pthread_cond_signal(&g_ctx->auth.cond);

    // 2. 자고 있는 LOG 스레드 강제 기상
    pthread_cond_signal(&g_ctx->log_queue.log_cond);

    // 3. 자고 있는 AI 분석 스레드 8명 모두 강제 기상
    pthread_cond_broadcast(&g_ctx->ai_queue.cond);

    // 4. UDS 소켓 대기 깨우기
    printf("[Main] 시그널 핸들러가 조준 중인 번호: %d\n", g_ctx->server_fd);
    if (g_ctx->server_fd != -1) {
        shutdown(g_ctx->server_fd, SHUT_RDWR);
    }

    // 5. PCAP 무한루프 깨우기
    if (g_ctx->mir_handle != NULL) {
        pcap_breakloop(g_ctx->mir_handle);
    }
  }

/*!
 * @brief 메인함수
 * @return 정상 종료 시 0, 오류 발생 시 0 이외의 값
 *
 */
int main(void) {
  srand(time(NULL));
  
  EngineContext ctx = {0}; //선언과동시에초기화때 멤셋과같은역할로쓰는것
  g_ctx = &ctx; // 시그널 핸들러 연결
  ctx.keep_running = 1;
  ctx.server_fd = -1;

  // 출퇴근 및 만료 정책 기본값 세팅
  ctx.start_time = 9;
  ctx.end_time = 18;
  ctx.expire_interval = 600;

  //인증쪽 뮤텍스/조건변수 초기화
  pthread_mutex_init(&ctx.auth.lock, NULL);
    
  pthread_condattr_t attr;
  pthread_condattr_init(&attr);
  pthread_condattr_setclock(&attr, CLOCK_MONOTONIC);
  pthread_cond_init(&ctx.auth.cond, &attr);
  pthread_condattr_destroy(&attr);

  //ai 큐 뮤텍스/조건변수 초기화
  pthread_mutex_init(&ctx.ai_queue.lock, NULL);
  pthread_cond_init(&ctx.ai_queue.cond, NULL);

  //log 큐 뮤텍스/조건변수 초기화
  pthread_mutex_init(&ctx.log_queue.queue_lock, NULL);
  pthread_cond_init(&ctx.log_queue.log_cond, NULL);

  signal(SIGINT, handle_sigint); // 컨트롤 C 용 시그널
  signal(SIGTERM, handle_sigint); // 서버 재부팅, os업데이트,서비스재시작용 시그널

  char errbuf[PCAP_ERRBUF_SIZE];
  struct bpf_program filter;
  char filter_exp[] = "src net 192.168.2.0 mask 255.255.255.0 and"
                      "(tcp dst port 80 or udp dst port 53) and dst host not 192.168.3.243";

  pcap_if_t *alldevs, *target;
  Device devices[3] = {0,};

  // 1. 전체 디바이스 목록 검색 (alldevs에는 다 이시점에서 들어감 순회로)
  if (pcap_findalldevs(&alldevs, errbuf) == -1 || alldevs == NULL) {
    fprintf(stderr, "Error finding devices: %s\n", errbuf);
    return 1;
  }

  // 2. 버퍼 누수 이슈로 하나 대신해서 할당시킬 target지정
  target = alldevs;

  // eno2부터니까 일단 for문대신 두번 next
  target = target->next;
  target = target->next;

  // 3. 만든 구조체 배열에 디바이스 정보 할당
  for (int i = 0; i < 3; i++) {
    if (target == NULL) {
      fprintf(stderr, "Error: Not enough devices found!\n");
      pcap_freealldevs(alldevs);
      return 1;
    }
    devices[i].dev = target;
    target = target->next;
  }


  target = target->next;
  printf("mirror(캡쳐용) Device : %s\n", devices[0].dev->name);
  printf("Inject(인젝션용) Device  : %s\n", devices[2].dev->name);

  devices[0].handle = pcap_open_live(devices[0].dev->name, BUFSIZ, 1, 1, errbuf);
  devices[2].handle = pcap_open_live(devices[2].dev->name, BUFSIZ, 0, 0, errbuf);

  if (devices[0].handle == NULL || devices[2].handle == NULL) {
    fprintf(stderr, "디바이스를 열 수 없습니다.\n");
    pcap_freealldevs(alldevs);
    return 1;
  }

  pcap_setdirection(devices[0].handle, PCAP_D_IN);
  pcap_setdirection(devices[2].handle, PCAP_D_OUT);

  ctx.mir_handle = devices[0].handle;
  ctx.inject_handle = devices[2].handle;

  if (pcap_datalink(ctx.mir_handle) != DLT_EN10MB) {
    fprintf(stderr, "이더넷 장비가 아닙니다!\n");
    pcap_close(ctx.mir_handle);
    pcap_close(ctx.inject_handle);
    pcap_freealldevs(alldevs);
    return 1;
  }

  if (pcap_compile(ctx.mir_handle, &filter, filter_exp, 0, PCAP_NETMASK_UNKNOWN) == -1 || 
    pcap_setfilter(ctx.mir_handle, &filter) == -1) {
    fprintf(stderr, "필터 설정 실패.\n");
    pcap_close(ctx.mir_handle);
    pcap_close(ctx.inject_handle);
    pcap_freealldevs(alldevs);
    return 1;
  }

  pcap_freecode(&filter);

  //방패 깎기 및 초기 txt파일로 고정데이터 집어넣기
  ctx.black_manager.shield_A = create_hash_table();
  ctx.black_manager.shield_B = create_hash_table();
  ctx.white_manager.shield_A = create_hash_table();
  ctx.white_manager.shield_B = create_hash_table();
 
  ctx.black_manager.active_shield = ctx.black_manager.shield_A;
  ctx.white_manager.active_shield = ctx.white_manager.shield_A;

  //2번째 덮어쓰기후 노드지우면 그 도메인 ai분석가는 문제가있을수있으므로 테이블을 따로팜
  ctx.fixed_black_shield = create_hash_table();
  ctx.fixed_white_shield = create_hash_table();
  
  printf("고정 데이터 로드 중...\n");
  load_domains_from_txt(ctx.fixed_black_shield, "/tmp/ai_blacklist.txt", LOG_MANUAL_BLOCK, -1);
  load_domains_from_txt(ctx.fixed_white_shield, "/tmp/ai_whitelist.txt", LOG_MANUAL_PASS, -1);

  // 스레드 가동
  pthread_t uds_tid, clean_tid, log_tid;
  pthread_t ai_threads[AI_WORKERS];

  typedef struct {
        EngineContext *ctx_ptr;
        int id;
    } WorkerArgs;
    WorkerArgs w_args[AI_WORKERS]; //ai스레드에 넘길변수 

 if (pthread_create(&uds_tid, NULL, uds_server_thread, &ctx) != 0) {
        fprintf(stderr, "UDS 수신 스레드 생성 실패\n");
        return 1;
    }

  // uds쓰레드 열었으면 초기동기화 진행
  printf("\n========= [시스템] Django/Flask 초기 동기화 요청 중 =========\n");

  // 파이썬 스크립트가 실행을 마치고 꺼질 때까지 main 함수는 여기서 블락
  system("/root/intranet-access-controller/sungkwang-pcap/pcap_webServer/venv/bin/python /root/intranet-access-controller/sungkwang-pcap/pcap_webServer/sync_runner.py &");

  printf("[시스템] 백그라운드 동기화 셋업 완료! PCAP 패킷 감시를 시작합니다.\n\n");


  // 나머지 스레드 가동
  if (pthread_create(&clean_tid, NULL, clean_thread, &ctx) != 0) {
    fprintf(stderr, "스마트 만료 스레드 생성 실패\n");
    return 1;
  }

  if (pthread_create(&log_tid, NULL, log_thread, &ctx) != 0) {
    fprintf(stderr, "로그 전송 스레드 생성 실패\n");
    return 1;
  }

  for (int i = 0; i < AI_WORKERS; i++) {
    w_args[i].ctx_ptr = &ctx;
    w_args[i].id = i + 1;
    if (pthread_create(&ai_threads[i], NULL, ai_worker_thread, &w_args[i]) != 0) {
      perror("AI 워커 스레드 생성 실패");
      return 1;
    }
    printf("[Main] AI 헌터 스레드 %d번 대기조 편성 완료\n", w_args[i].id);
  }

  // 루프시작(인젝트는 args로 넘김)
  pcap_loop(ctx.mir_handle, 0, packet_handler, (u_char *)&ctx);

  // 자원반납(역순)
  pcap_close(devices[0].handle);
  pcap_close(devices[2].handle);


  
 pthread_join(log_tid, NULL);
  for (int i = 0; i < AI_WORKERS; i++) {
    pthread_join(ai_threads[i], NULL);
  }
  pthread_join(clean_tid, NULL);
  pthread_join(uds_tid, NULL); 

  unlink(SOCKET_PATH);

  pthread_mutex_destroy(&ctx.auth.lock);
  pthread_cond_destroy(&ctx.auth.cond);

  pthread_mutex_destroy(&ctx.ai_queue.lock);
  pthread_cond_destroy(&ctx.ai_queue.cond);

  pthread_mutex_destroy(&ctx.log_queue.queue_lock);
  pthread_cond_destroy(&ctx.log_queue.log_cond);

  pcap_freealldevs(alldevs);

  if (ctx.black_manager.shield_A) free_hash_table(ctx.black_manager.shield_A); 
  if (ctx.black_manager.shield_B) free_hash_table(ctx.black_manager.shield_B);
  if (ctx.white_manager.shield_A) free_hash_table(ctx.white_manager.shield_A); 
  if (ctx.white_manager.shield_B) free_hash_table(ctx.white_manager.shield_B);

  printf("\nLoop 이후 자원반납 깔끔하게 싹 하고 return 0 됨\n");

  return 0;
}
