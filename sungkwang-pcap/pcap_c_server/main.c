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

  //환경에따라서 인터페이스 순서가 변경되면 이상한 인터페이스가지고 놀수도있으니 하드코딩으로 바꿈
  const char *mir_dev = "eno2";    // 미러링 패킷 캡처용
  const char *inject_dev = "eno4"; // 차단 패킷 인젝션용      
               

  ctx.mir_handle = pcap_open_live(mir_dev, BUFSIZ, 1, 1, errbuf);
  if (ctx.mir_handle == NULL) {
    fprintf(stderr, "캡처 디바이스(%s)를 열 수 없습니다: %s\n", mir_dev, errbuf);
    return 1;
  }

  ctx.inject_handle = pcap_open_live(inject_dev, BUFSIZ, 0, 0, errbuf);
  if (ctx.inject_handle == NULL) {
    fprintf(stderr, "인젝션 디바이스(%s)를 열 수 없습니다: %s\n", inject_dev, errbuf);
    pcap_close(ctx.mir_handle); // 먼저 열었던 캡처 핸들 닫기
    return 1;
  }

  pcap_setdirection(ctx.mir_handle, PCAP_D_IN);
  pcap_setdirection(ctx.inject_handle, PCAP_D_OUT);

  if (pcap_datalink(ctx.mir_handle) != DLT_EN10MB) {
    fprintf(stderr, "이더넷 장비가 아닙니다!\n");
    pcap_close(ctx.mir_handle);
    pcap_close(ctx.inject_handle);
    return 1;
  }
  if (pcap_datalink(ctx.inject_handle) != DLT_EN10MB) {
    fprintf(stderr, "이더넷 장비가 아닙니다!\n");
    pcap_close(ctx.mir_handle);
    pcap_close(ctx.inject_handle);
    return 1;
  }

 if (pcap_compile(ctx.mir_handle, &filter, filter_exp, 0, PCAP_NETMASK_UNKNOWN) == -1) {
    fprintf(stderr, "필터 컴파일 실패: %s\n", pcap_geterr(ctx.mir_handle));
    pcap_close(ctx.mir_handle);
    pcap_close(ctx.inject_handle);
    return 1;
  }

  if (pcap_setfilter(ctx.mir_handle, &filter) == -1) {
    fprintf(stderr, "필터 적용 실패: %s\n", pcap_geterr(ctx.mir_handle));
    pcap_freecode(&filter); 
    pcap_close(ctx.mir_handle);
    pcap_close(ctx.inject_handle);
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
  pcap_close(ctx.inject_handle);
  pcap_close(ctx.mir_handle);


  
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


  if (ctx.black_manager.shield_A) free_hash_table(ctx.black_manager.shield_A); 
  if (ctx.black_manager.shield_B) free_hash_table(ctx.black_manager.shield_B);
  if (ctx.white_manager.shield_A) free_hash_table(ctx.white_manager.shield_A); 
  if (ctx.white_manager.shield_B) free_hash_table(ctx.white_manager.shield_B);

  printf("\nLoop 이후 자원반납 깔끔하게 싹 하고 return 0 됨\n");

  return 0;
}
