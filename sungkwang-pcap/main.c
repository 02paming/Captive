#include "pcap_project.h"

// 디바이스와 핸들을 하나로 묶어 관리
typedef struct Device {
  pcap_if_t *dev;
  pcap_t *handle;
} Device;


AuthRecord whitelist[256] = {0}; 
pthread_mutex_t lock = PTHREAD_MUTEX_INITIALIZER;
pthread_cond_t cond = PTHREAD_COND_INITIALIZER;
volatile sig_atomic_t keep_running = 1;
int server_fd = -1;
pcap_t* handle = NULL; //추후에 그냥 여기쓸거 구조체변수를 전역으로 빼볼생각 (코드정리)
//지금 devices[0].handle를 시그널함수에 가져다 못쓰기때문에(main함수에서 구조체변수로만들어진놈이라 stack영역으로 지역변수임)
uint8_t latest_mac_cache[256][6] = {0};
BlackListInfo check_manager;

void handle_sigint(int sig) {
    printf("\n[Main] 종료 신호 감지! 스레드들을 깨웁니다...\n");
    keep_running = 0; // 깃발 내리기
    
    // 1. 자고 있는 GC 스레드 강제 기상 (비상벨)
    pthread_cond_signal(&cond);
    
    // 2. UDS 소켓 대기 깨우기
    printf("[Main] 시그널 핸들러가 조준 중인 번호: %d\n", server_fd);
    if (server_fd != -1){
      shutdown(server_fd, SHUT_RDWR);
    }
    
    // 3. PCAP 무한루프 깨우기
    if (handle != NULL) 
    pcap_breakloop(handle);
    
}

int main(void) {

  //블랙리스트 구조체 전역변수 초기화구문
  for (int i = 0; i < MAX_BLACKLIST_COUNT; i++)
    check_manager.target_url[i] = NULL;
  check_manager.count = 0;
  pthread_mutex_init(&check_manager.lock, NULL);  
  
  load_blacklist();

  signal(SIGINT, handle_sigint); //컨트롤 C 용 시그널
  signal(SIGTERM, handle_sigint); // 서버 재부팅, os업데이트,서비스재시작용 시그널

  char errbuf[PCAP_ERRBUF_SIZE];
  struct bpf_program filter;
  char filter_exp[] = "src net 192.168.2.0 mask 255.255.255.0 and tcp "
                        "dst port 80 and dst host not 192.168.3.243";

  pcap_if_t *alldevs, *target;
  Device devices[3] = {
      0,
  };

  //뮤텍스 초기화
  if (pthread_mutex_init(&lock, NULL) != 0) {
        fprintf(stderr, "뮤텍스 초기화 실패\n");
        return 1;
  }

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

  pthread_condattr_t attr;
  pthread_condattr_init(&attr);
  pthread_condattr_setclock(&attr, CLOCK_MONOTONIC);
  pthread_cond_init(&cond, &attr);
  pthread_condattr_destroy(&attr);

  // 3.5 UDS 수신 대기하는 스레드 생성
  pthread_t uds_tid,clean_tid;
    if (pthread_create(&uds_tid, NULL, uds_server_thread, NULL) != 0) {
        fprintf(stderr, "UDS 스레드 생성 실패\n");
        return 1;
    }

//uds쓰레드 열었으면 초기동기화 진행 
    printf("[시스템] 초기 동기화 스크립트를 실행합니다...\n");
    
    // 파이썬 스크립트가 실행을 마치고 꺼질 때까지 main 함수는 여기서 블락
    system("/root/Captive_Web/venv/bin/python /root/intranet-access-controller/sungkwang-pcap/sync_runner.py"); //가상환경의 파이썬에서 

    //동기화가 완전히 끝난 후 아래코드들 진행
    printf("[시스템] 동기화 완료! PCAP 패킷 감시를 시작합니다.\n");

    if (pthread_create(&clean_tid, NULL, clean_thread, NULL) != 0) {
        fprintf(stderr, "clean 스레드 생성 실패\n");
        return 1;
    }

  // 4. 배열을 활용한 지정한 디바이스를통한 핸들세션 열기
  devices[0].handle = pcap_open_live(devices[0].dev->name, BUFSIZ, 1, 1, errbuf); // rx (Promisc) 패킷을 들어오게끔만
  devices[2].handle = pcap_open_live(devices[2].dev->name, BUFSIZ, 0, 0, errbuf); // tx 패킷이 나가게만

  if (devices[0].handle == NULL || devices[2].handle == NULL) {
    fprintf(stderr, "Couldn't open devices.\n");
    pcap_freealldevs(alldevs);
    return 1;
  }

  handle = devices[0].handle; //pcap_loop 핸들 전역변수에 쓰기 (pcap_loop 부수는용)

  pcap_setdirection(devices[0].handle, PCAP_D_IN);  // rx
  pcap_setdirection(devices[2].handle, PCAP_D_OUT); // tx

  // 5. 캡처 디바이스의 데이터링크 검증
  if (pcap_datalink(devices[0].handle) != DLT_EN10MB) {
    fprintf(stderr, "Error: Device %s 은 이더넷이 아닙니다!\n",
            devices[0].dev->name);
    pcap_close(devices[0].handle);
    pcap_close(devices[2].handle);
    pcap_freealldevs(alldevs);
    return 1;
  }

  // 6. 필터 컴파일 적용
  // setfilter는 컴파일함수와 한세트이므로 그냥 || 으로 묶고 자원반납구문 줄임
  if (pcap_compile(devices[0].handle, &filter, filter_exp, 0, PCAP_NETMASK_UNKNOWN) == -1 || pcap_setfilter(devices[0].handle, &filter) == -1) {
    fprintf(stderr, "Filter setup failed.\n");
    pcap_close(devices[0].handle);
    pcap_close(devices[2].handle);
    pcap_freealldevs(alldevs);
    return 1;
  }
  pcap_freecode(&filter);

  // 7. 루프시작(인젝트는 args로 넘김)
  pcap_loop(devices[0].handle, 0, packet_handler, (u_char *)devices[2].handle);

  // // 8. 자원반납(역순)
  pcap_close(devices[0].handle);
  pcap_close(devices[2].handle);

  pthread_join(clean_tid,NULL);
  pthread_join(uds_tid, NULL); //실제로 종료될때까지 현재 스레드가 대기, 과거 좀비프로세스 마냥 이 과정이없으면 스레드가 좀비로 남아있을수있음
  unlink(SOCKET_PATH); // 끄기전 기존 uds서버역할을한 파일경로 지우고가기 rm느낌

  pthread_mutex_destroy(&lock);
  pthread_cond_destroy(&cond);

  pcap_freealldevs(alldevs);
  printf("loop 이후 자원반납 깔끔하게 싹 하고 return 0 됨\n");


  return 0;
}