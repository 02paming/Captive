#include "pcap_project.h"

void *uds_server_thread(void *arg) {

  int client_fd;
  struct sockaddr_un addr;
  char buffer[128]; // 명령어 처리를 위해 버퍼를 약간 여유있게 늘림

  server_fd = socket(AF_UNIX, SOCK_STREAM, 0);
  printf("[UDS 스레드] 방금 만든 소켓 번호: %d\n", server_fd);
  if (server_fd < 0) {
    perror("UDS 소켓 생성 실패");
    return NULL;
  }

  unlink(SOCKET_PATH); // 끄기전 기존 uds서버역할을한 파일경로 지우고가기 rm느낌

  memset(&addr, 0, sizeof(addr));
  addr.sun_family = AF_UNIX;
  strncpy(addr.sun_path, SOCKET_PATH, sizeof(addr.sun_path) - 1);

  if (bind(server_fd, (struct sockaddr *)&addr, sizeof(addr)) < 0) {
    perror("UDS 바인드 실패");
    close(server_fd);
    return NULL;
  }

  if (listen(server_fd, 5) < 0) {
    perror("UDS 리슨 실패");
    close(server_fd);
    return NULL;
  }

  while (keep_running) {
    // printf("1. [UDS 스레드] accept 대기 중...\n");
    client_fd = accept(server_fd, NULL, NULL);
    if (client_fd < 0) {
      printf("[UDS 스레드] 종료 신호 확인.\n");
      if (!keep_running)
        break;
      continue;
    }
    time_t cur_time = time(NULL);

    int read_bytes = read(client_fd, buffer, sizeof(buffer) - 1);
    if (read_bytes > 0) {
      buffer[read_bytes] = '\0';

      char command[16] = {0};
      int host_id = -1;
      char mac_str[20] = {0};
      long long expire_timestamp = 0;

      // 파이썬에서 명령어, IP, MAC문자열을 통으로 전송
      // sscanf를 사용해 문자열과 정수같이 파싱하는구조진행해봄  buffer의
      // 공백까지만이라 auth 55 mac주소 이렇게있을때 딱딱 파싱이됨
      if (sscanf(buffer, "%15s %d %19s %lld", command, &host_id, mac_str, &expire_timestamp) >= 2) {

        // 배열 범위 초과 방지(게이트웨이,브로드캐스트 제외)
        if (host_id >= 0 && host_id < 254) {

          // [추가된 로직] 0. 파이썬의 MAC 조회 요청 (GETMAC) 처리
          // printf("2. [UDS 스레드] 클라이언트 연결됨! 데이터 읽기 시작...\n");
          if (strcmp(command, "GETMAC") == 0) {

            // 캐시에 값이 비어있는지(00:00...) 먼저 확인
            int is_empty = 1;
            for (int i = 0; i < 6; i++) {
              if (latest_mac_cache[host_id][i] != 0) {
                is_empty = 0;
                break;
              }
            }

            // 비어있다면 에러 포맷 전송, 값이 있다면 문자열로 예쁘게 변환해서
            // 전송
            if (is_empty) {
              write(client_fd, "00:00:00:00:00:00", 17); // 비어있다면 이렇게보내겠다.
            } else {
              char response[32] = {0};
              struct ether_addr *mac_ptr = (struct ether_addr *)latest_mac_cache[host_id];
              ether_ntoa_r(mac_ptr, response); // ether_ntoa_r를 사용해 스레드
                                               // 안전하게 문자열 반환
              write(client_fd, response, strlen(response));
            }
          }
          // [기존 로직] AUTH, EXPIRE 등 화이트리스트 배열을 조작하는 로직은
          // 뮤텍스 락 안으로 진입
          else {
            // 뮤텍스라는 개념을 공부함
            // 여러스레드가 하나뿐인 공용장소를(지금으로썬 화이트리스트배열)
            // 동시에 건드려 데이터가 꼬이는걸 방지 지금 uds스레드에선
            // 인증완료(1)라고 적는곳 pcap스레드에선 계속지나가는 패킷을
            // 검수하며 화이트리스트배열을 읽는곳 이때 적고있는중에 읽는다면
            // 오작동이날수있음 이를 방지하기위해 배열의 값을 변경하거나
            // 읽어오는 그 아주 짧은 찰나의 순간에, 절대 두 스레드가 동시에
            // 접근하지 못하도록 방지하는 개념 공용으로읽을메모리는
            // 보관함에넣어두고 필요할때는 열쇠를 들고갓다가 반납해라는 개념

            pthread_mutex_lock(&lock);

            // 1. 신규 인증 (AUTH) 처리
            if (strcmp(command, "AUTH") == 0 && mac_str[0] != '\0') { // 맥이 비어있지않나까지 보고 들어가야함

              struct ether_addr *mac_ptr = ether_aton(mac_str); //만약 accept하자마자 쓰레드를 만들어서 그곳에서 이 할일들을하는구조였다면 ether_aton_r 구조로해야함
              //현재 이 uds수신쓰레드 자체는 싱글스레드이기때문에 그냥 이거 써도됨써도됨

              if (mac_ptr != NULL) {
                memcpy(whitelist[host_id].mac_addr, mac_ptr->ether_addr_octet, ETH_ALEN);

                whitelist[host_id].is_active = 1;
                whitelist[host_id].is_mac_bound = 1;
                whitelist[host_id].last_seen = cur_time;
                whitelist[host_id].expire_time = cur_time + 600; // 테스트용 1분

                printf("[UDS 스레드] Host ID %d 신규 인증 완료! (MAC: %s)\n", host_id, mac_str);
              } else {
                printf("[UDS 에러] 잘못된 MAC 문자열 형식입니다: %s\n", mac_str);
              }
            }
            // 2. 중복 로그인 밀어내기 (EXPIRE) 처리
            else if (strcmp(command, "EXPIRE") == 0) {
              whitelist[host_id].is_active = 0;
              whitelist[host_id].is_mac_bound = 0; // MAC 바인딩 해제
              memset(whitelist[host_id].mac_addr, 0, 6); // ETH_ALEN(6바이트) MAC 주소 완벽 삭제
              whitelist[host_id].last_seen = 0;
              whitelist[host_id].expire_time = 0;

              printf("[UDS 스레드] Host ID %d 중복 로그인으로 강제 퇴출 혹은 관리자에의한 강제 인증해제.\n", host_id);
            }

            // 3. 서버 재시작시 초기동기화 (RESTORE) 처리
            else if (strcmp(command, "RESTORE") == 0) {
              struct ether_addr mac_struct;
              struct ether_addr *mac_ptr = ether_aton_r(mac_str, &mac_struct); // 문자열맥을 네트워크단위로 aton한값
                                         // mac_struct의 주소값을 이더넷주소
                                         // 포인터변수에 저장
              // uint8_t ether_addr_octet[ETH_ALEN]; 에 저장한것

              if (mac_ptr != NULL) {
                memcpy(whitelist[host_id].mac_addr, mac_ptr->ether_addr_octet, ETH_ALEN);
                whitelist[host_id].is_active = 1;
                whitelist[host_id].is_mac_bound = 1;
                //  복구 시점 기준 미활동 타이머(7일)는 리셋하고 절대
                //  만료시간(30일)은 리셋되지말고 불러오는개념
                whitelist[host_id].last_seen = cur_time;
                whitelist[host_id].expire_time = (time_t)expire_timestamp;

                printf("[UDS 복구] Host ID %d 복구 완료! (MAC: %s, 만료시간: %ld)\n", host_id, mac_str, whitelist[host_id].expire_time - cur_time);
              }
            }

            else if (strcmp(command, "RELOAD") == 0) {
              printf("UDS 스레드: 관리자가 차단사이트를 갱신함\n");

              // 현재 화이트리스트 뮤텍스(&lock) 안쪽이므로,
              // 블랙리스트 전용 뮤텍스(&check_manager.lock)만 안전하게 추가로
              // 잠금 후 실행 pthread_mutex_lock(&check_manager.lock);
              // load_blacklist();
              // pthread_mutex_unlock(&check_manager.lock);

              // printf("[갱신완료] 경로 -> \"/tmp/blacklist.txt\", 현재
              // 차단사이트: [%d]개\n", check_manager.count);

              // 1. 현재 뒤에서 쉬고 있는 예비 방패(Background Shield)가 A인지
              // B인지 찾기
              HashTable *bg_shield = (black_manager.active_shield == black_manager.shield_A) ? black_manager.shield_B : black_manager.shield_A;

              // 2. 예비 방패 초기화 및 최신 도메인 파일 2개 이어서 덮어쓰기
              clear_hash_table(bg_shield); // 기존 찌꺼기 제거
              load_domains_from_txt(bg_shield, "/tmp/blacklist.txt",LOG_MANUAL_BLOCK);
              load_domains_from_txt(bg_shield,"/tmp/ai_blacklist.txt",LOG_AI_BLOCK); // AI 파일도 잊지 말고 합치기!

              // 3. [가장 중요한 0초 컷 교체] 패킷 검사 스레드의 시선을 새
              // 방패로 원자적(Atomic)으로 돌림
              __atomic_store_n(&black_manager.active_shield, bg_shield, __ATOMIC_SEQ_CST);

              printf("[C엔진] 무중단 RELOAD 완료! (수동+AI 도메인 병합됨)\n");
            }

            // 디버깅용 리스트 출력
            printf("\n=== [현재 인증된 IP 목록] ===\n");
            for (int i = 0; i < 254; i++) {
              if (whitelist[i].is_active == 1) {
                printf(" 인증됨: Host ID %d\n", i);
                printf(" 인증된 맥주소 : MAC %s\n", ether_ntoa((struct ether_addr *)whitelist[i].mac_addr));
              }
            }
            printf("=============================\n\n");

            pthread_mutex_unlock(&lock);
          }
        }
      }
    }
    close(client_fd);
    // printf("3. [UDS 스레드] 클라이언트 종료 및 통신 완료. 다시
    // 돌아갑니다!\n\n");
  }

  return NULL;
}