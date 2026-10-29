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

      // [1단계 파싱] 제일 앞에 있는 명령어(command) 한 단어만 먼저 추출
      if (sscanf(buffer, "%15s", command) == 1) {

        // =================================================================
        // [신규] 1. 도메인 델타 업데이트 (ADD_BLACK, DEL_BLACK, ADD_WHITE, DEL_WHITE)
        // =================================================================
        if (strcmp(command, "ADD_BLACK") == 0 || strcmp(command, "DEL_BLACK") == 0 ||
            strcmp(command, "ADD_WHITE") == 0 || strcmp(command, "DEL_WHITE") == 0) {

          char domain[256] = {0};
          // 명령어 다음 문자열(hacker.com 등)을 추출 (%*s는 첫 번째 문자열 무시)
          if (sscanf(buffer, "%*s %255s", domain) == 1) {

            // 타겟 방패 매니저 확인 및 동작 플래그 설정
            DoubleBufferManager *target_manager = (strstr(command, "BLACK") != NULL) ? &black_manager : &white_manager;
            int is_add = (strncmp(command, "ADD", 3) == 0) ? 1 : 0;
            int log_type = (target_manager == &black_manager) ? LOG_MANUAL_BLOCK : LOG_MANUAL_PASS;

            // 1. 현재 뒤에서 쉬고 있는 예비 방패(Standby) 찾기
            HashTable *standby_shield = (target_manager->active_shield == target_manager->shield_A) ? target_manager->shield_B : target_manager->shield_A;

            // 2. 쉬고 있는 방패에 도메인 1개 추가 또는 삭제 (락 없음!)
            if (is_add) {
                insert_hash_table(standby_shield, domain, log_type);
            } else {
                delete_from_hash_table(standby_shield, domain); 
            }

            // 3. [0초 컷 교체] 패킷 검사 스레드의 시선을 새 방패로 휙 돌림 (Swap)
            __atomic_store_n(&target_manager->active_shield, standby_shield, __ATOMIC_SEQ_CST);

            // 4. 뒤로 밀려나 쉬게 된 구형 방패 동기화
            HashTable *old_active_shield = (standby_shield == target_manager->shield_A) ? target_manager->shield_B : target_manager->shield_A;

            if (is_add) {
                insert_hash_table(old_active_shield, domain, log_type);
            } else {
                delete_from_hash_table(old_active_shield, domain);
            }

            printf("[UDS 스레드] 무중단 %s 완료: %s\n", command, domain);
          }
        }
        // =================================================================
        // [기존] 2. IP/MAC 기반 제어 (GETMAC, AUTH, EXPIRE, RESTORE)
        // =================================================================
        else {
          int host_id = -1;
          char mac_str[20] = {0};
          long long expire_timestamp = 0;

          // %*s를 통해 명령어(command)는 건너뛰고 나머지 숫자/문자열 파싱
          if (sscanf(buffer, "%*s %d %19s %lld", &host_id, mac_str, &expire_timestamp) >= 1) {
            if (host_id >= 0 && host_id < 254) {

              // 2-1. GETMAC 처리 (락 불필요)
              if (strcmp(command, "GETMAC") == 0) {
                int is_empty = 1;
                for (int i = 0; i < 6; i++) {
                  if (latest_mac_cache[host_id][i] != 0) {
                    is_empty = 0;
                    break;
                  }
                }
                if (is_empty) {
                  write(client_fd, "00:00:00:00:00:00", 17);
                } else {
                  char response[32] = {0};
                  struct ether_addr *mac_ptr = (struct ether_addr *)latest_mac_cache[host_id];
                  ether_ntoa_r(mac_ptr, response);
                  write(client_fd, response, strlen(response));
                }
              }
              // 2-2. AUTH, EXPIRE, RESTORE 처리 (뮤텍스 락 진입)
              else {
                pthread_mutex_lock(&lock);

                // 1. 신규 인증 (AUTH)
                if (strcmp(command, "AUTH") == 0 && mac_str[0] != '\0') {
                  struct ether_addr *mac_ptr = ether_aton(mac_str);
                  if (mac_ptr != NULL) {
                    memcpy(whitelist[host_id].mac_addr, mac_ptr->ether_addr_octet, ETH_ALEN);
                    whitelist[host_id].is_active = 1;
                    whitelist[host_id].is_mac_bound = 1;
                    whitelist[host_id].last_seen = cur_time;
                    whitelist[host_id].expire_time = cur_time + 600;
                    printf("[UDS 스레드] Host ID %d 신규 인증 완료! (MAC: %s)\n", host_id, mac_str);
                  } else {
                    printf("[UDS 에러] 잘못된 MAC 문자열 형식입니다: %s\n", mac_str);
                  }
                }
                // 2. 중복 로그인 밀어내기 (EXPIRE)
                else if (strcmp(command, "EXPIRE") == 0) {
                  whitelist[host_id].is_active = 0;
                  whitelist[host_id].is_mac_bound = 0;
                  memset(whitelist[host_id].mac_addr, 0, 6);
                  whitelist[host_id].last_seen = 0;
                  whitelist[host_id].expire_time = 0;
                  printf("[UDS 스레드] Host ID %d 강제 퇴출.\n", host_id);
                }
                // 3. 서버 재시작시 초기동기화 (RESTORE)
                else if (strcmp(command, "RESTORE") == 0) {
                  struct ether_addr mac_struct;
                  struct ether_addr *mac_ptr = ether_aton_r(mac_str, &mac_struct);
                  if (mac_ptr != NULL) {
                    memcpy(whitelist[host_id].mac_addr, mac_ptr->ether_addr_octet, ETH_ALEN);
                    whitelist[host_id].is_active = 1;
                    whitelist[host_id].is_mac_bound = 1;
                    whitelist[host_id].last_seen = cur_time;
                    whitelist[host_id].expire_time = (time_t)expire_timestamp;
                    printf("[UDS 복구] Host ID %d 복구 완료! (MAC: %s)\n", host_id, mac_str);
                  }
                }
                // ※ RELOAD 로직 완전 삭제됨

                // 디버깅 출력
                printf("\n=== [현재 인증된 IP 목록] ===\n");
                for (int i = 0; i < 254; i++) {
                  if (whitelist[i].is_active == 1) {
                    printf(" 인증됨: Host ID %d / MAC: %s\n", i, ether_ntoa((struct ether_addr *)whitelist[i].mac_addr));
                  }
                }
                printf("=============================\n\n");

                pthread_mutex_unlock(&lock);
              }
            }
          }
        }
      }
    }
    close(client_fd);
  }

  return NULL;
}