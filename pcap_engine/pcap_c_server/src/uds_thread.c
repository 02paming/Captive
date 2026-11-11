#include "pcap_common.h"
#include "thread_workers.h"  
#include "hash_manager.h"   
#include "pcap_utils.h"      
void *uds_server_thread(void *arg) {

  EngineContext *ctx = (EngineContext *)arg;

  int client_fd;
  struct sockaddr_un addr;
  char buffer[512]; // 명령어 처리를 위해 버퍼를 약간 여유있게 늘림

  ctx->server_fd = socket(AF_UNIX, SOCK_STREAM, 0);
  printf("[UDS 스레드] 방금 만든 소켓 번호: %d\n", ctx->server_fd);
  if (ctx->server_fd < 0) {
    SYSTEM_LOG(LOG_ERR, "[에러] UDS 소켓 생성 실패");
    return NULL;
  }

  unlink(SOCKET_PATH); // 끄기전 기존 uds서버역할을한 파일경로 지우고가기 rm느낌

  memset(&addr, 0, sizeof(addr));
  addr.sun_family = AF_UNIX;
  strncpy(addr.sun_path, SOCKET_PATH, sizeof(addr.sun_path) - 1);

  if (bind(ctx->server_fd, (struct sockaddr *)&addr, sizeof(addr)) < 0) {
    SYSTEM_LOG(LOG_ERR, "[에러] UDS 바인드 실패");
    close(ctx->server_fd);
    return NULL;
  }
  if (chmod(SOCKET_PATH, 0666) == -1) {
    SYSTEM_LOG(LOG_ERR, "[에러] chmod 오류");
}

  if (listen(ctx->server_fd, 5) < 0) {
    SYSTEM_LOG(LOG_ERR, "[에러] UDS 리슨 실패");
    close(ctx->server_fd);
    return NULL;
  }

  while (ctx->keep_running) {
    client_fd = accept(ctx->server_fd, NULL, NULL);
    if (client_fd < 0) {
      SYSTEM_LOG(LOG_INFO, "[UDS 스레드] 종료 신호 확인.");
      if (!ctx->keep_running)
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
          char source[32] = "USER";
          double ai_score = -1.0;
            
          // 명령어 다음 문자열(hacker.com 등)을 추출 (%*s는 첫 번째 문자열 무시)
          if (sscanf(buffer, "%*s %255s %31s %lf", domain, source, &ai_score) >= 1) {
              //  printf("%.2f\n",ai_score);
            // 타겟 방패 매니저 확인 및 동작 플래그 설정
            DoubleBufferManager *target_manager = (strstr(command, "BLACK") != NULL) ? &ctx->black_manager : &ctx->white_manager;

            int is_add = (strncmp(command, "ADD", 3) == 0) ? 1 : 0;
            int log_type;
            if (target_manager == &ctx->black_manager) {
                if (strcmp(source, "AI") == 0) log_type = LOG_AI_BLOCK;
                else if (strcmp(source, "DOUBT") == 0) log_type = LOG_AI_DOUBT_BLOCK;
                else log_type = LOG_MANUAL_BLOCK; // USER
            } else {
                if (strcmp(source, "AI") == 0) log_type = LOG_AI_PASS;
                else if (strcmp(source, "DOUBT") == 0) log_type = LOG_AI_DOUBT_PASS;
                else log_type = LOG_MANUAL_PASS; // USER
            }

            // 1. 현재 뒤에서 쉬고 있는 예비 방패(Standby) 찾기
            HashTable *standby_shield = (target_manager->active_shield == target_manager->shield_A) ? target_manager->shield_B : target_manager->shield_A;

            // 2. 쉬고 있는 방패에 도메인 1개 추가 또는 삭제 (락 없음!)
            if (is_add) {
                insert_hash_table(standby_shield, domain, log_type, ai_score);
            } else {
                delete_from_hash_table(standby_shield, domain); 
            }

            // 3. [0초 컷 교체] 패킷 검사 스레드의 시선을 새 방패로 휙 돌림 (Swap)
            __atomic_store_n(&target_manager->active_shield, standby_shield, __ATOMIC_SEQ_CST);

            // 4. 뒤로 밀려나 쉬게 된 구형 방패 동기화
            HashTable *old_active_shield = (standby_shield == target_manager->shield_A) ? target_manager->shield_B : target_manager->shield_A;

            if (is_add) {
                insert_hash_table(old_active_shield, domain, log_type, ai_score);
            } else {
                delete_from_hash_table(old_active_shield, domain);
            }

            SYSTEM_LOG(LOG_INFO, "[UDS 스레드] 무중단 %s 완료: %s",command, domain);
          }
        }
        // =================================================================
        // 2. [신규 병합] 정책 갱신 (POLICY 출근 퇴근 주기)
        // =================================================================
        else if (strcmp(command, "POLICY") == 0) {
          int start_h, end_h, interval_sec;
          if (sscanf(buffer + 7, "%d %d %d", &start_h, &end_h, &interval_sec) == 3) {
              
            pthread_mutex_lock(&ctx->auth.lock);
            ctx->start_time = start_h;
            ctx->end_time = end_h;
            ctx->expire_interval = interval_sec;

            //  바뀐 정책을 즉시 반영하기 위해 자고 있는 스마트 만료 스레드를 강제로 깨웁니다!
            pthread_cond_signal(&ctx->auth.cond);
            pthread_mutex_unlock(&ctx->auth.lock);

            SYSTEM_LOG(LOG_INFO, "-> [UDS 스레드 정책 갱신] 근무시간 %d시~%d시, 미활동 대기 %d초",start_h, end_h, interval_sec);
          }
        }
        // =================================================================
        //  3. IP/MAC 기반 제어 (GETMAC, AUTH, EXPIRE, RESTORE)
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
                if (sscanf(buffer, "%*s %d", &host_id) == 1 && host_id > 0 && host_id < 254) {
                  int is_empty = 1;
                  for (int i = 0; i < 6; i++) {
                      if (ctx->auth.latest_mac_cache[host_id][i] != 0) {
                          is_empty = 0;
                          break;
                      }
                  }
                  if (is_empty) {
                      write(client_fd, "00:00:00:00:00:00", 17);
                  } else {
                      // char response[32] = {0};
                      // struct ether_addr *mac_ptr = (struct ether_addr *)ctx->auth.latest_mac_cache[host_id];
                      // ether_ntoa_r(mac_ptr, response);
                      char response[18] = {0}; // 맥17글자 + NULL 문자 공간
                      mac_to_string(ctx->auth.latest_mac_cache[host_id], response);
                      write(client_fd, response, strlen(response));
                  }
                }
              }
              // 2-2. AUTH, EXPIRE, RESTORE 처리 (뮤텍스 락 진입)
              else if (strcmp(command, "EXPIRE") == 0 || strcmp(command, "DEL") == 0 || strcmp(command, "KICK") == 0) {
                // 세 명령어 모두 "IP 강제 만료"를 의미함
                if (sscanf(buffer, "%*s %d", &host_id) == 1 && host_id > 0 && host_id < 254) {
                    pthread_mutex_lock(&ctx->auth.lock);
                    ctx->auth.records[host_id].is_active = 0;
                    ctx->auth.records[host_id].is_mac_bound = 0;
                    ctx->auth.records[host_id].last_seen = 0;
                    memset(ctx->auth.records[host_id].mac_addr, 0, ETH_ALEN);
                    pthread_mutex_unlock(&ctx->auth.lock);
                    SYSTEM_LOG(LOG_INFO, "[UDS 스레드] Host ID %d 강제 퇴출 (%s).",host_id, command);
                }
              }
              else if (strcmp(command, "AUTH") == 0 || strcmp(command, "RESTORE") == 0) {
                // 뒤에 MAC 주소와 기타 정보가 붙어오는 신규 인증/복구
                if (sscanf(buffer, "%*s %d %19s", &host_id, mac_str) >= 2 && host_id > 0 && host_id < 254) {
                  pthread_mutex_lock(&ctx->auth.lock);
                  struct ether_addr *mac_ptr = ether_aton(mac_str);
                  if (mac_ptr != NULL) {
                      memcpy(ctx->auth.records[host_id].mac_addr, mac_ptr->ether_addr_octet, ETH_ALEN);
                      ctx->auth.records[host_id].is_active = 1;
                      ctx->auth.records[host_id].is_mac_bound = 1;
                      ctx->auth.records[host_id].last_seen = cur_time;
                      // expire_time 할당 로직은 스마트 만료 도입으로 인해 완벽히 삭제됨
                      SYSTEM_LOG(LOG_INFO, "[UDS 스레드] Host ID %d 인증/복구 완료! (MAC: %s)", host_id, mac_str);
                  } else {
                      SYSTEM_LOG(LOG_ERR, "[UDS 에러] 잘못된 MAC 문자열 형식: %s",mac_str);
                  }
                  pthread_mutex_unlock(&ctx->auth.lock);
                }
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