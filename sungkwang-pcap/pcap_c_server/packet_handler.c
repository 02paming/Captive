#include "pcap_project.h"

// time_t last_time[256] = {0}; // IP별 마지막 접속 시간(초) 기록

void packet_handler(u_char *user_args, const struct pcap_pkthdr *header, const u_char *packet) {
  EngineContext *ctx = (EngineContext *)user_args;

  pcap_t *handle_inject = ctx->inject_handle;

  if (header->caplen < sizeof(struct ether_header)) return;
  struct ether_header *ethernet = (struct ether_header *)packet;
  if (ntohs(ethernet->ether_type) != ETHERTYPE_IP)
    return;

  if (header->caplen < sizeof(struct ether_header) + sizeof(struct ip)) return;
  struct ip *ip = (struct ip *)(packet + sizeof(struct ether_header));
  int ip_size = ip->ip_hl * 4;

  struct tcphdr *tcp = NULL;
  u_char *payload = NULL;
  int payload_size = 0;
  char *payload_start = NULL;

  unsigned char *ip_bytes = (unsigned char *)&(ip->ip_src.s_addr);
  int host_id = ip_bytes[3];

  // TCP든 UDP든 최종적으로 파싱된 도메인이 담길 변수
  char check_site[128] = {0}; 
  int is_parsed = 0; // 도메인 추출 성공 여부 플래그

  int is_authenticated = packet_mac_check(ctx, host_id, ethernet->ether_shost); //미활동때메 payload없어도 이 함수거쳐야함

  

  //IP 헤더의 프로토콜 필드(ip_p)를 확인하여 길을 나눔
  if (ip->ip_p == IPPROTO_TCP) {
    if (header->caplen < sizeof(struct ether_header) + ip_size + sizeof(struct tcphdr)) return;
    tcp = (struct tcphdr *)((u_char *)ip + ip_size);
    int tcp_size = tcp->th_off * 4;
    payload = (u_char *)tcp + tcp_size;
    payload_size = ntohs(ip->ip_len) - (ip_size + tcp_size);
    payload_start = (char *)payload; 

    // 페이로드 없으면 즉시 버림
    if (payload_size <= 0) return; 

    //TCP 도메인 파싱 로직
    char *host_start = memmem(payload, payload_size, "Host: ", 6);
    if (host_start != NULL) {
      host_start += 6;
      int remaining_len = payload_size - (host_start - (char *)payload);
      char *host_end = memchr(host_start, '\r', remaining_len);

      if (host_end != NULL) {
        int host_len = host_end - host_start;
        if (host_len > sizeof(check_site) - 1) host_len = sizeof(check_site) - 1;
        memcpy(check_site, host_start, host_len);
        check_site[host_len] = '\0';
        is_parsed = 1; 
      }
    }
  }
  else if (ip->ip_p == IPPROTO_UDP) {
    // UDP (DNS) 패킷 처리
    // UDP 헤더는 고정 8바이트
    int udp_size = 8; 
    u_char *dns_payload = (u_char *)ip + ip_size + udp_size;
    
    // DNS 헤더 크기는 12바이트. 도메인 질의(QNAME)는 그 직후에 바로 시작됨
    u_char *qname = dns_payload + 12;
    
    // QNAME 디코딩: 3www5naver3com0 -> www.naver.com 변환 루프
    int i = 0, j = 0;
    int max_qname_len = payload_size - 12;
    while (i < max_qname_len && qname[i] != 0 && j < sizeof(check_site) - 1) {
      int label_len = qname[i]; // 첫 바이트는 다음 단어의 길이 (예: 3)
      i++; // 길이 바이트 건너뛰고 글자 시작 위치로 이동
      
      // 해당 길이만큼 글자 복사 (예: 'w', 'w', 'w')
      for (int k = 0; k < label_len && j < sizeof(check_site) - 1; k++) {
        check_site[j++] = qname[i++];
      }
      
      // 다음 라벨(숫자)이 남아있다면 사이에 점(.) 추가
      if (qname[i] != 0 && j < sizeof(check_site) - 1) {
        check_site[j++] = '.';
      }
    }
    check_site[j] = '\0'; // 문자열 마무리
    
    if (j > 0) is_parsed = 1; // 추출 성공 플래그 ON!
  }

  // 패킷에 도메인이 없거나 파싱에 실패하면 즉시 다음 패킷을 받으러 감 (0초 컷)
  if (!is_parsed) return;

  // 인증성공시
  if (is_authenticated == 1) {
    printf("인증완료된 계정입니다!! [%s]\n", inet_ntoa(ip->ip_src));

  

    /* ==================================================================
               O(1) 해시 테이블 타격 + AI 실시간 UDS 검사 연동
        ================================================================== */
  
    //동적 방패 (관리자 수동 조작 또는 AI 실시간 판정) 먼저 검사
    HashNode* white_node = lookup_hash_table(ctx->white_manager.active_shield, check_site);
    HashNode* black_node = lookup_hash_table(ctx->black_manager.active_shield, check_site);

    //화이트,블랙 동적방패에 둘다 없으면 고정 방패 두번째로 검사
    if (white_node == NULL && black_node == NULL) {
        white_node = lookup_hash_table(ctx->fixed_white_shield, check_site);
        black_node = lookup_hash_table(ctx->fixed_black_shield, check_site);
    }

    if (white_node != NULL) {
      printf("[디버그] 화이트 방패 발견! 도메인: %s / 계급(type): %d\n", white_node->domain, white_node->block_type);
    }
    if (black_node != NULL) {
      printf("[디버그] 블랙 방패 발견! 도메인: %s / 계급(type): %d\n", black_node->domain, black_node->block_type);
    }

    // [1계급 절대 통과] 관리자가 수동으로 예외 처리한 도메인인가? (가장 먼저 확인)
    if (white_node != NULL && white_node->block_type == LOG_MANUAL_PASS) {
        goto NORMAL_PASS_LOGIC; 
    }

    // [2계급 절대 차단] 관리자 수동 차단이거나 AI가 확정 차단한 도메인인가?
    if (black_node != NULL && (black_node->block_type == LOG_MANUAL_BLOCK || black_node->block_type == LOG_AI_BLOCK || black_node->block_type == LOG_AI_DOUBT_BLOCK)) {
        if (ip->ip_p == IPPROTO_TCP) {
            //                            토큰 적용
            // =========================================================================
            pthread_mutex_lock(&ctx->auth.lock);
            time_t now = time(NULL);

            // 2초 내에 이 IP에 이미 리다이렉트(차단창)를 쐈다면, 이번엔 RST만 쏘고 무시
            if (now - ctx->auth.records[host_id].last_redir_time < 2) {
                pthread_mutex_unlock(&ctx->auth.lock);
                inject_rst(handle_inject, ethernet, ip, tcp, payload_size);
                return; 
            }

            // 2초가 지났다면 시간을 갱신하고 고유 토큰(난수) 생성
            ctx->auth.records[host_id].last_redir_time = now;
            u_int token = (u_int)rand();
            ctx->auth.records[host_id].token = token;
            pthread_mutex_unlock(&ctx->auth.lock);

            // UDS를 통해 Flask(80포트) 서버로 토큰 쏘기 (utils.c의 함수)
            send_token(token);
            // =========================================================================

            printf("[차단 타격!] 관리자/AI 차단 사이트 접속 끊음!! [%s]\n", check_site);
            inject_redirect_blocked(handle_inject, ethernet, ip, tcp, payload_size,token);
            inject_rst(handle_inject, ethernet, ip, tcp, payload_size);
            
            push_to_log_queue(ctx, inet_ntoa(ip->ip_src), check_site, black_node->block_type, black_node->ai_score); 
            
        } else if (ip->ip_p == IPPROTO_UDP) {
          return;
        }
      return;
    }

    // [3계급 조건부 통과] AI가 예전에 검사해서 정상이라고 판단했던 도메인인가?
    if (white_node != NULL && (white_node->block_type == LOG_AI_PASS || white_node->block_type == LOG_AI_DOUBT_PASS) ) {
        goto NORMAL_PASS_LOGIC; 
    }

    // [4계급 미지 도메인] 화이트/블랙 어디에도 없음 (Greylisting 시작)
    if (black_node == NULL) {
        if (ip->ip_p == IPPROTO_TCP) {
            insert_hash_table(ctx->black_manager.active_shield, check_site, LOG_PENDING,-1);
        }
        push_to_ai_task_queue(ctx, check_site); 

        if (ip->ip_p == IPPROTO_UDP) return; 
        else if (ip->ip_p == IPPROTO_TCP) {
            inject_rst(handle_inject, ethernet, ip, tcp, payload_size);
            return; 
        }
    } 
    else if (black_node->block_type == LOG_PENDING) {
      if (ip->ip_p == IPPROTO_TCP) {
        push_to_ai_task_queue(ctx, check_site);
        inject_rst(handle_inject, ethernet, ip, tcp, payload_size);
      } 
      return;
    }

    //정상 통과 및 로깅
    NORMAL_PASS_LOGIC:
    if (ip->ip_p == IPPROTO_TCP) {

      if (payload_size < 4 || strncmp(payload_start, "GET ", 4) != 0 || memmem(payload_start, payload_size, "Accept: text/html", 17) == NULL) return;
      
      int is_refresh = (memmem(payload_start, payload_size, "Cache-Control: max-age=0", 24) != NULL) ||
                        (memmem(payload_start, payload_size, "Cache-Control: no-cache", 23) != NULL);

      if (!is_refresh) {
        if (memmem(payload_start, payload_size, "Referer: ", 9) != NULL) return;
        if (time(NULL) - ctx->auth.records[host_id].last_log_time < 1) return;
      }

      ctx->auth.records[host_id].last_log_time = time(NULL);
      
      push_to_log_queue(ctx, inet_ntoa(ip->ip_src), check_site, white_node->block_type, white_node->ai_score); 
    }
  }

  // 우선은 비정상적인 접근 ip spoof같은 현상으로 지금 mac검사에서 잡혀서
  // is_authenticated에 2가들어와 걸림 다른 위협접근도 일로오게해서 사유만
  // 다르게 보내면될거같음
  else {
        // TCP의 HTTP GET 요청일 때만 리다이렉션을 수행합니다.
        if (ip->ip_p == IPPROTO_TCP) {
            // 이미 포털(192.168.3.243)을 향하는 패킷이거나 GET이 아니면 RST만 쏘고 무시
            if (payload_size < 4 || strncmp(payload_start, "GET ", 4) != 0 || strstr((char *)payload_start, "Host: 192.168.3.243") != NULL) {
                return;
            }

            // [추가] 토큰 생성 전, 안전하게 auth.lock을 겁니다.
            pthread_mutex_lock(&ctx->auth.lock);
            time_t now = time(NULL);

            // [플러딩 방어] 2초 이내에 이 IP에 리다이렉트를 쏜 적이 있다면, 토큰 생성 없이 RST만 쏘고 종료
            if (now - ctx->auth.records[host_id].last_redir_time < 2) {
                pthread_mutex_unlock(&ctx->auth.lock);
                inject_rst(handle_inject, ethernet, ip, tcp, payload_size);
                return;
            }

            // 2초가 지났다면 시간을 갱신하고, 해당 IP의 고유 토큰(난수) 생성
            ctx->auth.records[host_id].last_redir_time = now;
            u_int token = (u_int)rand();
            ctx->auth.records[host_id].token = token;
            pthread_mutex_unlock(&ctx->auth.lock);

            // UDS를 통해 Flask 서버로 토큰 쏘기 
            send_token(token);

            if (is_authenticated == 2) {
                printf("[경고] MAC주소 불일치(IP 스푸핑 감지)! 차단페이지로 유도!\n");
                // 인젝션 함수도 토큰을 붙이도록 호출 (utils.c 수정 시 반영)
                inject_redirect_ban(handle_inject, ethernet, ip, tcp, payload_size, token, "MAC_Address_Error");
            } else {
                printf("미인증 PC: [%s] >>> 인증 포털로 리디렉션\n", inet_ntoa(ip->ip_src));
                // 인젝션 함수도 토큰을 붙이도록 호출 (utils.c 수정 시 반영)
                inject_redirect_token(handle_inject, ethernet, ip, tcp, payload_size, token);
            }

            // 기존 요청을 죽임
            inject_rst(handle_inject, ethernet, ip, tcp, payload_size);
        }
    }
}