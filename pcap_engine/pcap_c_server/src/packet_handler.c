#include "pcap_common.h"
#include "hash_manager.h"
#include "pcap_utils.h"
#include <ctype.h>

// time_t last_time[256] = {0}; // IP별 마지막 접속 시간(초) 기록

/* ===== [측정용] 스트레스 테스트 카운터 (pcap_loop 스레드 1개만 증가시키므로 락 불필요) ===== */
unsigned long g_st[ST_COUNT] = {0};
const char *g_st_name[ST_COUNT] = {
  "IP 패킷 수신", "TCP 페이로드 있음", "UDP 수신",
  "HTTP Host 파싱 성공", "DNS 도메인 파싱 성공", "파싱 실패(버림)",
  "인증된 PC", "미인증 PC", "MAC 불일치",
  "차단: 302+로그", "차단: RST만(2초 내 재요청)",
  "통과: 로그 큐에 넣음", "통과: 로그 생략(3초 중복·Referer·GET 아님)",
  "미지 도메인 → AI 큐", "PENDING(AI 판정 대기)", "UDP 처리 후 로그 없음",
  "DNS 질의: 응답 기다림(AI 보류)", "DNS 응답 수신", "DNS 응답(주소 있음) → AI 큐",
  "NXDOMAIN 응답(AI 안 보냄)", "NXDOMAIN 급증 알림"
};

void packet_handler(u_char *user_args, const struct pcap_pkthdr *header, const u_char *packet) {
  EngineContext *ctx = (EngineContext *)user_args;

  pcap_t *handle_inject = ctx->inject_handle;

  if (header->caplen < sizeof(struct ether_header)) return;
  struct ether_header *ethernet = (struct ether_header *)packet;
  if (ntohs(ethernet->ether_type) != ETHERTYPE_IP)
    return;
  g_st[ST_IP]++;

  if (header->caplen < sizeof(struct ether_header) + sizeof(struct ip)) return;
  struct ip *ip = (struct ip *)(packet + sizeof(struct ether_header));
  int ip_size = ip->ip_hl * 4;

  // DNS 응답(DNS 서버 → 사내 PC)은 출발지가 DNS 서버라서 아래 인증·MAC 검사(출발지 기준)를 타면 안 됨 → 따로 처리
  if (ip->ip_p == IPPROTO_UDP && header->caplen >= sizeof(struct ether_header) + ip_size + 8) {
    const u_char *udp = (const u_char *)ip + ip_size;
    if (((udp[0] << 8) | udp[1]) == 53) {
      handle_dns_response(ctx, ethernet, ip, header->caplen);
      return;
    }
  }

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
    g_st[ST_TCP_PAYLOAD]++;

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
    g_st[ST_UDP]++;
    // [버그 수정] UDP 경로에서는 payload_size 가 계산되지 않아(0) max_qname_len 이 음수 → DNS 도메인을 한 번도 파싱하지 못했음
    payload_size = ntohs(ip->ip_len) - ip_size - udp_size;
    if (payload_size <= 12) return;
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
  if (!is_parsed) { g_st[ST_PARSE_FAIL]++; return; }
  if (ip->ip_p == IPPROTO_TCP) g_st[ST_HTTP_OK]++; else g_st[ST_DNS_OK]++;

  //사내망 포털(Flask 웹서버)로 향하는 접근은 AI 검사 및 로깅에서 완전 제외!
  // if (strstr(check_site, "192.168.3.243") != NULL) {
  //     return; 
  // }

  // 인증성공시
  if (is_authenticated == 1) {
    g_st[ST_AUTH]++;
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

            //토큰발급
            u_int token = check_and_generate_token(ctx, host_id);
            if (token == 0) {
                // 2초가 안 지났으므로 RST만 쏘고 종료
                inject_rst(handle_inject, ethernet, ip, tcp, payload_size);
                g_st[ST_BLOCK_RST_ONLY]++;
                return;
            }

            g_st[ST_BLOCK_LOGGED]++;
            printf("[차단 타격!] 관리자/AI 차단 사이트 접속 끊음!! [%s]\n", check_site);
            inject_redirect_blocked(handle_inject, ethernet, ip, tcp, payload_size,token);
            inject_rst(handle_inject, ethernet, ip, tcp, payload_size);
            
            push_to_log_queue(ctx, inet_ntoa(ip->ip_src), check_site, black_node->block_type, black_node->ai_score); 
            
        } else if (ip->ip_p == IPPROTO_UDP) {
          g_st[ST_UDP_NOLOG]++;
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
        // [버그 수정] DNS(UDP)는 TCP 헤더가 없으므로 토큰 발급·RST 주입 대상이 아님.
        // 기존 코드는 UDP 에서도 토큰을 먼저 발급해, 2초 규칙에 걸리면 tcp=NULL 로 inject_rst 를 호출해 세그폴트가 났음
        // (DNS 파싱이 안 되던 동안은 이 경로에 오지 않아 드러나지 않았음).
        // 또 DNS 가 토큰을 써 버리면 바로 뒤따르는 HTTP 요청이 2초 규칙에 걸려 안내 페이지 대신 RST 만 받게 됨.
        // → UDP 는 AI 큐에만 넣고(중복 방지를 위해 PENDING 등록) 바로 반환.
        // [NXDOMAIN 반영] 질의 시점엔 그 도메인이 실제로 있는지 모름 → DNS 응답을 보고 '주소 있음'일 때만 AI 요청 (handle_dns_response)
        // 응답을 못 받는 환경이면 CAPTIVE_DNS_QUERY_AI=1 로 예전처럼 질의 시점에 요청
        if (ip->ip_p == IPPROTO_UDP) {
            if (ctx->dns_query_ai) {
                insert_hash_table(ctx->black_manager.active_shield, check_site, LOG_PENDING, -1);
                push_to_ai_task_queue(ctx, check_site);
                g_st[ST_TO_AI]++;
            } else {
                g_st[ST_DNS_WAIT]++;
            }
            return;
        }

        //토큰발급
        u_int token = check_and_generate_token(ctx, host_id);
            if (token == 0) {
                // 2초가 안 지났으므로 RST만 쏘고 종료
                inject_rst(handle_inject, ethernet, ip, tcp, payload_size);
                return;
            }

        if (ip->ip_p == IPPROTO_TCP) {
            insert_hash_table(ctx->black_manager.active_shield, check_site, LOG_PENDING,-1);
        }
        push_to_ai_task_queue(ctx, check_site); 
        g_st[ST_TO_AI]++;

        if (ip->ip_p == IPPROTO_UDP) return; 
        else if (ip->ip_p == IPPROTO_TCP) {
            inject_redirect_analyzing(handle_inject, ethernet, ip, tcp, payload_size,token, check_site);
            inject_rst(handle_inject, ethernet, ip, tcp, payload_size);
            return; 
        }
    } 
    else if (black_node->block_type == LOG_PENDING) {
      g_st[ST_PENDING]++;
      if (ip->ip_p == IPPROTO_TCP) {
        //토큰발급
        u_int token = check_and_generate_token(ctx, host_id);
            if (token == 0) {
                // 2초가 안 지났으므로 RST만 쏘고 종료
                inject_rst(handle_inject, ethernet, ip, tcp, payload_size);
                return;
            }
        push_to_ai_task_queue(ctx, check_site);
        inject_redirect_analyzing(handle_inject, ethernet, ip, tcp, payload_size,token, check_site);
        inject_rst(handle_inject, ethernet, ip, tcp, payload_size);
      } 
      return;
    }

    //정상 통과 및 로깅
    NORMAL_PASS_LOGIC:
    if (ip->ip_p != IPPROTO_TCP) g_st[ST_UDP_NOLOG]++;
    if (ip->ip_p == IPPROTO_TCP) {

      // 1. 자기 자신(웹 포털 192.168.3.243)로 향하는 트래픽이면 무시! (부메랑 버그 차단)
        // if (strstr(check_site, "192.168.3.243") != NULL) return;

      if (payload_size < 4 || strncmp(payload_start, "GET ", 4) != 0 || memmem(payload_start, payload_size, "Accept: text/html", 17) == NULL) { g_st[ST_PASS_SKIP]++; return; }
      
      int is_refresh = (memmem(payload_start, payload_size, "Cache-Control: max-age=0", 24) != NULL) ||
                        (memmem(payload_start, payload_size, "Cache-Control: no-cache", 23) != NULL);

      if (!is_refresh) {
        if (memmem(payload_start, payload_size, "Referer: ", 9) != NULL) { g_st[ST_PASS_SKIP]++; return; }
        if (time(NULL) - ctx->auth.records[host_id].last_log_time <= 3) { g_st[ST_PASS_SKIP]++; return; }
      }

      ctx->auth.records[host_id].last_log_time = time(NULL);
      
      // SYSTEM_LOG(LOG_INFO, "[로그찍히나] 도메인: %s (Type: %d)", check_site, white_node->block_type);
      push_to_log_queue(ctx, inet_ntoa(ip->ip_src), check_site, white_node->block_type, white_node->ai_score); 
      g_st[ST_PASS_LOGGED]++;
    }
  }

  // 우선은 비정상적인 접근 ip spoof같은 현상으로 지금 mac검사에서 잡혀서
  // is_authenticated에 2가들어와 걸림 다른 위협접근도 일로오게해서 사유만
  // 다르게 보내면될거같음
  else {
        if (is_authenticated == 2) g_st[ST_MAC_MISMATCH]++; else g_st[ST_UNAUTH]++;
        // TCP의 HTTP GET 요청일 때만 리다이렉션을 수행합니다.
        if (ip->ip_p == IPPROTO_TCP) {
            // 이미 포털(192.168.3.243)을 향하는 패킷이거나 GET이 아니면 RST만 쏘고 무시
            if (payload_size < 4 || strncmp(payload_start, "GET ", 4) != 0 || strstr((char *)payload_start, "Host: 192.168.3.243") != NULL) {
                return;
            }

            u_int token = check_and_generate_token(ctx, host_id);
            if (token == 0) {
                // 2초가 안 지났으므로 RST만 쏘고 종료
                inject_rst(handle_inject, ethernet, ip, tcp, payload_size);
                return;
            }

            if (is_authenticated == 2) {
                SYSTEM_LOG(LOG_WARNING, "[보안경고] MAC주소 불일치(IP 스푸핑 감지)! IP: %s", inet_ntoa(ip->ip_src));
                // 인젝션 함수도 토큰을 붙이도록 호출 (utils.c 수정 시 반영)
                inject_redirect_ban(handle_inject, ethernet, ip, tcp, payload_size, token, "MAC_Address_Error");

                // 1. MAC 주소를 담을 18바이트 빈 공간 준비
                char mac_str[18];
                
                // 2. 방금 만든 깔끔한 유틸 함수 호출! (snprintf의 더러운 코드가 안 보임)
                mac_to_string(ethernet->ether_shost, mac_str);
                push_to_log_queue(ctx, inet_ntoa(ip->ip_src), mac_str, LOG_MAC_MISMATCH, 0); //3번째인자인 도메인자리를 맥으로도 같이씀
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

// =====================================================
// DNS 응답 처리 (NXDOMAIN 감시)
//  - NXDOMAIN(없는 도메인): AI 로 안 보냄(판정 1건 약 88ms 절약). 대신 PC별로 세다가
//    구간(기본 60초) 안에 기준(기본 20회)을 넘으면 '감염 의심' 알림 1건만 보냄
//    → DGA 악성코드는 없는 도메인을 수십~수백 번 조회하다가 등록된 하나(명령 서버)에 접속함
//    → 크롬도 시작할 때 무작위 도메인 3개 정도를 일부러 조회하니까 기준은 넉넉하게
//  - 정상 응답(주소 있음): 처음 보는 도메인이면 이때 AI 요청 (예전엔 질의 시점에 보냈음)
// =====================================================
void handle_dns_response(EngineContext *ctx, const struct ether_header *ethernet, const struct ip *ip, int caplen) {
  int ip_size = ip->ip_hl * 4;
  int udp_size = 8;
  int dns_len = ntohs(ip->ip_len) - ip_size - udp_size;
  int avail = caplen - (int)sizeof(struct ether_header) - ip_size - udp_size;
  if (dns_len > avail) dns_len = avail;          // 잘려서 캡처된 패킷 대비
  if (dns_len <= 12) return;                      // DNS 헤더(12바이트)도 없음

  const u_char *dns = (const u_char *)ip + ip_size + udp_size;
  int flags = (dns[2] << 8) | dns[3];
  if (!(flags & 0x8000)) return;                  // QR 비트 0 = 질의 → 응답 아님
  int rcode = flags & 0x000F;                     // 3 = NXDOMAIN
  int qdcount = (dns[4] << 8) | dns[5];
  int ancount = (dns[6] << 8) | dns[7];
  if (qdcount < 1) return;
  g_st[ST_DNS_RESP]++;

  // 응답 안에도 질문(도메인)이 그대로 들어있음: 3www5naver3com0 -> www.naver.com
  char name[128];
  int i = 12, j = 0;
  while (i < dns_len && dns[i] != 0 && j < (int)sizeof(name) - 1) {
    int label_len = dns[i];
    if (label_len & 0xC0) return;                 // 질문부에 압축 포인터는 안 옴 → 이상한 패킷은 버림
    i++;
    for (int k = 0; k < label_len && i < dns_len && j < (int)sizeof(name) - 1; k++) {
      name[j++] = (char)tolower(dns[i++]);
    }
    if (i < dns_len && dns[i] != 0 && j < (int)sizeof(name) - 1) name[j++] = '.';
  }
  name[j] = '\0';
  if (j == 0) return;
  i++;                                            // 도메인 끝 0 바이트
  int qtype = (i + 1 < dns_len) ? ((dns[i] << 8) | dns[i + 1]) : 0;

  // 응답의 목적지가 사내 PC
  const unsigned char *dst = (const unsigned char *)&ip->ip_dst.s_addr;
  int host_id = dst[3];
  if (host_id <= 0 || host_id >= 255) return;

  if (rcode == 3) {
    g_st[ST_NX]++;
    NxTracker *t = &ctx->nx[host_id];
    time_t now = time(NULL);
    if (t->window_start == 0 || now - t->window_start >= ctx->nx_window) {
      memset(t, 0, sizeof(*t));                   // 새 구간 시작
      t->window_start = now;
    }
    if (strcmp(t->last_name, name) == 0) return;  // A·AAAA 로 같은 도메인 응답이 연달아 오면 1번만 셈
    snprintf(t->last_name, sizeof(t->last_name), "%s", name);
    t->count++;
    if (t->nsamples < NX_SAMPLE_MAX) {
      snprintf(t->samples[t->nsamples++], sizeof(t->samples[0]), "%s", name);
    }

    if (t->count >= ctx->nx_threshold && !t->alerted) {
      t->alerted = 1;                             // 이번 구간엔 1건만
      g_st[ST_NX_ALERT]++;

      // 로그 큐 한 칸(target_host 128바이트)에 "MAC|횟수|구간초|예시1,예시2,..." 로 담아서 보냄
      char mac[18];
      mac_to_string(ethernet->ether_dhost, mac);
      char info[128];
      int n = snprintf(info, sizeof(info), "%s|%d|%d|", mac, t->count, ctx->nx_window);
      for (int s = 0; s < t->nsamples && n < (int)sizeof(info) - 1; s++) {
        int w = snprintf(info + n, sizeof(info) - n, "%s%s", s ? "," : "", t->samples[s]);
        if (w < 0 || w >= (int)sizeof(info) - n) { info[n] = '\0'; break; }  // 칸이 모자라면 그 예시는 뺌
        n += w;
      }
      char ip_str[16];
      snprintf(ip_str, sizeof(ip_str), "%s", inet_ntoa(ip->ip_dst));
      push_to_log_queue(ctx, ip_str, info, LOG_NX_ALERT, (double)t->count);
      SYSTEM_LOG(LOG_WARNING, "[보안경고] NXDOMAIN 급증(감염 의심)! IP: %s, %d초 안에 %d회", ip_str, ctx->nx_window, t->count);
    }
    return;
  }

  // 주소가 있는 정상 응답(A·AAAA)만 AI 대상 — 질의 시점에 이미 보내는 설정이면 패스
  if (rcode != 0 || ancount == 0 || (qtype != 1 && qtype != 28) || ctx->dns_query_ai) return;

  // 미인증 PC는 어차피 포털로 보내지니까 AI 판정 불필요 (예전 질의 처리와 같은 기준)
  pthread_mutex_lock(&ctx->auth.lock);
  int is_active = ctx->auth.records[host_id].is_active;
  pthread_mutex_unlock(&ctx->auth.lock);
  if (is_active != 1) return;

  HashNode *w = lookup_hash_table(ctx->white_manager.active_shield, name);
  HashNode *b = lookup_hash_table(ctx->black_manager.active_shield, name);
  if (w == NULL && b == NULL) {
    w = lookup_hash_table(ctx->fixed_white_shield, name);
    b = lookup_hash_table(ctx->fixed_black_shield, name);
  }
  if (w != NULL || b != NULL) return;             // 이미 아는 도메인 (판정 대기 PENDING 포함)

  insert_hash_table(ctx->black_manager.active_shield, name, LOG_PENDING, -1);
  push_to_ai_task_queue(ctx, name);
  g_st[ST_DNS_TO_AI]++;
}
