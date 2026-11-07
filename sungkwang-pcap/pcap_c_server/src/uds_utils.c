#include "pcap_common.h"
#include "pcap_utils.h"

// MAC 주소(6바이트)를 받아 "AA:BB:CC:DD:EE:FF" 형태의 17글자 대문자 문자열로 만들어주는 유틸 함수
void mac_to_string(const unsigned char *mac_bytes, char *mac_str_out) {
    // %02X 를 사용하므로 0이 절대 사라지지 않고 두 자리 대문자로 고정됩니다.
    sprintf(mac_str_out, "%02X:%02X:%02X:%02X:%02X:%02X",
            mac_bytes[0], mac_bytes[1], mac_bytes[2],
            mac_bytes[3], mac_bytes[4], mac_bytes[5]);
}

unsigned short csum(unsigned short *ptr, int nbytes)
{
    register long sum;
    unsigned short oddbyte;
    register short answer;
    sum = 0;
    while (nbytes > 1)
    {
        sum += *ptr++;
        nbytes -= 2;
    }
    if (nbytes == 1)
    {
        oddbyte = 0;
        *((u_char *)&oddbyte) = *(u_char *)ptr;
        sum += oddbyte;
    }
    sum = (sum >> 16) + (sum & 0xffff);
    sum = sum + (sum >> 16);
    answer = (short)~sum;
    return (answer);
}
// ===================================
// UDS 통신부
// ===================================
void uds_client_sock(const int ip){
  char msg[64];
  sprintf(msg, "GC|%d", ip);

  send_to_uds(msg);
}

void uds_client_sock_log(const LogPacket* local_log){
  char msg[512];
  
  if(local_log->is_ai_blocked == 1 || local_log->is_ai_blocked == 3 || local_log->is_ai_blocked == 4) {
    sprintf(msg, "BLACK|%s|%s|%d|%.2f", local_log->client_ip, local_log->target_host, local_log->is_ai_blocked,local_log->ai_score);
  }
  else if(local_log->is_ai_blocked == 2 || local_log->is_ai_blocked == 5 || local_log->is_ai_blocked == 6) {
    sprintf(msg, "WHITE|%s|%s|%d|%.2f", local_log->client_ip, local_log->target_host, local_log->is_ai_blocked,local_log->ai_score);
  }
  else if(local_log->is_ai_blocked == 99){
    sprintf(msg, "MAC|%s|%s", local_log->client_ip, local_log->target_host);
  }
  

  send_to_uds(msg);
}

void send_to_uds(const char* message) {
    int sockfd = socket(AF_UNIX, SOCK_STREAM, 0);
    if (sockfd < 0) {
        perror("[UDS] 소켓 생성 실패");
        return;
    }

    struct sockaddr_un addr;
    memset(&addr, 0, sizeof(addr));
    addr.sun_family = AF_UNIX;
    strncpy(addr.sun_path, GC_LOG_SOCKET_PATH, sizeof(addr.sun_path) - 1); 

    if (connect(sockfd, (struct sockaddr *)&addr, sizeof(addr)) == 0) {
        write(sockfd, message, strlen(message));
    } else {
        perror("[UDS 에러] 멍텅구리 서버 연결 실패 (꺼져있음)");
    }
    close(sockfd);
}

void send_token(u_int token) {
    int send_fd = socket(AF_UNIX, SOCK_STREAM, 0);
    if (send_fd == -1) return;

    struct sockaddr_un wr_token;
    memset(&wr_token, 0, sizeof(wr_token));
    wr_token.sun_family = AF_UNIX;
    strncpy(wr_token.sun_path, TOKEN_SOCK_PATH, sizeof(wr_token.sun_path) - 1);

    if (connect(send_fd, (struct sockaddr *)&wr_token, sizeof(wr_token)) == 0) {
        char buffer[64] = {0};
        snprintf(buffer, sizeof(buffer), "%u\n", token);
        write(send_fd, buffer, strlen(buffer));
        printf("토큰 전송 성공: %u, 경로: [%s]\n", token, TOKEN_SOCK_PATH);
    }
    close(send_fd);
}

// ==========================================
// [IP 및 MAC 주소 인증 검증] 
// ==========================================

int packet_mac_check(EngineContext *ctx, const int host_id, const uint8_t* packet_mac) {
    int is_authenticated = 0;

    if (host_id >= 0 && host_id < 254) {
        // MAC 캐시 저장
        memcpy(ctx->auth.latest_mac_cache[host_id], packet_mac, ETH_ALEN);

        // 인증 전용 락 획득
        pthread_mutex_lock(&ctx->auth.lock);

        if (ctx->auth.records[host_id].is_active == 1) {
            // 1. 최초 패킷: MAC 바인딩
            if (ctx->auth.records[host_id].is_mac_bound == 0) {
                memcpy(ctx->auth.records[host_id].mac_addr, packet_mac, ETH_ALEN);
                ctx->auth.records[host_id].is_mac_bound = 1;
            } 
            // 2. 두 번째 패킷부터: 위조 검증
            else {
                if (memcmp(packet_mac, ctx->auth.records[host_id].mac_addr, ETH_ALEN) != 0) {
                    printf("인증한 계정의 MAC과 일치하지 않습니다.\n");
                    pthread_mutex_unlock(&ctx->auth.lock);
                    return 2; // 스푸핑 감지
                }
            }

            // 3. 생존(마지막 활동) 시간 갱신 (출퇴근 스마트 만료용)
            if (ctx->auth.records[host_id].is_active == 1) {
                ctx->auth.records[host_id].last_seen = time(NULL);
            }
        }
        is_authenticated = ctx->auth.records[host_id].is_active == 1 ? 1 : 0;
        pthread_mutex_unlock(&ctx->auth.lock);
    }
    return is_authenticated;
}
// ==============================================
// [로그 큐 (LogQueue) 컨트롤] 
// ==============================================

//queue push
void push_to_log_queue(EngineContext *ctx, const char* ip, const char* domain, int is_blocked_flag, double score) {
    LogPacket log_data;
    memset(&log_data, 0, sizeof(LogPacket));
    
    strcpy(log_data.client_ip, ip);
    strncpy(log_data.target_host, domain, sizeof(log_data.target_host) - 1);
    log_data.is_ai_blocked = is_blocked_flag; 
    log_data.ai_score = score;

    pthread_mutex_lock(&ctx->log_queue.queue_lock);
    if (ctx->log_queue.count < MAX_LOG_QUEUE) {
        ctx->log_queue.nodes[ctx->log_queue.rear] = log_data;
        ctx->log_queue.rear = (ctx->log_queue.rear + 1) % MAX_LOG_QUEUE;
        ctx->log_queue.count++;
        pthread_cond_signal(&ctx->log_queue.log_cond); // 전송 스레드 기상
    } else {
        printf("[경고] 로그 큐 오버플로우\n"); 
    }
    pthread_mutex_unlock(&ctx->log_queue.queue_lock);
}


//quque pop
int pop_log_queue(EngineContext *ctx, LogPacket* out_log) {
    int success = 0;
    pthread_mutex_lock(&ctx->log_queue.queue_lock); 
    if (ctx->log_queue.count > 0) {
        *out_log = ctx->log_queue.nodes[ctx->log_queue.front];
        ctx->log_queue.front = (ctx->log_queue.front + 1) % MAX_LOG_QUEUE;
        ctx->log_queue.count--;
        success = 1;
    }
    pthread_mutex_unlock(&ctx->log_queue.queue_lock); 
    return success;
}
 

// =======================================
// [AI 분석 큐 (AIQueue) 컨트롤] 
// =======================================

//ai분석용 queue push
void push_to_ai_task_queue(EngineContext *ctx, const char *domain) {
    pthread_mutex_lock(&ctx->ai_queue.lock);
    if (ctx->ai_queue.count < MAX_AI_QUEUE) {
        strncpy(ctx->ai_queue.tasks[ctx->ai_queue.rear].domain, domain, 127);
        ctx->ai_queue.tasks[ctx->ai_queue.rear].domain[127] = '\0';
        
        ctx->ai_queue.rear = (ctx->ai_queue.rear + 1) % MAX_AI_QUEUE;
        ctx->ai_queue.count++;
        printf("1. 큐에 푸시됨: %s\n", domain);
        pthread_cond_signal(&ctx->ai_queue.cond); // AI 워커 깨움
    }
    pthread_mutex_unlock(&ctx->ai_queue.lock);
}

//ai분석용 queue pop
int pop_ai_queue(EngineContext *ctx, char* out_domain) {
    pthread_mutex_lock(&ctx->ai_queue.lock);

    while (ctx->ai_queue.count == 0 && ctx->keep_running) {
        pthread_cond_wait(&ctx->ai_queue.cond, &ctx->ai_queue.lock);
    }

    if (!ctx->keep_running && ctx->ai_queue.count == 0) {
        pthread_mutex_unlock(&ctx->ai_queue.lock);
        return 0; 
    }

    strncpy(out_domain, ctx->ai_queue.tasks[ctx->ai_queue.front].domain, 127);
    out_domain[127] = '\0'; 

    ctx->ai_queue.front = (ctx->ai_queue.front + 1) % MAX_AI_QUEUE; 
    ctx->ai_queue.count--;

    pthread_mutex_unlock(&ctx->ai_queue.lock);
    return 1; 
}

// ============================
// AI 서버 통신부 
// ============================

// AI에게 도메인을 묻고 결과를 반환 (1 = BLACK, 2 = BLACK_DOUBT, 3 = WHITE_DOUBT , 4 = WHITE)
int ask_ai_domain_status(const char* domain, double* out_score) {
  
  // 매개변수 포인터 유효성 검사 추가
    if (domain == NULL || out_score == NULL) {
        return LOG_AI_PASS; // 안전하게 통과 처리 (Fail-Open)
    }

    int sock = socket(AF_UNIX, SOCK_STREAM, 0);
    if (sock == -1) return LOG_AI_PASS; // 소켓 생성 실패 시 안전을 위해 PASS 처리 (Fail-Open)

    // 소켓 타임아웃 설정 (AI 서버가 죽었을 때 C엔진이 멈추는 것 방지, 10ms 한계)
    struct timeval tv;
    tv.tv_sec = 0;
    tv.tv_usec = 1000000; 
    setsockopt(sock, SOL_SOCKET, SO_RCVTIMEO, (const char*)&tv, sizeof(tv));
    setsockopt(sock, SOL_SOCKET, SO_SNDTIMEO, (const char*)&tv, sizeof(tv));

    struct sockaddr_un server_addr;
    memset(&server_addr, 0, sizeof(server_addr));
    server_addr.sun_family = AF_UNIX;
    strncpy(server_addr.sun_path, AI_SOCKET_PATH, sizeof(server_addr.sun_path) - 1);

    // 1. AI 서버에 연결
    if (connect(sock, (struct sockaddr*)&server_addr, sizeof(server_addr)) == -1) {
        close(sock);
        return LOG_AI_PASS; // 연결 실패 시 일단 통과시킴 (망 마비 방지)
    }

    // 2. 도메인 전송
    write(sock, domain, strlen(domain));

    // 3. 결과 수신 대기 (수십 ms 블로킹)
    char buffer[256];
    int n = read(sock, buffer, sizeof(buffer) - 1);
    close(sock);

    if (n > 0) {
        buffer[n] = '\0'; // 예: "BLOCK|85.50" 수신 완료

        // 4. 파이프(|) 기준으로 문자열 쪼개기 (Parsing)
        char* status_str = strtok(buffer, "|"); // 첫 번째 조각 "BLOCK"
        char* score_str = strtok(NULL, "|");    // 두 번째 조각 "85.50"

        // 5. 점수를 실수(double)로 변환해서 포인터에 저장
        if (score_str != NULL) {
            *out_score = atof(score_str);
        }

        // 6. 문자열 상태를 비교하여 pcap_project.h 에 정의한 정수형 상태값 리턴
        if (status_str != NULL) {
            if (strcmp(status_str, "BLACK") == 0)      return LOG_AI_BLOCK;
            if (strcmp(status_str, "BLACK_DOUBT") == 0) return LOG_AI_DOUBT_BLOCK;
            if (strcmp(status_str, "WHITE_DOUBT") == 0)   return LOG_AI_DOUBT_PASS;
            if (strcmp(status_str, "WHITE") == 0)       return LOG_AI_PASS;
        }
    }

    // 수신 데이터가 깨졌거나 이상할 경우 기본값(통과)
    return LOG_AI_PASS;
}
