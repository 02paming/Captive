#include "pcap_project.h"

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

int packet_mac_check(const int host_id, const uint8_t* packet_mac){
    int is_authenticated;
    

    if (host_id >= 0 && host_id < 254) {
        
        memcpy(latest_mac_cache[host_id], packet_mac, ETH_ALEN);

        pthread_mutex_lock(&lock);

        if (whitelist[host_id].is_active == 1) {
            // 1. 최초 패킷: MAC이 아직 안 묶여있는 경우 바인딩
            if (whitelist[host_id].is_mac_bound == 0) {
                memcpy(whitelist[host_id].mac_addr, packet_mac, ETH_ALEN);
                whitelist[host_id].is_mac_bound = 1;
            } 
            // 2. 두 번째 패킷부터: 기존 MAC과 들어온 MAC 비교 검증
            else {
                if (memcmp(packet_mac, whitelist[host_id].mac_addr, ETH_ALEN) != 0) {
                    // MAC이 다르면 IP 위조로 간주하고 다른곳으로 리다이렉팅시켜야함  (분기문에서 제어) 인증여부를 2로줌
                    printf("인증한계정의 MAC과 일치하지않습니다.\n");
                    pthread_mutex_unlock(&lock);
                    return  2;
                }
            }

            // 3. 검증을 통과하여 여전히 인증 상태라면 생존 시간 갱신 => 이 멤버변수를통해서 7일 미활동 초기화구문을사용할수있음
            if (whitelist[host_id].is_active == 1) {
                whitelist[host_id].last_seen = time(NULL);
            }
        }
        is_authenticated = whitelist[host_id].is_active == 1 ? 1 : 0;
        pthread_mutex_unlock(&lock);
    }

    return is_authenticated;
}


//queue push
void push_to_log_queue(const char* ip, const char* domain, int is_blocked_flag, double score) {
    LogPacket log_data;
    memset(&log_data, 0, sizeof(LogPacket));
    
    strcpy(log_data.client_ip, ip);
    strncpy(log_data.target_host, domain, sizeof(log_data.target_host) - 1);
    log_data.is_ai_blocked = is_blocked_flag; 
    log_data.ai_score = score;

    pthread_mutex_lock(&log_queue.queue_lock);
    if (log_queue.count < MAX_LOG_QUEUE) {
        log_queue.nodes[log_queue.rear] = log_data;
        log_queue.rear = (log_queue.rear + 1) % MAX_LOG_QUEUE;
        log_queue.count++;
        pthread_cond_signal(&log_queue.log_cond); // GC 스레드 기상!
    } else {
        printf("[경고] 로그 큐 오버플로우\n"); 
    }
    pthread_mutex_unlock(&log_queue.queue_lock);
}


//quque pop
int pop_log_queue(LogPacket* out_log) {
    int success = 0;
    
    pthread_mutex_lock(&log_queue.queue_lock); // 자물쇠 잠금
    
    if (log_queue.count > 0) {
        *out_log = log_queue.nodes[log_queue.front];
        log_queue.front = (log_queue.front + 1) % MAX_LOG_QUEUE;
        log_queue.count--;
        success = 1; // Pop 성공
      } else {
        // printf("[경고] 큐에서 pop할 데이터가 없습니다.\n");
      }
      
      pthread_mutex_unlock(&log_queue.queue_lock); // 자물쇠 해제 (핵심: I/O 전에 미리 품)
      
      return success;
    }
    
//ai분석용 queue push
void push_to_ai_task_queue(const char *domain) {
    pthread_mutex_lock(&ai_queue.lock);

    if (ai_queue.count < MAX_AI_QUEUE) {
        strncpy(ai_queue.tasks[ai_queue.rear].domain, domain, 127);
        ai_queue.tasks[ai_queue.rear].domain[127] = '\0';
        
        ai_queue.rear = (ai_queue.rear + 1) % MAX_AI_QUEUE;
        ai_queue.count++;
        printf("1. 큐에 푸시됨: %s\n", domain);
        // 자고 있는 AI 스레드를 깨움
        pthread_cond_signal(&ai_queue.cond); 
    }

    pthread_mutex_unlock(&ai_queue.lock);
}

//ai분석용 queue pop
int pop_ai_queue(char* out_domain) {
    pthread_mutex_lock(&ai_queue.lock);

    // 1. 큐가 비어있으면 누군가 깨워줄 때까지 대기
    while (ai_queue.count == 0 && keep_running) {
        pthread_cond_wait(&ai_queue.cond, &ai_queue.lock);
    }

    // 2. 종료 신호를 받았고 처리할 남은 큐도 없다면 락을 풀고 0 반환
    if (!keep_running && ai_queue.count == 0) {
        pthread_mutex_unlock(&ai_queue.lock);
        return 0; 
    }

    // 3. 큐에서 도메인 데이터 복사 
    strncpy(out_domain, ai_queue.tasks[ai_queue.front].domain, 127);
    out_domain[127] = '\0'; 

    // 4. 큐 인덱스 및 카운트 조정
    ai_queue.front = (ai_queue.front + 1) % MAX_AI_QUEUE; 
    ai_queue.count--;

    pthread_mutex_unlock(&ai_queue.lock);
    return 1; // 성공적으로 뺐음
}

// AI에게 도메인을 묻고 결과를 반환 (1 = BLACK, 2 = BLACK_DOUBT, 3 = WHITE_DOUBT , 4 = WHITE)
int ask_ai_domain_status(const char* domain, double* out_score) {
    int sock = socket(AF_UNIX, SOCK_STREAM, 0);
    if (sock == -1) return LOG_AI_PASS; // 소켓 생성 실패 시 안전을 위해 PASS 처리 (Fail-Open)

    // 소켓 타임아웃 설정 (AI 서버가 죽었을 때 C엔진이 멈추는 것 방지, 10ms 한계)
    struct timeval tv;
    tv.tv_sec = 0;
    tv.tv_usec = 500000; // 10ms (0.01초)
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
            if (strcmp(status_str, "BLOCK") == 0)      return LOG_AI_BLOCK;
            if (strcmp(status_str, "SUSPICIOUS") == 0) return LOG_AI_DOUBT_BLOCK;
            if (strcmp(status_str, "GREYLIST") == 0)   return LOG_AI_DOUBT_PASS;
            if (strcmp(status_str, "PASS") == 0)       return LOG_AI_PASS;
        }
    }

    // 수신 데이터가 깨졌거나 이상할 경우 기본값(통과)
    return LOG_AI_PASS;
}



// 1. djb2 알고리즘 (글자를 수학 공식에 넣어 0~100002 사이의 방 번호로 즉시 뱉어냄)
unsigned long hash_djb2(const char *str) {
    unsigned long hash = 5381;
    int c;
    while ((c = *str++)) {
        hash = ((hash << 5) + hash) + c; // hash * 33 + c
    }
    return hash % HASH_SIZE; // 10만 개의 방 안으로 번호 우겨넣기
}

// 2. 방패 깎기 (서버 켜질 때 & RELOAD 될 때 사용)
HashTable* create_hash_table() {
    HashTable *ht = (HashTable*)malloc(sizeof(HashTable));
    for (int i = 0; i < HASH_SIZE; i++) {
        ht->table[i] = NULL; // 처음에 모든 방은 비워둠
    }
    pthread_mutex_init(&ht->shield_lock, NULL);
    return ht;
}

// 3. 도메인 쑤셔넣기 (AI가 차단했거나, 처음 txt 파일 읽어올 때)
void insert_hash_table(HashTable *ht, const char *domain, int block_type, double score) {
    if (!ht || !domain) return;
    
    pthread_mutex_lock(&ht->shield_lock);

    unsigned long index = hash_djb2(domain); // 방 번호 찾기 (0초컷)
    
    // 이미 같은 도메인이 꽂혀있는지 확인 (중복 방지)
    HashNode *current = ht->table[index];
    while (current != NULL) {
        if (strcmp(current->domain, domain) == 0) {
            current->block_type = block_type; // 상태 덮어쓰기!
            current->ai_score = score;

    pthread_mutex_unlock(&ht->shield_lock);
            return; 
        }
        current = current->next;
    }
    
    // 새로운 도메인 노드 생성해서 그 방 맨 앞에 꽂기 (0.000001초 컷)
    HashNode *new_node = (HashNode*)malloc(sizeof(HashNode));
    strncpy(new_node->domain, domain, sizeof(new_node->domain) - 1);
    new_node->domain[sizeof(new_node->domain) - 1] = '\0';
    

    new_node->block_type = block_type;
    new_node->ai_score = score;

    new_node->next = ht->table[index];
    ht->table[index] = new_node;

    pthread_mutex_unlock(&ht->shield_lock);
}

// 4. 특정도메인(노드) 찾아서 삭제
int delete_from_hash_table(HashTable *ht, const char *domain) {
    if (!ht || !domain) return 0; // 실패(삭제할 내용 없음)

    // pthread_mutex_lock(&ht->shield_lock);

    unsigned long index = hash_djb2(domain); // 삭제할 방 번호 찾기
    HashNode *current = ht->table[index];
    HashNode *prev = NULL;

    // 해당 방의 연결 리스트를 순회하며 도메인 찾기
    while (current != NULL) {
        if (strcmp(current->domain, domain) == 0) { 
            // 🎯 찾았다! 
            
            // 1. 앞뒤 노드 연결줄 끊고 이어붙이기
            if (prev == NULL) {
                // 맨 앞 노드(Head)를 삭제하는 경우
                ht->table[index] = current->next;
            } else {
                // 중간이나 끝 노드를 삭제하는 경우
                prev->next = current->next;
            }

            // 2. 메모리 해제 (C언어 메모리 누수 방지)
            // (※ 주의: insert 하실 때 domain을 strdup나 malloc으로 동적 할당하셨다면
            // 여기서 free(current->domain); 도 반드시 해주셔야 합니다.)
            free(current); // 노드 자체를 메모리에서 완전히 날림

            // 3. 카운트 차감 (ht->count 가 있다면 추가)
            // ht->count--; 
            // pthread_mutex_unlock(&ht->shield_lock);
            return 1; // 삭제 성공! (true)
        }
        
        // 못 찾았으면 다음 노드로 이동
        prev = current;
        current = current->next;
    }

    // pthread_mutex_unlock(&ht->shield_lock);
    return 0; // 해당 도메인이 방패에 없음 (false)
}

// 4. 초고속 탐색 (패킷이 들어올 때마다 검사하는 제일 중요한 함수)
HashNode* lookup_hash_table(HashTable *ht, const char *domain) {
    if (!ht || !domain) return 0; // 0은 false를 의미
    
    // pthread_mutex_lock(&shield_lock);

    unsigned long index = hash_djb2(domain); // 수학 공식 돌려서 방 번호 즉시 도출
    HashNode *current = ht->table[index];
    
    // 그 방에 가서 도메인이 맞는지 딱 확인
    while (current != NULL) {
        if (strcmp(current->domain, domain) == 0) {
            // pthread_mutex_unlock(&shield_lock);
            return current; // 찾음! (true = 차단해라!)
        }
        current = current->next;
    }

    // pthread_mutex_unlock(&shield_lock);
    return NULL; // 못 찾음 (false = 미지의 도메인이니 AI한테 넘겨라!)
}

void clear_hash_table(HashTable* ht) {
    if (ht == NULL) return;
    
    for (int i = 0; i < HASH_SIZE; i++) {
        HashNode* current = ht->table[i];
        while (current != NULL) {
            HashNode* temp = current;
            current = current->next;
            free(temp); // ★ 이 free가 없으면 RELOAD 때마다 메모리가 터집니다!
        }
        ht->table[i] = NULL; // 다 지우고 나면 다시 빈 포인터로 초기화 (댕글린방지)
    }
}

// 5. 방패 폐기 (RELOAD 스위칭 후 쓸모없어진 옛날 방패를 메모리에서 날려버림)
void free_hash_table(HashTable *ht) {
    if (!ht) return;

    clear_hash_table(ht);

    free(ht); // 방패 본체 해제
}

// txt 파일을 한 줄씩 읽어서 방패에 무자비하게 꽂아 넣는 함수
void load_domains_from_txt(HashTable *ht, const char *filepath,int block_type, double score) {
    if (!ht || !filepath) return;

    FILE *file = fopen(filepath, "r");
    if (!file) {
        printf("[경고] %s 파일을 찾을 수 없습니다. (빈 방패로 시작합니다)\n", filepath);
        return;
    }

    char line[256];
    int count = 0;
    
    // 파일 끝까지 한 줄씩 읽기
    while (fgets(line, sizeof(line), file)) {
        // 뒤에 붙은 엔터바(\n, \r) 깔끔하게 제거
        line[strcspn(line, "\r\n")] = 0; 
        
        // 빈 줄이면 패스
        if (strlen(line) == 0) continue; 
        
        // 해시 테이블에 0초 컷 인서트
        insert_hash_table(ht, line,block_type,score);
        count++;
    }
    
    fclose(file);
    printf("[SYSTEM] %s 파일에서 %d개의 도메인을 방패에 장전 완료!\n", filepath, count);
}