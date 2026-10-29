#ifndef PCAP_PROJECT_H
#define PCAP_PROJECT_H

#define _DEFAULT_SOURCE
#define __USE_BSD
#define _GNU_SOURCE       // memmem 등 GNU 확장 함수 사용
#define __FAVOR_BSD       // BSD 스타일 네트워크 헤더 구조체 사용

#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>
#include <pthread.h>
#include <pcap.h>
#include <sys/socket.h>
#include <sys/un.h>
#include <sys/stat.h>
#include <arpa/inet.h>
#include <netinet/in.h>
#include <net/ethernet.h>
#include <netinet/ether.h>
#include <netinet/ip.h>
#include <netinet/tcp.h>
#include <time.h>
#include <signal.h>
#include <stdbool.h>

// =========================================================
// 1. 시스템 상수 및 소켓 경로 정의
// =========================================================
#define MAX_LOG_QUEUE 1024
#define MAX_AI_QUEUE  1024
#define HASH_SIZE     100003  // 해시 충돌 최소화를 위한 소수(Prime Number)
#define MAX_HOSTS     256     // C클래스 서브넷 호스트 개수 (0~255)

#define SOCKET_PATH    "/tmp/authrized_ip"
#define GC_SOCKET_PATH "/tmp/pcap_gc.sock"
#define AI_SOCKET_PATH "/tmp/ai_dga_socket.sock"

// 도메인 판정 및 방패 상태 열거형 (기존 #define 매크로 대체)
typedef enum {
    LOG_PASS         = 0, // 정상 통과 (AI 승인)
    LOG_MANUAL_BLOCK = 1, // 관리자 수동 블랙리스트 차단
    LOG_AI_BLOCK     = 2, // AI 자동 차단
    LOG_PENDING      = 3, // 임시 보류 (AI 검사 중, RST 유도)
    LOG_MANUAL_PASS  = 4  // 관리자 수동 화이트리스트 예외 통과
} BlockStatus;

// 시그널 핸들러(SIGINT 등) 제어를 위한 유일한 전역 플래그
extern volatile sig_atomic_t keep_running;

// =========================================================
// 2. 도메인 방패 (해시테이블 & 더블 버퍼링) 구조체
// =========================================================
typedef struct HashNode {
    char domain[128];
    int block_type;          // BlockStatus 값 저장
    struct HashNode *next;   // Chaining 포인터
} HashNode;

typedef struct HashTable {
    HashNode *table[HASH_SIZE];
} HashTable;

typedef struct {
    HashTable *shield_A;
    HashTable *shield_B;
    HashTable *volatile active_shield;
    pthread_mutex_t lock;    // ★ 기존 전역 shield_lock을 각 방패 매니저 내부로 캡슐화
} DoubleBufferManager;

// =========================================================
// 3. 사원 인증 및 MAC 세션 관리 구조체
// =========================================================
typedef struct {
    int is_active;           // 1: 인증됨, 0: 미인증/차단
    time_t expire_time;      // 절대 만료 시간
    time_t last_seen;        // 유휴 감지를 위한 마지막 통신 시간
    uint8_t mac_addr[6];     // 바인딩된 MAC 주소
    int is_mac_bound;        // MAC 바인딩 여부
} AuthRecord;

typedef struct {
    AuthRecord whitelist[MAX_HOSTS];        // 호스트별 인증 상태 테이블
    uint8_t latest_mac_cache[MAX_HOSTS][6]; // ARP/패킷 기반 최신 MAC 캐시
    pthread_mutex_t lock;                   // ★ 기존 전역 lock을 인증 매니저 내부로 캡슐화
} AuthManager;

// =========================================================
// 4. 비동기 작업 큐 (로그 전송 큐 & AI 분석 큐)
// =========================================================
typedef struct {
    char client_ip[16];
    char target_host[128];
    int is_ai_blocked;
} LogPacket;

typedef struct {
    LogPacket nodes[MAX_LOG_QUEUE];
    int front;
    int rear;
    int count;
    pthread_mutex_t lock;    // ★ 큐 전용 뮤텍스
    pthread_cond_t cond;     // ★ 기존 전역 cond를 로그 큐 내부로 캡슐화
} SharedLogQueue;

typedef struct {
    char domain[128];
} AITask;

typedef struct {
    AITask tasks[MAX_AI_QUEUE];
    int front;
    int rear;
    int count;
    pthread_mutex_t lock;
    pthread_cond_t cond;
} AIQueue;

// =========================================================
// 5. ★ 최상위 엔진 컨텍스트 (전역 변수 통합본)
// =========================================================
// main()에서 선언 후 모든 스레드와 pcap_loop에 포인터로 전달합니다.
typedef struct {
    pcap_t *handle;                    // 패킷 캡처 및 인젝션 핸들
    int server_fd;                     // UDS 서버 소켓 디스크립터
    AuthManager auth_mgr;              // 인증 및 MAC 캐시 매니저
    DoubleBufferManager black_manager; // 블랙리스트 방패 매니저
    DoubleBufferManager white_manager; // 화이트리스트 방패 매니저
    SharedLogQueue log_queue;          // 백엔드 전송용 로그 큐
    AIQueue ai_queue;                  // AI 판독 요청용 큐
} EngineContext;

// =========================================================
// 6. 네트워크 패킷 조작 보조 구조체
// =========================================================
typedef struct {
    u_int32_t source_address;
    u_int32_t dest_address;
    u_int8_t placeholder;
    u_int8_t protocol;
    u_int16_t tcp_length;
} Pseudo_header;

// =========================================================
// 7. 기능별 함수 원형 선언
// =========================================================

// [패킷 핸들러 및 네트워크 유틸]
// pcap_loop의 4번째 인자로 (u_char *)&ctx를 넘기면 args로 들어옵니다.
void packet_handler(u_char *args, const struct pcap_pkthdr *header, const u_char *packet);
unsigned short csum(unsigned short *ptr, int nbytes);
int packet_mac_check(AuthManager *auth_mgr, const int host_id, const uint8_t *packet_mac);

// [스레드 엔트리 함수 (void* arg로 EngineContext* 수신)]
void* uds_server_thread(void *arg);
void* clean_thread(void *arg);
void* ai_worker_thread(void *arg);

// [UDS 통신 및 큐 제어 함수]
void uds_client_sock(const int ip);
void uds_client_sock_log(const LogPacket *local_log);
int ask_ai_domain_status(const char *domain);

void push_to_log_queue(SharedLogQueue *queue, const char *ip, const char *domain, int is_blocked_flag);
int pop_log_queue(SharedLogQueue *queue, LogPacket *out_log);
void push_to_ai_task_queue(AIQueue *queue, const char *domain);

// [해시테이블 및 방패 제어 함수]
unsigned long hash_djb2(const char *str);
HashTable* create_hash_table(void);
void insert_hash_table(DoubleBufferManager *mgr, HashTable *ht, const char *domain, int block_type);
HashNode* lookup_hash_table(DoubleBufferManager *mgr, HashTable *ht, const char *domain);
void free_hash_table(HashTable *ht);
void clear_hash_table(HashTable *ht);
void load_domains_from_txt(DoubleBufferManager *mgr, HashTable *ht, const char *filepath, int block_type);

// [패킷 인젝션 함수]
void inject_redirect(pcap_t *handle_inject, const struct ether_header *ethernet,
                     const struct ip *ip, const struct tcphdr *tcp, uint32_t payload_size);
void inject_redirect_blocked(pcap_t *handle_inject, const struct ether_header *ethernet,
                             const struct ip *ip, const struct tcphdr *tcp, uint32_t payload_size);
void inject_rst(pcap_t *handle_inject, const struct ether_header *ethernet,
                const struct ip *ip, const struct tcphdr *tcp, uint32_t payload_size);

#endif // PCAP_PROJECT_H