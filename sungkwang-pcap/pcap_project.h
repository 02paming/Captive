#define _DEFAULT_SOURCE
#define __USE_BSD
#define _GNU_SOURCE       // memmem 같은 GNU 확장 함수를 쓰겠다고 선언
#define __FAVOR_BSD       // th_seq, th_sport 같은 유닉스(BSD) 스타일 구조체 이름을 쓰겠다고 선언

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

#define MAX_BLACKLIST_COUNT 128
#define MAX_LOG_QUEUE 1024
#define MAX_AI_QUEUE 1024

//보통수신용 소켓경로(양방향도쓰긴함 맥물어볼떄)
#define SOCKET_PATH "/tmp/authrized_ip"

//송신용(GC + LOG) 소켓경로
#define GC_LOG_SOCKET_PATH  "/tmp/pcap_gc.sock"

// 파이썬 AI 서버와 약속된 소켓 경로
#define AI_SOCKET_PATH "/tmp/ai_dga_socket.sock"

// 해시 테이블 방의 개수 (소수(Prime Number)로 해야 충돌이 제일 적게 납니다. 약 10만 개 방)
#define HASH_SIZE 200001

#define LOG_PENDING 0         // 임시 보류 (검사 중, RST만 쏴서 재전송 유도)
#define LOG_MANUAL_BLOCK 1    // 수동 블랙리스트 차단
#define LOG_MANUAL_PASS 2     // 관리자 수동 화이트리스트 예외처리
#define LOG_AI_BLOCK 3        // AI  차단
#define LOG_AI_DOUBT_BLOCK 4  // AI 의심 차단
#define LOG_AI_DOUBT_PASS 5   // AI 의심 정상 통과
#define LOG_AI_PASS 6         // AI 정상 통과

//워커스레드 즉, 일하는 카운터 종업원 몇명둘지
#define AI_WORKERS 8

//배열연결리스트 + 해쉬테이블 구조

// 1. 해시 노드 (방 안에 들어갈 데이터)
typedef struct HashNode {
    char domain[128];       // 도메인 주소 (예: naver.com)
    int block_type;         // 상태 플래그
    double ai_score;        // AI 평가 점수
    struct HashNode *next;  // 재수가 없어서 해시 번호가 겹쳤을 때 뒤에 꼬리로 달기 위한 포인터
} HashNode;

// 2. 방패 본체 (이것이 A방패, B방패가 됩니다) A방패(블랙리스트검증해쉬테이블 1개 , 화이트리스트검증해쉬테이블1개) 이런식임
typedef struct HashTable {
    HashNode *table[HASH_SIZE]; // 10만 개의 방을 가진 거대한 배열
    pthread_mutex_t shield_lock;
} HashTable;

// 1. 방패 2개와 활성 포인터를 담는 '더블 버퍼링 구조체' 정의
typedef struct {
    HashTable* shield_A;               // A 방패
    HashTable* shield_B;               // B 방패 (예비용) 
    HashTable* volatile active_shield; // 패킷 검사 스레드가 바라볼 진짜 포인터
} DoubleBufferManager;

// 2. 스레드들이 공유해서 볼 수 있도록 구조체 인스턴스 딱 1개만 전역 선언
extern DoubleBufferManager black_manager;
extern DoubleBufferManager white_manager;


typedef struct {
    int is_active;           // 1: 인증됨, 0: 차단
    time_t expire_time;      // 30일 절대 만료 시간
    time_t last_seen;        // 7일 유휴 감지를 위한 마지막 통신 시간
    uint8_t mac_addr[6];     // 바인딩된 MAC 주소
    int is_mac_bound;        // MAC 바인딩 여부 (1: 바인딩됨)
} AuthRecord; //인증레코드



//로그용(ai차단추가용으로도씀) 큐
typedef struct {
    char client_ip[16];
    char target_host[128]; 
    int is_ai_blocked;
    double ai_score;
} LogPacket; //인증된사원 일반접속로그

typedef struct{
    LogPacket nodes[MAX_LOG_QUEUE]; // 원형 큐 배열
    int front; // 파이썬으로 보낼 차례인 인덱스
    int rear;  // 새로 들어올 패킷을 넣을 인덱스
    int count; // 현재 큐에 쌓인 패킷 개수
    pthread_mutex_t queue_lock; // 로그 전송 전용 자물쇠
    pthread_cond_t log_cond;
}SharedLogQueue; //일반접속로그 전용 큐 구조체

//ai 분석용 큐
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


extern AuthRecord whitelist[256];
extern pthread_mutex_t lock;
extern pthread_cond_t cond;
extern volatile sig_atomic_t keep_running;
extern int server_fd;
extern pcap_t *handle;
extern uint8_t latest_mac_cache[256][6];
extern SharedLogQueue log_queue;
extern AIQueue ai_queue;


// TCP Checksum 계산을 위한 가상 헤더 구조체
typedef struct {
  u_int32_t source_address;
  u_int32_t dest_address;
  u_int8_t placeholder;
  u_int8_t protocol;
  u_int16_t tcp_length;
} Pseudo_header;

// 기능별 함수 원형 선언
void packet_handler(u_char *args, const struct pcap_pkthdr *header,
                    const u_char *packet);
unsigned short csum(unsigned short *ptr, int nbytes);

void uds_client_sock(const int ip);
void uds_client_sock_log(const LogPacket* local_log);
void send_to_uds(const char* message);

int packet_mac_check(const int host_id, const uint8_t* packet_mac);

void* uds_server_thread(void* arg);
void* clean_thread(void* arg);
void* ai_worker_thread(void* arg);
void* log_thread(void* arg);
void push_to_log_queue(const char* ip, const char* domain, int is_blocked_flag, double score);
int pop_log_queue(LogPacket* out_log);
void push_to_ai_task_queue(const char *domain);
int pop_ai_queue(char* out_domain);
int ask_ai_domain_status(const char* domain, double* out_score);

//해쉬테이블쪽
unsigned long hash_djb2(const char *str);
HashTable* create_hash_table();
void insert_hash_table(HashTable *ht, const char *domain, int block_type, double score);
int delete_from_hash_table(HashTable *ht, const char *domain);
HashNode* lookup_hash_table(HashTable *ht, const char *domain);
void free_hash_table(HashTable *ht);
void clear_hash_table(HashTable* ht);
void load_domains_from_txt(HashTable *ht, const char *filepath,int block_type, double score);



// 인젝션 함수 모듈화
void inject_redirect(pcap_t *handle_inject, const struct ether_header *ethernet,
                     const struct ip *ip, const struct tcphdr *tcp,
                     uint32_t payload_size);

void inject_redirect_blocked(pcap_t *handle_inject, const struct ether_header *ethernet, 
                      const struct ip *ip, const struct tcphdr *tcp,
                      uint32_t payload_size);


void inject_rst(pcap_t *handle_inject, const struct ether_header *ethernet,
                const struct ip *ip, const struct tcphdr *tcp,
                uint32_t payload_size);