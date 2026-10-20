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

#define SOCKET_PATH "/tmp/authrized_ip"
#define GC_SOCKET_PATH  "/tmp/pcap_gc.sock"

typedef struct {
  char *target_url[MAX_BLACKLIST_COUNT];
  u_int count;
  pthread_mutex_t lock;
} BlackListInfo; //블랙리스트 정보

typedef struct {
    int is_active;           // 1: 인증됨, 0: 차단
    time_t expire_time;      // 30일 절대 만료 시간
    time_t last_seen;        // 7일 유휴 감지를 위한 마지막 통신 시간
    uint8_t mac_addr[6];     // 바인딩된 MAC 주소
    int is_mac_bound;        // MAC 바인딩 여부 (1: 바인딩됨)
} AuthRecord; //인증레코드

typedef struct {
    char client_ip[16];
    char target_host[128]; 
} LogPacket; //인증된사원 일반접속로그

typedef struct{
    LogPacket nodes[MAX_LOG_QUEUE]; // 원형 큐 배열
    int front; // 파이썬으로 보낼 차례인 인덱스
    int rear;  // 새로 들어올 패킷을 넣을 인덱스
    int count; // 현재 큐에 쌓인 패킷 개수
    pthread_mutex_t queue_lock; // 로그 전송 전용 자물쇠
}SharedLogQueue; //일반접속로그 전용 큐 구조체

extern AuthRecord whitelist[256];
extern pthread_mutex_t lock;
extern pthread_cond_t cond;
extern volatile sig_atomic_t keep_running;
extern int server_fd;
extern pcap_t *handle;
extern uint8_t latest_mac_cache[256][6];
extern BlackListInfo check_manager;
extern LogPacket log_date;
extern SharedLogQueue log_queue;

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

int packet_mac_check(const int host_id, const uint8_t* packet_mac);

void* uds_server_thread(void* arg);
void* clean_thread(void* arg);
void load_blacklist(void);

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