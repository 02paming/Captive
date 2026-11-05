#ifndef PCAP_COMMON_H
#define PCAP_COMMON_H

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
#define HASH_SIZE 200001  // 해시 테이블 방의 개수 (소수(Prime Number)로 해야 충돌이 제일 적게 납니다. 약 10만 개 방)
#define AI_WORKERS 8      //워커스레드 즉, 일하는 카운터 종업원 몇명둘지


#define SOCKET_PATH "/tmp/authrized_ip"           // C 엔진 수신 (PC 인증/정책 제어)
#define TOKEN_SOCK_PATH "/tmp/token_socket"       // Flask 수신 (일회용 토큰 전송) 
#define GC_LOG_SOCKET_PATH "/tmp/pcap_gc.sock"    // Flask 수신 (만료 IP 및 접속 로그 전송)
#define AI_SOCKET_PATH "/tmp/ai_dga_socket.sock"  // AI 파이썬 워커 전송

//패킷의 계급이라보면됨
#define LOG_PENDING 0         // 임시 보류 (검사 중, RST만 쏴서 재전송 유도)
#define LOG_MANUAL_BLOCK 1    // 수동 블랙리스트 차단
#define LOG_MANUAL_PASS 2     // 관리자 수동 화이트리스트 예외처리
#define LOG_AI_BLOCK 3        // AI  차단
#define LOG_AI_DOUBT_BLOCK 4  // AI 의심 차단
#define LOG_AI_DOUBT_PASS 5   // AI 의심 정상 통과
#define LOG_AI_PASS 6         // AI 정상 통과



//배열연결리스트 + 해쉬테이블 구조
// 1. 해시 노드 (방 안에 들어갈 데이터)
typedef struct HashNode {
    char domain[128];       // 도메인 주소 (예: naver.com)
    int block_type;         // 상태 플래그
    double ai_score;        // AI 평가 점수
    struct HashNode *next;  // 재수가 없어서 해시 번호가 겹쳤을 때 뒤에 꼬리로 달기 위한 포인터
} HashNode;

// 방패 본체 (이것이 A방패, B방패가 됩니다) A방패(블랙리스트검증해쉬테이블 1개 , 화이트리스트검증해쉬테이블1개) 이런식임
typedef struct HashTable {
    HashNode *table[HASH_SIZE]; // 10만 개의 방을 가진 거대한 배열
    pthread_mutex_t shield_lock;
} HashTable;

// 2. 방패 2개와 활성 포인터를 담는 '더블 버퍼링 구조체' 정의
typedef struct {
    HashTable* shield_A;               // A 방패
    HashTable* shield_B;               // B 방패 (예비용) 
    HashTable* volatile active_shield; // 패킷 검사 스레드가 바라볼 진짜 포인터
} DoubleBufferManager;

typedef struct {
    int is_active;           // 1: 인증됨, 0: 차단
    uint8_t mac_addr[6];     // 바인딩된 MAC 주소
    int is_mac_bound;        // MAC 바인딩 여부 (1: 바인딩됨)
    time_t last_seen;        // 7일 유휴 감지를 위한 마지막 통신 시간
    time_t last_redir_time;  // 2초 내 중복 리다이렉트 방어용
    time_t last_log_time;    // 1초 내 중복 로깅(도배) 방어용 
    u_int token;             // 일회용 동적 토큰값
} AuthRecord; //인증레코드

// PC 인증 관리 전용 구조체
typedef struct {
    AuthRecord records[256];             // 기존 whitelist
    uint8_t latest_mac_cache[256][6];    // MAC 주소 캐시
    pthread_mutex_t lock;                // 이 인증 테이블만 전담하는 락!
    pthread_cond_t cond;                 // 만료 스레드 수면/기상 제어용
} AuthManager;

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


typedef struct {
    // [하드웨어 리소스]
    pcap_t *mir_handle;
    pcap_t *inject_handle;
    int server_fd;
    volatile sig_atomic_t keep_running;

    // [PC 인증 매니저 ] 
    AuthManager auth;

    // [동적 출퇴근 정책]
    int start_time;
    int end_time;
    int expire_interval;

    // [더블 버퍼링 방패 매니저(동적)]
    DoubleBufferManager black_manager;
    DoubleBufferManager white_manager;

    //[고정전용 화이트,블랙 해시테이블 (고정)]
    HashTable *fixed_black_shield;
    HashTable *fixed_white_shield;

    // [스레드 간 통신 큐]
    SharedLogQueue log_queue;
    AIQueue ai_queue;
} EngineContext;


// TCP Checksum 계산을 위한 가상 헤더 구조체
typedef struct {
  u_int32_t source_address;
  u_int32_t dest_address;
  u_int8_t placeholder;
  u_int8_t protocol;
  u_int16_t tcp_length;
} Pseudo_header;

#endif