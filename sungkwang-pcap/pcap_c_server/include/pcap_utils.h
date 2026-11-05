#ifndef PCAP_UTILS_H
#define PCAP_UTILS_H

#include "pcap_common.h"

// 패킷 처리 및 인젝션
void packet_handler(u_char *user_args, const struct pcap_pkthdr *header, const u_char *packet);
unsigned short csum(unsigned short *ptr, int nbytes);
void inject_redirect_blocked(pcap_t *handle_inject, const struct ether_header *ethernet, const struct ip *ip, const struct tcphdr *tcp, uint32_t payload_size, u_int token);
void inject_rst(pcap_t *handle_inject, const struct ether_header *ethernet, const struct ip *ip, const struct tcphdr *tcp, uint32_t payload_size);

// 일회용 토큰 및 밴 안내창 인젝션 함수 원형
void inject_redirect_token(pcap_t *handle_inject, const struct ether_header *ethernet, const struct ip *ip, const struct tcphdr *tcp, uint32_t payload_size, u_int token);
void inject_redirect_ban(pcap_t *handle_inject, const struct ether_header *ethernet, const struct ip *ip, const struct tcphdr *tcp, uint32_t payload_size, u_int token, const char* reason);

// UDS 통신
void uds_client_sock(const int ip);
void uds_client_sock_log(const LogPacket* local_log);
void send_to_uds(const char* message);
void send_token(u_int token);

// MAC 검증 및 큐 관리
int packet_mac_check(EngineContext *ctx, const int host_id, const uint8_t* packet_mac);
void push_to_log_queue(EngineContext *ctx, const char* ip, const char* domain, int is_blocked_flag, double score);
int pop_log_queue(EngineContext *ctx, LogPacket* out_log);
void push_to_ai_task_queue(EngineContext *ctx, const char *domain);
int pop_ai_queue(EngineContext *ctx, char* out_domain);
int ask_ai_domain_status(const char* domain, double* out_score);

#endif 