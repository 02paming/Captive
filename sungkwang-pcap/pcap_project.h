#include <stdio.h>
#include <pcap.h>
#include <net/ethernet.h>
#include <netinet/ip.h>
#include <netinet/tcp.h>
#include <ctype.h>
#include <stdlib.h>
#include <string.h>
#include <arpa/inet.h>

// TCP Checksum 계산을 위한 가상 헤더 구조체
typedef struct
{
    u_int32_t source_address;
    u_int32_t dest_address;
    u_int8_t placeholder;
    u_int8_t protocol;
    u_int16_t tcp_length;
} Pseudo_header;

// 기능별 함수 원형 선언
void packet_handler(u_char *args, const struct pcap_pkthdr *header, const u_char *packet);
unsigned short csum(unsigned short *ptr, int nbytes);

// 인젝션 함수 모듈화
void inject_redirect(pcap_t *handle_inject, const struct ether_header *ethernet, const struct ip *ip, const struct tcphdr *tcp, uint32_t payload_size);
void inject_rst(pcap_t *handle_inject, const struct ether_header *ethernet, const struct ip *ip, const struct tcphdr *tcp, uint32_t payload_size);