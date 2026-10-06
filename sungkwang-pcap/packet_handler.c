#include "pcap_project.h"

void packet_handler(u_char *args, const struct pcap_pkthdr *header, const u_char *packet)
{
    struct ether_header *ethernet = (struct ether_header *)packet;
    if (ntohs(ethernet->ether_type) != ETHERTYPE_IP)
        return;

    struct ip *ip = (struct ip *)(packet + 14);
    in_addr_t compare = inet_addr("192.168.1.119");
    if (ip->ip_src.s_addr != compare)
        return;

    int ip_size = ip->ip_hl * 4;
    struct tcphdr *tcp = (struct tcphdr *)(packet + 14 + ip_size);
    if (ntohs(tcp->th_dport) != 80)
        return;
    int tcp_size = tcp->th_off * 4;

    u_char *payload = (u_char *)(packet + 14 + ip_size + tcp_size);
    uint32_t payload_size = ntohs(ip->ip_len) - (ip_size + tcp_size);

    if (payload_size == 0)
        return;

    // 리다이렉트 무한 루프 방지
    if (strstr((char *)payload, "Host: httpforever.com") != NULL)
        return;

    pcap_t *handle_inject = (pcap_t *)args;

    // 1. 리다이렉트 패킷 생성 및 주입
    inject_redirect(handle_inject, ethernet, ip, tcp, payload_size);

    // 2. RST 패킷 생성 및 주입
    inject_rst(handle_inject, ethernet, ip, tcp, payload_size);
}