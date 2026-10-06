#include "pcap_project.h"

void packet_handler(u_char *args, const struct pcap_pkthdr *header, const u_char *packet)
{
    struct ether_header *ethernet = (struct ether_header *)packet;
    if (ntohs(ethernet->ether_type) != ETHERTYPE_IP)
        return;

    struct ip *ip = (struct ip *)(packet + 14);
    in_addr_t compare = inet_addr("192.168.2.55");
    if (ip->ip_src.s_addr != compare)
        return;

    int ip_size = ip->ip_hl * 4;
    struct tcphdr *tcp = (struct tcphdr *)(packet + 14 + ip_size);
    if (ntohs(tcp->th_dport) != 80)
        return;
    int tcp_size = tcp->th_off * 4;

    u_char *payload = (u_char *)(packet + 14 + ip_size + tcp_size);
    uint32_t payload_size = ntohs(ip->ip_len) - (ip_size + tcp_size);

    unsigned char* ip_bytes = (unsigned char*)&(ip->ip_src.s_addr);
    int host_id = ip_bytes[3];

    int is_authenticated = 0;

    if (host_id >= 0 && host_id < 254) {
        pthread_mutex_lock(&lock);
        is_authenticated = whitelist[host_id]; //화리속 인증된ip라면 1이들어있음
        pthread_mutex_unlock(&lock);
    }

    //인증성공시 
    if (is_authenticated == 1) {
        printf("인증완료된 ip입니다!! [%s]\n",inet_ntoa(ip->ip_src));
        return;  //인증완료되었음으로 인젝션필요없이 pass! return해줌
    }

    printf("인증이 아직안된 ip입니다. 인증해주세요! [%s]\n",inet_ntoa(ip->ip_src));

    if (payload_size == 0)
        return;

    // 리다이렉트 무한 루프 방지
    if (strstr((char *)payload, "Host: 192.168.3.243") != NULL)
        return;

    pcap_t *handle_inject = (pcap_t *)args;

    // 1. 리다이렉트 패킷 생성 및 주입
    inject_redirect(handle_inject, ethernet, ip, tcp, payload_size);

    // 2. RST 패킷 생성 및 주입
    inject_rst(handle_inject, ethernet, ip, tcp, payload_size);
}