#include "pcap_project.h"

void packet_handler(u_char *args, const struct pcap_pkthdr *header, const u_char *packet)
{
    pcap_t *handle_inject = (pcap_t *)args;

    struct ether_header *ethernet = (struct ether_header *)packet;
    if (ntohs(ethernet->ether_type) != ETHERTYPE_IP)
        return;

    struct ip *ip = (struct ip *)(packet + sizeof(struct ether_header));
    int ip_size = ip->ip_hl * 4;
    
    struct tcphdr *tcp = (struct tcphdr *)(packet + sizeof(struct ether_header) + ip_size);
    int tcp_size = tcp->th_off * 4;

    u_char *payload = (u_char *)(packet + sizeof(struct ether_header) + ip_size + tcp_size);
    uint32_t payload_size = ntohs(ip->ip_len) - (ip_size + tcp_size);

    unsigned char* ip_bytes = (unsigned char*)&(ip->ip_src.s_addr);
    int host_id = ip_bytes[3];

    //인증성공시 
    if (packet_mac_check(host_id, ethernet->ether_shost) == 1) {
        printf("인증완료된 계정입니다!! [%s]\n",inet_ntoa(ip->ip_src));

        if (payload_size == 0)
            return;
        
        char *payload_start = (char *)tcp + tcp_size;
        char *host_start = memmem(payload_start, payload_size, "Host: ", 6);

        if (host_start == NULL)
            return;

        char check_site[128] = {0};
        host_start += strlen("Host: ");

        int remaining_len = payload_size - (host_start - (char *)tcp);
        char *host_end = memchr(host_start, '\r', remaining_len);

        int host_len = host_end - host_start;
        if (host_len > sizeof(check_site) - 1)
        host_len = sizeof(check_site) - 1;

        memcpy(check_site, host_start, host_len);
        check_site[host_len] = '\0'; // 문자열의 끝을 명시

        int list_check = false;
        for (int i = 0; i < check_manager.count; i++) {
            if (strstr(check_manager.target_url[i], check_site) != NULL) {
                list_check = true;
                break;
            }
        }

        if (list_check) {
            printf("접근 금지사이트 접속 시도 감지!! [%s]\n",inet_ntoa(ip->ip_src));

            // 1. 리다이렉트 패킷 생성 및 주입 (블랙리스트 사이트접근시 차단사이트로)
            inject_redirect_blocked(handle_inject, ethernet, ip, tcp, payload_size);

            // 2. RST 패킷 생성 및 주입
            inject_rst(handle_inject, ethernet, ip, tcp, payload_size);
        }  
        return;  //인증완료되었음으로 인젝션필요없이 pass! return해줌
    }

    printf("인증이 아직안된 계정입니다. 인증해주세요! [%s]\n",inet_ntoa(ip->ip_src));

    if (payload_size == 0)
        return;

    // 리다이렉트 무한 루프 방지
    if (strstr((char *)payload, "Host: 192.168.3.243") != NULL)
        return;


    // 1. 리다이렉트 패킷 생성 및 주입
    inject_redirect(handle_inject, ethernet, ip, tcp, payload_size);

    // 2. RST 패킷 생성 및 주입
    inject_rst(handle_inject, ethernet, ip, tcp, payload_size);

    
}