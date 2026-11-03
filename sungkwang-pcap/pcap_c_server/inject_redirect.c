#include "pcap_project.h"

// =========================================================================
// [공통] 리다이렉트 패킷 생성 및 인젝션을 담당하여 코드 중복 제거
// =========================================================================
void send_fake_redirect_packet(pcap_t *handle_inject, const struct ether_header *ethernet, 
                               const struct ip *ip, const struct tcphdr *tcp, 
                               uint32_t payload_size, const char* redirectMsg, const char* log_msg) 
{
    uint32_t c_seq = ntohl(tcp->th_seq);
    uint32_t c_ack = ntohl(tcp->th_ack);
    uint16_t c_port = ntohs(tcp->th_sport);
    uint16_t s_port = ntohs(tcp->th_dport);

    char c_ip[20], s_ip[20];
    
    // strcpy 대신 snprintf를 사용하여 버퍼 오버플로우 방지
    snprintf(c_ip, sizeof(c_ip), "%s", inet_ntoa(ip->ip_src));
    snprintf(s_ip, sizeof(s_ip), "%s", inet_ntoa(ip->ip_dst));

    uint32_t fake_seq = c_ack;
    uint32_t fake_ack = c_seq + payload_size;

    u_char fake_packet[1500];
    memset(fake_packet, 0, sizeof(fake_packet));
    int fake_tcp_size = sizeof(struct tcphdr);

    struct ether_header *fake_eth = (struct ether_header *)fake_packet;
    struct ip *fake_ip = (struct ip *)(fake_packet + sizeof(struct ether_header));
    struct tcphdr *fake_tcp = (struct tcphdr *)(fake_packet + sizeof(struct ether_header) + sizeof(struct ip));

    u_char *fake_payload = fake_packet + sizeof(struct ether_header) + sizeof(struct ip) + fake_tcp_size;
    int fake_payload_len = strlen(redirectMsg);
    memcpy(fake_payload, redirectMsg, fake_payload_len);

    memcpy(fake_eth, ethernet, sizeof(struct ether_header));
    memcpy(fake_eth->ether_dhost, ethernet->ether_shost, ETH_ALEN);
    memcpy(fake_eth->ether_shost, ethernet->ether_dhost, ETH_ALEN);

    memcpy(fake_ip, ip, sizeof(struct ip));
    fake_ip->ip_hl = 5;
    fake_ip->ip_len = htons(sizeof(struct ip) + fake_tcp_size + fake_payload_len);
    fake_ip->ip_src.s_addr = inet_addr(s_ip);
    fake_ip->ip_dst.s_addr = inet_addr(c_ip);

    memcpy(fake_tcp, tcp, fake_tcp_size);
    fake_tcp->th_off = 5;
    fake_tcp->th_flags = TH_ACK | TH_PUSH;
    fake_tcp->th_ack = htonl(fake_ack);
    fake_tcp->th_seq = htonl(fake_seq);
    fake_tcp->th_sport = htons(s_port);
    fake_tcp->th_dport = htons(c_port);

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

    int inject_result = pcap_inject(handle_inject, fake_packet, sizeof(struct ether_header) + sizeof(struct ip) + fake_tcp_size + fake_payload_len);
    
    if (log_msg != NULL) {
        printf("%s : %d\n", log_msg, inject_result);
    }
}


// =========================================================================
// 1. 밴 페이지 리다이렉트
// =========================================================================
void inject_redirect_ban(pcap_t *handle_inject, const struct ether_header *ethernet, const struct ip *ip, const struct tcphdr *tcp, uint32_t payload_size, u_int token, const char* reason)
{
    char redirectMsg[512];
    memset(redirectMsg, 0, sizeof(redirectMsg));

    snprintf(redirectMsg, sizeof(redirectMsg),
             "HTTP/1.1 302 Found\r\n"
             "Location: http://192.168.3.243/ban?token=%u&reason=%s\r\n"
             "Content-Length: 0\r\n"
             "Connection: close\r\n"
             "\r\n", token, reason);

    char logMsg[256];
    snprintf(logMsg, sizeof(logMsg), "사유(%s) 및 토큰(%u) 포함 밴 페이지 인젝션", reason, token);

    // 공통 함수 호출
    send_fake_redirect_packet(handle_inject, ethernet, ip, tcp, payload_size, redirectMsg, logMsg);
}

// =========================================================================
// 2. 차단 페이지 리다이렉트
// =========================================================================
void inject_redirect_blocked(pcap_t *handle_inject, const struct ether_header *ethernet, const struct ip *ip, const struct tcphdr *tcp, uint32_t payload_size, u_int token)
{
    char find_url[] = "Host: ";
    char *url_start = memmem((u_char*)tcp + tcp->th_off * 4, payload_size, find_url, strlen(find_url)); 
    char target_url[512] = {0};
    
    if (url_start != NULL) {
        url_start += strlen(find_url);
        int remaining_len = payload_size - (url_start - (char*)tcp);
        char *url_end = memchr(url_start, '\r', remaining_len);

        if (url_end != NULL) {
            int url_len = url_end - url_start;
            if (url_len >= sizeof(target_url)) {
                url_len = sizeof(target_url) - 1;
            }
            memcpy(target_url, url_start, url_len);
            target_url[url_len] = '\0';
        } else {
            snprintf(target_url, sizeof(target_url), "unknown-url"); // strcpy 제거
        }
    } else{
        snprintf(target_url, sizeof(target_url), "unknown-url"); // strcpy 제거
    }

    char src_ip_str[20];
    snprintf(src_ip_str, sizeof(src_ip_str), "%s", inet_ntoa(ip->ip_src));

    char redirectMsg[1024];
    memset(redirectMsg, 0, sizeof(redirectMsg));
    snprintf(redirectMsg, sizeof(redirectMsg),
            "HTTP/1.1 302 Found\r\n"
            "Location: http://192.168.3.243/blocked?url=%s&ip=%s&token=%u\r\n"
            "Content-Length: 0\r\n"
            "Connection: close\r\n"
            "\r\n",
            target_url, src_ip_str, token);

    // 공통 함수 호출
    send_fake_redirect_packet(handle_inject, ethernet, ip, tcp, payload_size, redirectMsg, "차단용 사이트로 리다이렉트 인젝션");
}

// =========================================================================
// 3. 토큰 인증 포털 리다이렉트
// =========================================================================
void inject_redirect_token(pcap_t *handle_inject, const struct ether_header *ethernet, const struct ip *ip, const struct tcphdr *tcp, uint32_t payload_size, u_int token)
{
    char redirectMsg[512];
    memset(redirectMsg, 0, sizeof(redirectMsg));

    snprintf(redirectMsg, sizeof(redirectMsg),
             "HTTP/1.1 302 Found\r\n"
             "Location: http://192.168.3.243/?token=%u\r\n"
             "Content-Length: 0\r\n"
             "Connection: close\r\n"
             "\r\n", token);

    char logMsg[256];
    snprintf(logMsg, sizeof(logMsg), "일회용 토큰(%u) 포함 인증 포털 인젝션", token);

    // 공통 함수 호출
    send_fake_redirect_packet(handle_inject, ethernet, ip, tcp, payload_size, redirectMsg, logMsg);
}