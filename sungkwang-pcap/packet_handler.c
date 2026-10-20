#include "pcap_project.h"

time_t last_time[256] = {0}; // IP별 마지막 접속 시간(초) 기록

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
    int is_authenticated;
    is_authenticated = packet_mac_check(host_id, ethernet->ether_shost);

     if (payload_size == 0)
            return;

    //인증성공시 
    if (is_authenticated == 1) {
        printf("인증완료된 계정입니다!! [%s]\n",inet_ntoa(ip->ip_src));
       
        char *payload_start = (char *)tcp + tcp_size;
        char *host_start = memmem(payload_start, payload_size, "Host: ", 6);

        if (host_start == NULL)
            return;

        char check_site[128] = {0};
        host_start += strlen("Host: ");

        int remaining_len = payload_size - (host_start - (char *)payload_start);
        char *host_end = memchr(host_start, '\r', remaining_len);

        if (host_end == NULL) 
            return; 
   
        int host_len = host_end - host_start;
        if (host_len > sizeof(check_site) - 1)
        host_len = sizeof(check_site) - 1;

        memcpy(check_site, host_start, host_len);
        check_site[host_len] = '\0'; // 문자열의 끝을 명시

        int list_check = false;
        for (int i = 0; i < check_manager.count; i++) {
            // printf("남아있는 블랙리스트 [ %s ]\n",check_manager.target_url[i]);
            if (strcmp(check_manager.target_url[i], check_site) == 0) {
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
        } else{

            //인증후 정상적인 접속
            //즉 정상적인접속의 경우 첫 요청 패킷 단 하나만 담아서 db에 저장시켜야함
           if (payload_size < 4 || strncmp(payload_start, "GET ", 4) != 0 || 
                memmem(payload_start, payload_size, "Accept: text/html", 17) == NULL) {
                return;
            }

            // 2. 새로고침(F5) 여부 확인
            int is_refresh = (memmem(payload_start, payload_size, "Cache-Control: max-age=0", 24) != NULL) ||
                             (memmem(payload_start, payload_size, "Cache-Control: no-cache", 23) != NULL);

            // 3. 새로고침이 아닐 때만 중복/리다이렉트 필터 작동
            if (!is_refresh) {
                // httpbin.org 등 페이지 로드 후 내부에서 파생된 요청 뭐 js나 css 등등 차단
                // 단 사용자가 주소창에 직접 입력해 엔터를 치면 Referer가 없으므로 무조건 통과됨
                if (memmem(payload_start, payload_size, "Referer: ", 9) != NULL) {
                    return;
                }

                // 0.1초 만에 자동으로 튕기는 www.ccc.com 리다이렉트(1초 이내 연속 패킷) 차단
                if (time(NULL) - last_time[host_id] < 1) {
                    return;
                }
            }

            // 통과된 진짜 접속만 현재 시간 기록
            last_time[host_id] = time(NULL);



            LogPacket log_data;

            memset(&log_data, 0, sizeof(LogPacket));
    
            // IP,  그리고 기존에 파싱해둔 접속 도메인 복사
            strcpy(log_data.client_ip, inet_ntoa(ip->ip_src));
            strncpy(log_data.target_host, check_site, sizeof(log_data.target_host) - 1);

            
            //Queue Push 및 UDS 전송 스레드 기상
            pthread_mutex_lock(&log_queue.queue_lock); // 다른 스레드가 건드리지 못하게 문 잠금
            
            // 큐가 가득 차지 않았을 때만 데이터 삽입
            if (log_queue.count < MAX_LOG_QUEUE) {
                log_queue.nodes[log_queue.rear] = log_data; // 큐의 맨 뒤(rear)에 로그 삽입
                log_queue.rear = (log_queue.rear + 1) % MAX_LOG_QUEUE;
                log_queue.count++;
                
                // 자고 있는 UDS 전송 스레드에게 "데이터 들어왔다!" 하고 비상벨(알람) 울림
                pthread_cond_signal(&cond);
            } else {
                // 큐가 꽉 찼을 때의 예외 처리 로직 (printf 경고 등) 아마 경고뜰일은 없다보면됨 max_log인 1024명보다 많은인원이 동시에 이 로직에 오지않는이상
                printf("큐가 넘쳤습니다 \n");
            }
            
            pthread_mutex_unlock(&log_queue.queue_lock); //  작업이 끝나면 즉시 문 열어줌 (병목 방지)

        }
    }

    //우선은 비정상적인 접근 ip spoof같은 현상으로 지금 mac검사에서 잡혀서 is_authenticated에 2가들어와 걸림
    //다른 위협접근도 일로오게해서 사유만 다르게 보내면될거같음
    else if(is_authenticated == 2){

        printf("ip 스푸핑 감지!! 차단페이지로 페이지이동!\n");

        // 리다이렉트 무한 루프 방지
        if (strstr((char *)payload, "Host: 192.168.3.243/ban") != NULL)
            return;

        inject_redirect_ban(handle_inject, ethernet, ip, tcp, payload_size);

        inject_rst(handle_inject, ethernet, ip, tcp, payload_size);

    }

    else if(is_authenticated == 0){

        printf("인증이 아직안된 계정입니다. 인증해주세요! [%s]\n",inet_ntoa(ip->ip_src));

        // 리다이렉트 무한 루프 방지
        if (strstr((char *)payload, "Host: 192.168.3.243") != NULL)
            return;


        // 1. 리다이렉트 패킷 생성 및 주입
        inject_redirect(handle_inject, ethernet, ip, tcp, payload_size);

        // 2. RST 패킷 생성 및 주입
        inject_rst(handle_inject, ethernet, ip, tcp, payload_size);

    }
}