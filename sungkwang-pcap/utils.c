#include "pcap_project.h"

unsigned short csum(unsigned short *ptr, int nbytes)
{
    register long sum;
    unsigned short oddbyte;
    register short answer;
    sum = 0;
    while (nbytes > 1)
    {
        sum += *ptr++;
        nbytes -= 2;
    }
    if (nbytes == 1)
    {
        oddbyte = 0;
        *((u_char *)&oddbyte) = *(u_char *)ptr;
        sum += oddbyte;
    }
    sum = (sum >> 16) + (sum & 0xffff);
    sum = sum + (sum >> 16);
    answer = (short)~sum;
    return (answer);
}

void uds_client_sock(const int sockfd,const int ip){

    struct sockaddr_un addr;
    memset(&addr, 0, sizeof(addr));
    addr.sun_family = AF_UNIX;
    strncpy(addr.sun_path, GC_SOCKET_PATH, sizeof(addr.sun_path) - 1);

    // 파이썬 서버로 연결 시도 (안 켜져 있으면 에러 반환하고 무시함)
    if (connect(sockfd, (struct sockaddr *)&addr, sizeof(addr)) == 0) {
        char msg[32];
        sprintf(msg, "%d\n", ip); // 예: "50\n"
        
        // 차단된 Host ID 전송 후 즉시 연결 종료
        write(sockfd, msg, strlen(msg)); //순수 50크기만 쏨 \n제외
    }

    return;
}

int packet_mac_check(const int host_id, const uint8_t* packet_mac){
    int is_authenticated;
    

    if (host_id >= 0 && host_id < 254) {
        
        memcpy(latest_mac_cache[host_id], packet_mac, ETH_ALEN);

        pthread_mutex_lock(&lock);

        if (whitelist[host_id].is_active == 1) {
            // 1. 최초 패킷: MAC이 아직 안 묶여있는 경우 바인딩
            if (whitelist[host_id].is_mac_bound == 0) {
                memcpy(whitelist[host_id].mac_addr, packet_mac, ETH_ALEN);
                whitelist[host_id].is_mac_bound = 1;
            } 
            // 2. 두 번째 패킷부터: 기존 MAC과 들어온 MAC 비교 검증
            else {
                if (memcmp(packet_mac, whitelist[host_id].mac_addr, ETH_ALEN) != 0) {
                    // MAC이 다르면 IP 위조로 간주하고 즉시 인증 해제
                    printf("인증한계정의 MAC과 일치하지않습니다.\n");
                    whitelist[host_id].is_active = 0;
                }
            }

            // 3. 검증을 통과하여 여전히 인증 상태라면 생존 시간 갱신 => 이 멤버변수를통해서 7일 미활동 초기화구문을사용할수있음
            if (whitelist[host_id].is_active == 1) {
                whitelist[host_id].last_seen = time(NULL);
            }
        }
        is_authenticated = whitelist[host_id].is_active == 1 ? 1 : 0;
        pthread_mutex_unlock(&lock);
    }

    return is_authenticated;
}