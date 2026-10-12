#include "pcap_project.h"

void* clean_thread(void* arg) {

    

    // while(1){
    //     sleep(60);

    //     pthread_mutex_lock(&lock);

    //     time_t current_time = time(NULL);

    //     for(int i = 0; i < 254; i++){
    //         //인증됬다면
    //         if(whitelist[i].is_active == 1){
        
    //             //30일뒤면 절대적으로 인증초기화(우선은 테스트용으로 3분으로함)
    //             if (current_time > whitelist[i].expire_time) {
    //                 printf("30일 지났습니다. 재인증하십시오.\n");
    //                 whitelist[i].is_active = 0;
    //                 whitelist[i].is_mac_bound = 0;
    //             }

    //             //7일동안 아무 활동이없으면 인증초기화 (else if쓴 이유는 30일동안 지나서 위if 걸리고나서 인증초기화되면 굳이 이 if문 안와도됨)
    //             else if((current_time - whitelist[i].last_seen) > (7 * 24 * 60 * 60)) {
    //                 whitelist[i].is_active = 0;
    //                 whitelist[i].is_mac_bound = 0;
    //             }    
    //         }
    //     }

    //     pthread_mutex_unlock(&lock);
    // }


    struct timespec ts;
    

    printf("[GC Thread] 백그라운드 초기화 스레드 시작됨\n");

    while (keep_running) {
        pthread_mutex_lock(&lock); // 작업 전 자물쇠 잠금

        clock_gettime(CLOCK_MONOTONIC, &ts); //현재시간을 초단위/나노초단위로 구조체에저장
        ts.tv_sec += 30;   //초단위만 60초 미래로설정 일단 60초단위동기화로 sleep에서 변경하는 것이므로

        // 스레드는 자물쇠(뮤텍스)를 스스로 풀고 60초간 깊은 수면에 빠짐
        // 누군가 cond_signal로 깨우면 즉시 일어나서 자물쇠를 다시 잠금
        pthread_cond_timedwait(&cond, &lock, &ts);

        // 깨어난 직후 가장 먼저 할 일: 종료 신호인지 확인 
        if (!keep_running) {
            printf("[GC Thread] 종료 신호 확인. 락을 풀고 퇴근합니다.\n");
            pthread_mutex_unlock(&lock); // 쥐고 있던 자물쇠 풀기
            break; // while 루프 탈출
        }

        time_t current_time = time(NULL);

        for(int i = 0; i < 254; i++){    
            if(whitelist[i].expire_time > 0){
                long remain_sec = (long)(whitelist[i].expire_time - current_time);
                printf("[IP .%d] 남은 만료 시간: %ld초\n", i, remain_sec);
            }

            //인증됬다면
            if(whitelist[i].is_active == 1){
        
                //30일뒤면 절대적으로 인증초기화(우선은 테스트용으로 3분으로함)
                if (current_time > whitelist[i].expire_time) {
                    printf("30일 지났습니다. 재인증하십시오.\n");
                    whitelist[i].is_active = 0;
                    whitelist[i].is_mac_bound = 0;
                    whitelist[i].expire_time = 0;

                    //UDS 소켓 부분 (아래 7일쪽에도 서야하므로 추후 함수화해야할수도있음)
                    int sockfd = socket(AF_UNIX, SOCK_STREAM, 0);
                    if (sockfd < 0) {
                        perror("UDS 소켓 생성 실패");
                        continue;
                    }
                    
                    struct sockaddr_un addr;
                    memset(&addr, 0, sizeof(addr));
                    addr.sun_family = AF_UNIX;
                    strncpy(addr.sun_path, GC_SOCKET_PATH, sizeof(addr.sun_path) - 1);

                    // 2. 파이썬 서버로 연결 시도 (안 켜져 있으면 에러 반환하고 무시함)
                    if (connect(sockfd, (struct sockaddr *)&addr, sizeof(addr)) == 0) {
                        char msg[32];
                        sprintf(msg, "%d\n", i); // 예: "50\n"
                        
                        // 3. 차단된 Host ID 전송 후 즉시 연결 종료
                        write(sockfd, msg, strlen(msg)); //순수 50크기만 쏨 \n제외
                    }
                    close(sockfd); // 클라이언트 소켓은 다 쓰면 닫아버림
                    
                }

                //7일동안 아무 활동이없으면 인증초기화 (else if쓴 이유는 30일동안 지나서 위if 걸리고나서 인증초기화되면 굳이 이 if문 안와도됨)
                else if((current_time - whitelist[i].last_seen) > (7 * 24 * 60 * 60)) {
                    whitelist[i].is_active = 0;
                    whitelist[i].is_mac_bound = 0;
                }    
            }
        }

        pthread_mutex_unlock(&lock); // 배열 청소 끝, 자물쇠 풀기
    }

    return NULL;
}