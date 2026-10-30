#include "pcap_project.h"

void* clean_thread(void* arg) {
    struct timespec ts;
    printf("[GC Thread] 백그라운드 초기화 스레드 시작됨\n");

    while (keep_running) {
        pthread_mutex_lock(&lock); // 작업 전 자물쇠 잠금

        clock_gettime(CLOCK_MONOTONIC, &ts);
        ts.tv_sec += 10;   // 테스트용 10초 동기화

        // 10초 대기하되, 누군가 깨우면 즉시 기상!
        pthread_cond_timedwait(&cond, &lock, &ts);
        
        if (!keep_running) {
            printf("[GC Thread] 종료 신호 확인. 락을 풀고 퇴근합니다.\n");
            pthread_mutex_unlock(&lock);
            break;
        }

        time_t current_time = time(NULL);

        for(int i = 0; i < 254; i++){    
            if(whitelist[i].expire_time > 0){
                long real_time = (long)(whitelist[i].expire_time - current_time);
                long inactive_time = (long)(current_time - whitelist[i].last_seen);
                if (real_time < 0) real_time = 0;
                printf("[IP .%d] 남은 만료 시간: %ld초\n", i, real_time);
                printf("[IP .%d] 미활동 시간: %ld초\n", i, inactive_time);
            }

            if(whitelist[i].is_active == 1){
                if (current_time > whitelist[i].expire_time) {
                    printf("30일 지났습니다. 재인증하십시오.\n");
                    whitelist[i].is_active = 0;
                    whitelist[i].is_mac_bound = 0;
                    whitelist[i].expire_time = 0;
                    uds_client_sock(i);
                }
                else if((current_time - whitelist[i].last_seen) > (3 * 60)) { 
                    printf("7일동안 미활동ip입니다. 재인증하십시오.\n");
                    whitelist[i].is_active = 0;
                    whitelist[i].is_mac_bound = 0;
                    whitelist[i].expire_time = 0;
                    uds_client_sock(i);
                }
            }
        }
        pthread_mutex_unlock(&lock); // 배열 청소 끝
    }
    return NULL;
}