#include "pcap_project.h"

void* clean_thread(void* arg) {

    struct timespec ts;
    

    printf("[GC Thread] 백그라운드 초기화 스레드 시작됨\n");

    while (keep_running) {
        pthread_mutex_lock(&log_queue.queue_lock); // 작업 전 자물쇠 잠금

        clock_gettime(CLOCK_MONOTONIC, &ts); //현재시간을 초단위/나노초단위로 구조체에저장
        ts.tv_sec += 10;   //초단위만 60초 미래로설정 일단 60초단위동기화로 sleep에서 변경하는 것이므로 //test용 10초동기화

        // 스레드는 자물쇠(뮤텍스)를 스스로 풀고 60초간 깊은 수면에 빠짐
        // 누군가 cond_signal로 깨우면 즉시 일어나서 자물쇠를 다시 잠금
        pthread_cond_timedwait(&cond, &log_queue.queue_lock, &ts);

        // 깨어난 직후 가장 먼저 할 일: 종료 신호인지 확인 
        if (!keep_running) {
            printf("[GC Thread and log Thread] 종료 신호 확인. 락을 풀고 퇴근합니다.\n");
            pthread_mutex_unlock(&log_queue.queue_lock); // 쥐고 있던 자물쇠 풀기
            break; // while 루프 탈출
        }


        //추가 => 큐 방식으로 pop후 uds로 인증된사원 일반접속로그 보내기
        LogPacket local_log;

         while (pop_log_queue(&local_log)) {
            
            // PCAP 스레드가 멈추지 않도록 이미 위에서 자물쇠가 풀려있음!
            uds_client_sock_log(&local_log);
            
        }

        pthread_mutex_lock(&lock); //여기부터는 기존의 화이트리스트 전용 자물쇠 사용

        time_t current_time = time(NULL);

        for(int i = 0; i < 254; i++){    
            if(whitelist[i].expire_time > 0){
                long real_time = (long)(whitelist[i].expire_time - current_time); //만료시간
                long inactive_time = (long)(current_time - whitelist[i].last_seen); //미활동 기간 테스트용 3분으로해둠 180이되면 아래 if문 걸릴듯
                if (real_time < 0)
                    real_time = 0;
                printf("[IP .%d] 남은 만료 시간: %ld초\n", i, real_time);
                printf("[IP .%d] 미활동 시간: %ld초\n", i, inactive_time); //3분 테스트
            }

            //인증됬다면
            if(whitelist[i].is_active == 1){
            //어차피 두개의 조건중에서 하나만될텐데 소켓을 재활용할생각을 할이유가없었음 그리고 인증되었지만
            //조건에안걸리면 필요없는 소켓을 생성하고 close하고를 반복하는 무의미한작업을하기때문에 저 함수들안에서만진행

                //30일뒤면 절대적으로 인증초기화(우선은 테스트용으로 3분으로함)
                if (current_time > whitelist[i].expire_time) {
                    printf("30일 지났습니다. 재인증하십시오.\n");
                    whitelist[i].is_active = 0;
                    whitelist[i].is_mac_bound = 0;
                    whitelist[i].expire_time = 0;

                    //UDS 소켓 부분
                    uds_client_sock(i);
                }

                //7일동안 아무 활동이없으면 인증초기화 (else if쓴 이유는 30일동안 지나서 위if 걸리고나서 인증초기화되면 굳이 이 if문 안와도됨)
                else if((current_time - whitelist[i].last_seen) > (3 * 60)) {  //(7 * 24 * 60 * 60)  7일 test용 3분
                    printf("7일동안 미활동ip입니다. 재인증하십시오.\n");
                    whitelist[i].is_active = 0;
                    whitelist[i].is_mac_bound = 0;
                    whitelist[i].expire_time = 0;

                    uds_client_sock(i);
                }
            }
        }

        pthread_mutex_unlock(&lock); // 배열 청소 끝, 자물쇠 풀기
    }

    return NULL;
}