#include "pcap_project.h"

void* log_thread(void* arg) {
    printf("[Log Thread] 실시간 로그 전송 스레드 시작됨\n");
    LogPacket local_log;

    while (keep_running) {
        pthread_mutex_lock(&log_queue.queue_lock);

        // 큐가 비어있으면 얌전히 대기 (log_cond라는 전용 종소리에만 깸)
        while (log_queue.count == 0 && keep_running) {
            pthread_cond_wait(&log_queue.log_cond, &log_queue.queue_lock);
        }

        // 서버 종료 신호면 퇴근
        if (log_queue.count == 0 && !keep_running) {
            printf("[Log Thread] 종료 신호 확인. 퇴근합니다.\n");
            pthread_mutex_unlock(&log_queue.queue_lock);
            break;
        }
        
        pthread_mutex_unlock(&log_queue.queue_lock); // 자물쇠 풀기

        // 락이 풀린 상태에서 큐에 쌓인 로그 모두 전송 (백엔드가 느려도 안심!)
        while (pop_log_queue(&local_log)) {
            uds_client_sock_log(&local_log);
        }
    }
    return NULL;
}