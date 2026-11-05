#include "pcap_common.h"
#include "pcap_utils.h"

void* log_thread(void* arg) {

  EngineContext *ctx = (EngineContext *)arg;

  printf("[Log Thread] 실시간 로그 전송 스레드 시작됨\n");
  LogPacket local_log;

  while (ctx->keep_running) {
    pthread_mutex_lock(&ctx->log_queue.queue_lock);

    // 큐가 비어있으면 얌전히 대기 (log_cond라는 전용 종소리에만 깸)
    while (ctx->log_queue.count == 0 && ctx->keep_running) {
        pthread_cond_wait(&ctx->log_queue.log_cond, &ctx->log_queue.queue_lock);
    }

    // 서버 종료 신호면 퇴근
    if (ctx->log_queue.count == 0 && !ctx->keep_running) {
        printf("[Log Thread] 종료 신호 확인. 퇴근합니다.\n");
        pthread_mutex_unlock(&ctx->log_queue.queue_lock);
        break;
    }
    
    pthread_mutex_unlock(&ctx->log_queue.queue_lock); // 자물쇠 풀기

    // 락이 풀린 상태에서 큐에 쌓인 로그 모두 전송 (백엔드가 느려도 안심!)
    while (pop_log_queue(ctx, &local_log)) {
        uds_client_sock_log(&local_log);
    }
  }
    return NULL;
}