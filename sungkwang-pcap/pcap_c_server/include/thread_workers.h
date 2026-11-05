#ifndef THREAD_WORKERS_H
#define THREAD_WORKERS_H

#include "pcap_common.h"

typedef struct {
    EngineContext *ctx_ptr;
    int id;
} WorkerArgs;

// 백그라운드 스레드 함수 원형
void* uds_server_thread(void* arg);
void* clean_thread(void* arg);
void* ai_worker_thread(void* arg);
void* log_thread(void* arg);
void* domain_sync_thread(void* arg);

#endif 