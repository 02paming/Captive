#include "pcap_project.h"

void* ai_worker_thread(void* arg) {
    char check_site[128];

    while (keep_running) {
        pthread_mutex_lock(&ai_queue.lock);
        
        // 큐가 비어있으면 깨워줄 때까지 대기
        while (ai_queue.count == 0 && keep_running) {
            pthread_cond_wait(&ai_queue.cond, &ai_queue.lock);
        }

        // 종료 신호(Ctrl+C)를 받고 깨어났는데 처리할 남은 큐가 없다면 즉시 루프 탈출
        if (!keep_running && ai_queue.count == 0) {
            printf("[AI_스레드] 종료 신호 확인. 락을 풀고 퇴근합니다.\n");
            pthread_mutex_unlock(&ai_queue.lock);
            break;
        }

        // 큐에서 도메인 하나 빼기
        strncpy(check_site, ai_queue.tasks[ai_queue.front].domain, 127);
        ai_queue.front = (ai_queue.front + 1) % MAX_AI_QUEUE;
        ai_queue.count--;
        printf("2. 큐에서 꺼냄: %s\n", check_site);
        pthread_mutex_unlock(&ai_queue.lock);

        // ----------------------------------------------------
        // [여기는 락 밖이므로 방화벽 성능에 전혀 영향을 주지 않음!]
        // 1. 외부 서버로 UDS 통신해서 AI 판독 (수십 ms 소요)
        int ai_verdict = ask_ai_domain_status(check_site);

        // 2. 판독 결과에 따라 방패 업데이트 (O(1) 덮어쓰기)
        if (ai_verdict == 1) { 
            // 악성이면 블랙 방패의 상태를 PENDING(3) -> AI_BLOCK(2) 로 덮어쓰기
            printf("[AI 헌터] 신종 악성 감지! 블랙 방패 장전 [%s]\n", check_site);
            insert_hash_table(black_manager.active_shield, check_site, LOG_AI_BLOCK);
        } 
        else {
            // 정상이면 화이트 방패에 꽂아서 다음번엔 무사통과시키기
            // (블랙 방패에 있는 PENDING 찌꺼기는 무시됨. 어차피 핸들러에서 화이트를 먼저 봄)
            insert_hash_table(white_manager.active_shield, check_site, LOG_PASS);
        }
    }
    return NULL;
}