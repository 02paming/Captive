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
            // 1. 현재 뒤에서 쉬고 있는 예비 방패(Standby)가 A인지 B인지 찾기
            HashTable *standby_shield = (black_manager.active_shield == black_manager.shield_A) ? black_manager.shield_B : black_manager.shield_A;

            // 2. 쉬고 있는 방패에 도메인 1개 쏙 집어넣기 (아무도 안 보고 있으니 뮤텍스 Lock 불필요!)
            insert_hash_table(standby_shield, check_site, LOG_AI_BLOCK);

            // 3. 패킷 검사 스레드의 시선을 새 방패로 휙 돌림 (Swap)
            __atomic_store_n(&black_manager.active_shield, standby_shield, __ATOMIC_SEQ_CST);

            // 4. 이제 방금 전까지 실전에서 뛰다가 뒤로 밀려나 쉬게 된 구형 방패 찾기
            HashTable *old_active_shield = (standby_shield == black_manager.shield_A) ? black_manager.shield_B : black_manager.shield_A;
            
            // 5. 구형 방패에도 똑같이 도메인 1개 집어넣어서 양쪽 방패 상태 100% 동기화 (완료!)
            insert_hash_table(old_active_shield, check_site, LOG_AI_BLOCK);
        } 
        else {
            printf("[AI 헌터] 정상 감지! 화이트 방패 장전 [%s]\n", check_site);
            // 정상이면 화이트 방패에 꽂아서 다음번엔 무사통과시키기
            // (블랙 방패에 있는 PENDING 찌꺼기는 무시됨. 어차피 핸들러에서 화이트를 먼저 봄)
            // insert_hash_table(white_manager.active_shield, check_site, LOG_PASS);

            HashTable *standby_shield = (white_manager.active_shield == white_manager.shield_A) ? white_manager.shield_B : white_manager.shield_A;

            // 2. 쉬고 있는 방패에 도메인 1개 쏙 집어넣기 (아무도 안 보고 있으니 뮤텍스 Lock 불필요!)
            insert_hash_table(standby_shield, check_site, LOG_PASS);

            // 3. 패킷 검사 스레드의 시선을 새 방패로 휙 돌림 (Swap)
            __atomic_store_n(&white_manager.active_shield, standby_shield, __ATOMIC_SEQ_CST);

            // 4. 이제 방금 전까지 실전에서 뛰다가 뒤로 밀려나 쉬게 된 구형 방패 찾기
            HashTable *old_active_shield = (standby_shield == white_manager.shield_A) ? white_manager.shield_B : white_manager.shield_A;
            
            // 5. 구형 방패에도 똑같이 도메인 1개 집어넣어서 양쪽 방패 상태 100% 동기화 (완료!)
            insert_hash_table(old_active_shield, check_site, LOG_PASS);

        }
    }
    return NULL;
}