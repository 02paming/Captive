#include "pcap_project.h"

typedef struct {
  EngineContext *ctx_ptr;
  int id;
} WorkerArgs;

void* ai_worker_thread(void* arg) {

    WorkerArgs *w_args = (WorkerArgs *)arg;

    EngineContext *ctx = w_args->ctx_ptr;
    int worker_id = w_args->id;

    printf("[AI Worker %d] 대기 시작...\n", worker_id);

    char check_site[128];

    while (ctx->keep_running) {

      if(pop_ai_queue(ctx, check_site)){

        printf("[AI Worker %d] 큐에서 꺼냄: %s\n", worker_id, check_site);
        printf("[AI Worker %d] 도메인 검사 시작: %s\n", worker_id, check_site);

        // ----------------------------------------------------
        // [여기는 락 밖이므로 방화벽 성능에 전혀 영향을 주지 않음!]
        // 1. 외부 서버로 UDS 통신해서 AI 판독 (수십 ms 소요)
        // <판독하는곳>
        double ai_score = 0.0; //이 패킷의 대한 ai의 점수를 담을 곳
        int ai_verdict = ask_ai_domain_status(check_site, &ai_score);

        // [조건 A] 악성 판정 (확실한 BLOCK 또는 악성 의심 SUSPICIOUS)
        // 둘 다 일단 블랙 방패(차단)에 넣습니다. 상태 코드만 다르게 부여.
        if (ai_verdict == LOG_AI_BLOCK || ai_verdict == LOG_AI_DOUBT_BLOCK) { 
            
            if (ai_verdict == LOG_AI_BLOCK)
                printf("[AI 헌터 %d] 악성 감지! (%.1f점) 블랙 방패 장전 [%s]\n", worker_id, ai_score, check_site);
            else
                printf("[AI 헌터 %d] 악성 의심! (%.1f점) 블랙 방패 임시 장전 [%s]\n", worker_id, ai_score, check_site);
            
            // 1. 뒤에서 쉬고 있는 블랙 예비 방패 찾기
            HashTable *standby_shield = (ctx->black_manager.active_shield == ctx->black_manager.shield_A) ? ctx->black_manager.shield_B : ctx->black_manager.shield_A;
            
            // 2. 쉬는 방패에 삽입 (ai_verdict 값을 그대로 해시 상태로 사용!)
            insert_hash_table(standby_shield, check_site, ai_verdict, ai_score);
            
            // 3. 패킷 검사 스레드의 시선 돌리기 (Swap)
           __atomic_store_n(&ctx->black_manager.active_shield, standby_shield, __ATOMIC_SEQ_CST);
            
            // 4. 구형 방패 동기화
            HashTable *old_active_shield = (standby_shield == ctx->black_manager.shield_A) ? ctx->black_manager.shield_B : ctx->black_manager.shield_A;
            insert_hash_table(old_active_shield, check_site, ai_verdict, ai_score);
        } 
        
        // [조건 B] 정상 판정 (확실한 PASS 또는 정상 의심 GREYLIST)
        // 둘 다 일단 화이트 방패(통과)에 넣습니다.
        else if (ai_verdict == LOG_AI_PASS || ai_verdict == LOG_AI_DOUBT_PASS) {
            
            if (ai_verdict == LOG_AI_PASS)
                printf("[AI 헌터 %d] 정상 감지! (%.1f점) 화이트 방패 장전 [%s]\n", worker_id, ai_score, check_site);
            else
                printf("[AI 헌터 %d] 정상 의심! (%.1f점) 화이트 방패 임시 장전 [%s]\n", worker_id, ai_score, check_site);
                
            // 1. 뒤에서 쉬고 있는 화이트 예비 방패 찾기
            HashTable *standby_shield = (ctx->white_manager.active_shield == ctx->white_manager.shield_A) ? ctx->white_manager.shield_B : ctx->white_manager.shield_A;
            
            // 2. 쉬는 방패에 삽입 
            insert_hash_table(standby_shield, check_site, ai_verdict, ai_score);
            
            // 3. 패킷 검사 스레드의 시선 돌리기 (Swap)
            __atomic_store_n(&ctx->white_manager.active_shield, standby_shield, __ATOMIC_SEQ_CST);
            
            // 4. 구형 방패 동기화
            HashTable *old_active_shield = (standby_shield == ctx->white_manager.shield_A) ? ctx->white_manager.shield_B : ctx->white_manager.shield_A;
            insert_hash_table(old_active_shield, check_site, ai_verdict, ai_score);
        }
        else {
            printf("[AI 헌터 %d] 통신 오류 혹은 알 수 없는 판정 결과입니다.\n", worker_id);
        }
      }else{
        //pop이 0을 반환했다면 서버종료했다는뜻 컨트롤 c로 종료했단것
        printf("[AI Worker %d] 종료 신호 확인. 퇴근합니다.\n", worker_id);
        break;
      }       
    }
    return NULL;
}