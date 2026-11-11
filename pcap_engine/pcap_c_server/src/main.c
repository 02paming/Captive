/*!
 * @mainpage AI 기반 웹 접근제어 탐지 엔진
 *
 * @section overview 프로젝트 개요 
 * 미러링 패킷을 분석하여 유해 사이트 접근을 탐지합니다.
 *
 * @section architecture 시스템 구성
 * - 탐지 엔진 : 패킷 수집 및 접근 제어
 * - 웹 서버 : 관리자 페이지와 API 제공
 * - DB 서버 : 정책 및 로그 저장
 *
 * @section build 빌드 방법
 * @code{.sh}
 * make
 * @endcode
 *
 */

/*!
 * @file main.c
 * @brief 탐지엔진 초기화 및 실행 흐름 관리
 * @detail 
 * 디테일한 설명을 여기에 쓰시면 됩니다.
 *
 *
 */


#include "init_engine.h"
#include "pcap_common.h"
#include "thread_workers.h"
#include "pcap_utils.h"

EngineContext *g_ctx = NULL;

/*!
 * @brief 시그널 핸들링 함수
 * @param[in] sig 발생한 시그널 번호
 *
 */
 void handle_sigint(int sig) {
    if (!g_ctx) return;
    

    SYSTEM_LOG(LOG_INFO, "[Main] 종료 신호 감지! 스레드들을 깨웁니다...");
    g_ctx->keep_running = 0; // 깃발 내리기

    // 1. 자고 있는 만료 스레드 강제 기상 (비상벨)
    pthread_cond_signal(&g_ctx->auth.cond);

    // 2. 자고 있는 LOG 스레드 강제 기상
    pthread_cond_signal(&g_ctx->log_queue.log_cond);

    // 3. 자고 있는 AI 분석 스레드 8명 모두 강제 기상
    pthread_cond_broadcast(&g_ctx->ai_queue.cond);

    // 4. UDS 소켓 대기 깨우기
    printf("[Main] 시그널 핸들러가 조준 중인 번호: %d\n", g_ctx->server_fd);
    if (g_ctx->server_fd != -1) {
        shutdown(g_ctx->server_fd, SHUT_RDWR);
    }

    // 5. PCAP 무한루프 깨우기
    if (g_ctx->mir_handle != NULL) {
        pcap_breakloop(g_ctx->mir_handle);
    }
  }



//실행할 메인함수
/*!
 * @brief 메인함수
 * @return 정상 종료 시 0, 오류 발생 시 0 이외의 값
 *
 */
int main(void) {
    // "pcap_engine"이라는 이름으로 로그를 남기겠다고 커널에 신고합니다.
    openlog("pcap_engine", LOG_PID | LOG_CONS | LOG_NDELAY, LOG_DAEMON);
    int ret_code = 0; //리턴코드 기존에 그냥 return 1 이나 0했던거 변수화한것
    EngineContext ctx = {0};
    
    

    pthread_t uds_tid = 0, clean_tid = 0, log_tid = 0;
    pthread_t ai_threads[AI_WORKERS] = {0};
    WorkerArgs w_args[AI_WORKERS];
    
    signal(SIGINT, handle_sigint);
    signal(SIGTERM, handle_sigint);
    signal(SIGABRT, handle_sigint);
    signal(SIGSEGV, handle_sigint);

    // 1. 초기화 (실패 시 즉시 cleanup으로 점프)
    if (init_context(&ctx) != 0) {
        ret_code = 1; goto cleanup; //패킷핸들러함수때 정상일때 goto문 쓴것처럼 활용
    }
    //ctx멤버변수들 초기화 후 전역변수 초기화
    g_ctx = &ctx;

    // 2. 캡처 준비
    if (init_capture(&ctx) != 0) {
        ret_code = 1; goto cleanup;
    }

    // 3. 스레드 가동
    if (pthread_create(&uds_tid, NULL, uds_server_thread, &ctx) != 0) {
        SYSTEM_LOG(LOG_ERR, "[에러] UDS 수신 스레드 생성 실패");
        ret_code = 1; goto cleanup;
    }

    
    SYSTEM_LOG(LOG_INFO, "========= [시스템] Django/Flask 초기 동기화 요청 중 =========");
    system("/opt/captive_project/intranet-access-controller/sungkwang-pcap/pcap_webServer/venv/bin/python /opt/captive_project/intranet-access-controller/sungkwang-pcap/pcap_webServer/sync_runner.py &");
    SYSTEM_LOG(LOG_INFO, "[시스템] 백그라운드 동기화 셋업 완료! PCAP 패킷 감시를 시작합니다.");

    if (pthread_create(&clean_tid, NULL, clean_thread, &ctx) != 0) {
        SYSTEM_LOG(LOG_ERR, "[에러] 스마트 만료 스레드 생성 실패");
        ret_code = 1; goto cleanup;
    }

    if (pthread_create(&log_tid, NULL, log_thread, &ctx) != 0) {
        SYSTEM_LOG(LOG_ERR, "[에러] 로그 전송 스레드 생성 실패");
        ret_code = 1; goto cleanup;
    }
    
    for (int i = 0; i < AI_WORKERS; i++) {
        w_args[i].ctx_ptr = &ctx;
        w_args[i].id = i + 1;
        if (pthread_create(&ai_threads[i], NULL, ai_worker_thread, &w_args[i]) != 0) {
            SYSTEM_LOG(LOG_ERR, "[에러] AI 워커 스레드 생성 실패");
            ret_code = 1; goto cleanup;
        }
        SYSTEM_LOG(LOG_INFO, "[Main] AI 헌터 스레드 %d번 대기조 편성 완료", w_args[i].id);

    }

    // 4. 메인 엔진 가동
    pcap_loop(ctx.mir_handle, 0, packet_handler, (u_char *)&ctx);

cleanup:
    // 5. 스레드 합류 및 자원 일괄 해제
    if (log_tid != 0) pthread_join(log_tid, NULL);
    if (clean_tid != 0) pthread_join(clean_tid, NULL);
    if (uds_tid != 0) pthread_join(uds_tid, NULL);
    
    for (int i = 0; i < AI_WORKERS; i++) {
        if (ai_threads[i] != 0) pthread_join(ai_threads[i], NULL);
    }

    cleanup_all_resources(&ctx);
    
    SYSTEM_LOG(LOG_INFO, "Loop 이후 자원반납 깔끔하게 싹 하고 return %d 됨", ret_code);
    closelog();
    return ret_code;
}
