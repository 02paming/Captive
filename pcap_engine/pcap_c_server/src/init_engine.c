#include "pcap_common.h"
#include "init_engine.h"
#include "hash_manager.h"

// ---------------------------------------------------------
// 1. 컨텍스트 및 동기화 객체 초기화 (해쉬,뮤텍스,조건변수와 각종 멤버변수 기본값설정)
// ---------------------------------------------------------
int init_context(EngineContext *ctx) {
    memset(ctx, 0, sizeof(EngineContext));
    ctx->keep_running = 1;
    ctx->server_fd = -1;
    ctx->start_time = 9;
    ctx->end_time = 18;
    ctx->expire_interval = 600;

    pthread_mutex_init(&ctx->auth.lock, NULL);
    pthread_condattr_t attr;
    pthread_condattr_init(&attr);
    pthread_condattr_setclock(&attr, CLOCK_MONOTONIC);
    pthread_cond_init(&ctx->auth.cond, &attr);
    pthread_condattr_destroy(&attr);

    pthread_mutex_init(&ctx->ai_queue.lock, NULL);
    pthread_cond_init(&ctx->ai_queue.cond, NULL);

    pthread_mutex_init(&ctx->log_queue.queue_lock, NULL);
    pthread_cond_init(&ctx->log_queue.log_cond, NULL);

    ctx->black_manager.shield_A = create_hash_table();
    ctx->black_manager.shield_B = create_hash_table();
    ctx->white_manager.shield_A = create_hash_table();
    ctx->white_manager.shield_B = create_hash_table();
    ctx->black_manager.active_shield = ctx->black_manager.shield_A;
    ctx->white_manager.active_shield = ctx->white_manager.shield_A;

    ctx->fixed_black_shield = create_hash_table();
    ctx->fixed_white_shield = create_hash_table();

    if (!ctx->black_manager.shield_A || !ctx->fixed_black_shield) return -1;

    SYSTEM_LOG(LOG_INFO, "고정 데이터 로드 중...");
    load_domains_from_txt(ctx->fixed_black_shield, "/tmp/ai_blacklist.txt", LOG_MANUAL_BLOCK, -1);
    load_domains_from_txt(ctx->fixed_white_shield, "/tmp/ai_whitelist.txt", LOG_MANUAL_PASS, -1);

    return 0;
}

// ---------------------------------------------------------
// 2. PCAP 인터페이스 캡처 준비
// ---------------------------------------------------------
int init_capture(EngineContext *ctx) {
    char errbuf[PCAP_ERRBUF_SIZE];
    struct bpf_program filter;
    char filter_exp[] = "src net 192.168.2.0 mask 255.255.255.0 and"
                        "(tcp dst port 80 or udp dst port 53) and dst host not 192.168.3.243";

    const char *mir_dev = "eno2";
    const char *inject_dev = "eno4";

    ctx->mir_handle = pcap_open_live(mir_dev, BUFSIZ, 1, 1, errbuf);
    if (ctx->mir_handle == NULL) {
        SYSTEM_LOG(LOG_CRIT, "[에러] 캡처 디바이스(%s)를 열 수 없습니다: %s",mir_dev, errbuf);
        return -1;
    }

    ctx->inject_handle = pcap_open_live(inject_dev, BUFSIZ, 0, 0, errbuf);
    if (ctx->inject_handle == NULL) {
        SYSTEM_LOG(LOG_CRIT, "[에러] 인젝션 디바이스(%s)를 열 수 없습니다: %s",inject_dev, errbuf);
        return -1;
    }

    pcap_setdirection(ctx->mir_handle, PCAP_D_INOUT);
    pcap_setdirection(ctx->inject_handle, PCAP_D_OUT);

    if (pcap_datalink(ctx->mir_handle) != DLT_EN10MB || pcap_datalink(ctx->inject_handle) != DLT_EN10MB) {
        SYSTEM_LOG(LOG_CRIT, "[에러] 이더넷 장비가 아닙니다!");
        return -1;
    }

    if (pcap_compile(ctx->mir_handle, &filter, filter_exp, 0, PCAP_NETMASK_UNKNOWN) == -1) {
        SYSTEM_LOG(LOG_CRIT, "[에러] 필터 컴파일 실패: %s",pcap_geterr(ctx->mir_handle));
        return -1;
    }

    if (pcap_setfilter(ctx->mir_handle, &filter) == -1) {
        SYSTEM_LOG(LOG_CRIT, "[에러] 필터 적용 실패: %s",pcap_geterr(ctx->mir_handle));
        pcap_freecode(&filter);
        return -1;
    }
    pcap_freecode(&filter);

    return 0;
}

// ---------------------------------------------------------
// 3. 자원 일괄 정리 (메모리 leak 방지)
// ---------------------------------------------------------
void cleanup_all_resources(EngineContext *ctx) {
    SYSTEM_LOG(LOG_INFO, "[Cleanup] 사용한 자원(메모리, 핸들, 락)을 일괄 해제합니다.");
    system("pkill -f sync_runner.py");
    
    if (ctx->inject_handle) pcap_close(ctx->inject_handle);
    if (ctx->mir_handle) pcap_close(ctx->mir_handle);
    
    unlink(SOCKET_PATH);

    pthread_mutex_destroy(&ctx->auth.lock);
    pthread_cond_destroy(&ctx->auth.cond);
    pthread_mutex_destroy(&ctx->ai_queue.lock);
    pthread_cond_destroy(&ctx->ai_queue.cond);
    pthread_mutex_destroy(&ctx->log_queue.queue_lock);
    pthread_cond_destroy(&ctx->log_queue.log_cond);

    if (ctx->black_manager.shield_A) free_hash_table(ctx->black_manager.shield_A);
    if (ctx->black_manager.shield_B) free_hash_table(ctx->black_manager.shield_B);
    if (ctx->white_manager.shield_A) free_hash_table(ctx->white_manager.shield_A);
    if (ctx->white_manager.shield_B) free_hash_table(ctx->white_manager.shield_B);
    if (ctx->fixed_black_shield) free_hash_table(ctx->fixed_black_shield);
    if (ctx->fixed_white_shield) free_hash_table(ctx->fixed_white_shield);
}