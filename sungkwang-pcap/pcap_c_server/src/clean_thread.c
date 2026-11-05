#include "pcap_common.h"
#include "pcap_utils.h"

void* clean_thread(void* arg) {
  EngineContext *ctx = (EngineContext *)arg;

  struct timespec ts;
  printf("[GC Thread] 출퇴근 스마트 만료(GC) 스레드 시작됨\n");

  while (ctx->keep_running) {
    int expired_ips[256] = {0};
    int expire_count = 0;

    pthread_mutex_lock(&ctx->auth.lock); // 작업 전 인증 테이블 자물쇠 잠금

    clock_gettime(CLOCK_MONOTONIC, &ts);
    ts.tv_sec += 10;   // 테스트용 10초 동기화

    // 10초 대기하되, 누군가 깨우면 즉시 기상!
    pthread_cond_timedwait(&ctx->auth.cond, &ctx->auth.lock, &ts);
    
    if (!ctx->keep_running) {
      printf("[GC Thread] 종료 신호 확인. 락을 풀고 퇴근합니다.\n");
      pthread_mutex_unlock(&ctx->auth.lock);
      break;
    }

    time_t current_time = time(NULL);
    struct tm *timeinfo = localtime(&current_time);
    int current_hour = timeinfo->tm_hour;

    // DB에서 동기화된 출퇴근 및 만료 정책 꺼내기
    int start_h = ctx->start_time;
    int end_h = ctx->end_time;
    int interval = ctx->expire_interval; // 허용되는 미활동 대기 시간

    //출퇴근 스마트 만료 로직 기능으로 수정!
    // 출근 전이거나 퇴근 후일 때만 (즉, 업무 시간이 아닐 때만) 미활동 시간을 체크하여 만료시킴
    if (current_hour < start_h || current_hour >= end_h) {
        
      for(int i = 1; i < 254; i++) {    
        if(ctx->auth.records[i].is_active == 1) {
          long inactive_time = (long)(current_time - ctx->auth.records[i].last_seen);
          
          // 디버깅용 출력 (너무 길어지면 주석 처리)
          // printf("[IP .%d] 퇴근 후 미활동 시간: %ld초 / 기준: %d초\n", i, inactive_time, interval);

          // 설정된 미활동 시간(interval)을 초과했다면 인증 해제!
          if (inactive_time > interval) {
            // 구조체 데이터 싹 초기화
            ctx->auth.records[i].is_active = 0;
            ctx->auth.records[i].is_mac_bound = 0;
            ctx->auth.records[i].last_seen = 0;
            memset(ctx->auth.records[i].mac_addr, 0, ETH_ALEN);
            
            // 통신은 나중에 하기 위해 바구니에 담아둠
            expired_ips[expire_count++] = i;
          }
        }
      }
    } else {
        //저 if문에 안걸렸다는건 근무 시간중이라는뜻 
        //이때는 미활동 만료 검사를 아예 건너뛰어 한 번 인증 시 퇴근 때까지 무한 유지!
    }

    // 배열 청소가 끝났으므로 패킷 핸들러가 빨리 일할 수 있게 락을 즉시 풀어줍니다.
    pthread_mutex_unlock(&ctx->auth.lock); 

    // =========================================================================
    // 락이 풀린 안전한 상태에서 백엔드(플라스크)로 만료 통보 (지연 I/O)
    // =========================================================================
    for (int i = 0; i < expire_count; i++) {
      printf("[GC Thread] 야간 미활동 IP 인증 초기화 -> 192.168.2.%d\n", expired_ips[i]);
      
      uds_client_sock(expired_ips[i]);
    }
  }
  return NULL;
}