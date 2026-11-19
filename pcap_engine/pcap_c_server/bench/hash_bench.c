/*
 * hash_bench.c — SecureTech WAS(Captive) 해시 테이블 측정용 벤치마크 (M1·M2)
 *
 * 실제 엔진 코드(src/hash_table.c)를 그대로 링크해서 잰다. 측정용으로 해시 로직을 다시 쓰지 않는다.
 *
 *   M1  조회 시간: lookup_hash_table() — 있는 도메인(hit) / 없는 도메인(miss)
 *   M2  룰 1건 갱신 시간: uds_thread.c 의 ADD 흐름과 같은 순서
 *       ① 예비(standby) 테이블에 insert → ② __atomic_store_n 포인터 스왑 → ③ 이전 테이블에 insert
 *   M2' 갱신 중 조회: 조회 스레드 R개가 도는 동안 갱신 스레드 1개가 룰을 계속 추가할 때 조회 처리량 변화
 *
 * 빌드 (pcap_c_server 폴더에서, 엔진 Makefile 과 같은 플래그):
 *   gcc -Wall -Wextra -g -Iinclude bench/hash_bench.c src/hash_table.c -lpcap -pthread -o bench/hash_bench
 * 실행 예:
 *   ./bench/hash_bench                         # 기본: 룰 100000개(합성 도메인)
 *   ./bench/hash_bench -n 10000                # 룰 1만 개
 *   ./bench/hash_bench -f /tmp/ai_blacklist.txt  # 실제 블랙리스트 파일로
 */
#include "pcap_common.h"
#include "hash_manager.h"
#include <getopt.h>
#include <sys/utsname.h>

static inline long long now_ns(void) {
    struct timespec ts;
    clock_gettime(CLOCK_MONOTONIC, &ts);
    return (long long)ts.tv_sec * 1000000000LL + ts.tv_nsec;
}

static int cmp_ll(const void *a, const void *b) {
    long long x = *(const long long *)a, y = *(const long long *)b;
    return (x > y) - (x < y);
}

typedef struct { double avg, p50, p99, max; } Stat;

static Stat summarize(long long *v, int n, long long overhead) {
    qsort(v, n, sizeof(long long), cmp_ll);
    long long sum = 0;
    for (int i = 0; i < n; i++) sum += v[i];
    Stat s;
    s.avg = (double)sum / n - overhead;
    s.p50 = (double)v[n / 2] - overhead;
    s.p99 = (double)v[(int)(n * 0.99)] - overhead;
    s.max = (double)v[n - 1] - overhead;
    if (s.avg < 0) s.avg = 0;
    if (s.p50 < 0) s.p50 = 0;
    if (s.p99 < 0) s.p99 = 0;
    return s;
}

static void print_stat(const char *name, Stat s) {
    printf("| %-34s | %10.1f | %10.1f | %10.1f | %12.1f |\n", name, s.avg, s.p50, s.p99, s.max);
}

/* 도메인 목록 (합성 또는 파일) */
static char **domains = NULL;
static int n_domains = 0;

static void make_synthetic(int n) {
    domains = malloc(sizeof(char *) * n);
    for (int i = 0; i < n; i++) {
        domains[i] = malloc(64);
        /* 길이가 제각각인 도메인처럼 보이게 */
        snprintf(domains[i], 64, "d%07d-%x.example%d.com", i, (unsigned)(i * 2654435761u) & 0xfff, i % 97);
    }
    n_domains = n;
}

static void load_file(const char *path) {
    FILE *f = fopen(path, "r");
    if (!f) { perror(path); exit(1); }
    int cap = 1024; domains = malloc(sizeof(char *) * cap);
    char line[256];
    while (fgets(line, sizeof(line), f)) {
        line[strcspn(line, "\r\n")] = 0;
        if (!line[0]) continue;
        if (n_domains == cap) { cap *= 2; domains = realloc(domains, sizeof(char *) * cap); }
        domains[n_domains++] = strdup(line);
    }
    fclose(f);
}

/* ---- M2' 동시 실행용 ---- */
static DoubleBufferManager mgr;
static volatile int stop_flag = 0;
static long long reader_ops[64];

typedef struct { int id; } RArg;

static void *reader(void *p) {
    int id = ((RArg *)p)->id;
    unsigned seed = 12345 + id;
    long long ops = 0;
    while (!stop_flag) {
        const char *d = domains[rand_r(&seed) % n_domains];
        /* packet_handler.c 와 같은 방식: active_shield 를 그대로 읽어 조회 */
        lookup_hash_table(mgr.active_shield, d);
        ops++;
    }
    reader_ops[id] = ops;
    return NULL;
}

static int write_rate = 1000; /* 초당 갱신 횟수, 0 = 제한 없음 */

static void *writer(void *p) {
    long long *count = p;
    struct timespec gap = {0, write_rate > 0 ? 1000000000L / write_rate : 0};
    char buf[128];
    long long i = 0;
    while (!stop_flag) {
        snprintf(buf, sizeof(buf), "w%lld.writer-test.com", i++);
        HashTable *standby = (mgr.active_shield == mgr.shield_A) ? mgr.shield_B : mgr.shield_A;
        insert_hash_table(standby, buf, LOG_AI_BLOCK, 90.0);
        __atomic_store_n(&mgr.active_shield, standby, __ATOMIC_SEQ_CST);
        HashTable *old = (standby == mgr.shield_A) ? mgr.shield_B : mgr.shield_A;
        insert_hash_table(old, buf, LOG_AI_BLOCK, 90.0);
        if (write_rate > 0) nanosleep(&gap, NULL);
    }
    *count = i;
    return NULL;
}

static double run_concurrent(int readers, int with_writer, int seconds, long long *writes) {
    stop_flag = 0;
    memset(reader_ops, 0, sizeof(reader_ops));
    pthread_t rt[64], wt;
    RArg args[64];
    for (int i = 0; i < readers; i++) { args[i].id = i; pthread_create(&rt[i], NULL, reader, &args[i]); }
    *writes = 0;
    if (with_writer) pthread_create(&wt, NULL, writer, writes);
    sleep(seconds);
    stop_flag = 1;
    for (int i = 0; i < readers; i++) pthread_join(rt[i], NULL);
    if (with_writer) pthread_join(wt, NULL);
    long long total = 0;
    for (int i = 0; i < readers; i++) total += reader_ops[i];
    return (double)total / seconds;
}

int main(int argc, char **argv) {
    int n = 100000, lookups = 200000, swaps = 20000, readers = -1, seconds = 3;
    const char *file = NULL;
    int opt;
    while ((opt = getopt(argc, argv, "n:l:s:f:r:t:w:")) != -1) {
        switch (opt) {
            case 'n': n = atoi(optarg); break;
            case 'l': lookups = atoi(optarg); break;
            case 's': swaps = atoi(optarg); break;
            case 'f': file = optarg; break;
            case 'r': readers = atoi(optarg); break;
            case 't': seconds = atoi(optarg); break;
            case 'w': write_rate = atoi(optarg); break;
            default:
                fprintf(stderr, "usage: %s [-n 룰수] [-f 도메인파일] [-l 조회횟수] [-s 갱신횟수] [-r 조회스레드] [-t 초] [-w 초당갱신(0=무제한)]\n", argv[0]);
                return 1;
        }
    }
    if (file) load_file(file); else make_synthetic(n);
    if (readers < 0) { readers = (int)sysconf(_SC_NPROCESSORS_ONLN) - 1; if (readers < 1) readers = 1; }
    if (readers > 64) readers = 64;

    /* ---- 측정 환경 ---- */
    struct utsname u; uname(&u);
    char cpu[256] = "unknown";
    FILE *ci = fopen("/proc/cpuinfo", "r");
    if (ci) { char l[512]; while (fgets(l, sizeof l, ci)) if (!strncmp(l, "model name", 10)) { char *c = strchr(l, ':'); if (c) { snprintf(cpu, sizeof cpu, "%s", c + 2); cpu[strcspn(cpu, "\n")] = 0; } break; } fclose(ci); }
    time_t t = time(NULL);
    printf("## 해시 테이블 벤치마크 결과\n\n");
    printf("- 측정 시각: %s", ctime(&t));
    printf("- OS: %s %s / CPU: %s / 논리 코어: %ld\n", u.sysname, u.release, cpu, sysconf(_SC_NPROCESSORS_ONLN));
    printf("- 컴파일러: gcc %s / 최적화: %s\n", __VERSION__,
#ifdef __OPTIMIZE__
           "있음(-O1 이상)"
#else
           "없음(-O0, 엔진 Makefile 과 동일)"
#endif
    );
    printf("- 대상 코드: src/hash_table.c (HASH_SIZE=%d 버킷, djb2 + 체이닝)\n", HASH_SIZE);
    printf("- 도메인: %s %d개\n", file ? file : "합성 도메인", n_domains);
    printf("- 시간 측정: clock_gettime(CLOCK_MONOTONIC), 단위 ns(나노초, 1ms = 1,000,000ns)\n\n");

    /* 타이머 자체 비용 */
    long long *ov = malloc(sizeof(long long) * 100000);
    for (int i = 0; i < 100000; i++) { long long a = now_ns(); long long b = now_ns(); ov[i] = b - a; }
    qsort(ov, 100000, sizeof(long long), cmp_ll);
    long long overhead = ov[50000];
    printf("- 타이머 호출 비용(중앙값) %lldns 를 각 측정값에서 뺐습니다.\n\n", overhead);

    /* ---- 테이블 준비: 실제 엔진처럼 A/B 두 벌 ---- */
    mgr.shield_A = create_hash_table();
    mgr.shield_B = create_hash_table();
    long long t0 = now_ns();
    for (int i = 0; i < n_domains; i++) insert_hash_table(mgr.shield_A, domains[i], LOG_MANUAL_BLOCK, -1);
    long long t1 = now_ns();
    for (int i = 0; i < n_domains; i++) insert_hash_table(mgr.shield_B, domains[i], LOG_MANUAL_BLOCK, -1);
    mgr.active_shield = mgr.shield_A;

    /* 버킷 분포 */
    int used = 0, maxchain = 0;
    for (int b = 0; b < HASH_SIZE; b++) {
        int c = 0; for (HashNode *x = mgr.shield_A->table[b]; x; x = x->next) c++;
        if (c) used++;
        if (c > maxchain) maxchain = c;
    }
    printf("### 적재\n\n- %d개 적재 시간: %.1f ms (1건 평균 %.1f ns)\n", n_domains, (t1 - t0) / 1e6, (double)(t1 - t0) / n_domains);
    printf("- 사용 중인 버킷 %d / %d, 가장 긴 체인 %d개 (평균 체인 %.2f)\n\n", used, HASH_SIZE, maxchain, (double)n_domains / used);

    /* ---- M1: 조회 ---- */
    long long *v = malloc(sizeof(long long) * lookups);
    unsigned seed = 42;
    for (int i = 0; i < lookups; i++) {
        const char *d = domains[rand_r(&seed) % n_domains];
        long long a = now_ns(); HashNode *r = lookup_hash_table(mgr.active_shield, d); long long b = now_ns();
        if (!r) { fprintf(stderr, "조회 실패: %s\n", d); return 1; }
        v[i] = b - a;
    }
    Stat hit = summarize(v, lookups, overhead);
    char miss[128];
    for (int i = 0; i < lookups; i++) {
        snprintf(miss, sizeof miss, "unknown-%d.not-in-list.net", i);
        long long a = now_ns(); HashNode *r = lookup_hash_table(mgr.active_shield, miss); long long b = now_ns();
        if (r) { fprintf(stderr, "예상 밖 hit\n"); return 1; }
        v[i] = b - a;
    }
    Stat mis = summarize(v, lookups, overhead);

    printf("### M1 조회 시간 (1건씩 %d회 측정, ns)\n\n", lookups);
    printf("| %-34s | %10s | %10s | %10s | %12s |\n", "항목", "평균", "중앙값", "p99", "최대");
    printf("|---|---:|---:|---:|---:|\n");
    print_stat("조회 - 목록에 있는 도메인(hit)", hit);
    print_stat("조회 - 목록에 없는 도메인(miss)", mis);
    printf("\n");

    /* ---- M2: 룰 1건 갱신 ---- */
    long long *va = malloc(sizeof(long long) * swaps), *vb = malloc(sizeof(long long) * swaps),
              *vc = malloc(sizeof(long long) * swaps), *vt = malloc(sizeof(long long) * swaps);
    char buf[128];
    for (int i = 0; i < swaps; i++) {
        snprintf(buf, sizeof buf, "swap-%d.bench-add.com", i);
        long long s0 = now_ns();
        HashTable *standby = (mgr.active_shield == mgr.shield_A) ? mgr.shield_B : mgr.shield_A;
        insert_hash_table(standby, buf, LOG_AI_BLOCK, 90.0);
        long long s1 = now_ns();
        __atomic_store_n(&mgr.active_shield, standby, __ATOMIC_SEQ_CST);
        long long s2 = now_ns();
        HashTable *old = (standby == mgr.shield_A) ? mgr.shield_B : mgr.shield_A;
        insert_hash_table(old, buf, LOG_AI_BLOCK, 90.0);
        long long s3 = now_ns();
        va[i] = s1 - s0; vb[i] = s2 - s1; vc[i] = s3 - s2; vt[i] = s3 - s0;
    }
    printf("### M2 룰 1건 추가 + 스왑 (uds_thread.c 순서, %d회, ns)\n\n", swaps);
    printf("| %-34s | %10s | %10s | %10s | %12s |\n", "구간", "평균", "중앙값", "p99", "최대");
    printf("|---|---:|---:|---:|---:|\n");
    print_stat("① 예비 테이블에 insert", summarize(va, swaps, overhead));
    print_stat("② __atomic_store_n 포인터 스왑", summarize(vb, swaps, overhead));
    print_stat("③ 이전 테이블에 insert", summarize(vc, swaps, overhead));
    print_stat("①~③ 전체 (룰 1건 반영)", summarize(vt, swaps, 3 * overhead));
    printf("\n");

    /* ---- M2': 갱신 중 조회 처리량 ---- */
    long long w0, w1;
    double base = run_concurrent(readers, 0, seconds, &w0);
    double busy = run_concurrent(readers, 1, seconds, &w1);
    printf("### M2' 룰 갱신 중 조회 처리량 (조회 스레드 %d개 + 갱신 스레드 1개, 각 %d초, 갱신 목표 %s)\n\n", readers, seconds, write_rate > 0 ? "초당 제한" : "무제한");
    if (write_rate > 0) printf("- 갱신 목표: 초당 %d건 (-w 로 변경)\n\n", write_rate);
    printf("| 조건 | 초당 조회 수 | 갱신 횟수 |\n|---|---:|---:|\n");
    printf("| 갱신 없음 | %.0f | 0 |\n", base);
    printf("| 갱신 스레드가 룰 추가·스왑 | %.0f | %lld (초당 %.0f) |\n", busy, w1, (double)w1 / seconds);
    printf("\n- 조회 처리량 변화: %.1f%%\n", (busy - base) / base * 100.0);
    printf("- 주의: 이 측정은 '추가'만 합니다. 실제 엔진의 '삭제'는 노드를 즉시 free 하므로 동시 조회와 겹치면 위험할 수 있습니다(알려진 한계).\n");
    return 0;
}
