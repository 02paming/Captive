#!/usr/bin/env python3
"""
m4_batch_bench.py — M4: 접속 로그를 '건별 전송' vs '100건 묶음 전송'으로 보낼 때 차이 측정

대상: pcap_checker.py 의 POST /api/web_access_log (백엔드 8080)
  - 건별: {"client_ip":..., ...} 1건씩 HTTP 요청 N번   ← 개선 전 방식
  - 묶음: {"logs":[100건]} 으로 N/100번              ← 지금 pcap_proxy.py 방식 (BATCH_SIZE=100)

테스트 데이터 규칙 (DB 를 덜 어지럽히도록):
  - target_url 은 m4-bench-<실행ID>-<번호>.test → 나중에 이 패턴으로 지움
  - status_code 2(수동 정상) 사용 → 5·6(AI 판정)과 달리 화이트리스트 테이블을 건드리지 않음
  - client_ip(호스트 번호)는 인증 세션이 있는 PC 여야 INSERT 됨 → init_test_sessions.py 실행 후 10~150 중 하나

사용 예:
  python3 m4_batch_bench.py --base http://192.168.3.23:8080 --n 1000 --host 10 > m4_result.md
의존성: 표준 라이브러리만
"""
import argparse, json, statistics, time, urllib.request, uuid


def post(url, payload):
    data = json.dumps(payload).encode("utf-8")
    req = urllib.request.Request(url, data=data, headers={"Content-Type": "application/json"}, method="POST")
    t0 = time.perf_counter()
    with urllib.request.urlopen(req, timeout=30) as r:
        body = r.read().decode("utf-8", "ignore")
    return (time.perf_counter() - t0) * 1000, body


def make_logs(run_id, start, n, host):
    return [{"client_ip": str(host), "status_code": "2", "target_url": f"m4-bench-{run_id}-{i}.test", "ai_score": "-1"}
            for i in range(start, start + n)]


def processed(body):
    try:
        return int(json.loads(body).get("processed", 0))
    except Exception:
        return 0


def run(url, logs, batch):
    lat, ok = [], 0
    t0 = time.perf_counter()
    if batch <= 1:
        for lg in logs:
            ms, body = post(url, lg); lat.append(ms); ok += processed(body)
    else:
        for i in range(0, len(logs), batch):
            ms, body = post(url, {"logs": logs[i:i + batch]}); lat.append(ms); ok += processed(body)
    total = (time.perf_counter() - t0) * 1000
    return total, lat, ok


def main():
    ap = argparse.ArgumentParser()
    ap.add_argument("--base", default="http://192.168.3.23:8080")
    ap.add_argument("--n", type=int, default=1000, help="보낼 로그 수")
    ap.add_argument("--host", type=int, default=10, help="인증 세션이 있는 호스트 번호 (192.168.2.X 의 X)")
    ap.add_argument("--batch", type=int, default=100)
    ap.add_argument("--repeat", type=int, default=3)
    a = ap.parse_args()
    url = a.base.rstrip("/") + "/api/web_access_log"
    run_id = uuid.uuid4().hex[:6]

    print("## M4 로그 전송 방식 비교 결과\n")
    print(f"- 측정 시각: {time.strftime('%Y-%m-%d %H:%M:%S')} / 대상: {url}")
    print(f"- 로그 {a.n:,}건 × {a.repeat}회 반복, 묶음 크기 {a.batch} / 실행 ID: {run_id} (정리용)\n")
    print("| 회차 | 방식 | HTTP 요청 수 | 전체 시간 ms | 초당 로그 | 요청당 평균 ms | DB 반영 건수 |")
    print("|---|---|---:|---:|---:|---:|---:|")
    summary = {"건별": [], "묶음": []}
    seq = 0
    for r in range(1, a.repeat + 1):
        for name, b in (("건별", 1), ("묶음", a.batch)):
            logs = make_logs(run_id, seq, a.n, a.host); seq += a.n
            total, lat, ok = run(url, logs, b)
            summary[name].append(total)
            print(f"| {r} | {name} | {len(lat):,} | {total:,.0f} | {a.n / (total / 1000):,.0f} | {statistics.mean(lat):,.1f} | {ok:,} |")
    s1, s2 = statistics.mean(summary["건별"]), statistics.mean(summary["묶음"])
    print(f"\n**평균 전체 시간: 건별 {s1:,.0f}ms → 묶음 {s2:,.0f}ms (약 {s1 / s2:.1f}배 빠름), HTTP 요청 {a.n:,}회 → {(a.n + a.batch - 1) // a.batch:,}회**")
    print("\n- 'DB 반영 건수'가 보낸 수보다 적으면 해당 호스트의 인증 세션이 없는 것입니다(init_test_sessions.py 먼저 실행).")
    print("- DB 쿼리 수까지 보려면 MariaDB 에서 측정 전후로 `SHOW GLOBAL STATUS LIKE 'Com_insert';` 와 `'Com_select';` 값을 적어 차이를 계산하세요.")
    print(f"- 테스트 데이터 정리: `DELETE FROM web_access_log WHERE target_url LIKE 'm4-bench-{run_id}-%';`")


if __name__ == "__main__":
    main()
