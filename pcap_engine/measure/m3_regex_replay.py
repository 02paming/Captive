#!/usr/bin/env python3
"""
m3_regex_replay.py — M3: 정규식 1차 필터가 AI 모델 추론을 얼마나 건너뛰게 하는지 측정

실제 서버 코드(ai_uds_server.py)에서 정규식(REGEX_*)과 하드 룰(get_max_cons)을 '그대로' 읽어 와
도메인 목록을 같은 순서로 통과시킨다. 서버를 띄우거나 코드를 고칠 필요가 없다.

판정 순서 (ai_uds_server.py handle_client 와 동일):
  0) (선택) 고정 블랙/화이트 리스트에 있으면 C 엔진 해시에서 끝 → AI 서버까지 오지 않음
  1) 정규식 통과: IP / 내부 도메인 / 주요 사이트
  2) 정규식 차단: 의심 TLD / 숫자 7자리 이상 / 하이픈 패턴
  3) 하드 룰 차단: 길이 > 50 또는 자음 연속 > 10
  4) 위를 모두 통과 → AI 모델 추론 (predict_proba)

사용 예 (AI_machine_learning 폴더 위치를 --ai-dir 로):
  python3 m3_regex_replay.py --domains domains.txt --ai-dir ~/Captive/pcap_engine/AI_machine_learning \
      --fixed-black /tmp/ai_blacklist.txt --fixed-white /tmp/ai_whitelist.txt > m3_result.md
"""
import argparse, ast, os, re, statistics, sys, time


def load_server_rules(ai_dir):
    """ai_uds_server.py 에서 REGEX_* 상수와 get_max_cons 함수만 꺼내 실행 (서버·모델 초기화는 실행하지 않음)"""
    src_path = os.path.join(ai_dir, "ai_uds_server.py")
    src = open(src_path, encoding="utf-8").read()
    tree = ast.parse(src)
    keep = []
    for node in tree.body:
        if isinstance(node, ast.Assign) and any(isinstance(t, ast.Name) and t.id.startswith("REGEX_") for t in node.targets):
            keep.append(node)
        elif isinstance(node, ast.FunctionDef) and node.name == "get_max_cons":
            keep.append(node)
    ns = {"re": re}
    exec(compile(ast.Module(body=keep, type_ignores=[]), src_path, "exec"), ns)
    need = ["REGEX_IP_ONLY", "REGEX_LOCAL_DOMAIN", "REGEX_TOP_SITES", "REGEX_BAD_TLD",
            "REGEX_CONSECUTIVE_NUMS", "REGEX_BAD_HYPHENS", "get_max_cons"]
    missing = [k for k in need if k not in ns]
    if missing:
        sys.exit(f"ai_uds_server.py 에서 찾지 못함: {missing}")
    return ns


def classify(d, R):
    if R["REGEX_IP_ONLY"].match(d) or R["REGEX_LOCAL_DOMAIN"].match(d) or R["REGEX_TOP_SITES"].match(d):
        return "1_정규식_통과"
    if R["REGEX_BAD_TLD"].match(d) or R["REGEX_CONSECUTIVE_NUMS"].search(d) or R["REGEX_BAD_HYPHENS"].search(d):
        return "2_정규식_차단"
    if len(d) > 50 or R["get_max_cons"](d) > 10:
        return "3_하드룰_차단"
    return "4_AI_모델"


def read_list(path):
    if not path:
        return None
    with open(path, encoding="utf-8", errors="ignore") as f:
        return {l.strip().lower() for l in f if l.strip()}


def pct(a, b):
    return f"{a / b * 100:.1f}%" if b else "-"


def ms_stats(v):
    if not v:
        return "-", "-", "-"
    v = sorted(v)
    return f"{statistics.mean(v):.3f}", f"{v[len(v) // 2]:.3f}", f"{v[min(len(v) - 1, int(len(v) * 0.99))]:.3f}"


def main():
    ap = argparse.ArgumentParser()
    ap.add_argument("--domains", required=True, help="도메인 목록 파일 (한 줄에 하나)")
    ap.add_argument("--ai-dir", required=True, help="AI_machine_learning 폴더")
    ap.add_argument("--model", default="v1.0", help="모델 버전 (model/dga_model_vec_<버전>.pkl)")
    ap.add_argument("--fixed-black", help="고정 블랙리스트 (예: /tmp/ai_blacklist.txt)")
    ap.add_argument("--fixed-white", help="고정 화이트리스트 (예: /tmp/ai_whitelist.txt)")
    ap.add_argument("--all", action="store_true", help="중복 포함 전체 요청 기준 (기본: 고유 도메인 기준)")
    a = ap.parse_args()

    R = load_server_rules(a.ai_dir)
    raw = [l.strip().lower() for l in open(a.domains, encoding="utf-8", errors="ignore") if l.strip()]
    items = raw if a.all else list(dict.fromkeys(raw))
    fb, fw = read_list(a.fixed_black), read_list(a.fixed_white)

    model = vec = None
    model_note = ""
    try:
        import joblib
        model = joblib.load(os.path.join(a.ai_dir, "model", f"dga_model_vec_{a.model}.pkl"))
        vec = joblib.load(os.path.join(a.ai_dir, "model", f"vectorizer_{a.model}.pkl"))
    except Exception as e:
        model_note = f"모델을 불러오지 못해 AI 경로 처리 시간은 비워 둡니다 ({type(e).__name__}: {e})"

    counts, times, examples = {}, {}, {}
    fixed_hit = 0
    for d in items:
        if (fb and d in fb) or (fw and d in fw):
            fixed_hit += 1
            continue
        t0 = time.perf_counter()
        c = classify(d, R)
        if c == "4_AI_모델" and model is not None:
            model.predict_proba(vec.transform([d]))
        el = (time.perf_counter() - t0) * 1000
        counts[c] = counts.get(c, 0) + 1
        if c != "4_AI_모델" or model is not None:
            times.setdefault(c, []).append(el)
        examples.setdefault(c, [])
        if len(examples[c]) < 5:
            examples[c].append(d)

    reach = sum(counts.values())
    skipped = reach - counts.get("4_AI_모델", 0)
    basis = "전체 요청(중복 포함)" if a.all else "고유 도메인"

    print("## M3 정규식 사전 필터 측정 결과\n")
    print(f"- 측정 시각: {time.strftime('%Y-%m-%d %H:%M:%S')}")
    print(f"- 입력: {a.domains} — 원본 {len(raw):,}줄, 집계 기준: {basis} {len(items):,}개")
    print(f"- 규칙 출처: {os.path.join(a.ai_dir, 'ai_uds_server.py')} 의 REGEX_* · get_max_cons (서버 코드 그대로)")
    print(f"- 모델: {a.model}" + (f" — {model_note}" if model_note else ""))
    if fb is not None or fw is not None:
        print(f"- 고정 리스트: 블랙 {len(fb or []):,}개 / 화이트 {len(fw or []):,}개 → 여기에 있는 {fixed_hit:,}개는 C 엔진 해시에서 끝나 AI 서버까지 오지 않음")
    print(f"\n### AI 서버까지 온 {reach:,}개의 처리 경로\n")
    print("| 경로 | 개수 | 비율 | 평균 ms | 중앙값 ms | p99 ms | 예시 |")
    print("|---|---:|---:|---:|---:|---:|---|")
    for k in ["1_정규식_통과", "2_정규식_차단", "3_하드룰_차단", "4_AI_모델"]:
        n = counts.get(k, 0)
        m, p50, p99 = ms_stats(times.get(k, []))
        print(f"| {k} | {n:,} | {pct(n, reach)} | {m} | {p50} | {p99} | {', '.join(examples.get(k, [])[:3])} |")
    print(f"\n**AI 모델 추론을 건너뛴 비율: {skipped:,} / {reach:,} = {pct(skipped, reach)}** (정규식 통과·차단 + 하드 룰)")
    if fb is not None or fw is not None:
        total = len(items)
        print(f"**입력 전체 대비 AI 모델까지 가지 않은 비율: {fixed_hit + skipped:,} / {total:,} = {pct(fixed_hit + skipped, total)}** "
              f"(C 엔진 고정 리스트 {fixed_hit:,} + 정규식·하드 룰 {skipped:,})")
    rx = times.get("1_정규식_통과", []) + times.get("2_정규식_차단", []) + times.get("3_하드룰_차단", [])
    if rx and times.get("4_AI_모델"):
        print(f"- 정규식·하드 룰 경로 평균 {statistics.mean(rx):.3f}ms vs 모델 경로 평균 {statistics.mean(times['4_AI_모델']):.3f}ms "
              f"(약 {statistics.mean(times['4_AI_모델']) / max(statistics.mean(rx), 1e-9):.0f}배)")
    print("\n- 주의: 처리 시간은 판정 함수만 잰 값입니다(UDS 통신·로그 출력 제외). 서버의 [LOG] 소요 시간과는 다를 수 있습니다.")


if __name__ == "__main__":
    main()
