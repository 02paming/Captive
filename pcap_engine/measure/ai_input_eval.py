#!/usr/bin/env python3
"""
ai_input_eval.py — AI 입력 형식 개선 전후 비교 (학습에 쓰지 않은 데이터로)

전: 서버가 전체 도메인(www.naver.com)을 그대로 모델에 넣음
후: 학습(train.py)과 같게 등록 도메인 이름(naver)만 넣음 — ai_uds_server.to_model_input

데이터 (모두 학습 데이터 dga_train_ready_korea_v2.csv 와 '이름'이 겹치지 않는 것만):
  정상: Tranco 목록의 300,001위 이후에서 무작위 N개 → 그대로 / 'www.' 붙인 형태 두 가지
  DGA : dga_train_500k_balanced.csv 의 label=dga 중 학습에 안 쓴 것에서 무작위 N개
        (원본에 TLD 가 없어 .com/.net/.org/.info 를 순서대로 붙여 실제 접속 형태를 흉내 — 한계로 명시)
판정 기준: 모델 점수 50점 이상 = 악성 (서버의 실제 임계치는 DB 설정값)

사용: python3 ai_input_eval.py --ai-dir ../AI_machine_learning --tranco top1m.csv [--n 2000]
"""
import argparse, csv, os, random, statistics, sys, time
sys.path.insert(0, os.path.dirname(__file__))
from m3_regex_replay import load_server_rules

ap = argparse.ArgumentParser()
ap.add_argument("--ai-dir", required=True)
ap.add_argument("--tranco", required=True, help="Tranco CSV (rank,domain)")
ap.add_argument("--n", type=int, default=2000)
ap.add_argument("--seed", type=int, default=42)
ap.add_argument("--model", default="v1.0")
a = ap.parse_args()

import joblib
R = load_server_rules(a.ai_dir)
conv = R["to_model_input"]
model = joblib.load(os.path.join(a.ai_dir, "model", f"dga_model_vec_{a.model}.pkl"))
vec = joblib.load(os.path.join(a.ai_dir, "model", f"vectorizer_{a.model}.pkl"))
train = {r["domain"] for r in csv.DictReader(open(os.path.join(a.ai_dir, "data", "dga_train_ready_korea_v2.csv"), encoding="utf-8"))}
rnd = random.Random(a.seed)

normal = []
for row in csv.reader(open(a.tranco, encoding="utf-8")):
    if int(row[0]) > 300000 and conv(row[1]) not in train:
        normal.append(row[1])
normal = rnd.sample(normal, a.n)

dga_pool = [r["domain"] for r in csv.DictReader(open(os.path.join(a.ai_dir, "data", "dga_train_500k_balanced.csv"), encoding="utf-8"))
            if r["label"] == "dga" and r["domain"] not in train]
tlds = ["com", "net", "org", "info"]
dga = [f"{d}.{tlds[i % 4]}" for i, d in enumerate(rnd.sample(dga_pool, a.n))]

def scores(xs):
    return [p[1] * 100 for p in model.predict_proba(vec.transform(xs))]

def row(name, xs, malicious):
    b, f = scores(xs), scores([conv(x) for x in xs])
    rate = lambda s: sum(v >= 50 for v in s) / len(s) * 100
    lab = "탐지율" if malicious else "오탐률"
    return f"| {name} | {len(xs):,} | {lab} | {rate(b):.1f}% (평균 {statistics.mean(b):.1f}점) | **{rate(f):.1f}%** (평균 {statistics.mean(f):.1f}점) |"

print("## AI 입력 형식 개선 전후 (학습에 쓰지 않은 데이터)\n")
print(f"- 측정 시각: {time.strftime('%Y-%m-%d %H:%M:%S')} · 모델 {a.model} · 표본 각 {a.n:,}개 (seed {a.seed}) · 판정 기준 50점")
print(f"- 정상: {os.path.basename(a.tranco)} 300,001위 이후, 학습 이름과 겹치지 않는 것 / DGA: 500k 원본 중 학습 미사용분\n")
print("| 데이터 | 개수 | 지표 | 전 (전체 도메인 투입) | 후 (등록 도메인 이름 투입) |")
print("|---|---:|---|---:|---:|")
print(row("정상 (예: example.co.kr)", normal, False))
print(row("정상에 www. 붙임", ["www." + d for d in normal], False))
print(row("DGA + .com/.net/.org/.info", dga, True))
print("\n- 오탐률은 낮을수록, 탐지율은 높을수록 좋음")
print("- 한계: DGA 원본에 TLD 가 없어 흔한 TLD 를 붙여 흉내 냄. 정상은 Tranco 등록 도메인 단위(실제 접속엔 다양한 하위 도메인이 붙음)")
