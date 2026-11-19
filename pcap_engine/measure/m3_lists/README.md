# M3 입력 목록 (출처 고정)

| 파일 | 내용 | 출처 |
|---|---|---|
| `normal_tranco_L5KW4_top1000.txt` | 정상 인기 도메인 상위 1,000개 | Tranco 목록 ID **L5KW4** (2026-10-20 ~ 2026-11-18, 2026-11-18 생성), https://tranco-list.eu/list/L5KW4 |
| `dga_sample1000_seed42.txt` | DGA(악성) 도메인 1,000개 | `AI_machine_learning/data/dga_train_ready_korea_v1.csv` 의 label=1 에서 `random.seed(42)` 로 무작위 1,000개 |

주의
- Tranco 는 **등록 도메인 단위**(`google.com`)라, 실제 접속에서 보이는 `www.google.com` 같은 하위 도메인과는 다릅니다.
- DGA 샘플은 학습 데이터에서 TLD 를 뗀 **라벨만**(`uztxduklwk`) 있어, 정규식의 의심 TLD 규칙은 적용되지 않습니다.
- DGA 샘플은 학습 데이터에서 뽑았으므로 **모델 정확도 평가용이 아닙니다**. M3 는 처리 경로(정규식/하드 룰/모델) 비율과 경로별 처리 시간만 봅니다.

실행 (학원 서버, `pcap_engine` 폴더에서 — 결과는 `measure/results/<시각>/m3.md`)
```bash
M3_PY=<AI 서버 venv 의 python> DOMAINS=measure/m3_lists/normal_tranco_L5KW4_top1000.txt ./measure/run_measure.sh m3
M3_PY=<AI 서버 venv 의 python> DOMAINS=measure/m3_lists/dga_sample1000_seed42.txt ./measure/run_measure.sh m3
```
