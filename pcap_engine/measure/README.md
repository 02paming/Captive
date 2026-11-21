# 측정 도구 (M1~M7)

서류·면접에 쓰는 수치를 **재현 가능한 방법으로** 측정하기 위한 폴더입니다. 측정하지 않은 숫자는 서류에 쓰지 않습니다.

## 한 번에 실행 (일반 계정으로 — 스크립트 전체를 sudo 로 돌리지 않음)
```bash
cd pcap_engine
./measure/run_measure.sh bench m3 m4     # root 필요 없음
./measure/run_measure.sh m6 m7           # 안에서 엔진·valgrind·load_tester·종료 신호만 sudo 로 실행
```
결과: `measure/results/<시각>/`
| 단계 | 내용 | 필요한 것 |
|---|---|---|
| `bench` (M1·M2) | 해시 조회 시간, 룰 1건 반영 시간(예비 insert → `__atomic_store_n` → 이전 테이블 insert), 갱신 중 조회 처리량. **실제 `src/hash_table.c` 를 링크** | 없음 (언제든) |
| `m3` | 정규식 1차 필터가 AI 추론을 건너뛰게 한 비율 — `ai_uds_server.py` 의 정규식을 그대로 읽어 재생 | `DOMAINS=도메인목록` |
| `m4` | 로그 건별 전송 vs 100건 묶음 전송 (백엔드 `/api/web_access_log`) | 8080 백엔드 + 인증 세션 |
| `m6` | 부하 테스트: 보낸 패킷 → 커널 수신/드롭(`pcap_stats`) → 단계별 카운터 → 로그 | AI 서버·pcap_proxy 실행 중 |
| `m7` | Valgrind + 부하 (M6 와 분리 — Valgrind 는 처리 속도를 크게 떨어뜨림) | valgrind |

## 권한 (sudoers) — M6·M7 에만 필요

M6·M7 은 패킷 캡처·주입 때문에 아래 명령만 root 로 실행합니다. 시작할 때 실제 경로가 `run.log` 에 찍힙니다
(`load_tester 파이썬: ...  /  엔진: ...`). 서버 관리자가 `sudo visudo -f /etc/sudoers.d/captive-measure` 로 추가합니다.

```
# 경로는 서버에 맞게 바꾸기: ENG=엔진 실행 파일, PY=scapy 가 깔린 파이썬, LT=load_tester.py
Defaults:captive env_keep += "CAPTIVE_MIR_DEV CAPTIVE_INJECT_DEV"
Cmnd_Alias CAPTIVE_MEASURE = /절대경로/pcap_c_server/bin/my_pcap_app, \
  /usr/bin/valgrind --leak-check=full --show-leak-kinds=all --log-file=/tmp/captive_valgrind.txt /절대경로/pcap_c_server/bin/my_pcap_app, \
  /절대경로/venv/bin/python /절대경로/load_test/load_tester.py *, \
  /usr/bin/pkill -INT -x my_pcap_app, /usr/bin/pkill -9 -x my_pcap_app, /usr/bin/pkill -INT -f valgrind.*my_pcap_app
captive ALL=(root) NOPASSWD: CAPTIVE_MEASURE
```
- 엔진 실행 줄은 이미 허용돼 있다면 그대로 두고 나머지만 추가합니다.
- `env_keep` 줄은 가상 랜선(veth) 테스트 때 NIC 이름을 엔진에 넘기기 위해서만 필요합니다.
- 파이썬은 **실제로 실행되는 절대경로**와 같아야 합니다 (`which python3` 와 venv 경로가 다를 수 있음). 다르면 `LOAD_PY=/절대경로/venv/bin/python` 으로 지정.
- 주의: root 로 실행되는 스크립트(`load_tester.py`)를 `captive` 계정이 수정할 수 있으면 사실상 root 권한과 같습니다. 측정 기간에만 허용하고 끝나면 파일을 지우는 것을 권장합니다.
- 관리자 권한을 받을 수 없으면: 관리자에게 `./measure/run_measure.sh m6 m7` 실행만 부탁해도 됩니다.

## M3 도메인 목록 만들기 (MariaDB)
```sql
SELECT whitelist_domain FROM whitelist_addr WHERE source IN ('AI','DOUBT')
UNION ALL
SELECT blacklist_domain FROM blacklist_addr WHERE source IN ('AI','DOUBT');
```
결과를 한 줄에 하나씩 저장 → 부하 테스트용 도메인(load_tester 의 DGA 10개, example.com, m4-bench-*)은 빼고 →
`M3_PY=/AI서버_venv/bin/python DOMAINS=domains.txt ./measure/run_measure.sh m3`

## 가상 랜선(veth)으로 테스트 (실제 미러링 없이, 팀원과 동시에)
```bash
sudo ./measure/veth_setup.sh up pa      # 가상 랜선 만들기는 root 필요 → 관리자가 한 번 실행 (서버 재부팅 전까지 유지)
LOAD_IFACE=veth-pa CAPTIVE_MIR_DEV=veth-pb CAPTIVE_INJECT_DEV=veth-pb ./measure/run_measure.sh m6 m7
sudo ./measure/veth_setup.sh down pa
```
- 엔진 NIC 는 `CAPTIVE_MIR_DEV` / `CAPTIVE_INJECT_DEV`, load_tester 는 `TARGET_IFACE` / `TEST_DURATION` 환경변수로 바꿀 수 있습니다 (기본값은 eno2 / eno4 / 60초 그대로).
- veth 에서는 주입한 RST 가 같은 NIC 로 다시 캡처되어 `ps_recv` 가 보낸 패킷보다 많게 나옵니다(TCP 페이로드 없는 패킷이라 바로 버려짐). 실제 장비는 주입 NIC(eno4)가 달라 이 차이가 없습니다.

## 결과 해석
- **누락** = `ps_drop` + `ps_ifdrop` (커널이 버린 패킷). 로그 수는 누락 지표가 아닙니다 — 같은 PC 3초 1회(통과)·2초 1회(차단) 중복 억제와 DNS 무로그가 설계상 로그를 줄입니다.
- 결과 폴더를 통째로 공유하면 `측정기록` 과 서류 문장으로 정리합니다.

## 이 브랜치에서 함께 고친 것
- DNS(UDP) 도메인 파싱 버그 (UDP 길이 미계산 → DNS 를 한 번도 파싱하지 못함)
- 위 수정으로 드러난 세그폴트: 미지 도메인 분기에서 UDP 패킷에 `inject_rst(tcp=NULL)` 호출
- `push_to_log_queue` 의 strcpy → snprintf
- pcap_proxy: Flask 개발 서버 → Waitress

## AI 입력 형식 전후 비교 (`ai_input_eval.py`)
학습에 쓰지 않은 데이터로, 모델에 전체 도메인을 넣을 때(전)와 등록 도메인 이름만 넣을 때(후)를 비교합니다.
```bash
python3 measure/ai_input_eval.py --ai-dir AI_machine_learning --tranco <Tranco top-1m.csv> --n 2000 --seed 42
```
Tranco 목록은 https://tranco-list.eu 에서 받습니다(측정에 쓴 목록 ID: L5KW4). AI 서버 venv 의 python 으로 실행하세요(scikit-learn·tldextract 필요).
