# SecureTech — C 패킷 제어 엔진 (Captive)

![C](https://img.shields.io/badge/C-00599C?style=for-the-badge&logo=c&logoColor=white)
![Python](https://img.shields.io/badge/Python-3776AB?style=for-the-badge&logo=python&logoColor=white)
![Flask](https://img.shields.io/badge/Flask-000000?style=for-the-badge&logo=flask&logoColor=white)
![Scikit-Learn](https://img.shields.io/badge/Scikit_Learn-F7931E?style=for-the-badge&logo=scikit-learn&logoColor=white)
![Linux](https://img.shields.io/badge/Linux-FCC624?style=for-the-badge&logo=linux&logoColor=black)

> **L3 스위치 포트 미러링으로 사내망 트래픽 사본을 분석하고, Raw Socket 으로 TCP RST·HTTP 302 를 주입해 차단하는 Out-of-Path 사내망 접근 통제 시스템** — **SecureTech** 중 **C 패킷 제어 엔진 · AI 판정 서버(Python) · 캡티브 포털 프록시(Flask)** 를 담은 저장소입니다.

- 4인 팀 프로젝트 · 2026.10.01 ~ 2026.11.20
- 관리자 웹(React)·백엔드(Django)·DB 동기화 서버는 [SecureTech_WAS](https://github.com/02paming/SecureTech_WAS) 저장소에 있습니다.

🔗 **[![Notion](https://img.shields.io/badge/Notion_개발_일지_보러가기-000000?style=for-the-badge&logo=notion&logoColor=white)](https://app.notion.com/p/206597615cf6415c8859374a152ad97c)**

---

## 1. 무엇을 하나

1. 사원 PC 의 HTTP(80)·DNS(53) 요청을 **스위치 미러링 사본**으로 받아 접속 도메인을 꺼냅니다. 통신 경로 한가운데 장비를 두지 않아, 엔진이 멈춰도 사내망은 끊기지 않습니다.
2. **인증되지 않은 PC** 는 인증 페이지로, **차단 도메인** 은 차단 안내 페이지로 보냅니다 (위조 HTTP 302 + TCP RST 주입).
3. 처음 보는 도메인은 **AI 판정 서버**(Random Forest + N-gram)가 악성 점수를 매기고, 결과를 엔진 해시 테이블에 **서비스 중단 없이** 반영합니다.
4. 접속·차단 로그는 묶음으로 백엔드에 보내 DB 에 쌓고, 관리자는 웹에서 정책·임계치·모델 버전을 바꿉니다.

## 2. 구성과 통신 구간

![시스템 아키텍처 구조도](https://github.com/user-attachments/assets/c6ea5da3-6f75-47ee-99a5-a29eb2e91e31)

| 구성 요소 | 위치 | 역할 |
|---|---|---|
| 패킷 제어 엔진 (`pcap_engine/pcap_c_server`, C) | 분석망 서버 | libpcap 캡처, 도메인 파싱, 해시 조회, RST·302 주입, 스레드: 패킷 1 · AI 워커 8 · UDS 명령 1 · 만료 1 · 로그 1 |
| AI 판정 서버 (`AI_machine_learning/ai_uds_server.py`) | 분석망 서버 | 정규식·하드 룰 1차 필터 → Random Forest 점수, 모델·임계치 무중단 교체 |
| 캡티브 포털 프록시 (`pcap_webServer/pcap_proxy.py`, Flask + Waitress) | 분석망 서버 | 인증·차단·분석 중 안내 페이지, 엔진↔백엔드 중계, 로그 묶음 전송 |
| 동기화 백엔드 (8080) · 관리자 웹 (Nginx 80 → Gunicorn 8000) · DB | Web Server / DB Server | [SecureTech_WAS](https://github.com/02paming/SecureTech_WAS) |

| 구간 | 방식 | 이유 |
|---|---|---|
| 엔진 ↔ 프록시 ↔ AI 서버 (같은 서버) | **UDS (Unix Domain Socket)** | 같은 호스트 안 통신이라 네트워크 스택을 거치지 않고, 포트를 외부에 열지 않음 |
| 프록시 ↔ 동기화 백엔드 (8080) | HTTP REST | 서버가 다름. 엔진은 DB 를 모르고, **DB 접근 권한은 백엔드에만** 둠 |
| 사원 PC 트래픽 | L3 스위치 SPAN(미러링) → 엔진 캡처 NIC | 인라인 장비의 단일 장애점·지연을 피함 |

망은 클라이언트망(192.168.2.x)·분석망(192.168.3.x)·DB망(192.168.4.x)으로 **서브넷을 분리**했습니다.

## 3. 핵심 구현

### 2-Tier 해시 테이블 + A/B 스왑 (`hash_table.c`, `uds_thread.c`, `ai_worker_thread.c`)
- **고정 테이블**(시작 시 블랙·화이트리스트 각 10만 건 적재)과 **동적 테이블**(관리자·AI 가 실시간 갱신)을 분리 — 동적 룰을 지워도 기본 룰은 사라지지 않음. 조회 순서: 동적 → 고정.
- 동적 테이블은 A/B 두 벌. 쉬는 쪽을 고친 뒤 `__atomic_store_n`(GCC 내장 함수)으로 활성 포인터를 바꿈 → **패킷 검사(읽기) 경로는 락 없이** 조회. 쓰기는 테이블별 mutex.
- djb2 해시 + 체이닝, 버킷 200,001개(소수).

### 패킷 주입 (`inject_rst.c`, `inject_redirect.c`)
- 미러링 사본이라 원래 패킷을 버릴 수 없으므로, 실제 응답보다 먼저 **위조 HTTP 302**(사용자 방향)와 **TCP RST**(서버 방향)를 보냄.
- 출발지·목적지 뒤집기, 시퀀스·ACK 계산, IP·TCP(가상 헤더 포함) 체크섬 재계산.

### AI 판정과 무중단 교체 (`ai_uds_server.py`)
- 1차: 정규식(IP·내부 도메인·주요 사이트 통과 / 의심 TLD·숫자 7자리 연속·하이픈 패턴 차단) + 하드 룰(길이 50 초과·자음 10개 연속) → 통과한 도메인만 모델 추론.
- 모델 파일은 **락 밖에서 미리 읽고**, 락 안에서는 참조만 교체 → 교체 중에도 판정이 멈추지 않음. 실패 시 기존 모델 유지.
- 모델 v1.0 (RandomForest + N-gram): 정확도 96.72%, 정밀도 97.65%, 재현율 95.73%, F1 96.68% — 테스트 39,999건 (`model/model_metrics.json`, 학습 형식인 '등록 도메인 이름' 기준)
- 모델에는 학습과 같게 **등록 도메인 이름만** 넣음(`www.naver.com` → `naver`, `to_model_input`). TLD·전체 도메인 판단은 정규식과 고정·관리자 리스트가 담당
- **DNS 응답(NXDOMAIN) 활용**: 엔진이 DNS 응답도 함께 캡처해, 주소가 있는 응답만 AI 로 보내고 없는 도메인은 판정을 생략. 대신 PC별로 NXDOMAIN 수를 세어 기준(기본 60초에 20회)을 넘으면 '감염 의심' 알림 1건을 백엔드 `unauth_threat_log`(위협 종류 `DGA_NXDOMAIN`)에 남김 — DGA 악성코드는 없는 도메인을 대량 조회하다 등록된 하나에 접속하기 때문

### 로그 묶음 전송 (`pcap_proxy.py`)
- 100건이 차거나 1초가 지나면 한 번에 백엔드로 전송, 백엔드는 `executemany` 로 INSERT.

## 4. 측정

측정 환경: Intel Xeon E5-2630 v3 (8코어), CentOS/RHEL 8 계열, gcc 8.5 `-O0`(엔진 빌드와 동일), 2026-11-20.
수치는 **`pcap_engine/measure/`** 의 도구로 측정하며, 측정하지 않은 수치는 적지 않습니다. 실행 방법은 [measure/README.md](pcap_engine/measure/README.md).

| 항목 | 방법 | 결과 |
|---|---|---|
| 해시 조회 시간 | `make bench` — 실제 `hash_table.c` 링크, `clock_gettime`, 실제 블랙리스트 10만 건·20만 회 조회 × 3회 | **평균 약 0.17μs** (p99 약 0.42μs), 목록에 없는 도메인 약 0.13μs |
| 룰 1건 반영 시간 (예비 insert → 포인터 스왑 → 이전 테이블 insert) | 같은 벤치마크, 2만 회 × 3회 | **평균 약 0.52μs** (포인터 스왑만 약 16ns) |
| 룰 갱신 중 조회 처리량 | 조회 스레드 7개 + 초당 약 920건 갱신, 3초 × 3회 | 조회가 멈추지 않음, 처리량 감소 약 7% (초당 약 4,100만 → 3,800만 건) |
| AI 입력 형식 통일 전후 (학습에 안 쓴 데이터) | `measure/ai_input_eval.py` — 정상 Tranco 30만 위 이후 2,000개, DGA 학습 미사용분 2,000개(흔한 TLD 부착), seed 3개 | DGA 탐지율 **약 81% → 약 96%**, `www.` 붙은 정상 오탐률 약 5% → 약 3% (등록 도메인 그대로인 정상은 약 3%로 변화 없음) |
| NXDOMAIN 급증 탐지 | 가상 랜선 시나리오 6종 + 비정상 DNS 응답 3,000개, 실제 장비(사내 PC) | 감염식 50개 → 알림 1건·AI 0, 크롬식 3개 → 무시, 있는 도메인만 AI. ASan 오류 0·Valgrind 누수 0. 실제 장비에서 관리자 화면·Discord 경보 확인 |
| AI 판정 1건 처리 시간 vs 1차 필터 | `measure/m3_regex_replay.py` — 서버 규칙·모델 v1.0 그대로, DGA 샘플 1,000개 | 모델 추론 **평균 약 88ms** (p99 약 95ms) vs 정규식·하드 룰 약 0.05ms vs 엔진 해시 조회 약 0.17μs → 자주 쓰는 도메인을 엔진 고정 리스트에서 끝내는 이유 |
| 로그 건별 vs 묶음 전송 | 백엔드 API 에 1,000건 × 3회 | 건별 약 17.9초 → 100건 묶음 약 2.8초 (**약 6.5배**), HTTP 요청 1,000회 → 10회, DB 반영 1,000/1,000 |
| 부하 시 패킷 손실 | `load_tester.py`(Scapy 4스레드, 사원 PC 141대 흉내, HTTP·DNS 반반) + `pcap_stats` + 단계별 카운터, 60초 × 3회 | 회당 약 4.2만 패킷(초당 약 700, **발생기 한계**) — 커널 드롭 **0**, 파싱 실패 **0**, 로그 큐 손실 **0**, 보낸 수 = 엔진 수신 수 |
| 메모리 누수 | Valgrind + 30초 부하(약 2.1만 패킷) | 할당 200,844 / 해제 200,842 — 남은 2건(16바이트)은 `pcap_open_live` 안의 libpcap→libibverbs 내부 할당(핸들 2개당 8바이트, 부하와 무관하게 고정). **엔진 코드 누수 0** |

## 5. 실행

요구 사항: Linux, gcc, libpcap-dev, Python 3.9+, root 권한(캡처·주입)

운영 환경: Cisco Catalyst 3750G 1대 + HP DL360 Gen9 서버 3대(Web · PCAP · DB). PCAP Server — GCC 8.5.0, libpcap 1.9.1, Python 3.9.25, scikit-learn 1.6.1. 실행 순서는 AI 판정 서버 → 캡티브 포털 프록시 → 엔진(엔진이 두 서버의 UDS 소켓에 연결). 엔진 로그는 syslog(`journalctl -t pcap_engine`).

```bash
# 1) AI 판정 서버
cd pcap_engine/AI_machine_learning && pip install -r requirements.txt && python3 ai_uds_server.py

# 2) 캡티브 포털 프록시 (Waitress, 단일 프로세스)
cd pcap_engine/pcap_webServer && pip install -r requirements.txt && python3 pcap_proxy.py

# 3) 패킷 제어 엔진
cd pcap_engine/pcap_c_server && make && sudo ./bin/my_pcap_app
```

| 환경변수 | 기본값 | 설명 |
|---|---|---|
| `CAPTIVE_MIR_DEV` / `CAPTIVE_INJECT_DEV` | `eno2` / `eno4` | 엔진 캡처·주입 NIC |
| `PCAP_PROXY_PORT` | `5000` | 프록시 포트 |
| `CAPTIVE_NX_THRESHOLD` / `CAPTIVE_NX_WINDOW` | `20` / `60` | 한 PC가 이 초 안에 없는 도메인(NXDOMAIN) 응답을 이 횟수 이상 받으면 '감염 의심' 알림 1건 |
| `CAPTIVE_DNS_QUERY_AI` | `0` | `1`이면 예전처럼 DNS 질의 시점에 AI 요청 (DNS 응답을 미러링으로 못 받는 환경용) |
| `TARGET_IFACE` / `TEST_DURATION` | `eno2` / `60` | 부하 테스트(`load_test/load_tester.py`) |

실제 미러링 없이 테스트하려면 가상 랜선(veth): `sudo ./measure/veth_setup.sh up pa` ([measure/README.md](pcap_engine/measure/README.md) 참고).

## 6. 트러블슈팅

### 기본 룰이 동적 룰 삭제와 함께 사라짐 → 2-Tier 분리
- **현상**: 기본 블랙리스트와 관리자가 바꾸는 동적 룰이 한 테이블에 있어, 관리자가 룰을 지우면 기본 룰까지 사라지고 해당 도메인이 다시 AI 큐로 넘어감.
- **해결**: 고정·동적 테이블 분리, 조회 우선순위(동적 → 고정) 부여.

### 부팅 시 로그 테이블 전체 탐색 → 정책 테이블에 점수 저장
- **현상**: 엔진 부팅 때 과거 AI 점수를 복구하려고 커지는 `web_access_log` 를 전체 탐색해 부팅 지연·DB 부하.
- **해결**: 정책 테이블(`whitelist_addr`, `blacklist_addr`)에 `ai_score` 를 두고 초기 동기화는 정책 테이블에서 바로 조회.

### 부하 테스트에서 로그가 보낸 패킷보다 훨씬 적음 → DNS 파싱 버그 + 숨은 세그폴트
- **현상**: 60초 약 4만 패킷 전송에도 로그는 일부만 남음.
- **원인 추적**: 단계별 카운터 16개와 `pcap_stats` 를 추가해 측정. 대부분은 설계상 중복 억제(같은 PC 통과 3초 1회·차단 2초 1회, DNS 무로그)였지만, **UDP 경로에서 페이로드 길이를 계산하지 않아 DNS 를 한 번도 파싱하지 못하던 버그** 발견.
- **이어서**: 파싱을 고치자 미지 도메인 분기에서 UDP 패킷에 `inject_rst(tcp=NULL)` 을 호출하는 **세그폴트**가 드러남 → gdb 로 위치 확인, UDP 는 AI 큐에만 넣도록 수정(DNS 가 토큰을 먼저 써 HTTP 안내 페이지가 막히던 문제도 해결).
- **검증**: veth 가상 랜선 부하 테스트, AddressSanitizer 오류 0, Valgrind 누수 0.

## 7. 알려진 한계와 개선 계획

| 한계 | 개선 방향 |
|---|---|
| **HTTPS 미지원** — TLS 안으로 302 를 주입할 수 없음. 현재 HTTP(80)·DNS(53)만 대상 | TLS ClientHello 의 SNI 로 도메인을 보고 RST 차단 |
| **경쟁 조건** — 실제 서버 응답이 RST 보다 먼저 오면 차단 실패 (Out-of-Path 방식의 본질적 한계) | 차단 페이지 재요청 유도, 중요 구간은 인라인 장비와 병행 |
| 룰 삭제 시 노드를 즉시 `free` — 스왑 직전 포인터로 조회 중인 스레드가 있으면 해제된 메모리를 읽을 수 있음. 쓰기 스레드도 여러 개 | 쓰기 스레드 단일화 + 읽는 스레드가 빠져나간 뒤 해제(RCU 방식 유예) |
| AI 판정 1건 약 88ms (572MB Random Forest, 도메인마다 `predict_proba` 1회) | 트리 수·깊이 축소 또는 묶음 추론 후 정확도와 함께 재측정 |
| 로그 묶음 전송 전 프로세스가 죽으면 메모리의 최대 100건(1초분) 유실 가능 | 로컬 파일 버퍼 또는 메시지 큐 |
| 로그 누적에 따라 로그 분석 페이지가 느려짐 | 페이지네이션·인덱스·기간별 파티셔닝 |
| 포트·소켓 경로·서버 IP 하드코딩으로 한 서버에서 여러 명이 동시에 테스트하기 어려움 | 환경변수화 확대 + 사람별 테스트 DB + veth |
