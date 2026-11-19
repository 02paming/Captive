# 측정 도구 (M1~M7)

서류·면접에 쓰는 수치를 **재현 가능한 방법으로** 측정하기 위한 폴더입니다. 측정하지 않은 숫자는 서류에 쓰지 않습니다.

## 한 번에 실행
```bash
cd pcap_engine
sudo ./measure/run_measure.sh all        # 결과: measure/results/<시각>/
```
| 단계 | 내용 | 필요한 것 |
|---|---|---|
| `bench` (M1·M2) | 해시 조회 시간, 룰 1건 반영 시간(예비 insert → `__atomic_store_n` → 이전 테이블 insert), 갱신 중 조회 처리량. **실제 `src/hash_table.c` 를 링크** | 없음 (언제든) |
| `m3` | 정규식 1차 필터가 AI 추론을 건너뛰게 한 비율 — `ai_uds_server.py` 의 정규식을 그대로 읽어 재생 | `DOMAINS=도메인목록` |
| `m4` | 로그 건별 전송 vs 100건 묶음 전송 (백엔드 `/api/web_access_log`) | 8080 백엔드 + 인증 세션 |
| `m6` | 부하 테스트: 보낸 패킷 → 커널 수신/드롭(`pcap_stats`) → 단계별 카운터 → 로그 | AI 서버·pcap_proxy 실행 중 |
| `m7` | Valgrind + 부하 (M6 와 분리 — Valgrind 는 처리 속도를 크게 떨어뜨림) | valgrind |

## M3 도메인 목록 만들기 (MariaDB)
```sql
SELECT whitelist_domain FROM whitelist_addr WHERE source IN ('AI','DOUBT')
UNION ALL
SELECT blacklist_domain FROM blacklist_addr WHERE source IN ('AI','DOUBT');
```
결과를 한 줄에 하나씩 저장 → 부하 테스트용 도메인(load_tester 의 DGA 10개, example.com, m4-bench-*)은 빼고 →
`sudo DOMAINS=domains.txt ./measure/run_measure.sh m3`

## 가상 랜선(veth)으로 테스트 (실제 미러링 없이, 팀원과 동시에)
```bash
sudo ./measure/veth_setup.sh up pa
sudo LOAD_IFACE=veth-pa CAPTIVE_MIR_DEV=veth-pb CAPTIVE_INJECT_DEV=veth-pb ./measure/run_measure.sh m6 m7
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
