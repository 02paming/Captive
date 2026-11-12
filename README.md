#  SecureTech WAS (사내망 접근 통제 시스템)

![Python](https://img.shields.io/badge/Python-3776AB?style=for-the-badge&logo=python&logoColor=white)
![C](https://img.shields.io/badge/C-00599C?style=for-the-badge&logo=c&logoColor=white)
![Django](https://img.shields.io/badge/Django-092E20?style=for-the-badge&logo=django&logoColor=white)
![React](https://img.shields.io/badge/React-20232A?style=for-the-badge&logo=react&logoColor=61DAFB)
![MariaDB](https://img.shields.io/badge/MariaDB-003545?style=for-the-badge&logo=mariadb&logoColor=white)
![Scikit-Learn](https://img.shields.io/badge/Scikit_Learn-F7931E?style=for-the-badge&logo=scikit-learn&logoColor=white)

> **L3 스위치 미러링 및 Raw Socket 패킷 인젝션을 활용한 AI 기반 사내망 접근 통제 시스템**

본 프로젝트는 기업 내부망의 보안을 강화하기 위해 **네트워크 패킷을 실시간으로 스니핑 및 제어**하고, **머신러닝(Random Forest)을 통해 악성 도메인(DGA)을 자동 탐지**하여 차단하는 엔터프라이즈급 보안 솔루션입니다.

---

## 시스템 아키텍처 (System Architecture)

![시스템 아키텍처 구조도](https://github.com/user-attachments/assets/c6ea5da3-6f75-47ee-99a5-a29eb2e91e31)

* **망 분리 설계:** 방화벽 코어(C 엔진)와 웹 대시보드(React/Django)를 물리적/논리적으로 분리하고, Flask 프록시 및 UDS(Unix Domain Socket)를 통한 안전한 IPC 통신을 구현했습니다.
* **마이크로서비스 백엔드:** 포트 8000(명령 및 UI 처리)과 포트 8080(PCAP 로그 수집 및 동기화)으로 백엔드의 역할을 철저히 분리하여 트래픽 병목을 방지했습니다.

---

##  주요 기능 (Key Features)

### 1. 실시간 패킷 스니핑 및 제어 (C/libpcap)
* L3 스위치의 미러링 포트를 통해 사내망 트래픽(HTTP 80, DNS 53) 실시간 모니터링.
* 인가되지 않은 IP/MAC의 접근 또는 차단된 도메인 접속 시, **위조된 TCP RST 패킷 및 HTTP 302 Redirect(Captive Portal) 패킷을 Raw Socket으로 인젝션**하여 접속을 강제 차단.

### 2. Lock-Free 기반 초고속 해시테이블 (2-Tier Architecture)
* 10만 개 이상의 보안 룰셋을 O(1) 성능으로 검색하기 위해 **고정 방패(베이스라인)와 동적 방패(실시간 룰셋)로 분리된 2-Tier 해시 아키텍처** 적용.
* Double Buffering(A/B 스왑) 및 원자적 연산(`__atomic_store_n`)을 적용해 **락(Lock) 대기 없는 0초 컷 무중단 룰셋 갱신** 구현.

### 3. AI 기반 악성 도메인(DGA) 탐지 (Scikit-Learn)
* Random Forest 모델을 활용하여 접속 도메인의 악성 여부를 실시간으로 확률(0~100점) 판별.
* 관리자 웹 페이지에서 슬라이더 조작 시, **UDS를 통해 AI 워커 프로세스의 판단 임계치를 재부팅 없이 무중단(Zero-downtime)으로 즉각 반영**.

---

## 💡 핵심 트러블슈팅 (Troubleshooting Highlights)

### 🚨 룰 섀도잉 및 삭제 누수(Deletion Leak) 문제 해결
* **문제:** 10만 개의 초기 블랙리스트 도메인과 관리자가 실시간으로 제어하는 동적 룰셋이 하나의 해시테이블에 혼재되어 있어, 관리자가 동적 룰을 삭제할 경우 원래 존재하던 초기 고정 룰까지 영구 삭제(증발)되어 다시 AI 검사 큐로 넘어가는 심각한 아키텍처 결함 발생.
* **해결:** C 엔진 내부의 메모리 계층을 **'고정 방패(불변)'와 '동적 방패(변동)' 2-Tier로 완벽히 분리**. 패킷 검사 시 동적 방패(1순위) -> 고정 방패(2순위) 순으로 검색 우선순위를 부여하여, 수동 제어의 통제력을 유지하면서도 고정 데이터의 유실을 100% 방지함.

### 🚨 방대한 로그 조회로 인한 초기 동기화 병목 해결 (DB 정규화)
* **문제:** PCAP 엔진이 부팅될 때 과거의 AI 판정 점수를 복구하기 위해, 데이터가 방대한 `web_access_log` 테이블을 Full Scan하며 최신 로그를 찾는 비효율적 쿼리로 인해 심각한 부팅 지연 및 DB 부하 발생.
* **해결:** **로그 불변성의 원칙**에 입각하여 정책 테이블(`whitelist_addr`, `blacklist_addr`)에 `ai_score` 컬럼을 정규화하여 추가. 초기 동기화 시 로그 테이블을 뒤지지 않고 정책 테이블에서 점수를 즉시(`O(1)`) 꺼내오도록 파이프라인을 개편하여 DB 과부하를 원천 차단함.

---

##  개발 일지 및 상세 문서 

본 프로젝트의 더 자세한 개발 과정, 상세한 트러블슈팅 내역, 그리고 아키텍쳐들은 Notion 링크에서 확인하실 수 있습니다.

🔗 **[![Notion](https://img.shields.io/badge/Notion_개발_일지_및_포트폴리오_보러가기-000000?style=for-the-badge&logo=notion&logoColor=white)](https://app.notion.com/p/206597615cf6415c8859374a152ad97c?source=copy_link)**
