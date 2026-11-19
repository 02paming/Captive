#!/bin/bash
# =====================================================================
# run_measure.sh — 서류에 쓸 수치(M1~M7)를 한 번에 측정해 results/<시각>/ 에 모음
#
# 사용 (pcap_engine 폴더에서, 일반 계정으로 실행 — 스크립트 전체를 sudo 로 돌리지 않음):
#   ./measure/run_measure.sh bench m3 m4     # root 권한 필요 없음
#   ./measure/run_measure.sh m6 m7           # 엔진·valgrind·load_tester·종료 신호만 내부에서 sudo 로 실행
#   ./measure/run_measure.sh all
# sudo 가 필요한 명령 (sudoers 에 허용돼 있어야 함 — measure/README.md 참고):
#   <엔진 절대경로>/bin/my_pcap_app, valgrind, <LOAD_PY> load_tester.py, pkill
#
# 환경변수 (필요한 것만):
#   DOMAINS=domains.txt                 M3 입력 (DB에서 뽑은 도메인 목록, 한 줄에 하나)
#   BACKEND=http://192.168.3.23:8080    M4 대상 백엔드
#   HOST_ID=10                          M4 에서 쓸 인증된 호스트 번호
#   LOAD_IFACE=eno2                     load_tester 가 패킷을 보낼 NIC (veth 테스트 시 veth 한쪽)
#   CAPTIVE_MIR_DEV / CAPTIVE_INJECT_DEV 엔진 캡처·주입 NIC (기본 eno2 / eno4)
#   LOAD_SECONDS=60  VG_SECONDS=30  RUNS=3
#   LOAD_PY=python3                     load_tester.py 를 돌릴 파이썬 (scapy 가 깔린 venv 의 python 경로 권장)
#   M3_PY=python3                       m3 를 돌릴 파이썬 (joblib·scikit-learn 이 깔린 AI 서버 venv 의 python 권장)
#   AUTH_DIRECT=1                       init_test_sessions.py(Django 필요) 대신 엔진 UDS 로 직접 AUTH (veth 단독 테스트용)
#
# M6·M7 전제: AI 서버(ai_uds_server.py)와 pcap_proxy.py 가 떠 있어야 실제 경로 그대로 측정됨
# =====================================================================
set -u
cd "$(dirname "$0")/.." || exit 1
ROOT=$(pwd); ENG_DIR=$ROOT/pcap_c_server; LT=$ROOT/load_test
OUT=$ROOT/measure/results/$(date +%Y%m%d_%H%M%S); mkdir -p "$OUT"
RUNS=${RUNS:-3}; LOAD_SECONDS=${LOAD_SECONDS:-60}; VG_SECONDS=${VG_SECONDS:-30}
SUDO=sudo; [ "$(id -u)" = 0 ] && SUDO=""   # root 로 실행하면 sudo 생략
# sudoers 는 '절대경로'로 명령을 비교하므로 파이썬 경로를 절대경로로 고정
LOAD_PY=$(command -v "${LOAD_PY:-python3}"); M3_PY=$(command -v "${M3_PY:-python3}")
ENG_BIN="$ENG_DIR/bin/my_pcap_app"
STEPS=("$@"); [ ${#STEPS[@]} -eq 0 ] && STEPS=(all)
want() { for s in "${STEPS[@]}"; do [ "$s" = all ] || [ "$s" = "$1" ] && return 0; done; return 1; }
log() { echo "[$(date +%H:%M:%S)] $*" | tee -a "$OUT/run.log"; }

log "결과 폴더: $OUT"
{
  echo "# 측정 환경"; date; uname -a; lscpu 2>/dev/null | grep -E "Model name|^CPU\(s\)"; gcc --version | head -1
  echo; echo "# 고정 리스트 줄 수"; wc -l /tmp/ai_blacklist.txt /tmp/ai_whitelist.txt 2>&1
  echo; echo "# git"; git -C "$ROOT" log --oneline -1; git -C "$ROOT" branch --show-current
} > "$OUT/00_env.txt" 2>&1

# ---------- M1·M2 해시 벤치마크 ----------
if want bench; then
  log "M1·M2: make bench"; make -C "$ENG_DIR" bench >> "$OUT/run.log" 2>&1 || { log "벤치 빌드 실패"; exit 1; }
  for i in $(seq 1 "$RUNS"); do
    for n in 10000 100000; do log "  bench -n $n ($i/$RUNS)"; "$ENG_DIR/bin/hash_bench" -n $n > "$OUT/m1m2_n${n}_$i.md"; done
    if [ -s /tmp/ai_blacklist.txt ]; then log "  bench -f /tmp/ai_blacklist.txt ($i/$RUNS)"; "$ENG_DIR/bin/hash_bench" -f /tmp/ai_blacklist.txt > "$OUT/m1m2_real_$i.md"; fi
  done
fi

# ---------- M3 정규식 재생 ----------
if want m3; then
  if [ -n "${DOMAINS:-}" ] && [ -s "$DOMAINS" ]; then
    log "M3: $DOMAINS"
    "$M3_PY" "$ROOT/measure/m3_regex_replay.py" --domains "$DOMAINS" --ai-dir "$ROOT/AI_machine_learning" \
      --fixed-black /tmp/ai_blacklist.txt --fixed-white /tmp/ai_whitelist.txt > "$OUT/m3.md" 2>> "$OUT/run.log"
  else log "M3 건너뜀: DOMAINS=도메인목록파일 을 지정하세요 (measure/README 참고)"; fi
fi

# ---------- M4 묶음 전송 ----------
if want m4; then
  log "M4: ${BACKEND:-http://192.168.3.23:8080} host=${HOST_ID:-10}"
  python3 "$ROOT/measure/m4_batch_bench.py" --base "${BACKEND:-http://192.168.3.23:8080}" --n 1000 --host "${HOST_ID:-10}" > "$OUT/m4.md" 2>> "$OUT/run.log" \
    || log "M4 실패: 백엔드(8080)가 떠 있고 인증 세션이 있는지 확인"
fi

# ---------- 공통: 엔진 1회 실행 + 부하 ----------
auth_hosts() {
  if [ "${AUTH_DIRECT:-0}" = 1 ]; then
    python3 - <<'PY'
import socket
for h in range(10, 151):
    s = socket.socket(socket.AF_UNIX, socket.SOCK_STREAM); s.connect("/tmp/authrized_ip")
    s.sendall(f"AUTH {h} 00:11:22:33:44:{h:02X}\n".encode()); s.close()
print("AUTH 직접 전송 141건")
PY
  else (cd "$LT" && python3 init_test_sessions.py); fi
}
# 엔진 NIC 변경(CAPTIVE_MIR_DEV / CAPTIVE_INJECT_DEV)은 환경변수로 전달.
# sudo 는 기본적으로 환경변수를 지우므로, veth 테스트 때는 sudoers 에 아래 한 줄이 필요 (measure/README.md '권한' 절):
#   Defaults:captive env_keep += "CAPTIVE_MIR_DEV CAPTIVE_INJECT_DEV"
export CAPTIVE_MIR_DEV CAPTIVE_INJECT_DEV 2>/dev/null
engine_run() {  # $1=이름 $2=부하초 $3=valgrind(0/1)
  local name=$1 secs=$2 vg=$3 elog="$OUT/$1_engine.log"
  [ -S /tmp/ai_dga_socket.sock ] || log "  ⚠ AI 서버 소켓 없음 — ai_uds_server.py 를 먼저 띄우세요"
  [ -S /tmp/pcap_gc.sock ] || log "  ⚠ pcap_proxy 소켓 없음 — pcap_proxy.py 를 먼저 띄우세요"
  if [ "$vg" = 1 ]; then
    (cd "$ENG_DIR" && exec $SUDO valgrind --leak-check=full --show-leak-kinds=all --log-file=/tmp/captive_valgrind.txt "$ENG_BIN") > "$elog" 2>&1 &
    sleep 15
  else
    (cd "$ENG_DIR" && exec $SUDO "$ENG_BIN") > "$elog" 2>&1 &
    sleep 4
  fi
  auth_hosts >> "$OUT/run.log" 2>&1; sleep 1
  (cd "$LT" && $SUDO "$LOAD_PY" "$LT/load_tester.py" "${LOAD_IFACE:-eno2}" "$secs") > "$OUT/${name}_load.log" 2>&1
  sleep 3; $SUDO pkill -INT -x my_pcap_app; $SUDO pkill -INT -f "valgrind.*my_pcap_app"
  for _ in $(seq 1 60); do pgrep -x my_pcap_app >/dev/null || pgrep -f "valgrind.*my_pcap_app" >/dev/null || break; sleep 1; done
  $SUDO pkill -9 -x my_pcap_app 2>/dev/null
  [ "$vg" = 1 ] && cp /tmp/captive_valgrind.txt "$OUT/$name.valgrind.txt" 2>/dev/null
  { echo "## $name"; echo; echo '```'; grep "누적 발송" "$OUT/${name}_load.log"; sed -n '/\[측정\] 스트레스 테스트 결과/,/^=*$/p' "$elog" | grep -v "퇴근"; echo '```'; } >> "$OUT/m6_summary.md"
}

if want m6 || want m7; then
  log "load_tester 파이썬: $LOAD_PY  /  엔진: $ENG_BIN  (sudoers 에 이 절대경로가 있어야 함)"
  if [ -n "$SUDO" ]; then log "sudo 권한 확인 (비밀번호를 물으면 입력)"; sudo -v 2>/dev/null || log "  (sudo -v 실패 — 명령별 NOPASSWD 로 허용돼 있으면 그대로 진행됩니다. 막히면 measure/README.md '권한' 절 참고)"; fi
fi
if want m6; then
  log "M6: make (엔진)"; make -C "$ENG_DIR" >> "$OUT/run.log" 2>&1 || { log "엔진 빌드 실패"; exit 1; }
  for i in $(seq 1 "$RUNS"); do log "  M6 부하 ${LOAD_SECONDS}초 ($i/$RUNS)"; engine_run "m6_run$i" "$LOAD_SECONDS" 0; done
fi

if want m7; then
  command -v valgrind >/dev/null || { log "valgrind 미설치"; exit 1; }
  make -C "$ENG_DIR" >> "$OUT/run.log" 2>&1
  log "M7: Valgrind + 부하 ${VG_SECONDS}초"; engine_run "m7_valgrind" "$VG_SECONDS" 1
  grep -E "HEAP SUMMARY|in use at exit|total heap usage|definitely|indirectly|possibly|still reachable|ERROR SUMMARY" "$OUT/m7_valgrind.valgrind.txt" > "$OUT/m7_summary.txt" 2>/dev/null
fi

log "끝. 이 폴더를 통째로 Claude 에게 보내 주세요: $OUT"
