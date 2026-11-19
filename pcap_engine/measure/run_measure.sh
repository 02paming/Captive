#!/bin/bash
# =====================================================================
# run_measure.sh — 서류에 쓸 수치(M1~M7)를 한 번에 측정해 results/<시각>/ 에 모음
#
# 사용 (pcap_engine 폴더에서, root 권한 필요: 패킷 캡처·주입):
#   sudo ./measure/run_measure.sh all          # 전부
#   sudo ./measure/run_measure.sh bench        # M1·M2 만 (서버 필요 없음, 언제든 가능)
#   sudo ./measure/run_measure.sh m3 m4 m6 m7  # 골라서
#
# 환경변수 (필요한 것만):
#   DOMAINS=domains.txt                 M3 입력 (DB에서 뽑은 도메인 목록, 한 줄에 하나)
#   BACKEND=http://192.168.3.23:8080    M4 대상 백엔드
#   HOST_ID=10                          M4 에서 쓸 인증된 호스트 번호
#   LOAD_IFACE=eno2                     load_tester 가 패킷을 보낼 NIC (veth 테스트 시 veth 한쪽)
#   CAPTIVE_MIR_DEV / CAPTIVE_INJECT_DEV 엔진 캡처·주입 NIC (기본 eno2 / eno4)
#   LOAD_SECONDS=60  VG_SECONDS=30  RUNS=3
#   AUTH_DIRECT=1                       init_test_sessions.py(Django 필요) 대신 엔진 UDS 로 직접 AUTH (veth 단독 테스트용)
#
# M6·M7 전제: AI 서버(ai_uds_server.py)와 pcap_proxy.py 가 떠 있어야 실제 경로 그대로 측정됨
# =====================================================================
set -u
cd "$(dirname "$0")/.." || exit 1
ROOT=$(pwd); ENG_DIR=$ROOT/pcap_c_server; LT=$ROOT/load_test
OUT=$ROOT/measure/results/$(date +%Y%m%d_%H%M%S); mkdir -p "$OUT"
RUNS=${RUNS:-3}; LOAD_SECONDS=${LOAD_SECONDS:-60}; VG_SECONDS=${VG_SECONDS:-30}
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
    python3 "$ROOT/measure/m3_regex_replay.py" --domains "$DOMAINS" --ai-dir "$ROOT/AI_machine_learning" \
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
engine_run() {  # $1=이름 $2=부하초 $3=valgrind(0/1)
  local name=$1 secs=$2 vg=$3 elog="$OUT/$1_engine.log"
  [ -S /tmp/ai_dga_socket.sock ] || log "  ⚠ AI 서버 소켓 없음 — ai_uds_server.py 를 먼저 띄우세요"
  [ -S /tmp/pcap_gc.sock ] || log "  ⚠ pcap_proxy 소켓 없음 — pcap_proxy.py 를 먼저 띄우세요"
  if [ "$vg" = 1 ]; then
    (cd "$ENG_DIR" && exec valgrind --leak-check=full --show-leak-kinds=all --log-file="$OUT/$name.valgrind.txt" ./bin/my_pcap_app) > "$elog" 2>&1 &
    sleep 15
  else
    (cd "$ENG_DIR" && exec ./bin/my_pcap_app) > "$elog" 2>&1 &
    sleep 4
  fi
  auth_hosts >> "$OUT/run.log" 2>&1; sleep 1
  (cd "$LT" && TARGET_IFACE="${LOAD_IFACE:-eno2}" TEST_DURATION=$secs python3 load_tester.py) > "$OUT/${name}_load.log" 2>&1
  sleep 3; pkill -INT -x my_pcap_app; pkill -INT -f "valgrind.*my_pcap_app"
  for _ in $(seq 1 60); do pgrep -x my_pcap_app >/dev/null || pgrep -f "valgrind.*my_pcap_app" >/dev/null || break; sleep 1; done
  pkill -9 -x my_pcap_app 2>/dev/null
  { echo "## $name"; echo; echo '```'; grep "누적 발송" "$OUT/${name}_load.log"; sed -n '/\[측정\] 스트레스 테스트 결과/,/^=*$/p' "$elog" | grep -v "퇴근"; echo '```'; } >> "$OUT/m6_summary.md"
}

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
