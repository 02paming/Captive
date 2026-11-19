#!/bin/bash
# 가상 랜선(veth) 만들기/지우기 — 실제 미러링 없이 부하 테스트, 팀원과 동시에 테스트할 때
#   sudo ./measure/veth_setup.sh up  [이름접두어]   예) up pa  → veth-pa(보내는 쪽) ↔ veth-pb(엔진이 듣는 쪽)
#   sudo ./measure/veth_setup.sh down [이름접두어]
P=${2:-pa}; A=veth-${P}; B=veth-${P%a}b
case "${1:-}" in
  up)   ip link add "$A" type veth peer name "$B" && ip link set "$A" up && ip link set "$B" up
        echo "만듦: $A(load_tester 가 보내는 쪽) ↔ $B(엔진이 캡처하는 쪽)"
        echo "예) sudo LOAD_IFACE=$A CAPTIVE_MIR_DEV=$B CAPTIVE_INJECT_DEV=$B ./measure/run_measure.sh m6" ;;
  down) ip link del "$A" && echo "지움: $A/$B" ;;
  *)    echo "사용: $0 up|down [접두어]"; exit 1 ;;
esac
