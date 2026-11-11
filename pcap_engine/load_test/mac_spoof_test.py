from scapy.layers.l2 import Ether
from scapy.layers.inet import IP, TCP
from scapy.packet import Raw
from scapy.config import conf

# ==============================================================
# 1. 설정 (본인의 환경에 맞게 인터페이스를 꼭 수정하세요!)
# ==============================================================
# C 엔진이 패킷을 캡처하고 있는 네트워크 인터페이스 이름 (예: eno2, eth0, ens33 등)
TARGET_IFACE = "eno2" 

# ==============================================================
# 2. 패킷 조작 (MAC 주소 불일치 상황 연출)
# ==============================================================
# - 출발지 IP: 질문자님이 요청하신 특정 IP
src_ip = "192.168.2.55"

# - 출발지 MAC: 일부러 틀린(스푸핑된) MAC 주소를 넣습니다. 
#   (만약 192.168.2.55의 진짜 MAC이 이게 아니라면, C 엔진에서 99번 에러가 떠야 정상입니다.)
spoofed_mac = "00:11:22:33:44:55" 

# - 목적지 MAC: 게이트웨이(라우터)의 MAC 주소를 넣는 것이 좋지만, 
#   스위치를 통과하는 단순 브로드캐스트/멀티캐스트 핑거프린팅 테스트라면 가상의 값을 넣어도 패킷은 나갑니다.
dst_mac = "AA:BB:CC:DD:EE:FF"

# ==============================================================
# 3. HTTP GET 패킷 조립
# ==============================================================
print(f"[테스트 준비] {TARGET_IFACE} 인터페이스를 통해 패킷을 전송합니다.")
print(f" - 조작된 IP : {src_ip}")
print(f" - 조작된 MAC : {spoofed_mac}")

# HTTP 페이로드 (C 엔진의 GET 파싱 로직을 통과하기 위해 규격을 맞춥니다)
payload = (
    "GET / HTTP/1.1\r\n"
    "Host: test-spoofing.com\r\n"
    "Accept: text/html\r\n"
    "User-Agent: Scapy-Test\r\n"
    "\r\n"
)

# 계층별(L2 -> L3 -> L4 -> Payload) 패킷 조립
pkt = Ether(src=spoofed_mac, dst=dst_mac) / \
      IP(src=src_ip, dst="8.8.8.8") / \
      TCP(sport=12345, dport=80, flags="PA") / \
      Raw(load=payload)

# ==============================================================
# 4. 발사!
# ==============================================================
# L2socket을 이용해 이더넷 계층부터 통째로 밀어넣습니다.
s = conf.L2socket(iface=TARGET_IFACE)
s.send(pkt)
s.close()

print("\n✅ 단건 패킷 전송이 완료되었습니다!")
print("C 엔진 화면(printf)과 Django 대시보드에서 MAC_Address_Error(99번) 로그가 찍혔는지 확인하세요.")