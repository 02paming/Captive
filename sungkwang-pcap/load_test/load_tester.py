# 노란줄을 없애기 위한 명시적(Explicit) 임포트
from scapy.layers.l2 import Ether
from scapy.layers.inet import IP, TCP, UDP
from scapy.layers.dns import DNS, DNSQR
from scapy.packet import Raw
from scapy.config import conf
import random
import threading
import time

# ---------------------------------------------------------
# 설정 (본인 환경에 맞게 인터페이스 수정)
# ---------------------------------------------------------
TARGET_IFACE = "eno2"
TEST_DURATION = 60         
POOL_SIZE = 1500       # 메모리에 미리 만들어둘 패킷의 개수 (속도 향상의 핵심)

BENIGN_DOMAINS = [
    "naver.com", "google.com", "apple.com", "kakao.com", "daum.net",
    "microsoft.com", "amazon.com", "github.com", "netflix.com", "youtube.com",
    "coupang.com", "tistory.com", "wikipedia.org", "cloudflare.com", "aws.amazon.com"
]

DGA_DOMAINS = [
    "asdfadssdffqwer.com",
    "qazwsxedcrfvtgbyhnujmikolp.com",
    "zxcvbnmasdfghjklqwerty.com",
    "lkjhgfdsaqwertyuiop.net",
    "mnbvcxzlkjhgfdsapoiuytrewq.org",
    "1a2b3c4d5e6f7g8h9i.biz",
    "xdfgjkrtuiopzxcvbnm.info",
    "plokijuhygtfrdeswaq.com",
    "vgybhnjmkpoiuytrewasdfgh.cc",
    "zaq1xsw2cde3vfr4bgt5nhy6.net"
]

print("⏳ [초고속 발사를 위한 준비] 메모리에 1,000개의 패킷을 사전 제작(Pre-crafting) 중입니다...")

# ---------------------------------------------------------
# 패킷 풀(Pool) 사전 생성 로직
# ---------------------------------------------------------
packet_pool = []

for _ in range(POOL_SIZE):
    host_id = random.randint(10, 150)
    src_ip = f"192.168.2.{host_id}"
    src_mac = f"00:11:22:33:44:{host_id:02X}"
    dst_mac = "AA:BB:CC:DD:EE:FF"
    
    proto = random.choice(["HTTP", "DNS"])
    domain = random.choice(BENIGN_DOMAINS + DGA_DOMAINS)
    
    if proto == "HTTP":
        payload = (
            f"GET / HTTP/1.1\r\n"
            f"Host: {domain}\r\n"
            f"Accept: text/html\r\n"
            f"User-Agent: LoadTester/2.0\r\n"
            f"\r\n"
        )
        pkt = Ether(src=src_mac, dst=dst_mac) / \
              IP(src=src_ip, dst="8.8.8.8") / \
              TCP(sport=random.randint(1024, 65535), dport=80, flags="PA") / \
              Raw(load=payload)
    else:
        pkt = Ether(src=src_mac, dst=dst_mac) / \
              IP(src=src_ip, dst="8.8.8.8") / \
              UDP(sport=random.randint(1024, 65535), dport=53) / \
              DNS(rd=1, qd=DNSQR(qname=domain))
              
    packet_pool.append(pkt)

print(f"✅ 패킷 장전 완료! ({POOL_SIZE}개)")

# ---------------------------------------------------------
# 초고속 발사 스레드 로직
# ---------------------------------------------------------
def traffic_generator(thread_id, stop_event):
    print(f"🚀 [Thread-{thread_id}] 트래픽 발사 시작!")
    # Scapy의 L2 전용 소켓 사용 (제일 빠름)
    s = conf.L2socket(iface=TARGET_IFACE)
    
    packet_count = 0
    pool_idx = 0
    
    # while 루프 안에서는 '생성'을 절대 하지 않고, 만들어둔 배열에서 꺼내서 '쏘기'만 함
    while not stop_event.is_set():
        s.send(packet_pool[pool_idx])
        
        packet_count += 1
        pool_idx = (pool_idx + 1) % POOL_SIZE  # 배열을 빙글빙글 돎
        
    s.close()
    print(f"🛑 [Thread-{thread_id}] 종료. 누적 발송 패킷: {packet_count:,}개")

if __name__ == "__main__":
    print(f"\n🔥 C 엔진({TARGET_IFACE}) 극한 부하 테스트를 시작합니다.")
    
    stop_event = threading.Event()
    threads = []
    
    # 4개의 스레드로 동시 폭격
    for i in range(4):
        t = threading.Thread(target=traffic_generator, args=(i, stop_event))
        t.start()
        threads.append(t)
        
    try:
        # 지정된 시간 동안 테스트 유지
        time.sleep(TEST_DURATION)
    except KeyboardInterrupt:
        print("\n사용자에 의해 테스트 강제 종료됨.")
        
    stop_event.set()
    
    for t in threads:
        t.join()
        
    print("✅ 부하 테스트가 완료되었습니다. C 엔진의 로그를 확인하세요!")