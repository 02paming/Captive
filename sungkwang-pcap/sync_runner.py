import sys
import os


sys.path.append("pcap_webServer")

# 이제 파일 이름(모듈 이름)으로만 깔끔하게 임포트 가능
from pcap_test_backup import run_initial_sync  #type: ignore

run_initial_sync()

