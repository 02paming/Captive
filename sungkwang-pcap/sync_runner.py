import sys
import os

# Captive_Web 폴더 경로를 파이썬 시스템 경로에 추가
sys.path.append("/root/Captive_Web")

# 이제 파일 이름(모듈 이름)으로만 깔끔하게 임포트 가능
from pcap_test_backup import run_initial_sync  #type: ignore

run_initial_sync()

