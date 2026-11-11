import socket
import sys
import time

SYNC_WAIT_SOCKET = "/tmp/sync_wait_socket"
MAX_RETRIES = 30  # 최대 30초만 대기

def main():
    print("[SYNC_RUNNER] C 엔진의 호출을 받아 가동되었습니다. Flask 연결을 시도합니다...")
    
    retries = 0
    # 무한 루프 대신 30번만 시도하도록 변경
    while retries < MAX_RETRIES:
        client = socket.socket(socket.AF_UNIX, socket.SOCK_STREAM)
        try:
            client.connect(SYNC_WAIT_SOCKET)
            print("[SYNC_RUNNER] 로컬 Flask 백엔드 감지됨! 원격(8080) 동기화를 기다립니다...")
            
            data = client.recv(1024)
            if b"SYNC_DONE" in data:
                print("[SYNC_RUNNER] 초기 동기화 완벽 완료! C 엔진 pcap_loop를 기동합니다.")
                client.close()
                sys.exit(0) # 정상 종료
                
        except (ConnectionRefusedError, FileNotFoundError):
            print("[SYNC_RUNNER] 아직 로컬 Flask가 켜지지 않았습니다. 1초 후 재시도...")
            client.close()
            time.sleep(1)
            retries += 1
        except Exception as e:
            client.close()
            print(f"[SYNC_RUNNER 예외 발생] {e}. 1초 후 재시도...")
            time.sleep(1)
            retries += 1
            
    print("[SYNC_RUNNER] Flask가 30초 동안 켜지지 않아 동기화 대기를 포기합니다.")
    sys.exit(1) # 30초 지나면 좀비가 되지 않고 스스로 종료

if __name__ == "__main__":
    main()