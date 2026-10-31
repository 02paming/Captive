import socket
import sys
import time

SYNC_WAIT_SOCKET = "/tmp/sync_wait_socket"

def main():
    print("[SYNC_RUNNER] C 엔진의 호출을 받아 가동되었습니다. Flask 연결을 시도합니다...")
    
    # 1. 무한 루프로 Flask가 켜질 때까지 버팀 (C 엔진이 먼저 켜졌을 때 뻗는 것 방어)
    while True:
        client = socket.socket(socket.AF_UNIX, socket.SOCK_STREAM)
        try:
            client.connect(SYNC_WAIT_SOCKET)
            print("[SYNC_RUNNER] 로컬 Flask 백엔드 감지됨! 원격(8080) 동기화를 기다립니다...")
            
            # 2. Flask와 연결되면 SYNC_DONE이 올 때까지 블로킹 상태로 대기
            data = client.recv(1024)
            if b"SYNC_DONE" in data:
                print("[SYNC_RUNNER] 초기 동기화 완벽 완료! C 엔진 pcap_loop를 기동합니다.")
                client.close()
                sys.exit(0) # 0으로 정상 종료되어야 C 엔진의 system()이 깔끔하게 끝남
                
        except (ConnectionRefusedError, FileNotFoundError):
            # Flask가 아직 안 켜졌다면 3초 쉬고 다시 시도 (에러 뿜지 않고 묵묵히 버팀!)
            print("[SYNC_RUNNER] 아직 로컬 Flask가 켜지지 않았습니다. 1초 후 재시도...")
            client.close()
            time.sleep(1)
        except Exception as e:
            client.close()
            print(f"[SYNC_RUNNER 예외 발생] {e}. 1초 후 재시도...")
            time.sleep(1)
        finally:
            client.close()

if __name__ == "__main__":
    main()