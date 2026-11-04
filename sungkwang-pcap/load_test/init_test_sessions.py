
import socket
import requests

API_SERVER_URL = "http://192.168.3.23:8080/api/verify"
SOCKET_PATH = "/tmp/authrized_ip" # C 엔진 소켓 경로 (h 오타 주의)

def send_uds_auth(host_id, mac_addr):
    client_socket = socket.socket(socket.AF_UNIX, socket.SOCK_STREAM)
    try:
        client_socket.connect(SOCKET_PATH)
        message = f"AUTH {host_id} {mac_addr}\n"
        client_socket.sendall(message.encode("utf-8"))
        return True
    except Exception as e:
        print(f"[UDS 에러] Host ID {host_id} 전송 실패: {e}")
        return False
    finally:
        client_socket.close()

def run_bulk_auth(start_ip=10, end_ip=150):
    print(f"=== 192.168.2.{start_ip} ~ {end_ip} 더미 사원 연동 일괄 인증 시작 ===")
    
    success_count = 0
    for host_id in range(start_ip, end_ip + 1):
        client_ip = f"192.168.2.{host_id}"
        client_mac = f"00:11:22:33:44:{host_id:02X}"
        
        # '사원 더미데이터.txt'에 있는 형식과 일치시킴 (예: 더미사원10, 사번 10)
        payload = {
            "emp_name": f"더미사원{host_id}",
            "emp_number": host_id,
            "user_online_ip": host_id,
            "user_online_mac": client_mac
        }
        
        try:
            # 1단계: 다른 PC의 DB 서버에 /api/verify 요청 (단, DB의 Employees에 이 사원들이 미리 들어있어야 함!)
            res = requests.post(API_SERVER_URL, json=payload, timeout=3)
            
            if res.status_code == 200 and res.json().get("is_valid") == True:
                # 2단계: 검증 성공 시 C 엔진 메모리에도 AUTH 등록
                if send_uds_auth(host_id, client_mac):
                    success_count += 1
                    print(f"[인증 동기화 성공] IP: {client_ip} (더미사원{host_id})")
                else:
                    print(f"[C엔진 반영 실패] IP: {client_ip}")
            else:
                print(f"[검증 거절] IP: {client_ip} - DB에 '더미사원{host_id}' (사번 {host_id})가 존재하지 않습니다.")
                
        except Exception as e:
            print(f"[통신 에러] IP: {client_ip} - {e}")

    print(f"=== 일괄 인증 완료 (성공: {success_count}건) ===")

if __name__ == "__main__":
    run_bulk_auth(start_ip=10, end_ip=150)