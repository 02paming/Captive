import socket
import requests

# 본인 환경에 맞게 URL과 소켓 경로를 확인하세요
API_SERVER_URL = "http://192.168.3.23:8080/api/verify"
SOCKET_PATH = "/tmp/authrized_ip" # C 엔진 소켓 경로 (오타 그대로 유지)

def send_uds_auth(host_id, mac_addr):
    client_socket = socket.socket(socket.AF_UNIX, socket.SOCK_STREAM)
    try:
        client_socket.connect(SOCKET_PATH)
        # C 엔진에 인증 정보(IP 55번, 정상 MAC) 등록
        message = f"AUTH {host_id} {mac_addr}\n"
        client_socket.sendall(message.encode("utf-8"))
        return True
    except Exception as e:
        print(f"[UDS 에러] Host ID {host_id} 전송 실패: {e}")
        return False
    finally:
        client_socket.close()

if __name__ == "__main__":
    host_id = 55
    client_ip = f"192.168.2.{host_id}"
    
    # [중요] 이 MAC 주소가 "정상(진짜)" MAC 주소로 등록됩니다.
    normal_mac = "0A:0A:0A:AA:AA:AA"
    
    # DB 연동을 위한 더미 사원 정보
    payload = {
        "emp_name": f"더미사원{host_id}",
        "emp_number": host_id,
        "user_online_ip": host_id,
        "user_online_mac": normal_mac
    }
    
    print(f"=== {client_ip} 단일 인증(정상 MAC 등록) 시작 ===")
    
    try:
        # 1단계: DB 갱신
        res = requests.post(API_SERVER_URL, json=payload, timeout=3)
        
        if res.status_code == 200 and res.json().get("is_valid") == True:
            # 2단계: C 엔진 메모리에 AUTH 등록
            if send_uds_auth(host_id, normal_mac):
                print(f"[인증 완료] IP: {client_ip} / 등록된 정상 MAC: {normal_mac}")
                print("이제 이 IP로 다른 MAC 주소(예: 00:11:22:33:44:55)를 달고 패킷을 쏘면 스푸핑으로 차단됩니다!")
            else:
                print(f"[C엔진 반영 실패] UDS 소켓({SOCKET_PATH})을 확인하세요.")
        else:
            print(f"[검증 거절] DB에 '더미사원{host_id}' 가 존재하지 않거나, 사원 상태가 정상이 아닙니다.")
            
    except Exception as e:
        print(f"[통신 에러] API 서버 연결 실패: {e}")