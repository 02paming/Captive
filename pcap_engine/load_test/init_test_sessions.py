import socket
import requests

#  장고(8080) 서버 주소 세팅
API_BASE_URL = "http://192.168.3.23:8080/api"
API_VERIFY_URL = f"{API_BASE_URL}/verify"
# (주의) 아래 URL은 장고 쪽에 '일반 사원 목록을 반환해 주는 API'가 있다고 가정한 주소입니다.
# 팀원분께 "is_manager=0 인 사원 100명의 사번과 이름을 JSON으로 주는 API를 만들어 달라"고 요청해야 합니다.
API_DUMMY_EMPLOYEES_URL = f"{API_BASE_URL}/get_dummy_employees" 

SOCKET_PATH = "/tmp/authrized_ip" # C 엔진 제어 소켓 경로

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

def fetch_employees_from_django(limit=100):
    """
    장고 서버(8080)에 요청하여 인증에 사용할 일반 사원 목록(사번, 이름)을 받아옵니다.
    """
    try:
        print(f"[시스템] 장고(8080) 서버에 더미 사원 {limit}명 정보 요청 중...")
        # 파라미터로 몇 명을 가져올지 넘겨줍니다 (장고 쪽에 구현 필요)
        res = requests.get(f"{API_DUMMY_EMPLOYEES_URL}?limit={limit}", timeout=5)
        
        if res.status_code == 200:
            # 예시 응답 포맷: {"data": [{"emp_number": 285, "name": "강서준"}, ...]}
            data = res.json().get("data", [])
            print(f"[시스템] 사원 정보 {len(data)}명 수신 완료!")
            return data
        else:
            print(f"[오류] 장고 서버 응답 에러: {res.status_code} - {res.text}")
            return None
    except Exception as e:
        print(f"[통신 오류] 장고 서버와 연결할 수 없습니다: {e}")
        return None

def run_bulk_auth(start_ip=10, limit=100):
    print(f"=== 192.168.2.{start_ip} 대역 더미 사원 연동 일괄 인증 시작 ===")
    
    # 1단계: 장고(8080) API를 찔러서 DB에 있는 사원 100명의 사번과 이름을 받아옵니다.
    employees = fetch_employees_from_django(limit)
    if not employees:
        print("[실패] 사원 정보를 불러오지 못해 인증을 취소합니다.")
        return

    success_count = 0
    
    # 2단계: 받아온 정보로 /api/verify 인증 요청 및 C 엔진 등록
    for idx, emp in enumerate(employees):
        host_id = start_ip + idx
        client_ip = f"192.168.2.{host_id}"
        client_mac = f"00:11:22:33:44:{host_id:02X}"
        
        emp_number = emp.get('emp_number')
        emp_name = emp.get('name')
        
        payload = {
            "emp_name": emp_name,
            "emp_number": str(emp_number),
            "user_online_ip": str(host_id), 
            "user_online_mac": client_mac
        }
        
        try:
            res = requests.post(API_VERIFY_URL, json=payload, timeout=3)
            
            if res.status_code == 200 and res.json().get("is_valid") == True:
                if send_uds_auth(host_id, client_mac):
                    success_count += 1
                    print(f"[성공] IP: {client_ip:<15} | 사번: {emp_number:<5} | 이름: {emp_name}")
                else:
                    print(f"[C엔진 반영 실패] IP: {client_ip}")
            else:
                print(f"[검증 거절] IP: {client_ip} | 사번: {emp_number} | 이름: {emp_name} - 응답: {res.text}")
                
        except Exception as e:
            print(f"[통신 에러] IP: {client_ip} - {e}")

    print(f"=== 일괄 인증 완료 (성공: {success_count}/{len(employees)}건) ===")

if __name__ == "__main__":
    run_bulk_auth(start_ip=10, limit=100)