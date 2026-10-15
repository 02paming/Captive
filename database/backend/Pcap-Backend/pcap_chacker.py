import os
import sys
import socket
import json
import urllib.request
from datetime import datetime
from urllib.parse import parse_qs
import django

# 1. Django 환경 설정 및 MariaDB 10.3 버전 체크 우회
os.environ.setdefault('DJANGO_SETTINGS_MODULE', 'backend_pcap_test.settings')
from django.db.backends.base.base import BaseDatabaseWrapper
BaseDatabaseWrapper.check_database_version_supported = lambda self: None
django.setup()

from django.db import transaction, connection, close_old_connections
from packet_test_app.models import Employees, OnlineList

# 허용할 IP 목록
ALLOWED_IPS = ['192.168.3.243', '127.0.0.1']
HOST = '0.0.0.0'
PORT = 8080

# =========================================================
# [설정] 연동 변수명 및 PCAP 서버 주소 (변경 완료)
# =========================================================
KEY_EMP_NAME = 'emp_name'       # [___사원이름_변수명___]
KEY_EMP_NUM = 'emp_number'      # [___사원번호_변수명___]
KEY_CLIENT_IP = 'user_online_list'   # [___접속PC_IP_변수명___] (기존 user_online_ip -> user_online_list)
KEY_CLIENT_MAC = 'user_mac_addr'  # [추가] 접속PC MAC 주소
PCAP_SERVER_SYNC_URL = "http://192.168.3.243/api/update_domains"

def parse_request_body(body_str):
    body_str = body_str.strip()
    data = {}
    if not body_str:
        return data

    if body_str.startswith('{'):
        try:
            data = json.loads(body_str)
        except json.JSONDecodeError:
            pass
    elif '=' in body_str:
        parsed_qs = parse_qs(body_str)
        data = {k: v[0] for k, v in parsed_qs.items()}
    elif ',' in body_str:
        parts = [p.strip() for p in body_str.split(',')]
        if len(parts) >= 2:
            data[KEY_EMP_NUM] = parts[0]
            data[KEY_EMP_NAME] = parts[1]
        if len(parts) >= 3:
            data[KEY_CLIENT_IP] = parts[2]
        if len(parts) >= 4:
            data[KEY_CLIENT_MAC] = parts[3] # [추가] 4번째 인자로 MAC 주소가 들어올 경우
    return data

def create_http_response(status_code, body_dict):
    status_text = "200 OK" if status_code == 200 else "400 Bad Request"
    if status_code == 403:
        status_text = "403 Forbidden"
    body_json = json.dumps(body_dict, ensure_ascii=False)
    response = (
        f"HTTP/1.1 {status_text}\r\n"
        f"Content-Type: application/json; charset=utf-8\r\n"
        f"Content-Length: {len(body_json.encode('utf-8'))}\r\n"
        f"Connection: close\r\n"
        f"\r\n"
        f"{body_json}"
    )
    return response.encode('utf-8')

def run_server():
    server_socket = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    server_socket.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
    server_socket.bind((HOST, PORT))
    server_socket.listen(5)

    print(f"=========================================================")
    print(f" [PCAP 인증 및 동기화 서버 구동] 포트: {PORT}")
    print(f" - 로그인/인증 경로: POST /api/verify")
    print(f" - 로그아웃 경로   : POST /api/logout")
    print(f" - 도메인 동기화   : POST /api/sync_domains")
    print(f"=========================================================")

    while True:
        client_sock, addr = server_socket.accept()
        client_ip = addr[0]

        if client_ip not in ALLOWED_IPS:
            client_sock.sendall(create_http_response(403, {"error": "Forbidden IP"}))
            client_sock.close()
            continue

        try:
            close_old_connections()
            raw_data = client_sock.recv(4096).decode('utf-8', errors='ignore')
            if not raw_data:
                client_sock.close()
                continue

            header_part, _, body_str = raw_data.partition('\r\n\r\n')
            request_line = header_part.splitlines()[0] if header_part else ""
            parts = request_line.split(' ')
            path = parts[1] if len(parts) > 1 else "/api/verify"
            parsed = parse_request_body(body_str)

            # ---------------------------------------------------------
            # 1. 도메인 동기화 처리 (/api/sync_domains)
            # ---------------------------------------------------------
            if path.startswith('/api/sync_domains'):
                with connection.cursor() as cursor:
                    cursor.execute("SELECT blacklist_domain FROM blacklist_addr WHERE deleted_at IS NULL")
                    active_domains = cursor.fetchall()
                
                domain_list = [{"domain": row[0]} for row in active_domains]
                payload = json.dumps({"active_domains": domain_list}).encode('utf-8')
                
                try:
                    req = urllib.request.Request(
                        PCAP_SERVER_SYNC_URL, 
                        data=payload, 
                        headers={'Content-Type': 'application/json'}
                    )
                    urllib.request.urlopen(req, timeout=3)
                    print(f"   [도메인 동기화 완료]: 총 {len(domain_list)}개의 활성 도메인 전송")
                    res = {"is_sync_success": True, "count": len(domain_list)}
                except Exception as e:
                    print(f"   [도메인 동기화 실패]: PCAP 서버 접속 에러 ({e})")
                    res = {"is_sync_success": False, "error": str(e)}

                client_sock.sendall(create_http_response(200, res))
                continue

            # ---------------------------------------------------------
            # 2. 내부망 로그아웃 처리 (/api/logout)
            # ---------------------------------------------------------
            raw_name = parsed.get(KEY_EMP_NAME) or parsed.get('name')
            raw_num = parsed.get(KEY_EMP_NUM) or parsed.get('employee_number')
            user_online_list = parsed.get(KEY_CLIENT_IP)
            user_mac_addr = parsed.get(KEY_CLIENT_MAC) # [추가] MAC 주소 파싱

            if path.startswith('/api/logout'):
                if not user_online_list:
                    res = {"is_logout": False, "message": "IP 정보가 제공되지 않았습니다."}
                else:
                    target_online_list = int(user_online_list)
                    
                    # [수정] MAC 주소가 함께 전송되었을 경우 조건에 포함
                    if user_mac_addr:
                        deleted_cnt, _ = OnlineList.objects.filter(online_ip=target_online_list, online_mac_addr=user_mac_addr).delete()
                    else:
                        deleted_cnt, _ = OnlineList.objects.filter(online_ip=target_online_list).delete()
                    
                    print(f"[내부망 로그아웃/만료 완료]: IP({target_online_list}) 세션 제거됨 (삭제된 행: {deleted_cnt})")
                    res = {"is_logout": True, "deleted_count": deleted_cnt}
                    
                client_sock.sendall(create_http_response(200, res))
                continue

            # ---------------------------------------------------------
            # 3. 내부망 로그인 검증 및 중복 차단 (/api/verify)
            # ---------------------------------------------------------
            emp_name = str(raw_name).strip() if raw_name else ""
            emp_num = int(raw_num) if raw_num is not None else -1
            user_online_list = int(str(user_online_list).strip())
            # [추가] MAC 주소가 없을 경우 기본값 할당
            user_mac_addr = str(user_mac_addr).strip() if user_mac_addr else "UNKNOWN" 

            print(f"   [요청 정보]: 사번={emp_num}, 이름='{emp_name}', 접속IP='{user_online_list}', MAC='{user_mac_addr}'")

            is_already_online = OnlineList.objects.filter(employee_id=emp_num).exists()

            if is_already_online:
                print(f"   [중복 접속 차단]: 사번 {emp_num} ('{emp_name}') 사원은 이미 로그인 중입니다.")
                result_data = {"is_valid": False}
            else:
                emp_exists = Employees.objects.filter(
                    employee_number=emp_num,
                    name=emp_name,
                    deleted_at__isnull=True
                ).exists()

                if emp_exists:
                    now_time = datetime.now()
                    with transaction.atomic():
                        # [수정] 생성 시 online_mac_addr 파라미터 추가
                        OnlineList.objects.create(employee_id=emp_num, online_ip=user_online_list, login_time=now_time, online_mac_addr=user_mac_addr)
                        with connection.cursor() as cursor:
                            # [수정] INSERT 쿼리에 online_mac_addr 추가
                            cursor.execute(
                                "INSERT INTO online_list_log (employee_id, online_ip, login_time, online_mac_addr) VALUES (%s, %s, %s, %s)",
                                [emp_num, user_online_list, now_time, user_mac_addr]
                            )
                    print(f"   [로그인 성공]: 사번 {emp_num} ('{emp_name}') 접속 및 로그 기록 완료")
                    result_data = {"is_valid": True}
                    
                else:
                    print(f"   [검증 실패]: 이름과 사번이 일치하는 현직 사원이 아닙니다.")
                    result_data = {"is_valid": False}

            client_sock.sendall(create_http_response(200, result_data))

        except Exception as e:
            print(f"[에러 발생]: {e}")
            client_sock.sendall(create_http_response(200, {"is_valid": False}))
        finally:
            client_sock.close()

if __name__ == '__main__':
    run_server()