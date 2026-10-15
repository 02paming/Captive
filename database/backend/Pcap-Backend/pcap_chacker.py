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
# [설정] 연동 변수명 및 PCAP 서버 주소
# =========================================================
KEY_EMP_NAME = 'emp_name'       # [___사원이름_변수명___]
KEY_EMP_NUM = 'emp_number'      # [___사원번호_변수명___]
KEY_CLIENT_IP = 'user_online_ip'     # [___접속PC_IP_변수명___]
KEY_CLIENT_MAC = 'user_online_mac'   # [___접속PC_MAC_변수명___]
KEY_BLACKLIST_DOMAIN = 'blacklist_domain' # [추가] 차단된 도메인 변수명
PCAP_SERVER_SYNC_URL = "http://192.168.3.243/api/update_domains"

# =========================================================
# [추가] 웹 서버(Django) 새로고침 요청 URL (블랙리스트 로그용)
# =========================================================
# 실제 구축한 웹 서버 API 경로로 변경
WEB_SERVER_BLACKLIST_REFRESH_URL = "http://127.0.0.1:8000/api/refresh_blacklist_log" 

def trigger_blacklist_refresh():
    """블랙리스트 로그가 DB에 추가될 때 웹 서버로 알림(HTTP GET)을 보내는 함수"""
    try:
        req = urllib.request.Request(WEB_SERVER_BLACKLIST_REFRESH_URL, method="GET")
        urllib.request.urlopen(req, timeout=2)
        print("   [웹 서버 알림]: 블랙리스트 접근 로그 갱신 요청 전송 완료")
    except Exception as e:
        print(f"   [웹 서버 알림 실패]: {e}")

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
            data[KEY_CLIENT_MAC] = parts[3]
        if len(parts) >= 5:
            data[KEY_BLACKLIST_DOMAIN] = parts[4] # [추가] 5번째 인자로 도메인이 들어올 경우
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
    print(f" - 활성 세션 조회  : GET  /api/active_sessions")
    print(f" - 블랙리스트 로그 : POST /api/blacklist_log")
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

            method = parts[0] if len(parts) > 0 else "GET"
            path = parts[1] if len(parts) > 1 else "/api/verify"
            parsed = parse_request_body(body_str)

            # 파싱 데이터 준비
            raw_name = parsed.get(KEY_EMP_NAME) or parsed.get('name')
            raw_num = parsed.get(KEY_EMP_NUM) or parsed.get('employee_number')
            user_online_ip = parsed.get(KEY_CLIENT_IP)
            user_online_mac = parsed.get(KEY_CLIENT_MAC, "00:00:00:00:00:00")
            blacklist_domain = parsed.get(KEY_BLACKLIST_DOMAIN) or parsed.get('domain')

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
            if path.startswith('/api/logout'):
                if not user_online_ip:
                    res = {"is_logout": False, "message": "IP 정보가 제공되지 않았습니다."}
                else:
                    target_online_ip = int(user_online_ip)
                    
                    if user_online_mac and user_online_mac != "00:00:00:00:00:00":
                        deleted_cnt, _ = OnlineList.objects.filter(online_ip=target_online_ip, online_mac_addr=user_online_mac).delete()
                    else:
                        deleted_cnt, _ = OnlineList.objects.filter(online_ip=target_online_ip).delete()
                    
                    print(f"[내부망 로그아웃/만료 완료]: IP({target_online_ip}) 세션 제거됨 (삭제된 행: {deleted_cnt})")
                    res = {"is_logout": True, "deleted_count": deleted_cnt}
                    
                client_sock.sendall(create_http_response(200, res))
                continue

            # ---------------------------------------------------------
            # 3. 내부망 로그인 검증 및 중복 차단 (/api/verify)
            # ---------------------------------------------------------
            if path.startswith("/api/verify"):
                emp_name = str(raw_name).strip() if raw_name else ""
                emp_num = int(raw_num) if raw_num is not None else -1
                user_online_ip = int(str(user_online_ip).strip())
                user_online_mac = str(user_online_mac).strip() if user_online_mac else "UNKNOWN" 

                print(f"  [요청 정보]: 사번={emp_num}, 이름='{emp_name}', 접속IP='{user_online_ip}', 접속MAC='{user_online_mac}'")

                emp_exists = Employees.objects.filter(
                    employee_number=emp_num,
                    name=emp_name,
                    deleted_at__isnull=True
                ).exists()

                if emp_exists:
                    now_time = datetime.now()
                    kick_host_id = None 

                    with transaction.atomic():
                        existing_session = OnlineList.objects.filter(employee_id=emp_num).first()
                        
                        if existing_session:
                            kick_host_id = existing_session.online_ip
                            print(f"  [중복 접속 처리]: 사번 {emp_num} 기존 IP({kick_host_id}) 밀어내기 진행.")
                            
                            existing_session.online_ip = user_online_ip
                            existing_session.online_mac_addr = user_online_mac
                            existing_session.login_time = now_time
                            existing_session.save()
                        else:
                            OnlineList.objects.create(
                                employee_id=emp_num, 
                                online_ip=user_online_ip, 
                                online_mac_addr=user_online_mac,
                                login_time=now_time
                            )

                        with connection.cursor() as cursor:
                            cursor.execute(
                                "INSERT INTO online_list_log (employee_id, online_ip, login_time, online_mac_addr) VALUES (%s, %s, %s, %s)",
                                [emp_num, user_online_ip, now_time, user_online_mac]
                            )

                    print(f"  [로그인 성공]: 사번 {emp_num}('{emp_name}') 접속 및 로그 기록 완료")
                    
                    result_data = {
                        "is_valid": True,
                        "kick_host_id": kick_host_id
                    }

                else:
                    print(f"  [검증 실패]: 이름과 사번이 일치하는 현직 사원이 아닙니다.")
                    result_data = {"is_valid": False}

                client_sock.sendall(create_http_response(200, result_data))
                continue

            # ---------------------------------------------------------
            # 4. 초기 동기화용 활성 세션 리스트 조회 (GET /api/active_sessions)
            # ---------------------------------------------------------
            if method == "GET" and path.startswith('/api/active_sessions'):
                try:
                    active_sessions = OnlineList.objects.all()
                    
                    session_list = []
                    for session in active_sessions:
                        login_timestamp = int(session.login_time.timestamp()) 
                        
                        session_list.append({
                            "host_id": session.online_ip,      
                            "mac": session.online_mac_addr,    
                            "login_time": login_timestamp      
                        })
                    
                    res = {
                        "status": "success", 
                        "count": len(session_list),
                        "data": session_list
                    }
                    client_sock.sendall(create_http_response(200, res))
                except Exception as e:
                    print(f"  [초기 세션 조회 실패]: {e}")
                    client_sock.sendall(create_http_response(500, {"status": "error", "message": str(e)}))
                continue

            # ---------------------------------------------------------
            # 5. [신규 추가] 블랙리스트 접근 시도 로그 저장 (/api/blacklist_log)
            # ---------------------------------------------------------
            if method == "POST" and path.startswith('/api/blacklist_log'):
                emp_num = int(raw_num) if raw_num is not None else -1
                target_domain = str(blacklist_domain).strip() if blacklist_domain else ""
                
                if emp_num != -1 and target_domain:
                    now_time = datetime.now()
                    try:
                        with connection.cursor() as cursor:
                            cursor.execute(
                                "INSERT INTO blacklist_addr_access_log (employee_id, blacklist_domain, access_time) VALUES (%s, %s, %s)",
                                [emp_num, target_domain, now_time]
                            )
                        print(f"  [블랙리스트 차단 로그]: 사번 {emp_num} -> '{target_domain}' 접근 시도 기록 완료")
                        
                        # [핵심] DB 저장 완료 후 웹 서버에 갱신 알림 트리거 전송
                        trigger_blacklist_refresh()
                        
                        res = {"is_logged": True}
                    except Exception as e:
                        print(f"  [블랙리스트 차단 로그 실패]: DB 삽입 에러 - {e}")
                        res = {"is_logged": False, "error": str(e)}
                else:
                    print("  [블랙리스트 차단 로그 실패]: 사번 또는 도메인 정보가 누락되었습니다.")
                    res = {"is_logged": False, "error": "Missing employee_number or domain"}
                
                client_sock.sendall(create_http_response(200, res))
                continue

        except Exception as e:
            print(f"[에러 발생]: {e}")
            client_sock.sendall(create_http_response(200, {"is_valid": False}))
        finally:
            client_sock.close()

if __name__ == '__main__':
    run_server()