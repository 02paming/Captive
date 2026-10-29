import socket
import requests  # 서버 간 HTTP 통신을 위한 라이브러리 추가
import threading # uds 서버역할의 스레드를 백그라운드로 하나돌리기위함
import os
import time
from flask import Flask, request, render_template, jsonify, abort

app = Flask(__name__)

SOCKET_PATH = "/tmp/authorized_ip"               # C 프로그램(Control Plane)이 열어두고 대기하는 UDS 소켓 파일 경로
GC_SOCKET_PATH = "/tmp/ip_update_socket"        # 파이썬 uds서버 -> 스레드가 열어두고 대기하는 uds 소켓파일 경로
TOKEN_SOCKET_PATH = "/tmp/token_socket"         # 파이썬 uds서버 -> 토큰 수신 경로
LOG_SOCK_PATH = "/tmp/packet_log_socket"

API_SERVER_URL = "http://192.168.3.23:8080/api/verify"                  # 웹서버+백엔드 PC(192.168.3.23)의 인증 검증 API 주소
API_AUTH_IP_DELETE = "http://192.168.3.23:8080/api/logout"              # 웹서버+백엔드 pc의 인증테이블 인증데이터 삭제 api 주소
API_INITIAL_SYNC = "http://192.168.3.23:8080/api/active_sessions"       # 초기동기화 api
API_POLICY = "http://192.168.3.23:8080/api/policy"

DJANGO_API_URL_NORMAL = "http://192.168.3.23:8080/api/web_access_log" 
DJANGO_API_URL_BLOCK = "http://192.168.3.23:8080/api/blacklist_log"

valid_tokens = set()              #발급된 토큰들을 임시로 저장하는 공간

# =========================================================================
# [신규 추가] 활동 로그 수신 전용 스레드 함수
# =========================================================================
def log_uds_server_thread():
    # 기존에 남아있는 찌꺼기 소켓 파일 제거
    if os.path.exists(LOG_SOCK_PATH):
        os.remove(LOG_SOCK_PATH)
        
    server = socket.socket(socket.AF_UNIX, socket.SOCK_STREAM)
    server.bind(LOG_SOCK_PATH)
    server.listen(10)  # 로그가 몰릴 수 있으므로 대기열을 10으로 넉넉히 줍니다.
    
    print(f"[로그 스레드] 활동 로그 수신 대기 중... ({LOG_SOCK_PATH})")
    
    while True:
        try:
            conn, _ = server.accept()
            # C 코드에서 snprintf로 쏜 문자열을 받음
            data = conn.recv(1024).decode('utf-8').strip()
            
            if data:
                # C에서 보낸 데이터 분리 (예: "LOG_NORMAL 192.168.2.10 www.naver.com")
                parts = data.split()
                if len(parts) >= 3:
                    log_type = parts[0]
                    client_ip = parts[1]
                    target_url = parts[2]
                    
                    # pcap_checker.py의 파서가 인식할 수 있도록 키(key) 이름을 맞춤
                    if log_type == "LOG_NORMAL":
                        # /api/web_access_log 는 'client_ip', 'target_url' 키를 기대함
                        payload = {"client_ip": client_ip, "target_url": target_url}
                        requests.post(DJANGO_API_URL_NORMAL, json=payload, timeout=2)
                        
                    elif log_type == "LOG_BLOCK":
                        # /api/blacklist_log 는 'user_online_ip', 'blacklist_domain' 키를 기대함
                        # (pcap_checker.py의 KEY_CLIENT_IP, KEY_BLACKLIST_DOMAIN 변수 참조)
                        payload = {"user_online_ip": client_ip, "blacklist_domain": target_url}
                        requests.post(DJANGO_API_URL_BLOCK, json=payload, timeout=2)
                        
        except Exception as e:
            # 타임아웃이나 연결 에러가 나도 스레드가 죽지 않도록 방어
            print(f"[로그 스레드 에러] {e}") 
            pass
        finally:
            conn.close()
            
#토큰 수신용 UDS서버 스레드
def token_uds_server():
    if os.path.exists(TOKEN_SOCKET_PATH):
        os.remove(TOKEN_SOCKET_PATH)

    server = socket.socket(socket.AF_UNIX, socket.SOCK_STREAM)
    server.bind(TOKEN_SOCKET_PATH)
    server.listen(5)

    print(f"[UDS 서버] C 프로그램(Token) 통보 대기 중... ({TOKEN_SOCKET_PATH})")

    while True:
        try:
            conn, _ = server.accept()
            data = conn.recv(1024).decode('utf-8').strip()

            if data:
                print(f"[UDS 수신] C 프로그램 -> 동적 토큰 발급됨: {data}")
                valid_tokens.add(data)

        except Exception as e:
            print(f"[토큰 서버 에러] {e}")
        finally:
            if 'conn' in locals():
                conn.close()

# 추가 인증초기화 usd 서버 역할의 함수 (백엔드로쏴서 인증테이블 db 행 삭제용(혹은 status 업데이트로갈건지 추후 상의))
def gc_uds_server():
    if os.path.exists(GC_SOCKET_PATH): #여기 웹서버 프로세스 재시작할때 기존에 쓰던 GC_SOCKET_PATH의 파일이 남아있으면 bind()때 이미사용중이라고 에러발생 대비
        os.remove(GC_SOCKET_PATH) #exits()로 진짜있는지 확인후 있다면 remove 
        # 파일의 권한,삭제,조회등 os의 커널명령을 직접내리려면 import os가 필요 그래서 쓰는중

    server = socket.socket(socket.AF_UNIX, socket.SOCK_STREAM)
    server.bind(GC_SOCKET_PATH)
    server.listen(5)
    # os.chmod(GC_SOCKET_PATH, 0o666) 클라 , 서버 둘다 root 이기때문에 굳이 필요없음
  
    print(f"[UDS 서버] C 프로그램(GC) 통보 대기 중... ({GC_SOCKET_PATH})")

    while True:
        conn, _ = server.accept() #소켓fd와 , 주소 튜플로반환
        print("수신성공!!!!")
        data = conn.recv(1024).decode('utf-8').strip()
        
        if data:
            user_online_ip = data #인증ip 
            print(f"[UDS 수신] C 프로그램 -> Host ID {user_online_ip} 차단 통보")
            
            # DB 쿼리 없이, 순수하게 백엔드 서버로 JSON 데이터만 쏴줍니다.
            try:
                # POST 방식
                response = requests.post(
                    API_AUTH_IP_DELETE, 
                    json={"user_online_ip": user_online_ip}, 
                    timeout=3 # 3초 안에 응답 안 오면 끊음 (C 프로그램엔 영향 없음)
                )
                print(f"[API 전달 완료] 백엔드 응답 코드: {response.status_code}")
                res = response.json()
                # 실패시
                if res.get("is_login") == False:
                    print(res.get("message"))

            except Exception as e:
                print(f"[API 전달 실패] 백엔드 서버 연결 오류: {e}")
                
        conn.close()

@app.after_request
def add_header(response):
    response.headers["Cache-Control"] = "no-store, no-cache, must-revalidate, max-age=0"
    return response

@app.route("/", methods=["GET"])
def index():
    #바로 출력하지말고 토큰값을 가져와서 출력
    req_token = request.args.get("token")

    #토큰이 없거나, C프로그램이 보내준 유효 토큰 목록에 없다면 403 차단
    if not req_token or req_token not in valid_tokens:
        abort(403)

    valid_tokens.remove(req_token)
    return render_template("index.html")

@app.route("/blocked", methods=["GET"])
def blocked_site():
    req_token = request.args.get("token")
    if not req_token or req_token not in valid_tokens:
        abort(403)

    valid_tokens.remove(req_token)
    return render_template("blocked_page.html")

@app.route("/auth", methods=["POST"])
def auth():
    user_name = request.form.get("emp_name")
    user_emp_number = request.form.get("emp_number")
    client_ip = request.remote_addr
    host_id = client_ip.split(".")[-1]

    # [추가 1] C 프로그램의 mac_addr_cache 에서 MAC 주소 얻어오기
    client_mac = send_and_receive_uds(f"GETMAC {host_id}")
    
    # 만약 C 프로그램이 켜져있지 않거나 값을 못가져왔다면 예외처리
    if not client_mac:
        client_mac = "00:00:00:00:00:00"

    try:
        # [수정] DB서버(Django)에 검증 요청할 때 MAC 주소도 함께 전송
        api_response = requests.post(API_SERVER_URL, json={
            "emp_name": user_name,
            "emp_number": user_emp_number,
            "user_online_ip": host_id,
            "user_online_mac": client_mac # 팀원의 장고 서버가 받을 수 있게 추가
        }, timeout=3)
        
        if api_response.status_code == 200:
            result_data = api_response.json()
            
            if result_data.get("is_valid") == True:
                # 중복 로그인으로 밀려난 기존 PC 처리
                kick_host_id = result_data.get("kick_host_id")
                if kick_host_id:
                    send_and_receive_uds(f"DEL {kick_host_id}")

                try:
                    # [추가 2] 검증 성공 시, IP와 MAC을 함께 묶어서 C 프로그램에 최종 승인(AUTH) 통보
                    send_and_receive_uds(f"AUTH {host_id} {client_mac}") 
                    return render_template("success.html", user_name=user_name, user_emp_number=user_emp_number)
                except Exception as e:
                    return f"❌ 시스템 내부 오류(UDS 통신 실패): {str(e)}", 500
            else:
                return render_template("fail.html")
        else:
            return render_template("fail.html")
    except Exception as e:
        return render_template("fail.html")

def send_and_receive_uds(message):
    client_socket = socket.socket(socket.AF_UNIX, socket.SOCK_STREAM)
    try:
        client_socket.connect(SOCKET_PATH)
        # C 프로그램으로 명령어 전송
        client_socket.sendall(f"{message}\n".encode("utf-8"))

        # 만약 전송한 명령어가 GETMAC 이라면 C 프로그램의 응답(MAC 주소)을 기다림
        if message.startswith("GETMAC"):
            # Null 바이트와 공백을 깔끔하게 제거하여 수신
            response = client_socket.recv(1024).decode("utf-8").strip('\x00\n\r ')
            return response
            
        return True # GETMAC이 아닌 단순 전송(RELOAD, AUTH 등)은 True 반환
        
    except socket.error as e:
        print(f"[UDS 에러] 통신 실패: {e}")
        return None
    finally:
        client_socket.close()

@app.route("/ban", methods=["GET"])
def ban_site():
    req_token = request.args.get("token")
    
    # 토큰 검증은 index나 blocked와 완전히 동일하게 처리
    if not req_token or req_token not in valid_tokens:
        abort(403)

    valid_tokens.remove(req_token)
    return render_template("ban_page.html")

# =========================================================
# 웹서버 백엔드(192.168.3.23)가 변경된 정책을 실시간으로 쏴주는 곳
# =========================================================
@app.route("/api/update_policy", methods=["POST"])
def update_policy_realtime():
    data = request.json
    safe_start = data.get("safe_zone_start", 9)
    safe_end = data.get("safe_zone_end", 18)
    interval = data.get("expire_interval", 600)
    
    try:
        # C 프로그램(방화벽 엔진)으로 UDS 정책 갱신 신호 전송
        send_and_receive_uds(f"POLICY {safe_start} {safe_end} {interval}")
        print(f"\n[PCAP 로그] 관리자 정책 실시간 갱신 수신: 출근 {safe_start}시, 퇴근 {safe_end}시, 주기 {interval}초")
        return jsonify({"status": "success"}), 200
    except Exception as e:
        print(f"[PCAP 에러] 정책 갱신 UDS 전송 실패: {e}")
        return jsonify({"status": "error", "message": str(e)}), 500

# 웹서버 백엔드(192.168.3.23)가 쏴주는 데이터를 받는 곳
@app.route("/api/update_domains", methods=["POST"])
def update_domains():
    data = request.json
    domains = data.get("active_domains", [])
    
    # 1. 받은 도메인들을 텍스트 파일로 저장 (C 프로그램이 읽기 쉽게)
    with open("/tmp/blacklist.txt", "w", encoding="utf-8") as f:
        for item in domains:
            f.write(f"{item['domain']}\n")
            
    print(f"\n[PCAP 로그] 총 {len(domains)}개의 금지 도메인을 blacklist.txt 에 갱신했습니다.")
    
    # 2.  C 프로그램에게 UDS로 RELOAD 신호 쏘기! // 함수 재활용 payload는 없음으로 "0"
    try:
        send_and_receive_uds("RELOAD")
        print("[PCAP 로그] C 프로그램으로 RELOAD 신호를 전송했습니다.")
    except Exception as e:
        print(f"[PCAP 에러] RELOAD 신호 전송 실패: {e}")
    
    return jsonify({"status": "success", "count": len(domains)}), 200

# 초기 db의 인증되어있는 테이블 동기화
def run_initial_sync():
    print("=== [방화벽 초기 동기화 시작] ===")
    
    # ==================================================
    # 1단계: 정책 동기화 (독립된 try-except)
    # ==================================================
    try:
        policy_res = requests.get(API_POLICY, timeout=3)
        if policy_res.status_code == 200:
            policy_data = policy_res.json().get("data", {})
            safe_start = policy_data.get("safe_zone_start", 9)
            safe_end = policy_data.get("safe_zone_end", 18)
            interval = policy_data.get("expire_interval", 600)
            
            send_and_receive_uds(f"POLICY {safe_start} {safe_end} {interval}")
            print(f" -> [정책 동기화 완료] 출근: {safe_start}시, 퇴근: {safe_end}시, 주기: {interval}초")
        else:
            raise Exception("API 응답 상태코드 오류")
    except Exception as e:
        # API가 없거나 에러가 나면 뻗지 않고 기본값(9, 18, 600)을 C로 쏴줍니다!
        print(f" -> [경고] 정책 API 호출 실패({e}). 기본 정책을 적용합니다.")
        send_and_receive_uds(f"POLICY 9 18 600")

    # ==================================================
    # 2단계: 기존 인증된 PC 세션 동기화 (독립된 try-except)
    # ==================================================
    try:
        session_res = requests.get(API_INITIAL_SYNC, timeout=3)
        if session_res.status_code == 200:
            active_sessions = session_res.json().get("data", [])
            success_count = 0
            
            for session in active_sessions:
                host_id = session["host_id"]
                mac = session["mac"]
                
                if mac and mac != "00:00:00:00:00:00":
                    send_and_receive_uds(f"RESTORE {host_id} {mac}")
                    success_count += 1
                    print(f" -> [복구 전송] IP: 192.168.2.{host_id} / MAC: {mac}")
                    
            print(f"=== [세션 동기화 완료] 총 {success_count}대 복구 ===")
        else:
            print(" -> [경고] 세션 API 응답 오류!")
    except Exception as e:
        print(f" -> [오류] 세션 동기화 중 에러 발생: {e}")

def is_c_server_alive(sock_path):
    """소켓 파일이 실제 살아있는 프로세스와 연결되어 있는지 테스트합니다."""
    if not os.path.exists(sock_path):
        return False
    try:
        # 껍데기 파일인지 확인하기 위해 살짝 찔러보기
        tester = socket.socket(socket.AF_UNIX, socket.SOCK_STREAM)
        tester.connect(sock_path)
        tester.close()
        return True # 연결 성공! C 프로그램이 진짜로 살아있음
    except socket.error:
        # 파일은 있지만 연결이 거부됨 (C 프로그램이 꺼져서 남은 좀비 파일임)
        return False

def master_sync_thread():
    sock_path = "/tmp/authorized_ip"
    
    # ==================================================
    # 1. C 프로그램(방화벽 엔진) 대기 루프 (좀비 파일 완벽 방어)
    # ==================================================
    print(f"[*] C 프로그램 방화벽({sock_path})이 켜질 때까지 대기합니다...")
    
    # 단순히 파일 존재 여부가 아니라, 실제 통신이 될 때까지 무한 대기!
    while not is_c_server_alive(sock_path):
        time.sleep(1)
        
    print("[*] C 프로그램 소켓 통신 확인 완료! (정상 가동 중)")

    # ==================================================
    # 2. 장고(Django) 서버 대기 및 무한 재시도 루프
    # ==================================================
    print("[*] 장고(Django) 웹 서버 연결 및 동기화를 시도합니다...")
    
    while True:
        try:
            session_res = requests.get(API_INITIAL_SYNC, timeout=3)
            
            if session_res.status_code == 200:
                # --- 2-1. 정책 동기화 (API가 없어도 안 뻗게 방어) ---
                policy_res = requests.get(API_POLICY, timeout=3)
                if policy_res.status_code == 200:
                    policy_data = policy_res.json().get("data", {})
                    safe_start = policy_data.get("safe_zone_start", 9)
                    safe_end = policy_data.get("safe_zone_end", 18)
                    interval = policy_data.get("expire_interval", 600)
                else:
                    print(" -> [알림] 정책 API 미구현 상태입니다. 기본 정책을 적용합니다.")
                    safe_start, safe_end, interval = 9, 18, 600
                    
                send_and_receive_uds(f"POLICY {safe_start} {safe_end} {interval}")
                print(f" -> [정책 동기화 완료] 출근: {safe_start}시, 퇴근: {safe_end}시, 주기: {interval}초")

                # --- 2-2. 세션 동기화 ---
                active_sessions = session_res.json().get("data", [])
                success_count = 0
                for session in active_sessions:
                    host_id = session["host_id"]
                    mac = session["mac"]
                    if mac and mac != "00:00:00:00:00:00":
                        send_and_receive_uds(f"RESTORE {host_id} {mac}")
                        success_count += 1
                        
                print(f"=== [모든 초기 동기화 완벽 성공] 총 {success_count}대 복구 ===")
                break # 임무를 완수했으므로 영광스럽게 무한 루프 탈출!
            
            else:
                print(f" -> [상태 대기] 장고 서버 응답 상태코드: {session_res.status_code}. 5초 후 재시도...")
                
        except Exception as e:
            # [가장 중요한 수정] 왜 실패했는지 원인을 콘솔에 적나라하게 출력합니다!
            print(f" -> [장고 서버 연결 실패] 사유: {e}")
            print(f" -> 5초 후 다시 두드립니다...")
            
        time.sleep(5)

# 스레드 실행부
if __name__ == "__main__":
    threading.Thread(target=gc_uds_server, daemon=True).start()
    threading.Thread(target=token_uds_server, daemon=True).start()
    threading.Thread(target=log_uds_server_thread, daemon=True).start()

    # 이제 1회성 함수 대신, 마스터 스레드를 백그라운드에서 돌립니다.
    threading.Thread(target=master_sync_thread, daemon=True).start()
    
    app.run(host="0.0.0.0", port=80)