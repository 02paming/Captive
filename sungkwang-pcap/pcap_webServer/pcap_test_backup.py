import socket
import requests  # 서버 간 HTTP 통신을 위한 라이브러리 추가
import threading  # uds 서버역할의 스레드를 백그라운드로 하나돌리기위함
import os
import time
from concurrent.futures import ThreadPoolExecutor
from flask import Flask, request, render_template, jsonify, abort



app = Flask(__name__)
# 0. 내부 ai프로세스와 통신
CONFIG_SOCKET_PATH = "/tmp/ai_config.sock"

# =========================================================================
# 1. C 엔진과 통신하는 UDS 소켓 경로 모음
# =========================================================================
SOCKET_PATH = "/tmp/authrized_ip"               # [WR] C 수신 (명령어)
GC_LOG_SOCKET_PATH = "/tmp/pcap_gc.sock"        # [RC] 파이썬 수신 (만료, 접속 로그)
TOKEN_SOCKET_PATH = "/tmp/token_socket"         # [RC] 파이썬 수신 (일회용 토큰)
SYNC_WAIT_SOCKET = "/tmp/sync_wait_socket"      # [RC] 파이썬 수신 (Handshake 조율용) 


# =========================================================================
# 2. 원격 웹 서버(192.168.3.23:8080) API 경로 모음
# =========================================================================
API_SERVER_URL = "http://192.168.3.23:8080/api/verify"              # 웹서버+백엔드 PC(192.168.3.23)의 인증 검증 API 주소
API_AUTH_IP_DELETE = "http://192.168.3.23:8080/api/logout"          # 웹서버 + 백엔드 pc의 인증테이블 인증데이터 삭제 api 주소
API_POLICY = "http://192.168.3.23:8080/api/policy"                  # 정책 호출 : 출근시간,퇴근시간
API_INITIAL_SYNC = "http://192.168.3.23:8080/api/active_sessions"   # 초기동기화 -인증 api 
API_DOMAINS_SYNC = "http://192.168.3.23:8080/api/active_domains"    # 초기동기화 -도메인 api 
API_BLACKLIST_LOG = "http://192.168.3.23:8080/api/blacklist_log"    # 위협탐지로그
API_WEB_ACCESS_LOG = "http://192.168.3.23:8080/api/web_access_log"  # 인증된사원 웹접속로그

# C 엔진이 발급한 일회용 토큰을 임시 저장할 메모리 공간
valid_tokens = set()

#로그 병목현상 해결을 위한 100개모아쏘거나 1초뒤쏘기
#로그 스레드풀 생성
executor = ThreadPoolExecutor(max_workers=10)

BATCH_SIZE = 100          # 100개가 모이면 즉시 전송
BATCH_INTERVAL_SEC = 1.0  # 1초가 지나면 무조건 전송

log_buffer_white = []
log_buffer_black = []
buffer_lock = threading.Lock()
last_flush_time = time.time()


# =========================================================================
# 3. 토큰 수신용 UDS 서버 스레드
# =========================================================================
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
                valid_tokens.add(data) # 메모리에 토큰 저장
        except Exception as e:
            print(f"[토큰 서버 에러] {e}")
        finally:
            if 'conn' in locals():
                conn.close()
# =========================================================================
# 4. 마스터 동기화 스레드 (부팅 시 기동 순서 꼬임 방어) 기존 run_initial_sync() 에서 바꾼것임
# =========================================================================   
def master_sync_thread():
    if os.path.exists(SYNC_WAIT_SOCKET):
        os.remove(SYNC_WAIT_SOCKET)
        
    sync_server = socket.socket(socket.AF_UNIX, socket.SOCK_STREAM)
    sync_server.bind(SYNC_WAIT_SOCKET)
    sync_server.listen(1)
    
    print(f"[*] C 엔진(sync_runner) 연결 대기 중... ({SYNC_WAIT_SOCKET})")
    
    while True:
        conn, _ = sync_server.accept()
        print("[*] C 엔진 가동 감지! 장고(Django) 웹 서버와 동기화를 시작합니다.")
        
        # 8080 서버가 켜져서 응답할 때까지 무한 핑퐁 대기
        while True:
            try:
                session_res = requests.get(API_INITIAL_SYNC, timeout=3)
                
                if session_res.status_code == 200:
                    active_sessions = session_res.json().get("data", [])
                    
                    # 1. 정책 동기화 (팀원 기능 병합 - 출퇴근 시간)
                    try:
                        policy_res = requests.get(API_POLICY, timeout=3)
                        if policy_res.status_code == 200:
                            policy_data = policy_res.json().get("data", {})
                            safe_start = policy_data.get("safe_zone_start", 9)
                            safe_end = policy_data.get("safe_zone_end", 18)
                            interval = policy_data.get("expire_interval", 600)
                        else:
                            safe_start, safe_end, interval = 9, 18, 600
                        send_host_id_via_uds(f"POLICY {safe_start} {safe_end} {interval}", "")
                    except:
                        # 8080에서 정책 API를 못 만들었을 때 뻗지 않도록 방어
                        send_host_id_via_uds("POLICY 9 18 600", "")
                        
                    # 2. 기존 인증된 PC 세션 복구 동기화
                    for session in active_sessions:
                        host_id = session["host_id"]
                        mac = session["mac"]
                        if mac and mac != "00:00:00:00:00:00":
                            send_host_id_via_uds("RESTORE", f"{host_id} {mac}")

                    # 3. 도메인 동기화 (성광님의 기존 ADD_BLACK / ADD_WHITE 단건 전송 방식 유지!)
                    try:
                        domain_res = requests.get(API_DOMAINS_SYNC, timeout=3)
                        if domain_res.status_code == 200 and domain_res.json().get("status") == "success":
                            db_domains = domain_res.json().get("data", [])
                            for item in db_domains:
                                
                                sync_type = item["type"].upper() # BLACK 또는 WHITE
                                domain = item["domain"]
                                source = item.get("source", "USER")
                                ai_score = item.get("ai_score", -1.0)
                                cmd = f"ADD_{sync_type}"
                                payload = f"{domain} {source} {ai_score}"
                                print(payload)
                                send_host_id_via_uds(cmd, payload)

                            print(f"=== [도메인 동기화] 총 {len(db_domains)}개 복구 ===")
                    except Exception as e:
                        print(f" -> [경고] 도메인 DB 요청 실패: {e}")
                            
                    print(f"=== [초기 동기화 완벽 성공] ===")
                    
                    # 4. sync_runner.py에게 종료 신호 전송 (C 엔진 pcap_loop 가동!)
                    conn.sendall(b"SYNC_DONE")
                    break 
                    
                else:
                    print(f" -> [대기] 장고 응답코드: {session_res.status_code}. 5초 후 재시도...")
            except Exception as e:
                print(f" -> [연결 실패] 사유: {e}. 5초 후 재시도...")
            time.sleep(5)
            
        conn.close()

# =========================================================================
# 5. 기존 UDS 통신 및 라우팅 (토큰 검증 추가)
# =========================================================================
@app.after_request
def add_header(response):
  response.headers["Cache-Control"] = "no-store, no-cache, must-revalidate, max-age=0"
  return response


@app.route("/", methods=["GET"])
def index():
  req_token = request.args.get("token")
  if not req_token or req_token not in valid_tokens:
      abort(403) # 권한 없음 에러
  valid_tokens.remove(req_token) # 한 번 쓴 토큰 폐기
  return render_template("index.html")


@app.route("/ban", methods=["GET"])
def ban_site():
  req_token = request.args.get("token")
  if not req_token or req_token not in valid_tokens:
      abort(403)
  valid_tokens.remove(req_token)
  
  # C 엔진이 보낸 ?reason=MAC_Address_Error 쿼리를 템플릿에 전달 가능
  reason = request.args.get("reason", "알 수 없는 사유")
  return render_template("ban_page.html", reason=reason)


@app.route("/blocked", methods=["GET"])
def blocked_site():

  req_token = request.args.get("token")
  if not req_token or req_token not in valid_tokens:
      abort(403)
  valid_tokens.remove(req_token)

  # print(" [디버깅] 들어온 args 전체:", dict(request.args))
  # get이 객체의 키값꺼내는것 아래에도 자주쓰였음 지금은 쿼리스트링 키값가져옴 args에서

  # blocked_url = request.args.get("url")
  # client_ip = request.args.get("ip")
  # host_id = client_ip.split(".")[-1]

  # if blocked_url and client_ip:
  #   payload = {
  #       "blacklist_domain": blocked_url,
  #       "user_online_ip": host_id
  #   }
  #   try:
  #     res = requests.post(API_BLACKLIST_LOG, json=payload, timeout=2)
  #     print(f" PCAP 백엔드로 전달 성공 (상태코드: {res.status_code})")
  #   except Exception as e:
  #     print(f" PCAP 백엔드 통신 실패: {e}")

  return render_template("blocked_page.html")


@app.route("/auth", methods=["POST"])
def auth():
  user_name = request.form.get("emp_name")
  user_emp_number = request.form.get("emp_number")

  print(
      f"\n[PCAP 로그] 1. 멍텅구리 웹에서 인증 요청 수신 - 이름: {user_name}, 사번: {user_emp_number}")
  print(f"[PCAP 로그] 2. 웹서버+백엔드({API_SERVER_URL})로 검증 요청 쏘는 중...")

  # =========================================================
  # [NEW] 망 분리 통신: 웹서버+백엔드로 데이터 전송 및 응답 대기
  # =========================================================
  try:
    client_ip = request.remote_addr
    host_id = client_ip.split(".")[-1]
    client_mac = send_host_id_via_uds("GETMAC", host_id)

    if not client_mac:
      print("[MAC] mac을 찾지못했습니다")
      client_mac = "00:00:00:00:00:00"
    else:
      print(f"[MAC] mac을 찾았습니다. {client_mac}")

    # JSON 형태로 이름과 사번을 담아서 POST 요청을 날림 (타임아웃 3초)
    api_response = requests.post(API_SERVER_URL, json={
        "emp_name": user_name,  # ID
        "emp_number": user_emp_number,  # NUMBER
        "user_online_ip": host_id,  # IP
        "user_online_mac": client_mac  # MAC
    }, timeout=3)

    # 웹서버+백엔드 API가 정상적으로(200 OK) 대답을 줬다면
    if api_response.status_code == 200:
      result_data = api_response.json()

      # API가 보내온 JSON에서 'is_valid' 값이 True인지 확인
      if result_data.get("is_valid") == True:
        print("[PCAP 로그] 3. 결과 수신 성공! 인증 통과됨.")

        # 없앨ip와 새로인증등록할ip(이건 그냥 host_id쓰면됨) 없앨 ip 응답구조 백엔드에서 추가해야함
        kick_host_id = result_data.get("kick_host_id")
        new_host_id = host_id

        # 기존 로직: C 프로그램(UDS)에 command(인증인지 초기화인지, ip, mac) 넘겨주기
        try:

          # 1. 기존 등록되있던 ip를 없애는 명령을 먼저 C로 전송
          if kick_host_id:
            send_host_id_via_uds("EXPIRE", kick_host_id)
          # 2. 새로인증등록할ip를 승인하는 명령을 C로 전송
          auth_payload = f"{new_host_id} {client_mac}"
          send_host_id_via_uds("AUTH", auth_payload)
          return render_template("success.html", user_name=user_name, user_emp_number=user_emp_number)

        except Exception as e:
          return f"❌ 시스템 내부 오류(UDS 통신 실패): {str(e)}", 500
      else:
        print("[PCAP 로그] 3. 결과 수신 완료. 하지만 인증 거부됨(사번 불일치).")
        return render_template("fail.html")
    else:
      print(f"[PCAP 에러] API 서버가 이상한 코드를 뱉었습니다: {api_response.status_code}")
      return render_template("fail.html")

  except requests.exceptions.Timeout:
    print("[PCAP 에러] API 서버가 3초 안에 응답하지 않습니다. (방화벽이나 망 연결 확인)")
    return render_template("fail.html")
  except requests.exceptions.ConnectionError:
    print("[PCAP 에러] API 서버에 연결할 수 없습니다. (서버가 꺼져있거나 IP가 틀림)")
    return render_template("fail.html")
  except Exception as e:
    print(f"[PCAP 에러] 알 수 없는 통신 에러: {e}")
    return render_template("fail.html")



@app.route("/api/update_domains", methods=["POST"])
def update_domains():
    data = request.json
    
    # 장고 웹서버에서 '단건'으로 보낸 액션(add/delete), 타입(black/white), 도메인을 받음
    action = data.get("action")  # "add" 또는 "delete"
    sync_type = data.get("sync_type") # "black" 또는 "white"
    domain = data.get("domain") # "hacker.com"
    source = data.get("source", "USER")
    ai_score = data.get("ai_score", -1.0)
    
    # 1. 텍스트 파일 생성(f.write) 로직 완전히 삭제됨!
    # 2. UDS 명령어 조합 (예: ADD_BLACK, DEL_WHITE 등)
    command = f"{'ADD' if action == 'add' else 'DEL'}_{sync_type.upper()}"
    
    # 3. 파일 없이 곧바로 C엔진으로 단건 쏴주기
    try:
        payload = f"{domain} {source} {ai_score}" if action == 'add' else domain
        # print(payload)
        send_host_id_via_uds(command, payload)
        print(f"[PCAP 갱신] C엔진으로 0초 컷 업데이트 완료: {command} {payload}")
    except Exception as e:
        print(f"[PCAP 에러] UDS 신호 전송 실패: {e}")
        
    return jsonify({"status": "success", "domain": domain, "command": command}), 200

# 신규추가! 웹서버 백엔드가 pcap백엔드로 쏘고 거기서 멍텅구리백엔드(여기)로 쏘면서 관리자가 지정한 ip(혹은id) 차단하는곳


@app.route('/api/update_online', methods=['POST'])
def update_online():
  # 1. pcap백엔드가 던진 JSON 받기
  data = request.json
  kick_host_id = data.get("kick_host_id")

  if kick_host_id is not None:
    try:
      # 2. 기존에 만들어둔 UDS 통신 함수로 바로 삭제하러감
      send_host_id_via_uds("EXPIRE", kick_host_id)
      print(f"[PCAP 로그] 웹 관리자 명령으로 '{kick_host_id}' UDS(EXPIRE) 전송 완료.")

      # 3. 8080 징검다리에게 잘 받았다고 대답
      return jsonify({"is_sync_success": True}), 200

    except Exception as e:
      print(f"[PCAP 에러] UDS 전송 실패: {e}")
      return jsonify({"is_sync_success": False, "error": str(e)}), 500

  return jsonify({"is_sync_success": False, "error": "kick_host_id 누락"}), 400


# 기존 함수로 대체!
# def send_reload_signal_via_uds():
#     client_socket = socket.socket(socket.AF_UNIX, socket.SOCK_STREAM)
#     try:
#         # 기존 사원 인증 IP를 넘겨주던 소켓 경로와 동일한 곳으로 연결
#         client_socket.connect(SOCKET_PATH)

#         # IP 주소 대신 "RELOAD" 라는 문자열을 전송!
#         message = "RELOAD\n"
#         client_socket.sendall(message.encode("utf-8"))
#         print("[PCAP 로그] C 프로그램으로 RELOAD 신호를 전송했습니다.")

#     except socket.error as e:
#         print(f"[PCAP 에러] UDS Socket 연결 실패: {e}")
#     finally:
#         client_socket.close()


def send_host_id_via_uds(command, auth_payload):
  # (기존 UDS 통신 코드는 변경 없음)
  client_socket = socket.socket(socket.AF_UNIX, socket.SOCK_STREAM)
  try:
    client_socket.connect(SOCKET_PATH)
    message = f"{command} {auth_payload}\n"
    client_socket.sendall(message.encode("utf-8"))

    if command == "GETMAC":  # 맥 받는 요청용 uds일때
      response = client_socket.recv(1024).decode("utf-8").strip()

      # 정상적인 응답이 왔다면 MAC 반환, 빈 값이면 None 반환
      if response and response != "00:00:00:00:00:00":
        return response
      return None

  except socket.error as e:
    raise RuntimeError(f"UDS Socket 연결 실패: {e}")
  finally:
    client_socket.close()

def flush_logs():
    """타이머나 개수가 찼을 때 쌓인 로그를 pcap백엔드로 한 방에 전송"""
    global log_buffer_white, log_buffer_black, last_flush_time
    
    with buffer_lock:
        whites_to_send = log_buffer_white[:]
        blacks_to_send = log_buffer_black[:]
        log_buffer_white.clear()
        log_buffer_black.clear()
        last_flush_time = time.time()
        
    # WHITE 로그 묶음 전송
    if whites_to_send:
        try:
            requests.post(API_WEB_ACCESS_LOG, json={"logs": whites_to_send}, timeout=5)
            print(f"[배치 전송] WHITE 로그 {len(whites_to_send)}개 묶음 전송 완료")
        except Exception as e:
            print(f"[API 벌크 전달 실패 - WHITE]: {e}")
            
    # BLACK 로그 묶음 전송
    if blacks_to_send:
        try:
            requests.post(API_BLACKLIST_LOG, json={"logs": blacks_to_send}, timeout=5)
            print(f"[배치 전송] BLACK 로그 {len(blacks_to_send)}개 묶음 전송 완료")
        except Exception as e:
            print(f"[API 벌크 전달 실패 - BLACK]: {e}")

def batch_timer_thread():
    """1초마다 로그 배열을 검사해서 쌓인 게 있으면 비워주는 백그라운드 타이머"""
    while True:
        time.sleep(BATCH_INTERVAL_SEC)
        if len(log_buffer_white) > 0 or len(log_buffer_black) > 0:
            flush_logs()

# 웹서버 백엔드(192.168.3.23)가 쏴주는 데이터를 받는 곳
# 추가 인증초기화 usd 서버 역할의 함수 (백엔드로쏴서 인증테이블 db 행 삭제용(혹은 status 업데이트로갈건지 추후 상의))
def gc_uds_server():
  # 여기 웹서버 프로세스 재시작할때 기존에 쓰던 GC_SOCKET_PATH의 파일이 남아있으면 bind()때 이미사용중이라고 에러발생 대비
  if os.path.exists(GC_LOG_SOCKET_PATH):
    os.remove(GC_LOG_SOCKET_PATH)  # exits()로 진짜있는지 확인후 있다면 remove
    # 파일의 권한,삭제,조회등 os의 커널명령을 직접내리려면 import os가 필요 그래서 쓰는중

  server = socket.socket(socket.AF_UNIX, socket.SOCK_STREAM)
  server.bind(GC_LOG_SOCKET_PATH)
  server.listen(100)
  # os.chmod(GC_SOCKET_PATH, 0o666) 클라 , 서버 둘다 root 이기때문에 굳이 필요없음

  print(f"[UDS 서버] C 프로그램(GC,LOG) 통보 대기 중... ({GC_LOG_SOCKET_PATH})")

  while True:
        try:
            conn, _ = server.accept()
            # 2. 스레드풀에 할 일을 넣기
            executor.submit(handle_uds_client, conn)
        except Exception as e:
            print(f"[UDS 서버 accpet 에러] {e}")



# gc_uds_server쓰레드속 할일만 따로뺀 쓰레드
def handle_uds_client(conn):
  try:
    data = conn.recv(1024).decode('utf-8').strip()

    print(data)

    if data:
      parts = data.split('|')
      command = parts[0]

      # c 수신 uds처럼 커멘드로 분기하는 로직
      # GC일떄(인증초기화)
      # ["GC", "55"]
      if command == "GC" and len(parts) >= 2:
        user_online_ip = parts[1]
        print(f"[UDS 수신] GC 차단 통보 -> Host IP {user_online_ip}")
        try:
          response = requests.post(
              API_AUTH_IP_DELETE,
              json={"user_online_ip": user_online_ip},
              timeout=3
          )
          print(f"[API 전달 완료] 백엔드 응답 코드: {response.status_code}")
        except Exception as e:
          print(f"[API 전달 실패] 백엔드 서버 연결 오류: {e}")

      # 일반 log일때(인증된사원 일반접속로그)
      # ["LOG",55,"ccc.com"]
      elif command == "WHITE" and len(parts) >= 5:
        client_ip = parts[1]
        target_url = parts[2]
        status_code = parts[3].strip() # 2(수동정상), 5(AI의심정상), 6(AI정상)
        ai_score = parts[4].strip()
        
        data = {
            "client_ip": client_ip.split(".")[-1],
            "status_code": status_code, 
            "target_url": target_url,
            "ai_score": ai_score
        }
        # print(data)

        print(f"[UDS 수신] 웹 접속 로그 -> {client_ip} ({target_url})")
        with buffer_lock:
            log_buffer_white.append(data)
            if len(log_buffer_white) >= BATCH_SIZE:
                threading.Thread(target=flush_logs, daemon=True).start()

      elif command == "BLACK" and len(parts) >= 5:
        client_ip = parts[1]
        target_url = parts[2]
        status_code = parts[3].strip() # 1(수동차단), 3(AI차단), 4(AI의심차단)
        ai_score = parts[4].strip()
        
        data = {
            "client_ip": client_ip.split(".")[-1],
            "status_code": status_code, # 숫자 코드 그대로 토스
            "target_url": target_url,
            "ai_score": ai_score
        }
        # print(data)
        print(f"\n[UDS 수신] 블랙 접속 로그 (DB 업데이트 요청) -> IP: {client_ip} / 도메인: {target_url}")

        with buffer_lock:
            log_buffer_black.append(data)
            if len(log_buffer_black) >= BATCH_SIZE:
                threading.Thread(target=flush_logs, daemon=True).start()
       
  finally:
    conn.close()

# =========================================================
# 6. 관리자 페이지에서 변경한 AI 임계치 실시간 수신
# =========================================================
@app.route("/api/update_ai_threshold", methods=["POST"])
def update_ai_threshold():
    data = request.json
    
    # 장고에서 안 보냈을 경우를 대비해 기존 DB 기본값을 방어 코드로 설정
    black = data.get("black_limit", 70.0)
    black_doubt = data.get("black_doubt_limit", 51.0)
    white_doubt = data.get("white_doubt_limit", 31.0)
    
    # AI 파이썬 프로세스가 읽기 편하게 띄어쓰기로 묶음 (예: "80.0 60.0 40.0")
    payload = f"{black} {black_doubt} {white_doubt}"
    
    try:
        # AI 프로세스의 설정 전용 UDS 소켓으로 발사!
        client = socket.socket(socket.AF_UNIX, socket.SOCK_STREAM)
        client.connect(CONFIG_SOCKET_PATH)
        client.sendall(payload.encode('utf-8'))
        client.close()
        
        print(f"\n[PCAP 로그] AI 임계치 실시간 변경 통보 완료: {payload}")
        return jsonify({"status": "success"}), 200
        
    except Exception as e:
        print(f"[PCAP 에러] AI 설정 UDS 전송 실패 (AI 프로세스가 꺼져있음): {e}")
        return jsonify({"status": "error", "message": str(e)}), 500


# =========================================================
# 7. 관리자 페이지에서 변경한 AI 모델 실시간 수신
# ========================================================= 
@app.route("/api/update_ai_model", methods=["POST"])
def update_ai_model():
    version = request.json.get("model_version") # 예: "v1.1"
    
    # AI 프로세스가 알아먹게 명령어 조합 (예: "MODEL v1.1")
    payload = f"MODEL {version}"
    
    client = socket.socket(socket.AF_UNIX, socket.SOCK_STREAM)
    client.connect(CONFIG_SOCKET_PATH) 
    client.sendall(payload.encode('utf-8'))
    client.close()
    
    return jsonify({"status": "success"})

if __name__ == "__main__":
  # ptread_create 처럼 백그라운드로 이 함수 while true로 계속 돌고있을거임 (accept에서 블락상태)
  threading.Thread(target=gc_uds_server, daemon=True).start()  # 로깅 & 만료 처리
  threading.Thread(target=token_uds_server, daemon=True).start() # 토큰 수신 
  threading.Thread(target=master_sync_thread, daemon=True).start() # 무적 동기화 
  threading.Thread(target=batch_timer_thread, daemon=True).start()
  app.run(host="0.0.0.0", port=80)
