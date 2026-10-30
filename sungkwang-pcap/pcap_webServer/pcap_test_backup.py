import socket
import requests  # 서버 간 HTTP 통신을 위한 라이브러리 추가
import threading  # uds 서버역할의 스레드를 백그라운드로 하나돌리기위함
import os
import time
from flask import Flask, request, render_template, jsonify

app = Flask(__name__)

# C 프로그램(Control Plane)이 열어두고 대기하는 UDS 소켓 파일 경로
SOCKET_PATH = "/tmp/authrized_ip"

# 파이썬 uds서버 스레드가 열어두고 대기하는 uds 소켓파일 경로
GC_LOG_SOCKET_PATH = "/tmp/pcap_gc.sock"

# [NEW] 웹서버+백엔드 PC(192.168.3.23)의 인증 검증 API 주소
API_SERVER_URL = "http://192.168.3.23:8080/api/verify"

# 추가 => 웹서버 + 백엔드 pc의 인증테이블 인증데이터 삭제 api 주소
API_AUTH_IP_DELETE = "http://192.168.3.23:8080/api/logout"

# 추가 초기동기화 api
API_INITIAL_SYNC = "http://192.168.3.23:8080/api/active_sessions"
API_DOMAINS_SYNC = "http://192.168.3.23:8080/api/active_domains"

# 추가 위협탐지로그
API_BLACKLIST_LOG = "http://192.168.3.23:8080/api/blacklist_log"

# 추가 인증된사원 웹접속로그
API_WEB_ACCESS_LOG = "http://192.168.3.23:8080/api/web_access_log"

# 추가 AI가 감지한 블랙리스트 추가
# API_AI_BLACKLIST_INSERT = "http://192.168.3.23:8080/api/ai_block"




@app.after_request
def add_header(response):
  response.headers["Cache-Control"] = "no-store, no-cache, must-revalidate, max-age=0"
  return response


@app.route("/", methods=["GET"])
def index():
  return render_template("index.html")


@app.route("/ban", methods=["GET"])
def ban_site():
  return render_template("ban_page.html")


@app.route("/blocked", methods=["GET"])
def blocked_site():

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
    
    # 1. 텍스트 파일 생성(f.write) 로직 완전히 삭제됨!
    # 2. UDS 명령어 조합 (예: ADD_BLACK, DEL_WHITE 등)
    command = f"{'ADD' if action == 'add' else 'DEL'}_{sync_type.upper()}"
    
    # 3. 파일 없이 곧바로 C엔진으로 단건 쏴주기
    try:
        send_host_id_via_uds(command, domain)
        print(f"[PCAP 갱신] C엔진으로 0초 컷 업데이트 완료: {command} {domain}")
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

# 웹서버 백엔드(192.168.3.23)가 쏴주는 데이터를 받는 곳

# 추가 인증초기화 usd 서버 역할의 함수 (백엔드로쏴서 인증테이블 db 행 삭제용(혹은 status 업데이트로갈건지 추후 상의))
def gc_uds_server():
  # 여기 웹서버 프로세스 재시작할때 기존에 쓰던 GC_SOCKET_PATH의 파일이 남아있으면 bind()때 이미사용중이라고 에러발생 대비
  if os.path.exists(GC_LOG_SOCKET_PATH):
    os.remove(GC_LOG_SOCKET_PATH)  # exits()로 진짜있는지 확인후 있다면 remove
    # 파일의 권한,삭제,조회등 os의 커널명령을 직접내리려면 import os가 필요 그래서 쓰는중

  server = socket.socket(socket.AF_UNIX, socket.SOCK_STREAM)
  server.bind(GC_LOG_SOCKET_PATH)
  server.listen(5)
  # os.chmod(GC_SOCKET_PATH, 0o666) 클라 , 서버 둘다 root 이기때문에 굳이 필요없음

  print(f"[UDS 서버] C 프로그램(GC,LOG) 통보 대기 중... ({GC_LOG_SOCKET_PATH})")

  while True:
    conn, _ = server.accept()  # 소켓fd와 , 주소 튜플로반환
    print("수신성공!!!!")

    # 비동기로 할일 줘버림 이 구조를 기존 c의 uds수신쪽에도해야하나했지만 여기는 db와 통신하는곳이기때문에 병목이올수있어서 이곳에는 추가함
    client_thread = threading.Thread(target=handle_uds_client, args=(conn,))
    client_thread.daemon = True  # 메인 스레드 종료 시 함께 종료
    client_thread.start()


# gc_uds_server쓰레드속 할일만 따로뺀 쓰레드
def handle_uds_client(conn):
  try:
    data = conn.recv(1024).decode('utf-8').strip()

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
        print(data)
        print(f"[UDS 수신] 웹 접속 로그 -> {client_ip} ({target_url})")
        try:
          response = requests.post(
              API_WEB_ACCESS_LOG,
              json=data,
              timeout=3
          )
        except Exception as e:
          print(f"[API 전달 실패] 로그 저장 오류: {e}")

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
        
        print(f"\n[UDS 수신] 블랙 접속 로그 (DB 업데이트 요청) -> IP: {client_ip} / 도메인: {target_url}")
        
        # 2. 파일 쓰기 대신 백엔드의 /api/ai_block API로 POST 전송
        try:
            response = requests.post(
                API_BLACKLIST_LOG, 
                json=data,
                timeout=3
            )
            print(f"   [API 전달 성공] DB에 AI 차단 도메인 반영 완료")
        except Exception as e:
            print(f"   [API 전달 실패] DB 업데이트 오류: {e}")
  finally:
    conn.close()


# 초기 db의 인증되어있는 테이블 동기화로직 (서버 재부팅시 다 c전역변수들 초기화되는거 방지)
def run_initial_sync():
  print("=== [방화벽 초기 동기화 시작] ===")

  try:
    response = requests.get(API_INITIAL_SYNC)
    domain_res = requests.get(API_DOMAINS_SYNC)

    #인증정보동기화
    if response.status_code == 200:

      # 딕셔너리화
      result = response.json()

      if result.get("status") == "success":
        active_sessions = result.get("data", [])

        success_count = 0
        for session in active_sessions:

          host_id = session["host_id"]
          mac = session["mac"]
          login_timestamp = session["login_time"]

          # 30일 만료 시간 계산 (초 단위 덧셈: 30일 * 24시간 * 60분 * 60초)
          expire_timestamp = login_timestamp + 600

          # C 프로그램에 RESTORE 명령어로 IP, MAC, 만료시간 일괄 전송
          try:
            if mac and mac != "00:00:00:00:00:00":
              payload = f"{host_id} {mac} {expire_timestamp}"
              send_host_id_via_uds("RESTORE", payload)
              success_count += 1
              cur_time = int(time.time())  # 이 함수가 실행될때 즉 초기동기화할때의 시간
              real_time = expire_timestamp - cur_time  # 만료시간
              if real_time < 0:
                real_time = 0  # 다 만료되고 동기화하면 만료시간 0으로뜨게하기 음수보기싫으니
              print(
                  f" -> [복구 전송] IP: 2.{host_id} / MAC: {mac} / 만료시간: {real_time}")
          except Exception as e:
            print(
                f"run_initial_sync() 중 에러발생!! (메인pcap서버 안켜서 uds에러일확률 큼!) {e}")
        print(f"=== [초기 동기화 완료] 총 {success_count}대 복구 ===")
      else:
        print(f"백엔드 응답오류 : success가 아니라는뜻!")
    else:
      print("HTTP상태응답코드 오류 : 200이 아니라는뜻!")

      #도메인동기화
    if domain_res.status_code == 200 and domain_res.json().get("status") == "success":
        db_domains = domain_res.json().get("data", [])
        
        for item in db_domains:
            # item 딕셔너리에 {"type": "black", "domain": "hacker.com"} 이 있다고 가정
            cmd = "ADD_BLACK" if item["type"] == "black" else "ADD_WHITE"
            
            # C엔진으로 도메인 1개씩 복구 명령 쏘기 (런타임 단건 갱신용 UDS 명령어 재활용!)
            send_host_id_via_uds(cmd, item["domain"])
            
        print(f"=== [초기 동기화 완료] DB 누적 도메인 총 {len(db_domains)}개 복구 ===")
  except Exception as e:
    print(f"run_initial_sync() 중 에러발생!! (백엔드서버안켜서 get안되서 에러낫을확률 큼) {e}")
  # 이 멍텅구리 웹서버를 안키고 pcap서버(c코드)를 키면 초기동기화가안됌 하지만 이후 웹서버를 키면서 다시됨 지장없음
  # 하지만 백엔드서버를 안키고있으면 get이안됨으로 에러발생


if __name__ == "__main__":
  # ptread_create 처럼 백그라운드로 이 함수 while true로 계속 돌고있을거임 (accept에서 블락상태)
  threading.Thread(target=gc_uds_server, daemon=True).start()
  run_initial_sync()
  app.run(host="0.0.0.0", port=80)
