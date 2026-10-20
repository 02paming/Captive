import socket
import requests  # 서버 간 HTTP 통신을 위한 라이브러리 추가
from flask import Flask, request, render_template, jsonify, abort

app = Flask(__name__)

# C 프로그램(Control Plane)이 열어두고 대기하는 UDS 소켓 파일 경로
SOCKET_PATH = "/tmp/authrized_ip"

# [NEW] 웹서버+백엔드 PC(192.168.3.23)의 인증 검증 API 주소
API_SERVER_URL = "http://192.168.3.23:8080/api/verify"

@app.after_request
def add_header(response):
    response.headers["Cache-Control"] = "no-store, no-cache, must-revalidate, max-age=0"
    return response

@app.route("/", methods=["GET"])
def index():
   # URL에 ?token=secure_token이 없으면 403 에러로 차단
    if request.args.get("token") != "secure_token":
        abort(403)
    return render_template("index.html")

@app.route("/blocked", methods=["GET"])
def blocked_site():
    return render_template("blocked_page.html")

@app.route("/auth", methods=["POST"])
def auth():
    user_name = request.form.get("emp_name")
    user_emp_number = request.form.get("emp_number")

    print(f"\n[PCAP 로그] 1. 멍텅구리 웹에서 인증 요청 수신 - 이름: {user_name}, 사번: {user_emp_number}")
    print(f"[PCAP 로그] 2. 웹서버+백엔드({API_SERVER_URL})로 검증 요청 쏘는 중...")

    # ⭐️ [수정된 부분] API 요청을 보내기 전에 IP를 미리 추출합니다.
    client_ip = request.remote_addr
    host_id = client_ip.split(".")[-1]

    # =========================================================
    # [NEW] 망 분리 통신: 웹서버+백엔드로 데이터 전송 및 응답 대기
    # =========================================================
    try:
        # JSON 형태로 이름과 사번을 담아서 POST 요청을 날림 (타임아웃 3초)
        api_response = requests.post(API_SERVER_URL, json={
            "emp_name": user_name,  # ID
            "emp_number": user_emp_number, # NUMBER
            "user_online_ip": host_id  # ⭐️ 이제 에러 없이 정상적으로 값이 들어갑니다.
        }, timeout=3)
        
        # 웹서버+백엔드 API가 정상적으로(200 OK) 대답을 줬다면
        if api_response.status_code == 200:
            result_data = api_response.json()
            
            # API가 보내온 JSON에서 'is_valid' 값이 True인지 확인
            if result_data.get("is_valid") == True:
                print("[PCAP 로그] 3. 결과 수신 성공! 인증 통과됨.")
                
                # 기존 로직: C 프로그램(UDS)에 IP 넘겨주기
                try:
                    # ⭐️ [수정된 부분] 위에서 이미 구했으므로 아래 두 줄은 삭제하고 통신 함수만 호출합니다.
                    send_host_id_via_uds(host_id) 
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

def send_host_id_via_uds(host_id):
    # (기존 UDS 통신 코드는 변경 없음)
    client_socket = socket.socket(socket.AF_UNIX, socket.SOCK_STREAM)
    try:
        client_socket.connect(SOCKET_PATH)
        message = f"{host_id}\n"
        client_socket.sendall(message.encode("utf-8"))
    except socket.error as e:
        raise RuntimeError(f"UDS Socket 연결 실패: {e}")
    finally:
        client_socket.close()

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
    
    # 2. [추가된 부분] C 프로그램에게 UDS로 RELOAD 신호 쏘기!
    send_reload_signal_via_uds()
    
    return jsonify({"status": "success", "count": len(domains)}), 200


# [추가된 부분] UDS로 RELOAD 문자열을 전송하는 함수x
def send_reload_signal_via_uds():
    client_socket = socket.socket(socket.AF_UNIX, socket.SOCK_STREAM)
    try:
        # 기존 사원 인증 IP를 넘겨주던 소켓 경로와 동일한 곳으로 연결
        client_socket.connect(SOCKET_PATH) 
        
        # IP 주소 대신 "RELOAD" 라는 문자열을 전송!
        message = "RELOAD\n"
        client_socket.sendall(message.encode("utf-8"))
        print("[PCAP 로그] C 프로그램으로 RELOAD 신호를 전송했습니다.")
        
    except socket.error as e:
        print(f"[PCAP 에러] UDS Socket 연결 실패: {e}")
    finally:
        client_socket.close()

if __name__ == "__main__":
    app.run(host="0.0.0.0", port=80)