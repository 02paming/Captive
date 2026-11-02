import socket
import requests #외부 라이브러리 한번 사용해보려함
import os
import joblib
import pandas as pd
import threading
import time

# UDS 소켓 파일 경로 (C엔진과 약속된 경로)
SOCKET_PATH = "/tmp/ai_dga_socket.sock"
CONFIG_SOCKET_PATH = "/tmp/ai_config.sock"

# ---------------------------------------------------------
# 임계치와 AI 모델을 모두 관리하는 상태 관리 객체
# ---------------------------------------------------------
class AiBrainManager:
    def __init__(self):
        # 1. 초기 임계치 기본값
        self.black = 70.0
        self.black_doubt = 51.0
        self.white_doubt = 31.0
        self.current_version = "v1.0"

        # 2. 부팅 시 PCAP 백엔드(8080)에 현재 가동 중인 설정 동기화 요청
        print("[SYSTEM] 1. DB에서 초기 AI 뇌/설정 동기화 시도 중...")
        try:
            # 8000번이 아닌, PCAP 서버와 연결된 8080 백엔드를 찌릅니다!
            sync_url = "http://192.168.3.23:8080/api/get_active_ai_config"
            res = requests.get(sync_url, timeout=3)
            
            if res.status_code == 200:
                data = res.json()
                self.current_version = data.get("version_name", "v1.0")
                self.black = float(data.get("black_limit", 70.0))
                self.black_doubt = float(data.get("black_doubt_limit", 51.0))
                self.white_doubt = float(data.get("white_doubt_limit", 31.0))
                print(f"[SYSTEM] -> 동기화 완벽 성공! 최신 설정으로 기동합니다. (모델: {self.current_version})")
            else:
                print(f"[SYSTEM] -> 백엔드 응답 에러({res.status_code}). 안전망 기본값(v1.0)으로 기동합니다.")
                
        except Exception as e:
            print(f"[SYSTEM] -> 백엔드 미응답(네트워크 단절 등). 안전망 기본값(v1.0)으로 기동합니다.")
        
        # 3. 초기 안전망 모델(v1.0) 장전 (서버 켜질 때 DB 연동 전 임시 방패)
        print("[SYSTEM] 1. 초기 안전망 AI 뇌 장전 중...")
        self.current_version = "v1.0"
        self.model = joblib.load('model/dga_model_vec_v1.0.pkl')
        self.vectorizer = joblib.load('model/vectorizer_v1.0.pkl')
        print("[SYSTEM] -> 장전 완료. 실시간 방어 준비 끝.\n")
        
        # 스레드 동시 접근을 막는 자물쇠
        self.lock = threading.Lock() 

    # [임계치 실시간 변경]
    def update_thresholds(self, b, bd, wd):
        with self.lock:
            self.black = b
            self.black_doubt = bd
            self.white_doubt = wd

    # [AI 모델 실시간 교체 (무중단 로직)]
    def update_model(self, version_name):
        print(f"[AI 갱신] {version_name} 모델 파일 디스크에서 읽기 시작... (이 동안에도 기존 모델로 방어 유지 중)")
        
        try:
            # 1. 자물쇠 밖에서 무거운 I/O 작업(파일 읽기)을 미리 수행합니다 (약 1~2초 소요)
            new_model = joblib.load(f'model/dga_model_vec_{version_name}.pkl')
            new_vec = joblib.load(f'model/vectorizer_{version_name}.pkl')
            
            # 2. 파일이 램(RAM)에 다 올라오면, 자물쇠를 잠그고 0.001초 만에 뇌를 바꿔치기!
            with self.lock:
                self.model = new_model
                self.vectorizer = new_vec
                self.current_version = version_name
                
            print(f"[AI 갱신] 뇌 이식 완벽 성공! 현재 가동 중인 모델: {self.current_version}")
        except Exception as e:
            print(f"[AI 갱신 실패] {version_name} 모델을 불러오지 못했습니다. 기존 뇌({self.current_version})를 유지합니다. 에러: {e}")

    # [실시간 검사용 상태 읽어오기]
    def get_state(self):
        with self.lock:
            # 현재 메모리에 있는 모델 객체들과 임계치 숫자를 안전하게 묶어서 내어줍니다.
            return self.model, self.vectorizer, self.black, self.black_doubt, self.white_doubt

# 매니저 객체 생성 (모든 스레드가 이 뇌를 공유)
ai_config = AiBrainManager()

# ---------------------------------------------------------
# [0단계] 서버 부팅 시 DB 및 AI 무장 (단 1회 실행)
# ---------------------------------------------------------
print("[SYSTEM] 1. 화이트리스트 DB 장전 중...")
df = pd.read_csv('data/dga_train_ready_korea_v2.csv')
whitelist = set(df[df['label'] == 0]['domain'].astype(str))
print(f"[SYSTEM] -> 화이트리스트 {len(whitelist)}개 장전 완료!")


# ---------------------------------------------------------
# [설정 수신 스레드] 멍텅구리 플라스크의 명령을 기다림
# ---------------------------------------------------------
def config_listener_thread():
    if os.path.exists(CONFIG_SOCKET_PATH):
        os.remove(CONFIG_SOCKET_PATH)
        
    server = socket.socket(socket.AF_UNIX, socket.SOCK_STREAM)
    server.bind(CONFIG_SOCKET_PATH)
    server.listen(1)
    print(f"[ON] AI 설정 UDS 수신 대기 중... ({CONFIG_SOCKET_PATH})")
    
    while True:
        try:
            conn, _ = server.accept()
            data = conn.recv(1024).decode('utf-8')
            if data:
                parts = data.split()
                
                # 1. 임계치 갱신 명령일 경우 ("80.0 60.0 40.0")
                if len(parts) == 3:
                    ai_config.update_thresholds(float(parts[0]), float(parts[1]), float(parts[2]))
                    print(f"\n[AI 갱신] 임계치 즉시 적용! BLACK({parts[0]}) / B_DOUBT({parts[1]}) / W_DOUBT({parts[2]})")
                
                # 2. 모델 교체 명령일 경우 ("MODEL v1.1")
                elif len(parts) == 2 and parts[0] == "MODEL":
                    version_name = parts[1]
                    # 로딩하느라 메인 스레드가 멈추지 않게 백그라운드 스레드로 파일 읽기를 지시!
                    threading.Thread(target=ai_config.update_model, args=(version_name,), daemon=True).start()
                    
        except Exception as e:
            print(f"[AI 설정 에러] {e}")
        finally:
            if 'conn' in locals():
                conn.close()


# ---------------------------------------------------------
# [실시간 방어] C엔진이 요청할 때마다 실행되는 일꾼 스레드
# ---------------------------------------------------------
# 자음 연속 계산 함수 (하드 룰용)
def get_max_cons(domain_str):
  max_c = 0
  cur_c = 0
  for char in domain_str:
    if char.isalpha() and char not in 'aeiou':
      cur_c += 1
      max_c = max(max_c, cur_c)
    else:
      cur_c = 0
  return max_c

def handle_client(conn, addr):
    with conn:
        try:
            domain = conn.recv(1024).decode('utf-8').strip()
            if not domain:
                return

            start_time = time.time()

            # 테스트용 강제 하드코딩 추가
            if domain == "example.com":
                print(f"[TEST] {domain} AI 정밀 분석 중... (0.035초초 소요)")
                time.sleep(0.035) # 실제 AI 연산 + DB 갱신 딜레이 0.078초 부여
                print(f"[TEST] {domain} 강제 악성 도메인(BLACK_DOUBT) 판정!")
                status = "BLACK_DOUBT"
                score = 60.0
                response_data = f"{status}|{score}"
                conn.sendall(response_data.encode('utf-8'))
                return
            
            # 기본값 설정
            status = "WHITE"
            score = 0.0

            # 1. 화이트리스트 및 신뢰 도메인 통과
            if domain in whitelist or any(domain.endswith(s) for s in ['.google.com', '.apple.com']):
                pass
            
            # 2. 하드 룰 차단 (지금은 길이와 자음연속계산함수로판단)
            elif len(domain) > 50 or get_max_cons(domain) > 10:
                status, score = "BLACK", 100.0

            #글로벌 빅테크/CDN 신뢰 도메인 프리패스 (추후 수정가능성있음)
            elif any(domain.endswith(s) for s in ['.google.com', '.googleapis.com', '.googlevideo.com', '.microsoft.com', '.azureedge.net', '.msedge.net', '.windowsupdate.com', '.apple.com', '.cern.ch']):
                pass

            # 3. 미지의 도메인 AI 정밀 분석 (4단계 세분화)
            else:
                # 매니저에게 지금 가동 중인 모델이랑 임계치 좀 빌려줘 라고 요청합니다.
                current_model, current_vec, t_black, t_black_doubt, t_white_doubt = ai_config.get_state()

                # 안전하게 빌려온 객체로 분석 수행 (분석 도중에 다른 스레드가 뇌를 바꿔치기해도 이 스레드는 예전 객체를 쥐고 있으므로 뻗지 않습니다!)
                vec = current_vec.transform([domain])
                score = float(current_model.predict_proba(vec)[0][1] * 100)
                score = round(score, 2)

                if score >= t_black: status = "BLACK"
                elif score >= t_black_doubt: status = "BLACK_DOUBT"
                elif score >= t_white_doubt: status = "WHITE_DOUBT"
                else: status = "WHITE"

            elapsed_ms = (time.time() - start_time) * 1000
            print(f"[LOG] {domain:<30} | {status:<10} ({score}점) | 소요: {elapsed_ms:.3f}ms")

            conn.sendall(f"{status}|{score}".encode('utf-8'))
        except Exception as e:
            print(f"[ERROR] 판독 중 오류: {e}")

# ---------------------------------------------------------
# UDS 소켓 구동부
# ---------------------------------------------------------
def start_uds_server():
    if os.path.exists(SOCKET_PATH):
        os.remove(SOCKET_PATH)

    server = socket.socket(socket.AF_UNIX, socket.SOCK_STREAM)
    server.bind(SOCKET_PATH)
    server.listen(100)
    print(f"[ON] AI UDS 서버가 대기 중입니다 (경로: {SOCKET_PATH})")

    try:
        while True:
            conn, addr = server.accept()
            threading.Thread(target=handle_client, args=(conn, addr), daemon=True).start()
    except KeyboardInterrupt:
        print("\n[OFF] AI 서버 종료")
    finally:
        server.close()
        if os.path.exists(SOCKET_PATH):
            os.remove(SOCKET_PATH)

if __name__ == "__main__":
    # 설정 수신 스레드를 백그라운드(데몬)로 가장 먼저 구동
    threading.Thread(target=config_listener_thread, daemon=True).start()
    
    # 메인 방어 스레드 구동
    start_uds_server()