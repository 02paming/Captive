import socket
import os
import joblib
import pandas as pd
import threading
import time

# UDS 소켓 파일 경로 (C엔진과 약속된 경로)
SOCKET_PATH = "/tmp/ai_dga_socket.sock"

# ---------------------------------------------------------
# [0단계] 서버 부팅 시 DB 및 AI 무장 (단 1회 실행)
# ---------------------------------------------------------
print("[SYSTEM] 1. 화이트리스트 DB 장전 중...")
df = pd.read_csv('data/dga_train_ready_korea_v2.csv')
whitelist = set(df[df['label'] == 0]['domain'].astype(str))
print(f"[SYSTEM] -> 화이트리스트 {len(whitelist)}개 장전 완료!")

print("[SYSTEM] 2. 벡터화 AI와 번역기를 불러오는 중...")
model = joblib.load('model/dga_model_vec.pkl')
vectorizer = joblib.load('model/vectorizer.pkl')
print("[SYSTEM] -> 장전 완료. 실시간 방어 준비 끝.\n")

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

# ---------------------------------------------------------
# [실시간 방어] C엔진이 요청할 때마다 실행되는 일꾼 스레드
# ---------------------------------------------------------


def handle_client(conn, addr):
    with conn:
        try:
            domain = conn.recv(1024).decode('utf-8').strip()
            if not domain:
                return

            start_time = time.time()

            # 테스트용 강제 하드코딩 추가
            # if domain == "example.com":
            #     print(f"[TEST] {domain} AI 정밀 분석 중... (0.035초초 소요)")
            #     time.sleep(0.035) # 실제 AI 연산 + DB 갱신 딜레이 0.078초 부여
            #     print(f"[TEST] {domain} 강제 악성 도메인(BLOCK) 판정!")
            #     conn.sendall(b"BLOCK")
            #     return
            
            # 기본값 설정
            status = "WHITE"
            score = 0.0

            # 1. 화이트리스트 및 신뢰 도메인 통과
            if domain in whitelist or any(domain.endswith(s) for s in ['.google.com', '.apple.com']):
                status = "WHITE"
                score = 0.0

            # 2. 하드 룰 차단 (명백한 악성)
            elif len(domain) > 50 or get_max_cons(domain) > 10:
                status = "BLACK"
                score = 100.0

            #글로벌 빅테크/CDN 신뢰 도메인 프리패스 (오탐지 방지용) 추후 수정해도됨
            elif any(
                domain.endswith(suffix)
                for suffix in [
                    '.google.com',
                    '.googleapis.com',
                    '.googlevideo.com',
                    '.microsoft.com',
                    '.azureedge.net',
                    '.msedge.net',
                    '.windowsupdate.com',
                    '.apple.com',
                    '.cern.ch',
                ]
            ):
              status = "WHITE"
              score = 0.0

            # 3. 미지의 도메인 AI 정밀 분석 (4단계 세분화)
            else:
                vec = vectorizer.transform([domain])
                score = float(model.predict_proba(vec)[0][1] * 100)
                score = round(score, 2) # 소수점 둘째 자리까지 깔끔하게 정리

                # 성광님이 지정하신 4단계 임계값 로직
                if score >= 70.0:
                    status = "BLACK"       # 70 ~ 100: 확실한 악성
                elif score >= 51.0:
                    status = "BLACK_DOUBT"  # 51 ~ 69: 악성에 가까운 의심
                elif score >= 31.0:
                    status = "WHITE_DOUBT"    # 31 ~ 50: 정상에 가까운 의심
                else:
                    status = "WHITE"        # 0 ~ 30: 정상

            elapsed_ms = (time.time() - start_time) * 1000
            print(f"[LOG] {domain:<30} | {status:<10} ({score}점) | 소요: {elapsed_ms:.3f}ms")

            #c언어가 파싱하기 쉬운 형태
            response_data = f"{status}|{score}"
            conn.sendall(response_data.encode('utf-8'))

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
      # C엔진 딜레이 방지를 위해 백그라운드 스레드로 처리
      threading.Thread(target=handle_client, args=(
          conn, addr), daemon=True).start()
  except KeyboardInterrupt:
    print("\n[OFF] AI 서버 종료")
  finally:
    server.close()
    if os.path.exists(SOCKET_PATH):
      os.remove(SOCKET_PATH)


if __name__ == "__main__":
  start_uds_server()
