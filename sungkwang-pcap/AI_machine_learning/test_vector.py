import pandas as pd
import joblib
import time


model_path = 'model/dga_model_vec.pkl'  
vectorizer_path = 'model/vectorizer.pkl' 
start_time = time.time()
# ---------------------------------------------------------
# [1단계] 1차 방어막 (화이트리스트 DB 장전)
# ---------------------------------------------------------
print("데이터베이스 불러오는 중...")
df = pd.read_csv('data/dga_train_ready_korea_v2.csv')
whitelist = set(df[df['label'] == 0]['domain'].astype(str))
print(f"-> 1차 화이트리스트 명단 {len(whitelist)}개 장전 완료!")

# ---------------------------------------------------------
# [2단계] 초정밀 벡터화 AI 및 번역기 장전
# ---------------------------------------------------------
print("벡터화 AI와 번역기를 불러오는 중...")
model = joblib.load(model_path)           
vectorizer = joblib.load(vectorizer_path) 

# 자음 연속 계산 함수 (하드 룰용)
def get_max_cons(domain_str):
    max_c = 0; cur_c = 0
    for char in domain_str:
        if char.isalpha() and char not in 'aeiou':
            cur_c += 1
            max_c = max(max_c, cur_c)
        else: cur_c = 0
    return max_c

test_domains = [
    "naver", 
    "google",
    "asdfadssdffqwer",             
    "qazwsxedcrfvtgbyhnujmikolp",  
    "zxcvbnmasdfghjklqwerty",
    "shemaletrannyporn",
    "hfljsda",
    "apple",
    "securetechkg.digital",
    "safdsafasdf",
    "fdsafasfasdf",
    "fasgfqwrevewqv",
    "tqvsdhjvois"
]

print("-" * 60)
print("🚀 실무형 다층 방어(DB + 하드룰 + AI) 시스템 테스트")
print("-" * 60)

for domain in test_domains:
    
    # 1. 화이트리스트 통과 로직 (가장 빠름)
    if domain in whitelist:
        print(f"도메인: {domain:<28} | 판정: 🟢 PASS [1차 DB 컷]")
        print("-" * 60)
        continue
        
    # 2. 하드 룰 차단 로직 (AI가 헷갈려하는 너무 길거나 자음 떡칠된 놈들 강제 처단)
    if len(domain) > 20 or get_max_cons(domain) > 8:
        print(f"도메인: {domain:<28} | 판정: 🔴 BLOCK [2차 하드 룰 컷]")
        print("사  유: 비정상적인 길이 또는 연속 자음 패턴 감지")
        print("-" * 60)
        continue

    # 3. 미지의 도메인 AI 정밀 분석 (정교한 짧은 DGA 전담)
    vec = vectorizer.transform([domain])
    probs = model.predict_proba(vec)[0]
    normal_prob = probs[0] * 100
    malware_prob = probs[1] * 100
    
    if malware_prob >= 70.0:
        status = "🔴 BLOCK [3차 AI 판독]"
    elif malware_prob >= 30.0:
        status = "🟡 GREYLIST [3차 AI 판독]"
    else:
        status = "🟢 PASS [3차 AI 판독]"
        
    print(f"도메인: {domain:<28} | 판정: {status}")
    print(f"확  률: 악성 {malware_prob:>6.2f}% (정상 {normal_prob:>6.2f}%)")
    print("-" * 60)

    
print(f"테스트완료! (소요 시간: {time.time() - start_time:.2f}초)")