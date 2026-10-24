import joblib
import math
import pandas as pd

#플랜 a버전 테스트용.py

# 1. 저장해둔 AI 뇌(모델) 깨우기
print("업그레이드된 dga_model.pkl 뇌를 불러오는 중...")
model = joblib.load('model/dga_model.pkl')

# 1차 방어막
df = pd.read_csv('data/dga_train_ready_korea_v2.csv')
whitelist = set(df[df['label'] == 0]['domain'].astype(str))
print(f"-> 1차 화이트리스트 명단 {len(whitelist)}개 장전 완료!")

# 2. 특징 추출 함수 (훈련할 때 썼던 5가지 공식을 똑같이 가져옴)
def get_entropy(domain_string):
    if not domain_string: return 0
    prob = [float(domain_string.count(c)) / len(domain_string) for c in dict.fromkeys(list(domain_string))]
    return -sum([p * math.log(p) / math.log(2.0) for p in prob])

def get_vowel_ratio(domain_string):
    if not domain_string: return 0
    vowels = 'aeiou'
    return sum(1 for c in domain_string if c in vowels) / len(domain_string)

def get_max_consecutive_consonants(domain_string):
    if not domain_string: return 0
    max_cons = 0
    current_cons = 0
    for char in domain_string:
        # 알파벳이면서 모음이 아니면(자음이면) 카운트 증가
        if char.isalpha() and char not in 'aeiou':
            current_cons += 1
            if current_cons > max_cons:
                max_cons = current_cons
        else:
            current_cons = 0
    return max_cons

def get_digit_ratio(domain_string):
    if not domain_string: return 0
    return sum(1 for c in domain_string if c.isdigit()) / len(domain_string)

# 3. 테스트해볼 도메인 목록
test_domains = [
    "naver", 
    "google",
    "asdfadssdffqwer",
    "qazwsxedcrfvtgbyhnujmikolp", # 아까 AI를 속였던 키보드 긁기 도메인
    "zxcvbnmasdfghjklqwerty",
    "sooplive",
    "chzzk"      
]

print("-" * 70)
print("AI 판독 테스트 시작 (업그레이드 버전)")
print("-" * 70)

# 4. 각 도메인마다 시험 쳐보기
for domain in test_domains:
    # ★ [1차 검문소] 훈련했던 정상 명단에 똑같은 글자가 있는지 먼저 확인
    if domain in whitelist:
        print(f"도메인: {domain:<28} | 판정: 🟢 정상(통과) [1차 DB 컷] | 악성일 확률:   0.0%")
        continue # 아래의 무거운 AI 계산은 건너뛰고 다음 도메인으로 넘어감!

    # -----------------------------------------------------------
    # ★ [2차 검문소] 명단에 없는 '처음 보는 놈'들만 특징 4과목 계산 (사진 속 부분)
    entropy = get_entropy(domain)
    vowel_ratio = get_vowel_ratio(domain)
    max_cons = get_max_consecutive_consonants(domain)
    digit_ratio = get_digit_ratio(domain)
    
    features = pd.DataFrame([[entropy, vowel_ratio, max_cons, digit_ratio]], 
                            columns=['entropy', 'vowel_ratio', 'max_cons', 'digit_ratio'])
    
    prediction = model.predict(features)[0] 
    probabilities = model.predict_proba(features)[0] 
    malware_prob = probabilities[1] * 100 
    
    result_text = "🔴 악성(차단) [2차 AI 판독]" if prediction == 1 else "🟢 정상(통과) [2차 AI 판독]"
    print(f"도메인: {domain:<28} | 판정: {result_text} | 악성일 확률: {malware_prob:>5.1f}%")