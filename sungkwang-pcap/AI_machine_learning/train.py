import pandas as pd
import math
from sklearn.ensemble import RandomForestClassifier
import joblib
import time

# #15,000,000개를 100,000만개로 추려서 csv파일로 만드는 과정

# chunk_size = 500000  # 50만 개씩 잘라서 가볍게 읽기
# benign_list, dga_list = [], []
# benign_count, dga_count = 0, 0
# target = 250000  # 각각 25만 개씩, 총 50만 개 목표

# print("데이터를 골고루 25만 개씩 추출합니다...")

# # 파일을 조각내서 스트리밍 방식으로 읽기 (메모리 안전)
# for chunk in pd.read_csv("final_15million.csv", chunksize=chunk_size):
#     # 각 조각에서 정상/악성 분리
#     b_chunk = chunk[chunk['label'] == 'benign']
#     d_chunk = chunk[chunk['label'] != 'benign'] # benign이 아닌 것을 모두 악성(dga)으로 간주
    
#     # 정상이 5만 개가 안 찼으면 추가
#     if benign_count < target:
#         need = target - benign_count
#         b_add = b_chunk.head(need)
#         benign_list.append(b_add)
#         benign_count += len(b_add)
        
#     # 악성이 5만 개가 안 찼으면 추가
#     if dga_count < target:
#         need = target - dga_count
#         d_add = d_chunk.head(need)
#         dga_list.append(d_add)
#         dga_count += len(d_add)
        
#     # 둘 다 5만 개를 채웠으면 즉시 파일 읽기 종료
#     if benign_count >= target and dga_count >= target:
#         break

# # 추출한 데이터 하나로 합치고 무작위로 섞기(셔플)
# df_balanced = pd.concat(benign_list + dga_list, ignore_index=True)
# df_balanced = df_balanced.sample(frac=1, random_state=42).reset_index(drop=True)

# print(f"추출 완료: 정상 {len(df_balanced[df_balanced['label']=='benign'])}개, 악성 {len(df_balanced[df_balanced['label']!='benign'])}개")

# # 훈련용 10만개 파일로 따로 저장해두기
# df_balanced.to_csv("dga_train_500k_balanced.csv", index=False)


#그 10만개 데이터를 다시한번 컬럼을 가공


# # 1. 다운로드한 데이터 로드
# df = pd.read_csv("dga_train_500k_balanced.csv") 

# # 2. 컬럼명을 domain과 label로 통일 (원본 파일의 컬럼명에 맞춰 변경 필요)
# df = df.rename(columns={'domain_name': 'domain', 'threat': 'label'})

# # 3. 라벨 데이터를 숫자로 변환 (정상=0, 악성/DGA=1)
# # (예: ExtraHop 데이터의 경우 'benign', 'dga' 문자열로 구분되어 있음)
# df['label'] = df['label'].apply(lambda x: 1 if str(x).lower() == 'dga' else 0)

# # 4. 모델 훈련에 필요한 두 기둥만 추출하여 최종 CSV로 저장
# df[['domain', 'label']].to_csv("dga_train_ready.csv", index=False)


#훈련 작업 시작

start_time = time.time() # 훈련 소요 시간 측정용

# 1. 엑셀 파일 불러오기
print("데이터 불러오는 중...")
df = pd.read_csv('dga_train_ready.csv') 
df = df.dropna(subset=['domain', 'label'])
df['domain'] = df['domain'].astype(str).str.lower() # 모두 소문자로 통일

# 2. 실무급 특징(Feature) 추출 함수 5가지 정의
def get_entropy(domain):
    if not domain: return 0
    prob = [float(domain.count(c)) / len(domain) for c in dict.fromkeys(list(domain))]
    return -sum([p * math.log(p) / math.log(2.0) for p in prob])

def get_vowel_ratio(domain):
    if not domain: return 0
    return sum(1 for c in domain if c in 'aeiou') / len(domain)

# (NEW) 힌트 3: 최대 연속 자음 개수
def get_max_consecutive_consonants(domain):
    if not domain: return 0
    max_cons = 0
    current_cons = 0
    for char in domain:
        # 모음이나 숫자, 기호가 아니면(즉, 자음이면) 카운트 증가
        if char.isalpha() and char not in 'aeiou':
            current_cons += 1
            if current_cons > max_cons:
                max_cons = current_cons
        else:
            current_cons = 0
    return max_cons

# (NEW) 힌트 4: 숫자 비율
def get_digit_ratio(domain):
    if not domain: return 0
    return sum(1 for c in domain if c.isdigit()) / len(domain)

# 3. 데이터에 5가지 특징 적용
print("강력한 실무급 5가지 특징(Feature)을 추출하는 중...")
df['length'] = df['domain'].apply(len)
df['entropy'] = df['domain'].apply(get_entropy)
df['vowel_ratio'] = df['domain'].apply(get_vowel_ratio)
df['max_cons'] = df['domain'].apply(get_max_consecutive_consonants)
df['digit_ratio'] = df['domain'].apply(get_digit_ratio)

# 4. 문제(X)와 정답(y) 나누기 (5과목 시험)
X = df[['length', 'entropy', 'vowel_ratio', 'max_cons', 'digit_ratio']]
y = df['label']

# 5. 모델 훈련 (더 깐깐하게 트리를 150개로 늘림)
print("업그레이드 AI 훈련 시작!")
model = RandomForestClassifier(n_estimators=150, random_state=42)
model.fit(X, y)

# 6. 저장
joblib.dump(model, 'dga_model.pkl')
print(f"훈련 완료! 더 강력해진 'dga_model.pkl' 생성됨 (소요 시간: {time.time() - start_time:.2f}초)")