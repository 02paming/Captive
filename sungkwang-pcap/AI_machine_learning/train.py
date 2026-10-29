import pandas as pd
import joblib
import time
import os
import json
from sklearn.ensemble import RandomForestClassifier
from sklearn.feature_extraction.text import TfidfVectorizer
from sklearn.model_selection import train_test_split
from sklearn.metrics import confusion_matrix, accuracy_score, precision_score, recall_score, f1_score



#정상도메인이 아주 좋은 최신데이터버전

# # 설정값: 각각 10만 개씩, 총 20만 개 추출
# TARGET_COUNT = 100000 

# print("🟢 1. Tranco 최신 정상 도메인(한국 패치) 다운로드 중...")
# tranco_url = "https://tranco-list.eu/top-1m.csv.zip"
# r = requests.get(tranco_url)
# z = zipfile.ZipFile(io.BytesIO(r.content))
# tranco_df = pd.read_csv(z.open('top-1m.csv'), names=['rank', 'domain'])

# # 한국(.kr) 포함 글로벌 상위권 추출
# kr_domains = tranco_df[tranco_df['domain'].astype(str).str.endswith('.kr')]
# global_top = tranco_df.head(TARGET_COUNT) 
# benign_df = pd.concat([kr_domains, global_top]).drop_duplicates(subset=['domain']).head(TARGET_COUNT)
# benign_df['label'] = 0
# benign_df = benign_df[['domain', 'label']]
# print(f" -> 정상 도메인 {len(benign_df)}개 확보 완료!")

# print("\n🔴 2. 기존 1500만 개 CSV에서 악성(DGA) 도메인 추출 중...")
# dga_list = []
# dga_count = 0

# # 메모리 터짐 방지를 위해 chunksize 사용
# for chunk in pd.read_csv("data/dga_train_500k_balanced.csv", chunksize=500000):
#     # 'label' 컬럼이 'benign'이 아닌 것을 모두 악성으로 간주
#     d_chunk = chunk[chunk['label'] != 'benign']
    
#     if dga_count < TARGET_COUNT:
#         need = TARGET_COUNT - dga_count
#         d_add = d_chunk.head(need)
#         dga_list.append(d_add[['domain']]) 
#         dga_count += len(d_add)
        
#     if dga_count >= TARGET_COUNT:
#         break

# dga_df = pd.concat(dga_list, ignore_index=True)
# dga_df['label'] = 1
# print(f" -> 악성 DGA 도메인 {len(dga_df)}개 확보 완료!")

# print("\n🔄 3. 데이터 혼합 및 무작위 셔플...")
# final_df = pd.concat([benign_df, dga_df], ignore_index=True)
# final_df = final_df.dropna()
# final_df['domain'] = final_df['domain'].astype(str).str.lower()

# # 완벽하게 섞기
# final_df = final_df.sample(frac=1, random_state=42).reset_index(drop=True)

# # 저장
# save_name = "data/dga_train_ready_korea_v1.csv"
# final_df.to_csv(save_name, index=False)
# print(f"\n🎉 완벽합니다! 정상 {len(benign_df)}개 + 악성 {len(dga_df)}개 = 총 {len(final_df)}개가 '{save_name}'로 저장되었습니다.")

# # 1. 방금 만든 불공평한 데이터 불러오기
# df = pd.read_csv('data/dga_train_ready_korea_v1.csv')

# def get_core_domain(domain):
#     # tldextract: www.ba.gov.br -> 'ba' 추출 / rockfish-weatherwear.co.kr -> 'rockfish-weatherwear' 추출
#     ext = tldextract.extract(str(domain))
#     # 만약 악성 데이터처럼 이미 껍데기가 없으면 그대로 반환됨
#     return ext.domain

# print("도메인 껍데기(.com, .co.kr, www 등)를 벗겨내어 공평한 링을 만드는 중...")
# df['domain'] = df['domain'].apply(get_core_domain)

# # 혹시 파싱 후 빈칸이 된 쓰레기값이 있다면 제거
# df = df[df['domain'] != '']
# df = df.dropna()

# # 2. 공평해진 최종 훈련 데이터 저장
# df.to_csv('data/dga_train_ready_korea_v2.csv', index=False)
# print("완료! 이제 dga_train_ready_korea_v2.csv 로 훈련(train.py)을 돌리시면 됩니다.")







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
    
#     # 정상이 25만 개가 안 찼으면 추가
#     if benign_count < target:
#         need = target - benign_count
#         b_add = b_chunk.head(need)
#         benign_list.append(b_add)
#         benign_count += len(b_add)
        
#     # 악성이 25만 개가 안 찼으면 추가
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

# # 훈련용 50만개 파일로 따로 저장해두기
# df_balanced.to_csv("dga_train_500k_balanced.csv", index=False)


#그 50만개 데이터를 다시한번 컬럼을 가공


# 1. 다운로드한 데이터 로드
# df = pd.read_csv("dga_train_500k_balanced.csv") 

# # 2. 컬럼명을 domain과 label로 통일 (원본 파일의 컬럼명에 맞춰 변경 필요)
# df = df.rename(columns={'domain_name': 'domain', 'threat': 'label'})

# # 3. 라벨 데이터를 숫자로 변환 (정상=0, 악성/DGA=1)
# # (예: ExtraHop 데이터의 경우 'benign', 'dga' 문자열로 구분되어 있음)
# df['label'] = df['label'].apply(lambda x: 0 if str(x).lower() == 'benign' else 1)

# # 4. 모델 훈련에 필요한 두 기둥만 추출하여 최종 CSV로 저장
# df[['domain', 'label']].to_csv("dga_train_ready.csv", index=False)




#훈련 작업 시작

# A방식으로 수학공식4가지 특징추출로 훈련 (해본결과 판정이 너무 소극적이고 아쉽게나옴 장점은 엄청빠름)

# start_time = time.time() # 훈련 소요 시간 측정용

# # 1. 엑셀 파일 불러오기
# print("데이터 불러오는 중...")
# df = pd.read_csv('data/dga_train_ready_korea_v2.csv') 
# df = df.dropna(subset=['domain', 'label'])
# df['domain'] = df['domain'].astype(str).str.lower() # 모두 소문자로 통일

# # 2. 실무급 특징(Feature) 추출 함수 4가지 정의
# def get_entropy(domain):
#     if not domain: return 0
#     prob = [float(domain.count(c)) / len(domain) for c in dict.fromkeys(list(domain))]
#     return -sum([p * math.log(p) / math.log(2.0) for p in prob])

# def get_vowel_ratio(domain):
#     if not domain: return 0
#     return sum(1 for c in domain if c in 'aeiou') / len(domain)

# # (NEW) 힌트 3: 최대 연속 자음 개수
# def get_max_consecutive_consonants(domain):
#     if not domain: return 0
#     max_cons = 0
#     current_cons = 0
#     for char in domain:
#         # 모음이나 숫자, 기호가 아니면(즉, 자음이면) 카운트 증가
#         if char.isalpha() and char not in 'aeiou':
#             current_cons += 1
#             if current_cons > max_cons:
#                 max_cons = current_cons
#         else:
#             current_cons = 0
#     return max_cons

# # (NEW) 힌트 4: 숫자 비율
# def get_digit_ratio(domain):
#     if not domain: return 0
#     return sum(1 for c in domain if c.isdigit()) / len(domain)

# # 3. 데이터에 4가지 특징 적용
# print("강력한 실무급 4가지 특징(Feature)을 추출하는 중...")
# df['entropy'] = df['domain'].apply(get_entropy)
# df['vowel_ratio'] = df['domain'].apply(get_vowel_ratio)
# df['max_cons'] = df['domain'].apply(get_max_consecutive_consonants)
# df['digit_ratio'] = df['domain'].apply(get_digit_ratio)

# # 4. 문제(X)와 정답(y) 나누기 (5과목 시험)
# X = df[['entropy', 'vowel_ratio', 'max_cons', 'digit_ratio']]
# y = df['label']

# # 5. 모델 훈련 (더 깐깐하게 트리를 150개로 늘림)
# print("업그레이드 AI 훈련 시작!")
# model = RandomForestClassifier(n_estimators=150, random_state=42)
# model.fit(X, y)

# # 6. 저장
# joblib.dump(model, 'model/dga_model.pkl')
# print(f"훈련 완료! 더 강력해진 'dga_model.pkl' 생성됨 (소요 시간: {time.time() - start_time:.2f}초)")



#B방식으로 (N-gram백터화모델사용으로)초정밀로 확실하게 판정이됨 단 a방식보다 느리기때문에 b를 채택하는데신 속도개선로직을 생각해야함(캐싱도입예정)
start_time = time.time()

# 1. 껍데기 벗긴 순수 알맹이 데이터(v2) 로드
print("데이터 불러오는 중...")
df = pd.read_csv('data/dga_train_ready_korea_v2.csv')
df = df.dropna(subset=['domain', 'label'])
df['domain'] = df['domain'].astype(str).str.lower()

# 2. 문제(X)와 정답(y) 나누기
X_raw = df['domain']
y = df['label']

# 3. 핵심: 문자열 벡터화 (글자를 2~3개씩 쪼개서 수학적 패턴으로 변환)
print("문자열 벡터화(N-gram) 진행 중... (시간이 조금 걸립니다)")
vectorizer = TfidfVectorizer(analyzer='char', ngram_range=(2, 3), max_features=5000)
X_vectorized = vectorizer.fit_transform(X_raw)

# 4. 훈련용(80%)과 테스트용(20%) 데이터 분할 (사진의 개념 적용)
X_train, X_test, y_train, y_test = train_test_split(X_vectorized, y, test_size=0.2, random_state=42)

# 5. 모델 훈련 (X_train과 y_train만 사용)
print("벡터화 기반 업그레이드 AI 훈련 시작!")
model = RandomForestClassifier(n_estimators=150, random_state=42, n_jobs=-1) #class_weight={0: 5.0, 1: 1.0},min_samples_leaf=5
model.fit(X_train, y_train)

print("평가지표(성적표) 계산 중...")
# 6. 테스트용 데이터(X_test)로 시험을 쳐서 예측값(y_pred) 추출 , 혼동 행렬(Confusion Matrix) 계산: TP, TN, FP, FN 분리
y_pred = model.predict(X_test)
tn, fp, fn, tp = confusion_matrix(y_test, y_pred).ravel()

# 7. 평가지표 계산 및 딕셔너리화
metrics_file = 'model/model_metrics.json'
history = []

# 7-1. 기존 성적표 파일이 존재하면 읽어오기
if os.path.exists(metrics_file):
    with open(metrics_file, 'r', encoding='utf-8') as f:
        try:
            history = json.load(f)
        except json.JSONDecodeError:
            history = []

# 7-2. 새 버전 번호 자동 생성 (기존 기록 개수 기준, 예: v1.0, v1.1...)
new_version = f"v1.{len(history)}"

# 7-3. 이번 훈련의 최종 성적표 딕셔너리 생성
current_metrics = {
    "version": new_version,
    "model_type": "기초 버전 RandomForest + N-gram",
    "trained_at": time.strftime("%Y-%m-%d %H:%M:%S"),
    "hyperparameters": {
        "n_estimators": 150,                # 방금 적용한 트리 개수 적어두기
        "max_features": 5000,               # 방금 적용한 단어장 크기 적어두기
        # "class_weight": "0: 5.0, 1: 1.0",   # 페널티 수치 적어두기
        # "min_samples_leaf": 5               # 꼬투리 잡기 방지 수치 적어두기
    },
    "confusion_matrix": {
        "TP": int(tp),
        "TN": int(tn),
        "FP": int(fp),
        "FN": int(fn)
    },
    "scores": {
        "accuracy": round(accuracy_score(y_test, y_pred) * 100, 2),
        "precision": round(precision_score(y_test, y_pred) * 100, 2),
        "recall": round(recall_score(y_test, y_pred) * 100, 2),
        "f1_score": round(f1_score(y_test, y_pred) * 100, 2)
    }
}

# 7-4. 리스트에 방금 친 시험 성적을 추가하고 파일로 덮어쓰기
history.append(current_metrics)
with open(metrics_file, 'w', encoding='utf-8') as f:
  json.dump(history, f, ensure_ascii=False, indent=4)

# 8. 기존처럼 모델과 벡터라이저 저장
joblib.dump(model, 'model/dga_model_vec.pkl')
joblib.dump(vectorizer, 'model/vectorizer.pkl')

print(f"훈련 및 평가 완료! 평가지표가 'model_metrics.json'에 저장되었습니다. (소요 시간: {time.time() - start_time:.2f}초)")

