import requests
import csv
from datetime import datetime

# GITHUB_TOKEN, REPO만 바꿔서 사용!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!#################

# GitHub Personal Access Token (필요 시 설정)
GITHUB_TOKEN = "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"
# 대상 리포지토리 (형식: "owner/repo")
REPO = "02paming/intranet-access-controller"

# GitHub API URL
API_URL = f"https://api.github.com/repos/{REPO}/issues"

# 헤더 설정
headers = {
    "Authorization": f"token {GITHUB_TOKEN}" if GITHUB_TOKEN else None
}

# 이슈 데이터 가져오기
def fetch_issues(api_url):
    issues = []
    page = 1

    while True:
        response = requests.get(api_url, headers=headers, params={"state": "all", "per_page": 100, "page": page})
        if response.status_code != 200:
            print(f"Failed to fetch issues: {response.status_code} {response.reason}")
            break

        data = response.json()
        if not data:  # 더 이상 데이터가 없으면 중단
            break

        issues.extend(data)
        page += 1

    return issues

# CSV 파일로 저장
def save_issues_to_csv(issues, filename):
    with open(filename, mode="w", newline="", encoding="utf-8") as file:
        writer = csv.writer(file)
        # 헤더 작성
        writer.writerow(["Number", "Title", "Body", "State", "Created At", "Updated At", "Closed At", "URL"])

        # 데이터 작성
        for issue in issues:
            writer.writerow([issue["number"], issue["title"], issue["body"], issue["state"], issue["created_at"], issue["updated_at"], issue["closed_at"], issue["html_url"]])

# 실행
if __name__ == "__main__":
    timestamp = datetime.now().strftime("%Y%m%d%H%M")
    issues = fetch_issues(API_URL)
    filename = f"github_issues_{timestamp}.csv"
    if issues:
        save_issues_to_csv(issues, filename)
        print("Issues have been saved to " + filename)
    else:
        print("No issues found or failed to fetch issues.")
