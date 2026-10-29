#백엔드 서버 실행 방법
1. 백엔드 서버가 깔린 컴퓨터에 원격 접속: ssh root@서버ip
2. 가상 환경 파일이 있는 위치까지 이동: cd ./.../
3. 가상 환경 실행: source 가상_환경_파일/bin/activate
4. 접속할 장고의 manage.py 파일이 있는 위치까지 이동: cd ./장고_프로젝트_파일
5-1. Web 서버와 통신할 백엔드 서버 실행: python manage.py runserver 0.0.0.0:8000
5-2. Pcap 서버와 통신할 백엔드 서버 실행: python 백엔드_파일명.py