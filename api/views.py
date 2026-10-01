from rest_framework.decorators import api_view
from rest_framework.response import Response
from rest_framework import status
from django.utils import timezone
from .models import ProspectiveMembers, Employees, NoAccessAddr, NoAccessAddrLog, OnlineIpLog
import datetime
import uuid


# 1. 회원가입 신청 (개인 아이디 입력 복구)
@api_view(['POST'])
def apply_signup(request):
    try:
        data = request.data
        ProspectiveMembers.objects.create(
            member_id=data.get('member_id'),  # 프론트에서 넘어온 개인 아이디
            password=data.get('password'),
            email=data.get('email'),  # 개인 이메일
            address=data.get('address'),
            phone_number=data.get('phone_number'),
            jumin_no=data.get('jumin_no'),
            name=data.get('name')
        )
        return Response({"status": "success"}, status=status.HTTP_201_CREATED)
    except Exception as e:
        return Response({"error": str(e)}, status=status.HTTP_400_BAD_REQUEST)


# 2. 로그인 (직원 조회 후 접속 로그 기록)
@api_view(['POST'])
def login(request):
    emp_id = request.data.get('employee_id')
    password = request.data.get('password')

    # 사원 아이디와 비밀번호로 직원 찾기
    employee = Employees.objects.filter(employee_id=emp_id, password=password).first()

    if employee:
        # 로그인 성공 시 온라인 로그에 기록 (테스트용으로 IP 임의 생성)
        client_ip = request.META.get('REMOTE_ADDR', '192.168.0.100')
        OnlineIpLog.objects.create(employee=employee, online_ip=client_ip)

        return Response({
            "status": "success",
            "user": {
                "emp_id": employee.employee_id,
                "name": employee.name,
                "is_manager": employee.is_manager  # 💡 이 줄이 반드시 포함되어야 합니다!
            }
        })
    return Response({"status": "error", "message": "정보가 일치하지 않습니다."}, status=status.HTTP_401_UNAUTHORIZED)


# 3. 차단 정책 목록 불러오기
@api_view(['GET'])
def get_blocklist(request):
    policies = NoAccessAddr.objects.filter(deleted_at__isnull=True).values('no_access_domain', 'no_access_ip')
    return Response(list(policies))


# 4. 차단 정책 추가
@api_view(['POST'])
def add_policy(request):
    try:
        NoAccessAddr.objects.create(
            no_access_domain=request.data.get('no_access_domain'),
            no_access_ip=request.data.get('no_access_ip')
        )
        return Response({"status": "success"}, status=status.HTTP_201_CREATED)
    except Exception as e:
        return Response({"error": str(e)}, status=status.HTTP_400_BAD_REQUEST)


# 5. 위협 로그 수집 (PCAP 엔진 연동)
@api_view(['POST'])
def report_violation(request):
    source_ip = request.data.get('source_ip')
    blocked_ip = request.data.get('blocked_ip')

    try:
        policy = NoAccessAddr.objects.filter(no_access_ip=blocked_ip).first()
        online_log = OnlineIpLog.objects.filter(online_ip=source_ip).order_by('-login_time').first()

        if policy and online_log:
            NoAccessAddrLog.objects.create(employee=online_log.employee, no_access_domain=policy)
            return Response({"status": "success"}, status=status.HTTP_201_CREATED)
        return Response({"status": "error"}, status=status.HTTP_404_NOT_FOUND)
    except Exception as e:
        return Response({"error": str(e)}, status=status.HTTP_500_INTERNAL_SERVER_ERROR)


# 6. 대시보드 - 실시간 접속 사원
@api_view(['GET'])
def get_online_users(request):
    logs = OnlineIpLog.objects.select_related('employee').order_by('-login_time')[:10]
    data = [{"id": log.id, "emp_name": log.employee.name, "ip": log.online_ip,
             "login_time": log.login_time.strftime("%Y-%m-%d %H:%M:%S")} for log in logs]
    return Response(data)


# 7. 대시보드 - 위협 탐지 로그
@api_view(['GET'])
def get_threat_logs(request):
    logs = NoAccessAddrLog.objects.select_related('employee', 'no_access_domain').order_by('-access_time')[:10]
    data = [{"id": log.id, "violator": f"{log.employee.name} ({log.employee.employee_id})",
             "blocked_domain": log.no_access_domain.no_access_domain,
             "time": log.access_time.strftime("%Y-%m-%d %H:%M:%S")} for log in logs]
    return Response(data)


# 8. 사원 목록 조회 (사번 ST~ 조합하여 전송)
@api_view(['GET'])
def get_employees(request):
    employees = Employees.objects.all()
    data = []
    for emp in employees:
        current_ym = emp.hire_date.strftime('%Y%m') if emp.hire_date else datetime.datetime.now().strftime('%Y%m')
        emp_code = f"ST{current_ym}{emp.employee_number:02d}"  # 동적 사번 생성
        data.append({
            "employee_id": emp.employee_id,
            "emp_code": emp_code,
            "name": emp.name,
            "phone_number": emp.phone_number,
            "email": emp.email,
            "jumin_no": emp.jumin_no,
            "address": emp.address
        })
    return Response(data)


# 9. 사원 정보 업데이트 (주소, 연락처만 수정 가능하도록 제한)
@api_view(['POST'])
def update_employee(request):
    emp_id = request.data.get('employee_id')
    try:
        employee = Employees.objects.get(employee_id=emp_id)
        # 중요 정보(사번, 이름, 주민번호, 이메일)는 덮어씌우지 않음
        employee.phone_number = request.data.get('phone_number', employee.phone_number)
        employee.address = request.data.get('address', employee.address)
        employee.save()
        return Response({"status": "success", "message": "수정 완료"})
    except Employees.DoesNotExist:
        return Response({"status": "error"}, status=status.HTTP_404_NOT_FOUND)


# 10. 가입 대기자 목록 조회 (관리자용)
@api_view(['GET'])
def get_pending_members(request):
    pending = ProspectiveMembers.objects.all().values()
    return Response(list(pending))


# 11. 가입 승인 (회사 이메일 발급 및 사번 조합 로직 완벽 수정)
@api_view(['POST'])
def approve_member(request):
    member_id = request.data.get('member_id')
    try:
        # 1. 대기자 정보 가져오기
        pending_user = ProspectiveMembers.objects.get(member_id=member_id)

        # 2. 회사 이메일 자동 생성 (개인이메일ID @ ST.co.kr)
        personal_email_id = pending_user.email.split('@')[0]
        company_email = f"{personal_email_id}@ST.co.kr"

        # 3. 정직원 테이블에 생성 (이때 DB에 의해 employee_number(PK)가 자동 부여됨)
        emp = Employees.objects.create(
            employee_id=pending_user.member_id,  # 프론트에서 받은 개인 아이디(test1111 등)
            password=pending_user.password,
            email=company_email,  # 💡 발급된 회사 이메일 저장
            address=pending_user.address,
            phone_number=pending_user.phone_number,
            jumin_no=pending_user.jumin_no,
            name=pending_user.name,
            is_manager=False
            # 💡 hire_date는 auto_now_add=True이므로 생략해도 자동 입력됨
        )

        # 4. 방금 생성된 직원의 고유번호(PK)를 가져와 사번(ST~) 조합
        current_ym = datetime.datetime.now().strftime('%Y%m')
        # employee_number를 2자리 숫자로 포맷 (예: 1 -> 01, 15 -> 15)
        emp_code = f"ST{current_ym}{emp.employee_number:02d}"

        # 5. 처리가 끝난 대기자 기록은 삭제
        pending_user.delete()

        # 프론트엔드로 성공 메시지 전달 (사번 포함)
        return Response({
            "status": "success",
            "message": f"{emp.name}님의 가입이 승인되었습니다.\n공식 사번: {emp_code}\n회사 이메일: {company_email}"
        })

    except ProspectiveMembers.DoesNotExist:
        return Response({"status": "error", "message": "해당 가입 대기자를 찾을 수 없습니다."}, status=status.HTTP_404_NOT_FOUND)
    except Exception as e:
        # 💡 에러 발생 시 정확히 어떤 에러인지 콘솔에 출력 (디버깅용)
        print(f"승인 처리 에러: {str(e)}")
        return Response({"status": "error", "message": str(e)}, status=status.HTTP_400_BAD_REQUEST)


# 12. 가입 거절 (대기자 기록 삭제)
@api_view(['POST'])
def reject_member(request):
    member_id = request.data.get('member_id')
    try:
        pending_user = ProspectiveMembers.objects.get(member_id=member_id)
        pending_user.delete()
        return Response({"status": "success", "message": "가입 요청이 거절(삭제)되었습니다."})
    except ProspectiveMembers.DoesNotExist:
        return Response({"status": "error"}, status=status.HTTP_404_NOT_FOUND)


# 13. 마이페이지 내 정보 조회
@api_view(['POST'])
def get_my_info(request):
    emp_id = request.data.get('employee_id')
    try:
        emp = Employees.objects.get(employee_id=emp_id)
        current_ym = emp.hire_date.strftime('%Y%m') if emp.hire_date else datetime.datetime.now().strftime('%Y%m')
        emp_code = f"ST{current_ym}{emp.employee_number:02d}"

        return Response({
            "status": "success",
            "data": {
                "emp_code": emp_code,
                "employee_id": emp.employee_id,
                "name": emp.name,
                "email": emp.email,
                "address": emp.address,
                "phone_number": emp.phone_number,
                "jumin_no": emp.jumin_no
            }
        })
    except Employees.DoesNotExist:
        return Response({"status": "error"}, status=status.HTTP_404_NOT_FOUND)


# 14. 회원가입 중복 검사 API
@api_view(['POST'])
def check_duplicate(request):
    field = request.data.get('field')  # 어떤 항목을 검사할지 (예: member_id)
    value = request.data.get('value')  # 사용자가 입력한 값

    if not field or not value:
        return Response({"status": "error", "message": "잘못된 요청입니다."}, status=status.HTTP_400_BAD_REQUEST)

    # 대기자 테이블과 정직원 테이블을 모두 검색하기 위한 딕셔너리 생성
    search_kwargs = {field: value}

    # 두 테이블 중 하나라도 해당 데이터가 존재하면 True
    is_duplicate = (
            ProspectiveMembers.objects.filter(**search_kwargs).exists() or
            Employees.objects.filter(**search_kwargs).exists()
    )

    if is_duplicate:
        # 필드명에 따라 에러 메시지 다르게 설정
        field_names = {
            'member_id': '아이디',
            'email': '이메일',
            'phone_number': '전화번호',
            'jumin_no': '주민등록번호'
        }
        name_kr = field_names.get(field, field)
        return Response({
            "is_duplicate": True,
            "message": f"이미 사용 중이거나 가입 대기 중인 {name_kr}입니다."
        })
    else:
        return Response({"is_duplicate": False})
