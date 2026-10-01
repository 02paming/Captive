from django.db import models


# 1. 가입 대기자 테이블 (prospective_members)
class ProspectiveMembers(models.Model):
    member_id = models.CharField(max_length=50, primary_key=True)  # PK
    password = models.CharField(max_length=255)
    date_of_request = models.DateField(auto_now_add=True)
    email = models.CharField(max_length=255, unique=True)
    address = models.CharField(max_length=255)
    phone_number = models.CharField(max_length=11, unique=True)
    jumin_no = models.CharField(max_length=13, unique=True)
    name = models.CharField(max_length=255)

    class Meta:
        db_table = 'prospective_members'


# 2. 정직원 테이블 (employees)
class Employees(models.Model):
    employee_number = models.AutoField(primary_key=True)  # PK (INT형 자동증가)
    employee_id = models.CharField(max_length=50, unique=True)  # 사원 아이디 (member_id 복사본)
    hire_date = models.DateField(auto_now_add=True)  # 입사일
    deleted_at = models.DateField(null=True, blank=True)
    email = models.CharField(max_length=255, unique=True)
    address = models.CharField(max_length=255)
    phone_number = models.CharField(max_length=11, unique=True)
    jumin_no = models.CharField(max_length=13, unique=True)
    is_manager = models.BooleanField(default=False)
    name = models.CharField(max_length=255)
    password = models.CharField(max_length=255)

    class Meta:
        db_table = 'employees'


# 3. 차단 정책 테이블 (no_access_addr)
class NoAccessAddr(models.Model):
    no_access_domain = models.CharField(max_length=255, primary_key=True)  # PK
    no_access_ip = models.CharField(max_length=15)
    deleted_at = models.DateField(null=True, blank=True)

    class Meta:
        db_table = 'no_access_addr'


# 4. 차단 로그 테이블 (no_access_addr_log)
class NoAccessAddrLog(models.Model):
    # db_column을 지정하여 엑셀 문서의 'employee_id'와 일치시킴
    employee = models.ForeignKey(Employees, on_delete=models.CASCADE, db_column='employee_id')
    no_access_domain = models.ForeignKey(NoAccessAddr, on_delete=models.CASCADE, db_column='no_access_domain')
    access_time = models.DateTimeField(auto_now_add=True)

    class Meta:
        db_table = 'no_access_addr_log'


# 5. 접속 로그 테이블 (online_ip_log)
class OnlineIpLog(models.Model):
    employee = models.ForeignKey(Employees, on_delete=models.CASCADE, db_column='employee_id')
    online_ip = models.CharField(max_length=15)
    login_time = models.DateTimeField(auto_now_add=True)

    class Meta:
        db_table = 'online_ip_log'
