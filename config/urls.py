from django.urls import path
from api import views

urlpatterns = [
    # 웹(React) 연동 주소
    path('auth/apply/', views.apply_signup, name='apply_signup'),
    path('auth/login/', views.login, name='login'),

    # PCAP 엔진 및 정책 연동 주소
    path('policies/blocklist/', views.get_blocklist, name='get_blocklist'),
    path('policies/add/', views.add_policy, name='add_policy'),
    path('logs/violation/', views.report_violation, name='report_violation'),

    # 대시보드 연동 주소 (새로 추가)
    path('dashboard/online/', views.get_online_users, name='get_online_users'),
    path('dashboard/threats/', views.get_threat_logs, name='get_threat_logs'),

    # 사원 관리 주소 (새로 추가)
    path('employees/', views.get_employees, name='get_employees'),
    path('employees/update/', views.update_employee, name='update_employee'),

    # 회원가입 승인 관리 주소 (새로 추가)
    path('auth/pending/', views.get_pending_members, name='get_pending_members'),
    path('auth/approve/', views.approve_member, name='approve_member'),
    path('auth/reject/', views.reject_member, name='reject_member'),

    path('auth/me/', views.get_my_info, name='get_my_info'),
    path('auth/check-duplicate/', views.check_duplicate, name='check_duplicate'),
]
