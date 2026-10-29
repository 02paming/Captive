from rest_framework import serializers
from .models import ProspectiveMembers, Employees, NoAccessAddr


class ProspectiveMemberSerializer(serializers.ModelSerializer):
    class Meta:
        model = ProspectiveMembers
        fields = '__all__'


class EmployeeSerializer(serializers.ModelSerializer):
    class Meta:
        model = Employees
        fields = ['employee_id', 'name', 'email', 'is_manager']  # 보안을 위해 비밀번호는 제외


class NoAccessAddrSerializer(serializers.ModelSerializer):
    class Meta:
        model = NoAccessAddr
        fields = ['no_access_domain', 'no_access_ip']
