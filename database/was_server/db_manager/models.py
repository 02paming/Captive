from django.db import models

# Create your models here.

class Users(models.Model):
    user_id = models.CharField(max_length=50, primary_key=True)
    user_password = models.CharField(max_length=255)

    class Meta:
        db_table = 'users' # DB에 실제 생성되어 있는 테이블명
        managed = False    # Django의 자동 마이그레이션 대상에서 제외