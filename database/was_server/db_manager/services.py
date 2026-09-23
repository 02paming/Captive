from .models import Users


def create_new_user(user_id, raw_password):
    """새로운 사용자를 DB에 생성하는 모듈"""
    # 1. 중복 체크
    if Users.objects.filter(user_id=user_id).exists():
        return False, "이미 존재하는 아이디입니다."

    # 2. DB에 데이터 삽입 (INSERT)
    Users.objects.create(user_id=user_id, user_password=raw_password)
    return True, "회원가입이 완료되었습니다."


def authenticate_user(user_id, raw_password):
    """사용자 로그인 정보를 검증하는 모듈"""
    try:
        # DB에서 회원 조회 (SELECT)
        user = Users.objects.get(user_id=user_id, user_password=raw_password)
        return True, user
    except Users.DoesNotExist:
        return False, "아이디 또는 비밀번호가 일치하지 않습니다."