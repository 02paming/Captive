from django.shortcuts import render, redirect
from . import services  # 분리한 DB 모듈 가져오기


def create_user_view(request):
    if request.method == 'POST':
        input_id = request.POST.get('user_id')
        input_pw = request.POST.get('user_password')

        # 서비스 모듈 호출
        is_success, message = services.create_new_user(input_id, input_pw)

        if is_success:
            return redirect('login')
        else:
            return render(request, 'signup.html', {'error': message})


def login_user_view(request):
    if request.method == 'POST':
        input_id = request.POST.get('user_id')
        input_pw = request.POST.get('user_password')

        # 서비스 모듈 호출
        is_success, result = services.authenticate_user(input_id, input_pw)

        if is_success:
            user = result
            request.session['user_id'] = user.user_id  # 세션 저장
            return redirect('main')
        else:
            error_message = result
            return render(request, 'login.html', {'error': error_message})