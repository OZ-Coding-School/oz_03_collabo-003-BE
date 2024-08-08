from django.urls import path

from .views import DeleteAccountView
from .views import LoginView
from .views import LogoutView
from .views import PasswordResetConfirmView
from .views import PasswordResetRequestView
from .views import RegisterView
from .views import UserView

# URL 패턴 정의
urlpatterns = [
    path("register/", RegisterView.as_view(), name="register"),  # 회원가입
    path("login/", LoginView.as_view(), name="login"),  # 로그인
    path(
        "user/", UserView.as_view(), name="user"
    ),  # 사용자 정보 조회 (쿠키로 JWT 토큰 인증)
    path("logout/", LogoutView.as_view(), name="logout"),  # 로그아웃
    path(
        "delete/", DeleteAccountView.as_view(), name="delete-account"
    ),  # 계정 삭제 (회원 탈퇴)
    path(
        "password-reset/",
        PasswordResetRequestView.as_view(),
        name="password-reset-request",
    ),  # 비밀번호 재설정 요청
    path(
        "password-reset/confirm",
        PasswordResetConfirmView.as_view(),
        name="password-reset-confirm",
    ),  # 비밀번호 재설정 확인
]
