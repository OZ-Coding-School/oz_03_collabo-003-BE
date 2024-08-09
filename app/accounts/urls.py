from django.urls import path

from .views import PasswordResetView
from .views import RefreshTokenView
from .views import UserAccountView
from .views import UserLoginView
from .views import UserLogoutView
from .views import UserProfileView
from .views import UserRegistrationView

urlpatterns = [
    # 회원가입 요청을 처리하는 API
    # 사용자가 회원가입을 위해 이메일 확인 링크를 수신하고 가입을 완료할 수 있도록 합니다.
    path("register/", UserRegistrationView.as_view(), name="user-register"),
    # 로그인 API
    # 사용자가 이메일과 비밀번호로 로그인하고 JWT 액세스 토큰과 리프레시 토큰을 받습니다.
    path("login/", UserLoginView.as_view(), name="user-login"),
    # 사용자 정보 조회 API
    # JWT 토큰을 통해 인증된 사용자의 프로필 정보를 반환합니다.
    path("profile/", UserProfileView.as_view(), name="user-profile"),
    # 로그아웃 API
    # 사용자가 로그아웃하고 JWT 토큰 및 리프레시 토큰 쿠키를 삭제합니다.
    path("logout/", UserLogoutView.as_view(), name="user-logout"),
    # 리프레시 토큰 API
    # 유효한 리프레시 토큰을 제공하면 새로운 액세스 토큰을 발급받습니다.
    path("refresh-token/", RefreshTokenView.as_view(), name="refresh-token"),
    # 비밀번호 재설정 요청 및 확인 API
    # 비밀번호 재설정 요청을 받고, 비밀번호를 재설정하기 위한 링크를 이메일로 발송합니다.
    # 유효한 재설정 토큰을 통해 비밀번호를 새로 설정할 수 있습니다.
    path("password-reset/", PasswordResetView.as_view(), name="password-reset"),
    # 회원 탈퇴 API
    # 인증된 사용자가 자신의 계정을 삭제하고 JWT 토큰을 무효화합니다.
    path("account-delete/", UserAccountView.as_view(), name="account-delete"),
]
