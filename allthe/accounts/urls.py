from django.urls import path
from django.urls import re_path
from drf_yasg import openapi
from drf_yasg.views import get_schema_view
from rest_framework import permissions

from .views import CheckBusinessStatusView
from .views import GoogleCallback
from .views import GoogleLogin
from .views import GoogleLogout
from .views import KakaoCallback
from .views import KakaoLogin
from .views import KakaoLogout
from .views import NaverCallback
from .views import NaverLogin
from .views import NaverLogout
from .views import PasswordResetView
from .views import RefreshTokenView
from .views import UserAccountView
from .views import UserLoginView
from .views import UserLogoutView
from .views import UsernameCheckView
from .views import UserProfileView
from .views import UserRegistrationView

schema_view = get_schema_view(
    openapi.Info(
        title="Social Login API",
        default_version="v1",
        description="Documentation of Social Login APIs",
        terms_of_service="https://www.google.com/policies/terms/",
        contact=openapi.Contact(email="contact@myapi.local"),
        license=openapi.License(name="BSD License"),
    ),
    public=True,
    permission_classes=(permissions.AllowAny,),
)

urlpatterns = [
    # 회원가입 요청을 처리하는 API
    path("register/", UserRegistrationView.as_view(), name="user-register"),
    # 로그인 API
    path("login/", UserLoginView.as_view(), name="user-login"),
    # 사용자 정보 조회 API
    path("profile/", UserProfileView.as_view(), name="user-profile"),
    # 로그아웃 API
    path("logout/", UserLogoutView.as_view(), name="user-logout"),
    # 리프레시 토큰 API
    path("refresh-token/", RefreshTokenView.as_view(), name="refresh-token"),
    # 비밀번호 재설정 요청 및 확인 API
    path("password-reset/", PasswordResetView.as_view(), name="password-reset"),
    # 회원 탈퇴 API
    path("account-delete/", UserAccountView.as_view(), name="account-delete"),
    # 사용자 이름 중복 확인 API
    path("check-username/", UsernameCheckView.as_view(), name="check-username"),
    # 소셜 로그인 관련 API
    path("kakao/login/", KakaoLogin.as_view(), name="kakao-login"),
    path("kakao/login/callback/", KakaoCallback.as_view(), name="kakao-callback"),
    path("kakao/logout/", KakaoLogout.as_view(), name="kakao-logout"),
    path("google/login/", GoogleLogin.as_view(), name="google-login"),
    path("google/login/callback/", GoogleCallback.as_view(), name="google-callback"),
    path("google/logout/", GoogleLogout.as_view(), name="google-logout"),
    path("naver/login/", NaverLogin.as_view(), name="naver-login"),
    path("naver/login/callback/", NaverCallback.as_view(), name="naver-callback"),
    path("naver/logout/", NaverLogout.as_view(), name="naver-logout"),
    # 사업자번호 상태 확인 API
    path(
        "check-business-status/",
        CheckBusinessStatusView,
        name="check-business-status",
    ),
    # Swagger URL
    re_path(
        r"^swagger/$",
        schema_view.with_ui("swagger", cache_timeout=0),
        name="schema-swagger-ui",
    ),
]
