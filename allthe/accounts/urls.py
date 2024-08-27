from django.urls import path, re_path
from drf_yasg import openapi
from drf_yasg.views import get_schema_view
from rest_framework import permissions

from .views import (
    CheckBusinessStatusView,
    GoogleCallback, GoogleLogin, GoogleLogout,
    KakaoCallback, KakaoLogin, KakaoLogout,
    NaverCallback, NaverLogin, NaverLogout,
    PasswordResetView, RefreshTokenView, UserAccountView,
    UserLoginView, UserLogoutView, UsernameCheckView,
    UserProfileView, FinalSignupView, SendVerificationCodeView
)

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
    # 사용자 관련 API
    path("register/", FinalSignupView.as_view(), name="user-register"),
    path("login/", UserLoginView.as_view(), name="user-login"),
    path("profile/", UserProfileView.as_view(), name="user-profile"),
    path("logout/", UserLogoutView.as_view(), name="user-logout"),
    path("refresh-token/", RefreshTokenView.as_view(), name="refresh-token"),
    path("password-reset/", PasswordResetView.as_view(), name="password-reset"),
    path("account-delete/", UserAccountView.as_view(), name="account-delete"),
    path("check-username/", UsernameCheckView.as_view(), name="check-username"),
    path("send-verification-code/", SendVerificationCodeView.as_view(), name="send-verification-code"),

    # 소셜 로그인 관련 API
    path("kakao/login/", KakaoLogin.as_view(), name="kakao-login"),
    path("kakao/callback/", KakaoCallback.as_view(), name="kakao-callback"),
    path("kakao/logout/", KakaoLogout.as_view(), name="kakao-logout"),
    path("google/login/", GoogleLogin.as_view(), name="google-login"),
    path("google/callback/", GoogleCallback.as_view(), name="google-callback"),
    path("google/logout/", GoogleLogout.as_view(), name="google-logout"),
    path("naver/login/", NaverLogin.as_view(), name="naver-login"),
    path("naver/callback/", NaverCallback.as_view(), name="naver-callback"),
    path("naver/logout/", NaverLogout.as_view(), name="naver-logout"),

    # 사업자번호 상태 확인 API
    path("check-business-status/", CheckBusinessStatusView, name="check-business-status"),

    # Swagger 문서화 URL
    re_path(
        r"^swagger/$",
        schema_view.with_ui("swagger", cache_timeout=0),
        name="schema-swagger-ui",
    ),
]
