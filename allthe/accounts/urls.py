from django.urls import path
from django.urls import re_path
from drf_yasg import openapi
from drf_yasg.views import get_schema_view
from rest_framework import permissions

from .views import CheckBusinessStatusView
from .views import FinalSignupView
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
from .views import SendVerificationCodeView
from .views import UpdateRoleView
from .views import UserAccountView
from .views import UserLoginView
from .views import UserLogoutView
from .views import UsernameCheckView
from .views import UserProfileView
from .views import VerifyCodeView

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
    path(
        "password-reset/confirm",
        PasswordResetView.as_view(),
        name="password-reset-confirm",
    ),
    path("account-delete/", UserAccountView.as_view(), name="account-delete"),
    path("check-username/", UsernameCheckView.as_view(), name="check-username"),
    path(
        "send-verification-code/",
        SendVerificationCodeView.as_view(),
        name="send-verification-code",
    ),
    path("verify-code/", VerifyCodeView.as_view(), name="verify_code"),
    path("me/role/", UpdateRoleView.as_view(), name="update_role"),
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
        "check-business-status/", CheckBusinessStatusView, name="check-business-status"
    ),
    # Swagger 문서화 URL
    re_path(
        r"^swagger/$",
        schema_view.with_ui("swagger", cache_timeout=0),
        name="schema-swagger-ui",
    ),
]
