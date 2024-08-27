import datetime
import json
import os
import random
import jwt
import requests
from django.conf import settings
from django.contrib.auth import get_user_model
from django.core.mail import send_mail
from django.http import HttpResponse
from django.http import JsonResponse
from django.shortcuts import redirect
from django.urls import reverse
from django.utils import timezone
from django.views import View
from django.views.decorators.csrf import csrf_exempt
from dotenv import load_dotenv
from drf_yasg import openapi
from drf_yasg.utils import swagger_auto_schema
from rest_framework import status
from rest_framework.exceptions import AuthenticationFailed
from rest_framework.permissions import BasePermission
from rest_framework.permissions import IsAuthenticated
from rest_framework.response import Response
from rest_framework.views import APIView
from rest_framework_simplejwt.tokens import RefreshToken

from .serializers import PasswordResetConfirmSerializer
from .serializers import PasswordResetRequestSerializer
from .serializers import UsernameCheckSerializer
from .serializers import UserSerializer
from .serializers import EmailSerializer
from .models import VerificationCode


User = get_user_model()


load_dotenv()

KAKAO_APP_KEY = os.getenv("KAKAO_APP_KEY")
KAKAO_SECRET = os.getenv("KAKAO_SECRET")
GOOGLE_APP_KEY = os.getenv("GOOGLE_APP_KEY")
GOOGLE_SECRET = os.getenv("GOOGLE_SECRET")
NAVER_APP_KEY = os.getenv("NAVER_APP_KEY")
NAVER_SECRET = os.getenv("NAVER_SECRET")
PORTONE_APP_KEY = os.getenv("PORTONE_APP_KEY")
PORTONE_SECRET = os.getenv("PORTONE_SECRET")
PORTONE_CHANNEL_KEY = os.getenv("PORTONE_CHANNEL_KEY")



    
class UsernameCheckView(APIView):
    def post(self, request):
        serializer = UsernameCheckSerializer(data=request.data)
        if serializer.is_valid():
            username = serializer.validated_data["username"]
            exists = User.objects.filter(username=username).exists()
            if exists:
                return Response({"message": "이미 존재하는 닉네임입니다."}, status=status.HTTP_400_BAD_REQUEST)
            else:
                return Response({"message": "사용 가능한 닉네임입니다."}, status=status.HTTP_200_OK)
        return Response(serializer.errors, status=status.HTTP_400_BAD_REQUEST)
    

class SendVerificationCodeView(APIView):
    """
    이메일로 인증 코드를 전송하는 API
    - 사용자가 제공한 이메일 주소로 인증 코드를 발송합니다.
    """

    def post(self, request):
        serializer = EmailSerializer(data=request.data)
        if serializer.is_valid():
            email = serializer.validated_data["email"]

            # 이메일로 인증 코드 생성 및 저장
            verification_code = str(random.randint(100000, 999999))
            expires_at = timezone.now() + datetime.timedelta(minutes=10)  # 코드 만료 시간 설정

            # 인증 코드 저장
            VerificationCode.objects.update_or_create(
                email=email,
                defaults={"code": verification_code, "expires_at": expires_at},
            )

            # 인증 코드 발송
            send_mail(
                "인증 코드 발송",
                f"안녕하세요,\n\n회원가입을 진행하려면 다음 인증 코드를 입력하십시오:\n{verification_code}\n\n코드는 10분 동안 유효합니다.",
                settings.DEFAULT_FROM_EMAIL,
                [email],
            )

            return Response({"detail": "인증 코드가 이메일로 전송되었습니다."}, status=status.HTTP_200_OK)
        return Response(serializer.errors, status=status.HTTP_400_BAD_REQUEST)
    

class VerifyCodeView(APIView):
    """
    인증 코드를 확인하는 API
    - 제공된 인증 코드가 유효한지 확인합니다.
    """

    def post(self, request):
        data = request.data
        email = data.get("email")
        verification_code = data.get("verification_code")

        try:
            code_entry = VerificationCode.objects.get(email=email)
            if code_entry.code == verification_code and timezone.now() <= code_entry.expires_at:
                return Response({"detail": "인증 코드가 확인되었습니다."}, status=status.HTTP_200_OK)
            elif code_entry.code != verification_code:
                return Response({"detail": "잘못된 인증 코드입니다."}, status=status.HTTP_400_BAD_REQUEST)
            else:
                return Response({"detail": "인증 코드가 만료되었습니다."}, status=status.HTTP_400_BAD_REQUEST)
        except VerificationCode.DoesNotExist:
            return Response({"detail": "인증 코드가 존재하지 않습니다."}, status=status.HTTP_400_BAD_REQUEST)
        
    
class FinalSignupView(APIView):
    """
    최종 회원가입 API
    - 인증 코드가 확인된 후 사용자 계정을 최종 등록합니다.
    """

    def post(self, request):
        data = request.data
        username = data.get("username")
        email = data.get("email")
        verification_code = data.get("verification_code")
        password = data.get("password")

        # 사용자 이름 중복 확인
        if User.objects.filter(username=username).exists():
            return Response(
                {"detail": "사용자 이름이 이미 존재합니다."},
                status=status.HTTP_400_BAD_REQUEST,
            )

        # 이메일 인증 코드 검증
        try:
            code_entry = VerificationCode.objects.get(email=email)
            if code_entry.code != verification_code:
                return Response(
                    {"detail": "잘못된 인증 코드입니다."},
                    status=status.HTTP_400_BAD_REQUEST,
                )
            if timezone.now() > code_entry.expires_at:
                return Response(
                    {"detail": "인증 코드가 만료되었습니다."},
                    status=status.HTTP_400_BAD_REQUEST,
                )
        except VerificationCode.DoesNotExist:
            return Response(
                {"detail": "이메일 인증 코드가 존재하지 않습니다."},
                status=status.HTTP_400_BAD_REQUEST,
            )

        # 이메일이 이미 존재하는 경우
        if User.objects.filter(email=email).exists():
            return Response(
                {"detail": "이메일이 이미 존재합니다."},
                status=status.HTTP_400_BAD_REQUEST,
            )

        # 사용자 생성
        serializer = UserSerializer(data={
            "username": username,
            "email": email,
            "password": password
        })
        if serializer.is_valid():
            user = serializer.save()
            user.is_active = True
            user.save()
            return Response(
                {"detail": "회원가입이 완료되었습니다."},
                status=status.HTTP_201_CREATED,
            )
        return Response(
            serializer.errors, status=status.HTTP_400_BAD_REQUEST
        )

class UserLoginView(APIView):
    def post(self, request):
        """
        로그인 API
        - 사용자의 이메일과 비밀번호로 인증 후, JWT 토큰과 리프레시 토큰을 발급합니다.
        """
        email = request.data.get("email")
        password = request.data.get("password")

        # 사용자 인증
        user = User.objects.filter(email=email).first()
        if user is None or not user.check_password(password):
            raise AuthenticationFailed("Invalid email or password")

        # Access Token 생성
        payload = {
            "id": user.id,
            "exp": timezone.now() + datetime.timedelta(days=7),
            "iat": timezone.now(),
        }
        access_token = jwt.encode(payload, settings.SECRET_KEY, algorithm="HS256")

        # Refresh Token 생성 및 저장
        expires_at = timezone.now() + datetime.timedelta(days=30)
        refresh_token = RefreshToken.objects.create(user=user, expires_at=expires_at)

        response = Response(
            {
                "id": user.id,
                "email": user.email,
                "username": user.username,
            }
        )
        # 쿠키에 토큰 설정
        response.set_cookie(
            key="jwt",
            value=access_token,
            httponly=True,
            expires=timezone.now() + datetime.timedelta(days=7),
        )
        response.set_cookie(
            key="refresh_token",
            value=str(refresh_token.token),
            httponly=True,
            expires=expires_at,
        )

        return response


class UserProfileView(APIView):
    def get(self, request):
        """
        사용자 정보 조회 API
        - JWT 토큰을 통해 인증된 사용자 정보 반환
        """
        token = request.COOKIES.get("jwt")
        if not token:
            raise AuthenticationFailed("Unauthenticated!")

        try:
            # JWT 토큰 디코딩 및 검증
            payload = jwt.decode(token, settings.SECRET_KEY, algorithms=["HS256"])
            user = User.objects.get(id=payload["id"])
        except jwt.ExpiredSignatureError:
            raise AuthenticationFailed("Token has expired")
        except jwt.InvalidTokenError:
            raise AuthenticationFailed("Invalid token")
        except User.DoesNotExist:
            raise AuthenticationFailed("User not found")

        # 사용자 정보 반환
        serializer = UserSerializer(user)
        return Response(serializer.data)


class UserLogoutView(APIView):
    def post(self, request):
        """
        로그아웃 API
        - JWT 토큰 및 리프레시 토큰 쿠키를 삭제하여 로그아웃 처리
        """
        response = Response({"message": "Successfully logged out"})
        response.delete_cookie("jwt")
        response.delete_cookie("refresh_token")
        return response


class RefreshTokenView(APIView):
    permission_classes = [IsAuthenticated]

    def post(self, request):
        """
        새로운 액세스 토큰을 발급하는 API
        - 유효한 리프레시 토큰을 통해 새로운 액세스 토큰을 발급합니다.
        """
        refresh_token = request.data.get("refresh_token")
        try:
            # 리프레시 토큰 조회
            token = RefreshToken.objects.get(token=refresh_token)
            if token.is_expired():
                return Response(
                    {"detail": "Refresh token expired"},
                    status=status.HTTP_401_UNAUTHORIZED,
                )

            # 새로운 액세스 토큰 생성
            user = token.user
            payload = {
                "id": user.id,
                "exp": timezone.now() + datetime.timedelta(days=7),
                "iat": timezone.now(),
            }
            new_access_token = jwt.encode(
                payload, settings.SECRET_KEY, algorithm="HS256"
            )
            return Response(
                {"access_token": new_access_token}, status=status.HTTP_200_OK
            )

        except RefreshToken.DoesNotExist:
            return Response(
                {"detail": "Invalid refresh token"}, status=status.HTTP_401_UNAUTHORIZED
            )


class PasswordResetView(APIView):
    def post(self, request):
        """
        비밀번호 재설정 요청 및 확인 API
        - 비밀번호 재설정 링크 발송 및 비밀번호 재설정
        """
        if "token" in request.data:
            return self.reset_password(request)
        else:
            return self.request_reset(request)

    def request_reset(self, request):
        """
        비밀번호 재설정 요청 API
        - 사용자의 이메일로 비밀번호 재설정 링크를 포함한 이메일을 발송합니다.
        """
        serializer = PasswordResetRequestSerializer(data=request.data)
        serializer.is_valid(raise_exception=True)
        email = serializer.validated_data["email"]

        # 사용자 존재 여부 확인
        user = User.objects.filter(email=email).first()
        if not user:
            return Response(
                {"detail": "User with this email does not exist."},
                status=status.HTTP_404_NOT_FOUND,
            )

        # 비밀번호 재설정 토큰 생성
        payload = {
            "id": user.id,
            "email": user.email,
            "exp": timezone.now() + datetime.timedelta(hours=1),
        }
        token = jwt.encode(payload, settings.SECRET_KEY, algorithm="HS256")
        reset_url = request.build_absolute_uri(
            reverse("password-reset-confirm") + f"?token={token}"
        )

        # 이메일 발송
        send_mail(
            "Password Reset Request",
            f"Hello,\n\nYou requested a password reset. Click the following link to reset your password:\n{reset_url}\n\nIf you did not request this, please ignore this email.",
            settings.DEFAULT_FROM_EMAIL,
            [email],
        )

        return Response({"reset_url": reset_url})

    def reset_password(self, request):
        """
        비밀번호 재설정 API
        - 유효한 비밀번호 재설정 토큰을 통해 비밀번호를 새로 설정합니다.
        """
        serializer = PasswordResetConfirmSerializer(data=request.data)
        serializer.is_valid(raise_exception=True)
        token = request.data.get("token")
        new_password = serializer.validated_data["password"]

        try:
            # 비밀번호 재설정 토큰 디코딩 및 검증
            payload = jwt.decode(token, settings.SECRET_KEY, algorithms=["HS256"])
            user = User.objects.filter(id=payload["id"], email=payload["email"]).first()
            if not user:
                return Response(
                    {"detail": "User not found."}, status=status.HTTP_404_NOT_FOUND
                )

            # 비밀번호 설정
            user.set_password(new_password)
            user.save()
            return Response({"detail": "Password has been reset successfully."})

        except jwt.ExpiredSignatureError:
            return Response(
                {"detail": "Token has expired."}, status=status.HTTP_400_BAD_REQUEST
            )
        except jwt.InvalidTokenError:
            return Response(
                {"detail": "Invalid token."}, status=status.HTTP_400_BAD_REQUEST
            )


class CookieAuthentication(BasePermission):
    def has_permission(self, request, view):
        """
        쿠키 기반 인증을 수행하는 권한 클래스
        - 요청의 쿠키에서 JWT 토큰을 추출하고, 이를 검증하여 사용자 인증을 수행합니다.
        """
        token = request.COOKIES.get("jwt")
        if not token:
            return False

        try:
            # JWT 토큰 디코딩 및 검증
            payload = jwt.decode(token, settings.SECRET_KEY, algorithms=["HS256"])
            request.user = User.objects.get(id=payload["id"])
            return True
        except jwt.ExpiredSignatureError:
            raise AuthenticationFailed("Token has expired.")
        except jwt.InvalidTokenError:
            raise AuthenticationFailed("Invalid token.")
        except User.DoesNotExist:
            raise AuthenticationFailed("User not found.")


class UserAccountView(APIView):
    permission_classes = [CookieAuthentication]

    def delete(self, request):
        """
        회원 탈퇴 API
        - 인증된 사용자의 계정을 삭제합니다.
        - JWT 토큰을 통해 사용자 인증을 수행합니다.
        """
        token = request.COOKIES.get("jwt")
        if not token:
            return Response(
                {"detail": "No authentication credentials provided."},
                status=status.HTTP_401_UNAUTHORIZED,
            )

        try:
            # JWT 토큰 디코딩 및 검증
            payload = jwt.decode(token, settings.SECRET_KEY, algorithms=["HS256"])
            user = User.objects.get(id=payload["id"])
            user.delete()
            response = Response(
                {"detail": "Account successfully deleted."},
                status=status.HTTP_204_NO_CONTENT,
            )
            response.delete_cookie("jwt")
            return response
        except jwt.ExpiredSignatureError:
            return Response(
                {"detail": "Token has expired."}, status=status.HTTP_401_UNAUTHORIZED
            )
        except jwt.InvalidTokenError:
            return Response(
                {"detail": "Invalid token."}, status=status.HTTP_401_UNAUTHORIZED
            )
        except User.DoesNotExist:
            return Response(
                {"detail": "User not found."}, status=status.HTTP_404_NOT_FOUND
            )


class KakaoLogin(APIView):
    @swagger_auto_schema(
        operation_description="Redirects to Kakao for user authentication",
        responses={302: "Redirects to Kakao authorization page"},
    )
    def get(self, request):
        redirect_uri = "http://127.0.0.1:8000/accounts/kakao/login/callback/"
        kakao_auth_url = f"https://kauth.kakao.com/oauth/authorize?client_id={KAKAO_APP_KEY}&redirect_uri={redirect_uri}&response_type=code"
        return redirect(kakao_auth_url)


class KakaoCallback(APIView):
    @swagger_auto_schema(
        operation_description="Handles Kakao callback, exchanges code for access token, and logs in the user",
        responses={
            200: openapi.Response(
                "Login successful",
                openapi.Schema(
                    type=openapi.TYPE_OBJECT,
                    properties={
                        "message": openapi.Schema(type=openapi.TYPE_STRING),
                        "access_token": openapi.Schema(type=openapi.TYPE_STRING),
                        "user_info": openapi.Schema(type=openapi.TYPE_OBJECT),
                    },
                ),
            ),
            400: openapi.Response(
                "Bad request",
                openapi.Schema(
                    type=openapi.TYPE_OBJECT,
                    properties={
                        "error": openapi.Schema(type=openapi.TYPE_STRING),
                        "details": openapi.Schema(type=openapi.TYPE_OBJECT),
                    },
                ),
            ),
        },
    )
    def get(self, request):
        code = request.GET.get("code")
        if not code:
            return Response(
                {"error": "No authorization code provided"},
                status=status.HTTP_400_BAD_REQUEST,
            )

        token_url = "https://kauth.kakao.com/oauth/token"
        headers = {"Content-Type": "application/x-www-form-urlencoded;charset=utf-8"}
        data = {
            "grant_type": "authorization_code",
            "client_id": KAKAO_APP_KEY,
            "client_secret": KAKAO_SECRET,
            "redirect_uri": "http://127.0.0.1:8000/accounts/kakao/login/callback/",
            "code": code,
        }

        response = requests.post(token_url, headers=headers, data=data)
        response_data = response.json()

        if response.status_code != 200:
            return Response(
                {"error": "Failed to obtain access token", "details": response_data},
                status=status.HTTP_400_BAD_REQUEST,
            )

        access_token = response_data.get("access_token")
        if not access_token:
            return Response(
                {"error": "No access token received"},
                status=status.HTTP_400_BAD_REQUEST,
            )

        user_info_url = "https://kapi.kakao.com/v2/user/me"
        headers = {"Authorization": f"Bearer {access_token}"}
        user_info_response = requests.get(user_info_url, headers=headers)
        user_info = user_info_response.json()

        email = user_info["kakao_account"]["email"]
        username = user_info["kakao_account"]["profile"]["nickname"]
        provider = "kakao"

        user, created = User.objects.update_or_create(
            email=email,
            defaults={
                "username": username,
                "social_provider": provider,
                "is_active": True,
                # "role":"client"
            },
        )

        refresh = RefreshToken.for_user(user)
        jwt_access_token = str(refresh.access_token)

        response = Response(
            {
                "message": "Login successful",
                "access_token": jwt_access_token,
                "user_info": user_info,
            },
            status=status.HTTP_200_OK,
        )
        response.set_cookie(
            "jwt_access_token",
            jwt_access_token,
            max_age=3600,
            httponly=True,
            secure=False,
            samesite="Lax",
        )
        response.set_cookie(
            "kakao_access_token",
            access_token,
            max_age=3600,
            httponly=True,
            secure=False,
            samesite="Lax",
        )
        return response


class KakaoLogout(APIView):
    @swagger_auto_schema(
        operation_description="Logs out the user from Kakao and deletes cookies",
        responses={
            200: openapi.Response("Logout successful"),
            400: openapi.Response(
                "Bad request",
                openapi.Schema(
                    type=openapi.TYPE_OBJECT,
                    properties={"error": openapi.Schema(type=openapi.TYPE_STRING)},
                ),
            ),
        },
    )
    def get(self, request):
        access_token = request.COOKIES.get("kakao_access_token")
        if not access_token:
            return HttpResponse({"error": "No access token found"}, status=400)

        logout_url = "https://kapi.kakao.com/v1/user/logout"
        headers = {"Authorization": f"Bearer {access_token}"}
        requests.post(logout_url, headers=headers)

        revoke_token_url = "https://kapi.kakao.com/v1/user/unlink"
        headers = {"Authorization": f"Bearer {access_token}"}
        requests.post(revoke_token_url, headers=headers)

        response = HttpResponse({"message": "Logged out successfully"})
        response.delete_cookie("kakao_access_token")
        response.delete_cookie("jwt_access_token")
        return response


class GoogleLogin(APIView):
    @swagger_auto_schema(
        operation_description="Redirects to Google for user authentication",
        responses={302: "Redirects to Google authorization page"},
    )
    def get(self, request):
        redirect_uri = "http://127.0.0.1:8000/accounts/google/login/callback/"
        google_auth_url = f"https://accounts.google.com/o/oauth2/auth?client_id={GOOGLE_APP_KEY}&redirect_uri={redirect_uri}&response_type=code&scope=email%20profile"
        return redirect(google_auth_url)


class GoogleCallback(APIView):
    @swagger_auto_schema(
        operation_description="Handles Google callback, exchanges code for access token, and logs in the user",
        responses={
            200: openapi.Response(
                "Login successful",
                openapi.Schema(
                    type=openapi.TYPE_OBJECT,
                    properties={
                        "message": openapi.Schema(type=openapi.TYPE_STRING),
                        "access_token": openapi.Schema(type=openapi.TYPE_STRING),
                        "user_info": openapi.Schema(type=openapi.TYPE_OBJECT),
                    },
                ),
            ),
            400: openapi.Response(
                "Bad request",
                openapi.Schema(
                    type=openapi.TYPE_OBJECT,
                    properties={
                        "error": openapi.Schema(type=openapi.TYPE_STRING),
                        "details": openapi.Schema(type=openapi.TYPE_OBJECT),
                    },
                ),
            ),
        },
    )
    def get(self, request):
        code = request.GET.get("code")
        if not code:
            return Response(
                {"error": "No authorization code provided"},
                status=status.HTTP_400_BAD_REQUEST,
            )

        token_url = "https://oauth2.googleapis.com/token"
        data = {
            "grant_type": "authorization_code",
            "client_id": GOOGLE_APP_KEY,
            "client_secret": GOOGLE_SECRET,
            "redirect_uri": "http://127.0.0.1:8000/accounts/google/login/callback/",
            "code": code,
        }

        response = requests.post(token_url, data=data)
        response_data = response.json()

        if response.status_code != 200:
            return Response(
                {"error": "Failed to obtain access token", "details": response_data},
                status=status.HTTP_400_BAD_REQUEST,
            )

        access_token = response_data.get("access_token")
        if not access_token:
            return Response(
                {"error": "No access token received"},
                status=status.HTTP_400_BAD_REQUEST,
            )

        user_info_url = "https://www.googleapis.com/oauth2/v2/userinfo"
        headers = {"Authorization": f"Bearer {access_token}"}
        user_info_response = requests.get(user_info_url, headers=headers)
        user_info = user_info_response.json()

        email = user_info["email"]
        username = user_info["name"]
        provider = "google"

        user, created = User.objects.update_or_create(
            email=email,
            defaults={
                "username": username,
                "social_provider": provider,
                "is_active": True,
                "role": "analyst",
            },
        )

        refresh = RefreshToken.for_user(user)
        jwt_access_token = str(refresh.access_token)

        response = Response(
            {
                "message": "Login successful",
                "access_token": jwt_access_token,
                "user_info": user_info,
            },
            status=status.HTTP_200_OK,
        )
        response.set_cookie(
            "jwt_access_token",
            jwt_access_token,
            max_age=3600,
            httponly=True,
            secure=False,
            samesite="Lax",
        )
        response.set_cookie(
            "google_access_token",
            access_token,
            max_age=3600,
            httponly=True,
            secure=False,
            samesite="Lax",
        )

        return response


class GoogleLogout(APIView):
    @swagger_auto_schema(
        operation_description="Logs out the user from Google and deletes cookies",
        responses={
            200: openapi.Response("Logout successful"),
            400: openapi.Response(
                "Bad request",
                openapi.Schema(
                    type=openapi.TYPE_OBJECT,
                    properties={"error": openapi.Schema(type=openapi.TYPE_STRING)},
                ),
            ),
        },
    )
    def get(self, request):
        access_token = request.COOKIES.get("google_access_token")
        if not access_token:
            return Response({"error": "No access token found"}, status=400)

        revoke_token_url = "https://oauth2.googleapis.com/revoke"
        params = {"token": access_token}
        requests.post(revoke_token_url, params=params)

        response = Response({"message": "Logged out successfully"})
        response.delete_cookie("google_access_token")
        response.delete_cookie("jwt_access_token")
        return response


class NaverLogin(APIView):
    @swagger_auto_schema(
        operation_description="Redirects to Naver for user authentication",
        responses={302: "Redirects to Naver authorization page"},
    )
    def get(self, request):
        redirect_uri = "http://127.0.0.1:8000/accounts/naver/login/callback/"
        state = "random_state"
        naver_auth_url = f"https://nid.naver.com/oauth2.0/authorize?response_type=code&client_id={NAVER_APP_KEY}&redirect_uri={redirect_uri}&state={state}"
        return redirect(naver_auth_url)


class NaverCallback(APIView):
    @swagger_auto_schema(
        operation_description="Handles Naver callback, exchanges code for access token, and logs in the user",
        responses={
            200: openapi.Response(
                "Login successful",
                openapi.Schema(
                    type=openapi.TYPE_OBJECT,
                    properties={
                        "message": openapi.Schema(type=openapi.TYPE_STRING),
                        "access_token": openapi.Schema(type=openapi.TYPE_STRING),
                        "user_info": openapi.Schema(type=openapi.TYPE_OBJECT),
                    },
                ),
            ),
            400: openapi.Response(
                "Bad request",
                openapi.Schema(
                    type=openapi.TYPE_OBJECT,
                    properties={
                        "error": openapi.Schema(type=openapi.TYPE_STRING),
                        "details": openapi.Schema(type=openapi.TYPE_OBJECT),
                    },
                ),
            ),
        },
    )
    def get(self, request):
        code = request.GET.get("code")
        state = request.GET.get("state")
        if not code:
            return Response(
                {"error": "No authorization code provided"},
                status=status.HTTP_400_BAD_REQUEST,
            )

        token_url = "https://nid.naver.com/oauth2.0/token"
        data = {
            "grant_type": "authorization_code",
            "client_id": NAVER_APP_KEY,
            "client_secret": NAVER_SECRET,
            "redirect_uri": "http://127.0.0.1:8000/accounts/naver/login/callback/",
            "code": code,
            "state": state,
        }

        response = requests.post(token_url, data=data)
        response_data = response.json()

        if response.status_code != 200:
            return Response(
                {"error": "Failed to obtain access token", "details": response_data},
                status=status.HTTP_400_BAD_REQUEST,
            )

        access_token = response_data.get("access_token")
        if not access_token:
            return Response(
                {"error": "No access token received"},
                status=status.HTTP_400_BAD_REQUEST,
            )

        user_info_url = "https://openapi.naver.com/v1/nid/me"
        headers = {"Authorization": f"Bearer {access_token}"}
        user_info_response = requests.get(user_info_url, headers=headers)
        user_info = user_info_response.json()

        email = user_info["response"]["email"]
        username = user_info["response"]["name"]
        provider = "naver"

        user, created = User.objects.update_or_create(
            email=email,
            defaults={
                "username": username,
                "social_provider": provider,
                "is_active": True,
            },
        )

        refresh = RefreshToken.for_user(user)
        jwt_access_token = str(refresh.access_token)

        response = Response(
            {
                "message": "Login successful",
                "access_token": jwt_access_token,
                "user_info": user_info,
            },
            status=status.HTTP_200_OK,
        )
        response.set_cookie(
            "jwt_access_token",
            jwt_access_token,
            max_age=3600,
            httponly=True,
            secure=False,
            samesite="Lax",
        )
        response.set_cookie(
            "naver_access_token",
            access_token,
            max_age=3600,
            httponly=True,
            secure=False,
            samesite="Lax",
        )

        return response


class NaverLogout(APIView):
    @swagger_auto_schema(
        operation_description="Logs out the user from Naver and deletes cookies",
        responses={
            200: openapi.Response("Logout successful"),
            400: openapi.Response(
                "Bad request",
                openapi.Schema(
                    type=openapi.TYPE_OBJECT,
                    properties={"error": openapi.Schema(type=openapi.TYPE_STRING)},
                ),
            ),
        },
    )
    def get(self, request):
        access_token = request.COOKIES.get("naver_access_token")
        if not access_token:
            return Response({"error": "No access token found"}, status=400)

        logout_url = "https://nid.naver.com/oauth2.0/token"
        params = {
            "grant_type": "delete",
            "client_id": NAVER_APP_KEY,
            "client_secret": NAVER_SECRET,
            "access_token": access_token,
            "service_provider": "NAVER",
        }
        requests.post(logout_url, params=params)

        response = Response({"message": "Logged out successfully"})
        response.delete_cookie("naver_access_token")
        response.delete_cookie("jwt_access_token")
        return response


@csrf_exempt
class CheckBusinessStatusView(View):
    def post(self, request):
        try:
            # 요청 본문에서 JSON 데이터 파싱
            data = json.loads(request.body)
            business_number = data.get("b_no")

            if not business_number:
                return JsonResponse({"message": "사업자번호가 필요합니다."}, status=400)

            # 외부 API 요청을 위한 URL 및 서비스 키
            api_url = "https://api.odcloud.kr/api/nts-businessman/v1/status"
            service_key = "81v1ccEVwCErTew95hfnA%2Br95pix3CQCzdfoXag6gg34TJeXJIawjx%2FGgYYeYrL6dTMt0DFvYKvIpAr8h3p35Q%3D%3D"

            # API 요청에 필요한 헤더와 파라미터 설정
            headers = {"Content-Type": "application/json", "Accept": "application/json"}
            params = {"serviceKey": service_key}
            payload = {"b_no": business_number}

            # 외부 API에 POST 요청 보내기
            response = requests.post(
                api_url, headers=headers, params=params, json=payload
            )
            response.raise_for_status()  # 요청 실패 시 예외 발생

            # API 응답 데이터 가져오기
            api_response_data = response.json()

            # 성공적인 조회 응답 반환
            return JsonResponse(
                {
                    "message": "조회가 성공적으로 완료되었습니다.",
                    "data": api_response_data,
                }
            )

        except requests.RequestException as e:
            return JsonResponse(
                {"message": "외부 API 요청 중 오류 발생", "error": str(e)}, status=400
            )
        except json.JSONDecodeError:
            return JsonResponse({"message": "잘못된 요청 데이터입니다."}, status=400)
