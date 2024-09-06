import datetime
import json
import logging
import os
import random
from urllib.parse import quote

import jwt
import requests
from accounts.authentication import CookieAuthentication
from django.conf import settings
from django.contrib.auth import get_user_model
from django.core.mail import send_mail
from django.http import HttpResponse
from django.http import HttpResponseRedirect
from django.http import JsonResponse
from django.shortcuts import redirect
from django.template.loader import render_to_string
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

from .models import VerificationCode
from .serializers import EmailSerializer
from .serializers import PasswordResetConfirmSerializer
from .serializers import PasswordResetRequestSerializer
from .serializers import UsernameCheckSerializer
from .serializers import UserSerializer

User = get_user_model()


load_dotenv()

KAKAO_APP_KEY = os.getenv("KAKAO_APP_KEY")
KAKAO_SECRET = os.getenv("KAKAO_SECRET")
KAKAO_URI = os.getenv("KAKAO_URI")
GOOGLE_APP_KEY = os.getenv("GOOGLE_APP_KEY")
GOOGLE_SECRET = os.getenv("GOOGLE_SECRET")
GOOGLE_URI = os.getenv("GOOGLE_URI")
NAVER_APP_KEY = os.getenv("NAVER_APP_KEY")
NAVER_SECRET = os.getenv("NAVER_SECRET")
NAVER_URI = os.getenv("NAVER_URI")
FRONT_DOMAIN = os.getenv("FRONT_DOMAIN")


# # Authentication Code
# class CookieAuthentication(BasePermission):
#     def has_permission(self, request, view):
#         """
#         쿠키 기반 인증을 수행하는 권한 클래스
#         - 요청의 쿠키에서 JWT 토큰을 추출하고, 이를 검증하여 사용자 인증을 수행합니다.
#         """
#         token = request.COOKIES.get("jwt")
#         if not token:
#             return False

#         try:
#             # JWT 토큰 디코딩 및 검증
#             payload = jwt.decode(token, settings.SECRET_KEY, algorithms=["HS256"])
#             request.user = User.objects.get(id=payload["id"])
#             return True
#         except jwt.ExpiredSignatureError:
#             raise AuthenticationFailed("Token has expired.")
#         except jwt.InvalidTokenError:
#             raise AuthenticationFailed("Invalid token.")
#         except User.DoesNotExist:
#             raise AuthenticationFailed("User not found.")


class MeView(APIView):
    """
    로그인한 사용자 자신의 정보를 조회하는 API
    """

    permission_classes = [IsAuthenticated]
    authentication_classes = [CookieAuthentication]  # 필요하다면 추가

    @swagger_auto_schema(
        operation_description="로그인한 사용자 정보 조회",
        responses={
            200: openapi.Response(
                description="로그인한 사용자 정보",
                schema=UserSerializer,  # UserSerializer를 스키마로 사용
            ),
            401: openapi.Response(
                description="인증되지 않은 사용자",
            ),
        },
    )
    def get(self, request):
        user = request.user

        # 사용자 정보 직렬화
        serializer = UserSerializer(user)

        return Response(serializer.data)


class UsernameCheckView(APIView):
    @swagger_auto_schema(
        operation_description="사용자 이름 중복 확인",
        request_body=openapi.Schema(
            type=openapi.TYPE_OBJECT,
            required=["username"],
            properties={
                "username": openapi.Schema(
                    type=openapi.TYPE_STRING, description="확인할 사용자 이름"
                ),
            },
        ),
        responses={
            200: openapi.Response(
                description="사용 가능한 사용자 이름",
                examples={"application/json": {"message": "사용 가능한 닉네임입니다."}},
            ),
            400: openapi.Response(
                description="이미 존재하는 사용자 이름",
                examples={
                    "application/json": {"message": "이미 존재하는 닉네임입니다."}
                },
            ),
        },
    )
    def post(self, request):
        serializer = UsernameCheckSerializer(data=request.data)

        if serializer.is_valid():
            username = serializer.validated_data["username"]
            exists = User.objects.filter(username=username).exists()

            if exists:
                return Response(
                    {"message": "이미 존재하는 닉네임입니다."},
                    status=status.HTTP_400_BAD_REQUEST,
                )
            else:
                return Response(
                    {"message": "사용 가능한 닉네임입니다."},
                    status=status.HTTP_200_OK,
                )

        return Response(
            serializer.errors,
            status=status.HTTP_400_BAD_REQUEST,
        )


class EmailCheckView(APIView):
    @swagger_auto_schema(
        operation_description="이메일 중복 확인",
        request_body=openapi.Schema(
            type=openapi.TYPE_OBJECT,
            required=["email"],
            properties={
                "email": openapi.Schema(
                    type=openapi.TYPE_STRING, description="확인할 이메일 주소"
                ),
            },
        ),
        responses={
            200: openapi.Response(
                description="사용 가능한 이메일",
                examples={"application/json": {"message": "사용 가능한 이메일입니다."}},
            ),
            400: openapi.Response(
                description="이미 존재하는 이메일",
                examples={
                    "application/json": {"message": "이미 존재하는 이메일입니다."}
                },
            ),
        },
    )
    #
    def post(self, request):
        serializer = EmailSerializer(data=request.data)
        if serializer.is_valid():
            email = serializer.validated_data["email"]
            exists = User.objects.filter(email=email).exists()
            if exists:
                return Response(
                    {"message": "이미 존재하는 이메일입니다."},
                    status=status.HTTP_400_BAD_REQUEST,
                )
            else:
                return Response(
                    {"message": "사용 가능한 이메일입니다."}, status=status.HTTP_200_OK
                )


class SendVerificationCodeView(APIView):
    """
    이메일로 인증 코드를 전송하는 API
    - 사용자가 제공한 이메일 주소로 인증 코드를 발송합니다.
    """

    @swagger_auto_schema(
        operation_description="이메일로 인증 코드 전송",
        request_body=openapi.Schema(
            type=openapi.TYPE_OBJECT,
            required=["email"],
            properties={
                "email": openapi.Schema(
                    type=openapi.TYPE_STRING, description="인증 코드를 받을 이메일 주소"
                ),
            },
        ),
        responses={
            200: openapi.Response(
                description="인증 코드 전송 성공",
                examples={
                    "application/json": {
                        "detail": "인증 코드가 이메일로 전송되었습니다."
                    }
                },
            ),
            400: "잘못된 요청",
        },
    )
    def post(self, request):
        serializer = EmailSerializer(data=request.data)
        if serializer.is_valid():
            email = serializer.validated_data["email"]

            # 이메일로 인증 코드 생성 및 저장
            verification_code = str(random.randint(100000, 999999))
            expires_at = timezone.now() + datetime.timedelta(
                minutes=10
            )  # 코드 만료 시간 설정

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

            return Response(
                {"detail": "인증 코드가 이메일로 전송되었습니다."},
                status=status.HTTP_200_OK,
            )
        return Response(serializer.errors, status=status.HTTP_400_BAD_REQUEST)


class VerifyCodeView(APIView):
    """
    인증 코드를 확인하는 API
    - 제공된 인증 코드가 유효한지 확인합니다.
    """

    @swagger_auto_schema(
        operation_description="인증 코드 확인",
        request_body=openapi.Schema(
            type=openapi.TYPE_OBJECT,
            required=["email", "verification_code"],
            properties={
                "email": openapi.Schema(
                    type=openapi.TYPE_STRING, description="이메일 주소"
                ),
                "verification_code": openapi.Schema(
                    type=openapi.TYPE_STRING, description="확인할 인증 코드"
                ),
            },
        ),
        responses={
            200: openapi.Response(
                description="인증 코드 확인 성공",
                examples={
                    "application/json": {"detail": "인증 코드가 확인되었습니다."}
                },
            ),
            400: openapi.Response(
                description="잘못된 인증 코드 또는 만료된 코드",
                examples={"application/json": {"detail": "잘못된 인증 코드입니다."}},
            ),
        },
    )
    def post(self, request):
        data = request.data
        email = data.get("email")
        verification_code = data.get("verification_code")

        try:
            code_entry = VerificationCode.objects.get(email=email)
            if (
                code_entry.code == verification_code
                and timezone.now() <= code_entry.expires_at
            ):
                return Response(
                    {"detail": "인증 코드가 확인되었습니다."}, status=status.HTTP_200_OK
                )
            elif code_entry.code != verification_code:
                return Response(
                    {"detail": "잘못된 인증 코드입니다."},
                    status=status.HTTP_400_BAD_REQUEST,
                )
            else:
                return Response(
                    {"detail": "인증 코드가 만료되었습니다."},
                    status=status.HTTP_400_BAD_REQUEST,
                )
        except VerificationCode.DoesNotExist:
            return Response(
                {"detail": "인증 코드가 존재하지 않습니다."},
                status=status.HTTP_400_BAD_REQUEST,
            )


class FinalSignupView(APIView):
    """
    최종 회원가입 API
    - 인증 코드가 확인된 후 사용자 계정을 최종 등록합니다.
    """

    @swagger_auto_schema(
        operation_description="최종 회원가입 처리",
        request_body=openapi.Schema(
            type=openapi.TYPE_OBJECT,
            required=["username", "email", "verification_code", "password"],
            properties={
                "username": openapi.Schema(
                    type=openapi.TYPE_STRING, description="사용자 이름"
                ),
                "email": openapi.Schema(
                    type=openapi.TYPE_STRING, description="이메일 주소"
                ),
                "verification_code": openapi.Schema(
                    type=openapi.TYPE_STRING, description="인증 코드"
                ),
                "password": openapi.Schema(
                    type=openapi.TYPE_STRING, description="비밀번호"
                ),
            },
        ),
        responses={
            201: openapi.Response(
                description="회원가입 성공",
                examples={"application/json": {"detail": "회원가입이 완료되었습니다."}},
            ),
            400: "잘못된 요청 또는 유효하지 않은 데이터",
        },
    )
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
        serializer = UserSerializer(
            data={"username": username, "email": email, "password": password}
        )
        if serializer.is_valid():
            user = serializer.save()
            user.is_active = True
            user.save()
            return Response(
                {"detail": "회원가입이 완료되었습니다."},
                status=status.HTTP_201_CREATED,
            )
        return Response(serializer.errors, status=status.HTTP_400_BAD_REQUEST)


class UserLoginView(APIView):
    @swagger_auto_schema(
        operation_description="사용자 로그인",
        request_body=openapi.Schema(
            type=openapi.TYPE_OBJECT,
            required=["email", "password"],
            properties={
                "email": openapi.Schema(
                    type=openapi.TYPE_STRING, description="이메일 주소"
                ),
                "password": openapi.Schema(
                    type=openapi.TYPE_STRING, description="비밀번호"
                ),
            },
        ),
        responses={
            200: openapi.Response(
                description="로그인 성공",
                examples={
                    "application/json": {
                        "userId": 1,
                        "email": "user@example.com",
                        "username": "username",
                        "accessToken": "access_token_here",
                        "refreshToken": "refresh_token_here",
                    }
                },
            ),
            401: "인증 실패",
        },
    )
    def post(self, request):
        """
        로그인 API
        - 사용자의 이메일과 비밀번호로 인증 후, JWT 토큰과 리프레시 토큰을 발급합니다.
        """
        email = request.data.get("email")
        password = request.data.get("password")

        # 사용자 인증
        user = User.objects.filter(email=email).first()
        if user is None:
            return Response(
                {"error": "존재하지 않는 사용자입니다."},
                status=status.HTTP_401_UNAUTHORIZED,
            )
        if not user.check_password(password):
            return Response(
                {"error": "비밀번호가 일치하지 않습니다."},
                status=status.HTTP_401_UNAUTHORIZED,
            )

        # Access Token 생성
        payload = {
            "id": user.id,
            "exp": timezone.now() + datetime.timedelta(days=7),
            "iat": timezone.now(),
        }
        access_token = jwt.encode(payload, settings.SECRET_KEY, algorithm="HS256")

        # Refresh Token 생성
        refresh = RefreshToken.for_user(user)
        refresh_token = str(refresh)

        response = Response(
            {
                "userId": user.id,
                "email": user.email,
                "username": user.username,
                "accessToken": access_token,
                "refreshToken": refresh_token,
            },
            status=200,  # 로그인 성공 시 상태 코드 200
        )

        # 쿠키에 토큰 설정
        response.set_cookie(
            key="jwt",
            value=access_token,
            httponly=True,
            expires=timezone.now() + datetime.timedelta(days=7),
            domain="allthe.store",  # 도메인 설정 필요
            secure=True,  # HTTPS에서만 쿠키를 전송하도록 설정
        )
        response.set_cookie(
            key="refresh_token",
            value=refresh_token,
            httponly=True,
            expires=timezone.now() + datetime.timedelta(days=30),
            domain="allthe.store",  # 도메인 설정 필요
            secure=True,  # HTTPS에서만 쿠키를 전송하도록 설정
        )

        return response


class UserProfileView(APIView):
    @swagger_auto_schema(
        operation_description="사용자 프로필 조회",
        responses={
            200: openapi.Response(
                description="프로필 조회 성공",
                examples={
                    "application/json": {
                        "id": 1,
                        "username": "username",
                        "email": "user@example.com",
                    }
                },
            ),
            401: "인증되지 않은 사용자",
        },
    )
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
    @swagger_auto_schema(
        operation_description="사용자 로그아웃",
        responses={
            200: openapi.Response(
                description="로그아웃 성공",
                examples={"application/json": {"message": "Successfully logged out"}},
            ),
        },
    )
    def post(self, request):
        user = request.user
        # 리프레시 토큰 모델에서 해당 사용자의 리프레시 토큰을 삭제
        RefreshToken.objects.filter(user=user).delete()

        response = Response({"message": "Successfully logged out"})
        response.delete_cookie("jwt")
        response.delete_cookie("refresh_token")
        return response


class RefreshTokenView(APIView):
    permission_classes = [IsAuthenticated]
    authentication_classes = [CookieAuthentication]  # 필요하다면 추가

    @swagger_auto_schema(
        operation_description="액세스 토큰 갱신",
        request_body=openapi.Schema(
            type=openapi.TYPE_OBJECT,
            required=["refresh_token"],
            properties={
                "refresh_token": openapi.Schema(
                    type=openapi.TYPE_STRING, description="리프레시 토큰"
                ),
            },
        ),
        responses={
            200: openapi.Response(
                description="토큰 갱신 성공",
                examples={
                    "application/json": {"access_token": "new_access_token_here"}
                },
            ),
            401: "유효하지 않은 리프레시 토큰",
        },
    )
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


class UpdateRoleView(APIView):
    permission_classes = [IsAuthenticated]
    authentication_classes = [CookieAuthentication]  # 필요하다면 추가

    @swagger_auto_schema(
        operation_description="사용자 역할 업데이트",
        request_body=openapi.Schema(
            type=openapi.TYPE_OBJECT,
            required=["role"],
            properties={
                "role": openapi.Schema(
                    type=openapi.TYPE_STRING, description="새로운 사용자 역할"
                ),
            },
        ),
        responses={
            200: openapi.Response(
                description="역할 업데이트 성공",
                examples={
                    "application/json": {
                        "message": "User role updated successfully.",
                        "role": "new_role",
                    }
                },
            ),
            400: "잘못된 역할",
            401: "인증되지 않은 사용자",
        },
    )
    def post(self, request, *args, **kwargs):
        user = request.user
        role = request.data.get("role")

        if role not in ["user", "analyst", "client"]:
            return Response(
                {"error": "Invalid role provided."}, status=status.HTTP_400_BAD_REQUEST
            )

        user.role = role
        user.save()

        return Response(
            {"message": "User role updated successfully.", "role": user.role},
            status=status.HTTP_200_OK,
        )


class PasswordResetView(APIView):
    @swagger_auto_schema(
        operation_description="비밀번호 재설정 요청",
        request_body=openapi.Schema(
            type=openapi.TYPE_OBJECT,
            required=["email"],
            properties={
                "email": openapi.Schema(
                    type=openapi.TYPE_STRING,
                    description="비밀번호를 재설정할 이메일 주소",
                ),
            },
        ),
        responses={
            200: openapi.Response(
                description="비밀번호 재설정 링크 전송 성공",
                examples={
                    "application/json": {
                        "detail": "비밀번호 재설정 링크가 이메일로 전송되었습니다."
                    }
                },
            ),
            404: "사용자를 찾을 수 없음",
        },
    )
    def post(self, request):
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
                {"detail": "해당 이메일을 가진 사용자가 존재하지 않습니다."},
                status=status.HTTP_404_NOT_FOUND,
            )

        # 비밀번호 재설정 토큰 생성
        payload = {
            "id": user.id,
            "email": user.email,
            "exp": timezone.now() + datetime.timedelta(hours=1),
        }
        token = jwt.encode(payload, settings.SECRET_KEY, algorithm="HS256")

        # 비밀번호 재설정 URL 설정
        reset_url = (
            f"{settings.FRONTEND_URL}/password-reset?email={quote(email)}&token={token}"
        )

        # HTML 이메일 내용 생성
        html_message = render_to_string(
            "password_reset_email.html", {"reset_url": reset_url}
        )

        # 이메일 발송
        send_mail(
            subject="비밀번호 재설정 요청",
            message="",  # 일반 텍스트 메시지는 비워둘 수 있음
            from_email=settings.DEFAULT_FROM_EMAIL,
            recipient_list=[email],
            html_message=html_message,  # HTML 메시지로 설정
        )

        return Response({"detail": "비밀번호 재설정 링크가 이메일로 전송되었습니다."})


class PasswordResetConfirmView(APIView):
    @swagger_auto_schema(
        operation_description="비밀번호 재설정 확인",
        request_body=openapi.Schema(
            type=openapi.TYPE_OBJECT,
            required=["new_password"],
            properties={
                "new_password": openapi.Schema(
                    type=openapi.TYPE_STRING, description="새로운 비밀번호"
                ),
            },
        ),
        manual_parameters=[
            openapi.Parameter(
                "token",
                openapi.IN_QUERY,
                description="비밀번호 재설정 토큰",
                type=openapi.TYPE_STRING,
            ),
        ],
        responses={
            200: openapi.Response(
                description="비밀번호 재설정 성공",
                examples={
                    "application/json": {
                        "detail": "비밀번호가 성공적으로 변경되었습니다."
                    }
                },
            ),
            400: "잘못된 토큰 또는 만료된 토큰",
        },
    )
    def post(self, request):
        """
        비밀번호 재설정 확인 API
        """

        token = request.query_params.get("token")
        serializer = PasswordResetConfirmSerializer(data=request.data)
        serializer.is_valid(raise_exception=True)
        new_password = serializer.validated_data.get("new_password")

        if not token or not new_password:
            return Response(
                {"detail": "토큰과 새 비밀번호가 필요합니다."},
                status=status.HTTP_400_BAD_REQUEST,
            )

        try:
            payload = jwt.decode(token, settings.SECRET_KEY, algorithms=["HS256"])
            user_id = payload["id"]

            # 사용자 조회 (try-except 블록 추가하여 에러 처리)
            try:
                user = User.objects.get(id=user_id)
            except User.DoesNotExist:
                return Response(
                    {"detail": "해당 사용자를 찾을 수 없습니다."},
                    status=status.HTTP_404_NOT_FOUND,
                )

            # 비밀번호 설정
            user.set_password(new_password)
            user.save()

            return Response(
                {"detail": "비밀번호가 성공적으로 재설정되었습니다."},
                status=status.HTTP_200_OK,
            )

        except jwt.ExpiredSignatureError:
            return Response(
                {"detail": "토큰이 만료되었습니다."}, status=status.HTTP_400_BAD_REQUEST
            )
        except jwt.InvalidTokenError:
            return Response(
                {"detail": "유효하지 않은 토큰입니다."},
                status=status.HTTP_400_BAD_REQUEST,
            )
        except Exception as e:
            # 예상치 못한 에러 발생 시
            logging.error(f"비밀번호 재설정 중 오류 발생: {str(e)}")
            return Response(
                {"detail": "시스템 오류가 발생했습니다."},
                status=status.HTTP_500_INTERNAL_SERVER_ERROR,
            )


class UserAccountView(APIView):
    permission_classes = [CookieAuthentication]

    @swagger_auto_schema(
        operation_description="회원 탈퇴",
        responses={
            204: openapi.Response(
                description="계정 삭제 성공",
                examples={
                    "application/json": {"detail": "Account successfully deleted."}
                },
            ),
            401: "인증되지 않은 사용자",
            404: "사용자를 찾을 수 없음",
        },
    )
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
        redirect_uri = KAKAO_URI
        kakao_auth_url = f"https://kauth.kakao.com/oauth/authorize?client_id={KAKAO_APP_KEY}&redirect_uri={redirect_uri}&response_type=code"
        response = redirect(kakao_auth_url)
        response["Cross-Origin-Opener-Policy"] = "same-origin"
        return response


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
            "redirect_uri": KAKAO_URI,
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

        # JWT 토큰 생성
        refresh = RefreshToken.for_user(user)
        jwt_access_token = str(refresh.access_token)

        redirect_url = (
            f"{FRONT_DOMAIN}redirect?userId={user.id}&username={username}&email={email}"
        )

        # Create a response with cookies
        response = HttpResponseRedirect(
            redirect_url
        )  # Use HttpResponseRedirect for redirection

        response.set_cookie(
            "jwt",
            jwt_access_token,
            max_age=3600,  # 1 hour
            httponly=True,
            secure=True,
            samesite="Lax",
            domain=".allthe.store",
        )
        response.set_cookie(
            "kakao_access_token",
            access_token,
            max_age=3600,  # 1 hour
            httponly=True,
            secure=True,
            samesite="Lax",
            domain=".allthe.store",
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
        response.delete_cookie("jwt")
        return response


class GoogleLogin(APIView):
    @swagger_auto_schema(
        operation_description="Redirects to Google for user authentication",
        responses={302: "Redirects to Google authorization page"},
    )
    def get(self, request):
        redirect_uri = GOOGLE_URI
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
            "redirect_uri": GOOGLE_URI,
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
                # "role": "analyst",
            },
        )

        refresh = RefreshToken.for_user(user)
        jwt_access_token = str(refresh.access_token)

        # 리다이렉션 URL 생성
        redirect_url = (
            f"{FRONT_DOMAIN}redirect?userId={user.id}&username={username}&email={email}"
        )

        # Create a response with cookies
        response = HttpResponseRedirect(
            redirect_url
        )  # Use HttpResponseRedirect for redirection

        response.set_cookie(
            "jwt",
            jwt_access_token,
            max_age=3600,  # 1 hour
            httponly=True,
            secure=True,
            samesite="Lax",
            domain=".allthe.store",
        )
        response.set_cookie(
            "google_access_token",
            access_token,
            max_age=3600,  # 1 hour
            httponly=True,
            secure=True,
            samesite="Lax",
            domain=".allthe.store",
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
        response.delete_cookie("jwt")
        return response


class NaverLogin(APIView):
    @swagger_auto_schema(
        operation_description="Redirects to Naver for user authentication",
        responses={302: "Redirects to Naver authorization page"},
    )
    def get(self, request):
        redirect_uri = NAVER_URI
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
            "redirect_uri": NAVER_URI,
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

        # 리다이렉션 URL 생성
        redirect_url = (
            f"{FRONT_DOMAIN}redirect?userId={user.id}&username={username}&email={email}"
        )

        # Create a response with cookies
        response = HttpResponseRedirect(
            redirect_url
        )  # Use HttpResponseRedirect for redirection

        response.set_cookie(
            "jwt",
            jwt_access_token,
            max_age=3600,  # 1 hour
            httponly=True,
            secure=True,
            samesite="Lax",
            domain=".allthe.store",
        )
        response.set_cookie(
            "naver_access_token",
            access_token,
            max_age=3600,  # 1 hour
            httponly=True,
            secure=True,
            samesite="Lax",
            domain=".allthe.store",
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
        response.delete_cookie("jwt")
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


# 통합로그아웃
class TotalLogoutView(APIView):
    permission_classes = [IsAuthenticated]
    authentication_classes = [CookieAuthentication]  # 필요하다면 추가

    def post(self, request):
        if request.user.social_provider == "kakao":
            return KakaoLogout().get(request)
        elif request.user.social_provider == "google":
            return GoogleLogout().get(request)
        elif request.user.social_provider == "naver":
            return NaverLogout().get(request)
        else:
            # 일반 로그아웃
            return UserLogoutView().post(request)
