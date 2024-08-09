import datetime
import jwt
from django.conf import settings
from django.contrib.auth import get_user_model
from django.core.mail import send_mail
from django.urls import reverse
from django.utils import timezone
from rest_framework import status
from rest_framework.exceptions import AuthenticationFailed
from rest_framework.permissions import BasePermission, IsAuthenticated
from rest_framework.response import Response
from rest_framework.views import APIView

from .models import RefreshToken
from .serializers import PasswordResetConfirmSerializer, PasswordResetRequestSerializer, UserSerializer

User = get_user_model()

class UserRegistrationView(APIView):
    def post(self, request):
        """
        회원가입 요청 API
        - 사용자가 입력한 이메일로 회원가입 확인 링크를 포함한 이메일을 발송합니다.
        - 이메일이 이미 존재하는 경우, 에러 메시지를 반환합니다.
        """
        serializer = UserSerializer(data=request.data)
        serializer.is_valid(raise_exception=True)
        email = serializer.validated_data.get("email")

        # 이메일이 이미 존재하는지 확인
        user = User.objects.filter(email=email).first()
        if user:
            return Response(
                {"detail": "이미 존재하는 이메일입니다."},
                status=status.HTTP_400_BAD_REQUEST,
            )

        # 이메일 인증을 위한 JWT 토큰 생성
        payload = {
            "email": email,
            "exp": timezone.now() + datetime.timedelta(hours=1),
        }
        token = jwt.encode(payload, settings.SECRET_KEY, algorithm="HS256")

        # 회원가입 확인 URL 생성
        registration_url = request.build_absolute_uri(
            reverse("registration-confirm") + f"?token={token}"
        )

        # 이메일 발송
        send_mail(
            "회원가입 확인",
            f"안녕하세요,\n\n회원가입을 완료하려면 다음 링크를 클릭하십시오:\n{registration_url}\n\n링크는 1시간 동안 유효합니다.",
            settings.DEFAULT_FROM_EMAIL,
            [email],
        )

        return Response({"detail": "회원가입 확인 이메일을 전송했습니다."})

    def get(self, request):
        """
        회원가입 확인 API
        - 이메일 인증 토큰을 통해 사용자를 활성화하고 회원가입을 완료합니다.
        - 유효하지 않은 토큰 또는 만료된 토큰에 대한 처리를 포함합니다.
        """
        token = request.query_params.get("token")
        if not token:
            return Response(
                {"detail": "Token is required"}, status=status.HTTP_400_BAD_REQUEST
            )

        try:
            # JWT 토큰 디코딩 및 검증
            payload = jwt.decode(token, settings.SECRET_KEY, algorithms=["HS256"])
            email = payload.get("email")
            if not email:
                return Response(
                    {"detail": "Invalid token"}, status=status.HTTP_400_BAD_REQUEST
                )

            # 사용자 조회
            user = User.objects.filter(email=email).first()
            if not user:
                # 새로운 사용자 생성 및 활성화
                serializer = UserSerializer(
                    data={"email": email, "password": "defaultpassword"}
                )
                if serializer.is_valid():
                    user = serializer.save()
                    user.is_active = True
                    user.save()
                else:
                    return Response(
                        serializer.errors, status=status.HTTP_400_BAD_REQUEST
                    )
            else:
                if user.is_active:
                    return Response(
                        {"detail": "User already active"},
                        status=status.HTTP_400_BAD_REQUEST,
                    )
                # 기존 사용자 활성화
                user.is_active = True
                user.save()

            return Response(
                {"detail": "회원가입이 완료되었습니다."}, status=status.HTTP_200_OK
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
        if 'token' in request.data:
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
