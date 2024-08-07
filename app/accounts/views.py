import datetime

import jwt
from django.conf import settings
from django.contrib.auth import get_user_model
from django.core.mail import send_mail
from django.urls import reverse
from django.utils import timezone
from rest_framework import status
from rest_framework.exceptions import AuthenticationFailed
from rest_framework.permissions import BasePermission
from rest_framework.permissions import IsAuthenticated
from rest_framework.response import Response
from rest_framework.views import APIView

from .models import RefreshToken
from .serializers import PasswordResetConfirmSerializer
from .serializers import PasswordResetRequestSerializer
from .serializers import UserSerializer

User = get_user_model()


class RegisterRequestView(APIView):
    def post(self, request):
        """
        회원가입 요청 API
        - 이메일로 회원가입 확인 링크 발송
        """
        serializer = UserSerializer(data=request.data)
        serializer.is_valid(raise_exception=True)
        email = serializer.validated_data.get("email")

        user = User.objects.filter(email=email).first()
        if user:
            return Response(
                {"detail": "이미 존재하는 이메일입니다."},
                status=status.HTTP_400_BAD_REQUEST,
            )

        payload = {
            "email": email,
            "exp": timezone.now() + datetime.timedelta(hours=1),
        }
        token = jwt.encode(payload, settings.SECRET_KEY, algorithm="HS256")
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


class RegistrationConfirmView(APIView):
    def get(self, request):
        """
        회원가입 확인 API
        - 유효한 이메일 인증 토큰을 통해 사용자를 활성화하고 회원가입을 완료합니다.
        """
        token = request.query_params.get("token")
        if not token:
            return Response(
                {"detail": "Token is required"}, status=status.HTTP_400_BAD_REQUEST
            )

        try:
            payload = jwt.decode(token, settings.SECRET_KEY, algorithms=["HS256"])
            email = payload.get("email")
            if not email:
                return Response(
                    {"detail": "Invalid token"}, status=status.HTTP_400_BAD_REQUEST
                )

            # 이메일로 사용자 검색
            user = User.objects.filter(email=email).first()
            if not user:
                # 사용자가 존재하지 않으면 새 사용자 생성
                # 비밀번호와 기타 정보는 초기화하거나 기본 값을 설정
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
                # 사용자 존재 시, 활성화 처리
                if user.is_active:
                    return Response(
                        {"detail": "User already active"},
                        status=status.HTTP_400_BAD_REQUEST,
                    )
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


class LoginView(APIView):
    def post(self, request):
        """
        Login API.
        - Authenticates user with email and password, and issues JWT and refresh tokens.
        """
        email = request.data.get("email")
        password = request.data.get("password")

        user = User.objects.filter(email=email).first()
        if user is None or not user.check_password(password):
            raise AuthenticationFailed("Invalid email or password")

        # Access Token
        payload = {
            "id": user.id,
            "exp": timezone.now() + datetime.timedelta(days=7),
            "iat": timezone.now(),
        }
        access_token = jwt.encode(payload, settings.SECRET_KEY, algorithm="HS256")

        # Refresh Token
        expires_at = timezone.now() + datetime.timedelta(days=30)
        refresh_token = RefreshToken.objects.create(user=user, expires_at=expires_at)

        response = Response(
            {
                "id": user.id,
                "email": user.email,
                "username": user.username,
            }
        )
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


class UserView(APIView):
    def get(self, request):
        """
        Retrieve user information API.
        - Returns user information based on JWT token.
        """
        token = request.COOKIES.get("jwt")
        if not token:
            raise AuthenticationFailed("Unauthenticated!")

        try:
            payload = jwt.decode(token, settings.SECRET_KEY, algorithms=["HS256"])
            user = User.objects.get(id=payload["id"])
        except jwt.ExpiredSignatureError:
            raise AuthenticationFailed("Token has expired")
        except jwt.InvalidTokenError:
            raise AuthenticationFailed("Invalid token")
        except User.DoesNotExist:
            raise AuthenticationFailed("User not found")

        serializer = UserSerializer(user)
        return Response(serializer.data)


class LogoutView(APIView):
    def post(self, request):
        """
        Logout API.
        - Deletes JWT and refresh token cookies.
        """
        response = Response({"message": "Successfully logged out"})
        response.delete_cookie("jwt")
        response.delete_cookie("refresh_token")
        return response


class RefreshTokenView(APIView):
    permission_classes = [IsAuthenticated]

    def post(self, request):
        """
        Issue a new access token API.
        """
        refresh_token = request.data.get("refresh_token")
        try:
            token = RefreshToken.objects.get(token=refresh_token)
            if token.is_expired():
                return Response(
                    {"detail": "Refresh token expired"},
                    status=status.HTTP_401_UNAUTHORIZED,
                )

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


class CookieAuthentication(BasePermission):
    def has_permission(self, request, view):
        token = request.COOKIES.get("jwt")
        if not token:
            return False

        try:
            payload = jwt.decode(token, settings.SECRET_KEY, algorithms=["HS256"])
            request.user = User.objects.get(id=payload["id"])
            return True
        except jwt.ExpiredSignatureError:
            raise AuthenticationFailed("Token has expired.")
        except jwt.InvalidTokenError:
            raise AuthenticationFailed("Invalid token.")
        except User.DoesNotExist:
            raise AuthenticationFailed("User not found.")


class DeleteAccountView(APIView):
    permission_classes = [CookieAuthentication]

    def delete(self, request):
        """
        Delete account API.
        - Only available to authenticated users.
        """
        token = request.COOKIES.get("jwt")
        if not token:
            return Response(
                {"detail": "No authentication credentials provided."},
                status=status.HTTP_401_UNAUTHORIZED,
            )

        try:
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


class PasswordResetRequestView(APIView):
    def post(self, request):
        """
        Password reset request API.
        - Sends a password reset link to the user's email.
        """
        serializer = PasswordResetRequestSerializer(data=request.data)
        serializer.is_valid(raise_exception=True)
        email = serializer.validated_data["email"]

        user = User.objects.filter(email=email).first()
        if not user:
            return Response(
                {"detail": "User with this email does not exist."},
                status=status.HTTP_404_NOT_FOUND,
            )

        payload = {
            "id": user.id,
            "email": user.email,
            "exp": timezone.now() + datetime.timedelta(hours=1),
        }
        token = jwt.encode(payload, settings.SECRET_KEY, algorithm="HS256")
        reset_url = request.build_absolute_uri(
            reverse("password-reset-confirm") + f"?token={token}"
        )

        # Send email
        send_mail(
            "Password Reset Request",
            f"Hello,\n\nYou requested a password reset. Click the following link to reset your password:\n{reset_url}\n\nIf you did not request this, please ignore this email.",
            settings.DEFAULT_FROM_EMAIL,
            [email],
        )

        return Response({"reset_url": reset_url})


class PasswordResetConfirmView(APIView):
    def post(self, request):
        """
        Password reset API.
        - Resets the user's password if the reset token is valid.
        """
        serializer = PasswordResetConfirmSerializer(data=request.data)
        serializer.is_valid(raise_exception=True)
        token = request.data.get("token")
        new_password = serializer.validated_data["password"]

        try:
            payload = jwt.decode(token, settings.SECRET_KEY, algorithms=["HS256"])
            user = User.objects.filter(id=payload["id"], email=payload["email"]).first()
            if not user:
                return Response(
                    {"detail": "User not found."}, status=status.HTTP_404_NOT_FOUND
                )

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
