import datetime
from django.utils import timezone
import jwt
from django.conf import settings
from django.contrib.auth import get_user_model
from rest_framework import status
from rest_framework.exceptions import AuthenticationFailed
from rest_framework.response import Response
from rest_framework.views import APIView
from rest_framework.permissions import BasePermission, IsAuthenticated  # Import IsAuthenticated
from .models import RefreshToken
from .serializers import UserSerializer, PasswordResetConfirmSerializer, PasswordResetRequestSerializer
from django.urls import reverse
from django.core.mail import send_mail

User = get_user_model()

# UserSerializer를 사용하여 유효한 사용자 데이터를 받아 새 사용자를 생성
class RegisterView(APIView):
    def post(self, request):
        """
        사용자 등록 API
        - 데이터 유효성 검사 후 사용자 생성
        """
        serializer = UserSerializer(data=request.data)
        serializer.is_valid(raise_exception=True)
        serializer.save()
        return Response(serializer.data, status=status.HTTP_201_CREATED)

#사용자의 이메일과 비밀번호를 검증하여 JWT 액세스 토큰과 리프레시 토큰을 발급
class LoginView(APIView):
    def post(self, request):
        """
        로그인 API
        - 이메일과 비밀번호로 사용자 인증 후 JWT 토큰과 리프레시 토큰 발급
        """
        email = request.data.get("email")
        password = request.data.get("password")

        user = User.objects.filter(email=email).first()
        if user is None or not user.check_password(password):
            raise AuthenticationFailed("Invalid email or password")

        # 액세스 토큰 생성
        payload = {
            "id": user.id,
            "exp": timezone.now() + datetime.timedelta(days=7),
            "iat": timezone.now(),
        }
        access_token = jwt.encode(payload, settings.SECRET_KEY, algorithm="HS256")

        # 리프레시 토큰 생성
        expires_at = timezone.now() + datetime.timedelta(days=30)
        refresh_token = RefreshToken.objects.create(user=user, expires_at=expires_at)

        # 응답 생성
        response = Response({
            "id": user.id,
            "email": user.email,
            "username": user.username,
        })
        #쿠키에 토큰 세팅
        response.set_cookie(key="jwt", value=access_token, httponly=True, expires=timezone.now() + datetime.timedelta(days=7))
        response.set_cookie(key="refresh_token", value=str(refresh_token.token), httponly=True, expires=expires_at)

        return response

#쿠키에 저장된 JWT 토큰을 통해 인증을 받은 후 현재 인증된 사용자의 정보를 반환
class UserView(APIView):
    def get(self, request):
        """
        사용자 정보 조회 API
        - JWT 토큰을 통해 인증된 사용자 정보 반환
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

#쿠키에서 JWT 액세스 토큰과 리프레시 토큰을 삭제
class LogoutView(APIView):
    def post(self, request):
        """
        로그아웃 API
        - JWT 토큰 및 리프레시 토큰 쿠키 삭제
        """
        response = Response({"message": "Successfully logged out"})
        response.delete_cookie("jwt")
        response.delete_cookie("refresh_token")
        return response


#유효한 리프레시 토큰을 사용하여 새로운 액세스 토큰을 발급
class RefreshTokenView(APIView):
    permission_classes = [IsAuthenticated]  # Ensure IsAuthenticated is imported

    def post(self, request):
        """
        새로운 액세스 토큰을 발급하는 API
        """
        refresh_token = request.data.get("refresh_token")
        try:
            token = RefreshToken.objects.get(token=refresh_token)
            if token.is_expired():
                return Response({"detail": "Refresh token expired"}, status=status.HTTP_401_UNAUTHORIZED)

            user = token.user
            payload = {
                "id": user.id,
                "exp": timezone.now() + datetime.timedelta(days=7),
                "iat": timezone.now(),
            }
            new_access_token = jwt.encode(payload, settings.SECRET_KEY, algorithm="HS256")
            return Response({"access_token": new_access_token}, status=status.HTTP_200_OK)

        except RefreshToken.DoesNotExist:
            return Response({"detail": "Invalid refresh token"}, status=status.HTTP_401_UNAUTHORIZED)

#쿠키에 저장된 JWT 토큰을 확인하고 유효성을 검증하여 요청 객체의 user 속성에 사용자 정보를 설정
class CookieAuthentication(BasePermission):
    def has_permission(self, request, view):
        token = request.COOKIES.get('jwt')
        if not token:
            return False
        
        try:
            payload = jwt.decode(token, settings.SECRET_KEY, algorithms=["HS256"])
            request.user = User.objects.get(id=payload['id'])
            return True
        except jwt.ExpiredSignatureError:
            raise AuthenticationFailed('Token has expired.')
        except jwt.InvalidTokenError:
            raise AuthenticationFailed('Invalid token.')
        except User.DoesNotExist:
            raise AuthenticationFailed('User not found.')

#계정 삭제 후 JWT 토큰을 쿠키에서 제거
class DeleteAccountView(APIView):
    permission_classes = [CookieAuthentication]

    def delete(self, request):
        """
        회원 탈퇴 API
        - JWT 토큰을 통해 인증된 사용자만 사용 가능
        - 인증된 사용자의 계정을 삭제합니다.
        """
        token = request.COOKIES.get("jwt")
        if not token:
            return Response({"detail": "No authentication credentials provided."}, status=status.HTTP_401_UNAUTHORIZED)

        try:
            payload = jwt.decode(token, settings.SECRET_KEY, algorithms=["HS256"])
            user = User.objects.get(id=payload["id"])
            user.delete()
            response = Response({"detail": "Account successfully deleted."}, status=status.HTTP_204_NO_CONTENT)
            response.delete_cookie("jwt")
            return response
        except jwt.ExpiredSignatureError:
            return Response({"detail": "Token has expired."}, status=status.HTTP_401_UNAUTHORIZED)
        except jwt.InvalidTokenError:
            return Response({"detail": "Invalid token."}, status=status.HTTP_401_UNAUTHORIZED)
        except User.DoesNotExist:
            return Response({"detail": "User not found."}, status=status.HTTP_404_NOT_FOUND)

#사용자에게 비밀번호 재설정 링크를 포함한 이메일을 발송
class PasswordResetRequestView(APIView):
    def post(self, request):
        """
        비밀번호 재설정 요청 API
        - 이메일을 통해 비밀번호 재설정 링크를 포함한 이메일 발송
        """
        serializer = PasswordResetRequestSerializer(data=request.data)
        serializer.is_valid(raise_exception=True)
        email = serializer.validated_data["email"]

        user = User.objects.filter(email=email).first()
        if not user:
            return Response({"detail": "User with this email does not exist."}, status=status.HTTP_404_NOT_FOUND)

        payload = {
            "id": user.id,
            "email": user.email,
            "exp": timezone.now() + datetime.timedelta(hours=1),
        }
        token = jwt.encode(payload, settings.SECRET_KEY, algorithm="HS256")
        reset_url = request.build_absolute_uri(reverse("password-reset-confirm") + f"?token={token}")

        # 이메일 발송
        send_mail(
            "Password Reset Request",
            f"Hello,\n\nYou requested a password reset. Click the following link to reset your password:\n{reset_url}\n\nIf you did not request this, please ignore this email.",
            settings.DEFAULT_FROM_EMAIL,
            [email]
        )

        return Response({"reset_url": reset_url})

#비밀번호 재설정 토큰을 검증하고, 사용자의 비밀번호를 새 비밀번호로 변경
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