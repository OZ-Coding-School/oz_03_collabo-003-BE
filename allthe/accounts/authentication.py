from django.conf import settings
from rest_framework.exceptions import AuthenticationFailed
from rest_framework.authentication import BaseAuthentication
import jwt
from .models import User


class CookieAuthentication(BaseAuthentication):
    def authenticate(self, request):
        """
        쿠키 기반 인증을 수행하는 인증 클래스
        - 요청의 쿠키에서 JWT 토큰을 추출하고, 이를 검증하여 사용자 인증을 수행합니다.
        """
        token = request.COOKIES.get("jwt")
        if not token:
            return None 

        try:
            # JWT 토큰 디코딩 및 검증
            payload = jwt.decode(token, settings.SECRET_KEY, algorithms=["HS256"])
            user = User.objects.get(id=payload["id"])
            return (user, None)  # user와 token을 반환
        except jwt.ExpiredSignatureError:
            raise AuthenticationFailed("Token has expired.")
        except jwt.InvalidTokenError:
            raise AuthenticationFailed("Invalid token.")
        except User.DoesNotExist:
            raise AuthenticationFailed("User not found.")