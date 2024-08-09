# accounts/middleware.py

from django.utils.deprecation import MiddlewareMixin
from rest_framework.exceptions import AuthenticationFailed
from rest_framework_simplejwt.authentication import JWTAuthentication

class JWTAuthenticationMiddleware(MiddlewareMixin):
    def process_request(self, request):
        """
        요청을 처리하는 미들웨어 메서드
        - 요청 헤더에서 JWT 토큰을 추출하여 인증을 수행합니다.
        - 인증된 사용자를 `request.user`에 설정합니다.
        """
        # JWTAuthentication 인스턴스를 생성합니다.
        auth = JWTAuthentication()

        # 'Authorization' 헤더가 요청 메타데이터에 포함되어 있는지 확인합니다.
        if "HTTP_AUTHORIZATION" in request.META:
            # 'Authorization' 헤더의 값을 가져옵니다.
            auth_header = request.META["HTTP_AUTHORIZATION"]
            try:
                # JWT 토큰을 인증합니다.
                user, _ = auth.authenticate(request)
                if user:
                    # 인증에 성공하면 `request.user`에 인증된 사용자 객체를 설정합니다.
                    request.user = user
            except AuthenticationFailed:
                # 인증에 실패하면 `request.user`를 `None`으로 설정합니다.
                request.user = None
        else:
            # 'Authorization' 헤더가 없으면 `request.user`를 `None`으로 설정합니다.
            request.user = None
