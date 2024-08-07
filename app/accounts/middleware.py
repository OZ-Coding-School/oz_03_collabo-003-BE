# accounts/middleware.py

from django.utils.deprecation import MiddlewareMixin
from rest_framework_simplejwt.authentication import JWTAuthentication
from rest_framework.exceptions import AuthenticationFailed

class JWTAuthenticationMiddleware(MiddlewareMixin):
    def process_request(self, request):
        auth = JWTAuthentication()
        # Check if 'Authorization' header is present
        if 'HTTP_AUTHORIZATION' in request.META:
            auth_header = request.META['HTTP_AUTHORIZATION']
            try:
                # Authenticate the JWT token
                user, _ = auth.authenticate(request)
                if user:
                    request.user = user
            except AuthenticationFailed:
                request.user = None
        else:
            request.user = None
