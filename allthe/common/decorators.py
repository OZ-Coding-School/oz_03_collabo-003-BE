from functools import wraps

from accounts.models import User
from contents.models import Content
from django.http import JsonResponse
from django.shortcuts import get_object_or_404
from rest_framework.response import Response


def client_required(view_func):
    """의뢰자 권한 확인 데코레이터"""

    @wraps(view_func)
    def _wrapped_view(request, *args, **kwargs):
        if not request.user.is_authenticated or request.user.role != "client":
            return JsonResponse({"error": "의뢰자 권한이 필요합니다."}, status=403)
        return view_func(request, *args, **kwargs)

    return _wrapped_view


def analyst_required(view_func):
    """분석가 권한 확인 데코레이터"""

    @wraps(view_func)
    def _wrapped_view(request, *args, **kwargs):
        if not request.user.is_authenticated or request.user.role != "analyst":
            return JsonResponse({"error": "분석가 권한이 필요합니다."}, status=403)
        return view_func(request, *args, **kwargs)

    return _wrapped_view


def admin_required(func):
    def _wrapped_view(request, *args, **kwargs):
        if not request.user.is_authenticated or not request.user.is_staff:
            return Response({"error": "인증 실패 또는 권한 없음"}, status=403)
        return func(request, *args, **kwargs)

    return _wrapped_view


def author_required(view_func):
    """작성자 확인 데코레이터 (콘텐츠 수정/삭제 등)"""

    @wraps(view_func)
    def _wrapped_view(request, content_id, *args, **kwargs):
        content = get_object_or_404(Content, pk=content_id)
        if content.user != request.user:
            return JsonResponse({"error": "작성자만 수정/삭제할 수 있습니다."}, status=403)
        return view_func(request, content_id, *args, **kwargs)

    return _wrapped_view
