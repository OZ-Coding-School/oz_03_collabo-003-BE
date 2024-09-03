from functools import wraps

from accounts.models import User
from contents.models import Content
from django.http import JsonResponse
from django.shortcuts import get_object_or_404


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


def admin_required(view_func):
    """관리자 권한 확인 데코레이터"""

    @wraps(view_func)
    def _wrapped_view(request, *args, **kwargs):
        if (
            not request.user.is_authenticated or request.user.role != "admin"
        ):  # admin 모델과 연동하여 실제 관리자 확인 로직 추가 필요
            return JsonResponse({"error": "관리자 권한이 필요합니다."}, status=403)
        return view_func(request, *args, **kwargs)

    return _wrapped_view


def author_required(view_func):
    """작성자 확인 데코레이터 (콘텐츠 수정/삭제 등)"""

    @wraps(view_func)
    def _wrapped_view(request, content_id, *args, **kwargs):
        content = get_object_or_404(Content, pk=content_id)
        if content.user != request.user:
            return JsonResponse(
                {"error": "작성자만 수정/삭제할 수 있습니다."}, status=403
            )
        return view_func(request, content_id, *args, **kwargs)

    return _wrapped_view
