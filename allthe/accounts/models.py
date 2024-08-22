import uuid

from django.conf import settings
from django.contrib.auth.models import AbstractUser
from django.contrib.auth.models import Group
from django.contrib.auth.models import Permission
from django.db import models
from django.utils import timezone

from .managers import CustomUserManager


class User(AbstractUser):
    """
    사용자 모델
    - 기본 Django `AbstractUser` 모델을 확장하여 이메일을 로그인 필드로 사용하며,
    인증 제공자와 생성 일자를 추가합니다.
    """

    email = models.EmailField(unique=True)  # 이메일 필드, 이메일이 유일해야 함
    # provider 필드는 social_provider 필드로 변경
    social_provider = models.CharField(
        max_length=100,
        choices=[
            ("kakao", "카카오"),
            ("naver", "네이버"),
            ("google", "구글"),
        ],
        blank=True,
        null=True,
    )  # 인증 제공자 (예: Google, Facebook)
    username = models.CharField(
        max_length=150, blank=True, null=True, unique=True
    )  # 사용자 이름, 공백 및 null 허용
    created_at = models.DateTimeField(
        default=timezone.now
    )  # 생성 일자, 기본값은 현재 시간

    # 추가된 필드
    role = models.CharField(
        max_length=255,
        choices=[
            ("user", "일반 사용자"),
            ("analyst", "분석가"),
            ("client", "의뢰자"),
        ],
        default="user",
    )
    business_number = models.CharField(max_length=255, blank=True, null=True)
    social_id = models.CharField(max_length=255, blank=True, null=True)
    refresh_token = models.CharField(max_length=255, blank=True, null=True)
    points = models.IntegerField(default=0)

    USERNAME_FIELD = "email"  # 기본 로그인 필드를 이메일로 설정
    REQUIRED_FIELDS = []  # 슈퍼유저 생성 시 추가 필드 없음

    objects = CustomUserManager()  # 사용자 관리에 사용되는 커스텀 매니저

    # 사용자와 그룹 간의 관계 설정
    groups = models.ManyToManyField(
        Group,
        related_name="custom_user_set",  # 사용자와 그룹의 관계에서 사용하는 이름
        blank=True,  # 빈 그룹을 허용
    )
    # 사용자와 권한 간의 관계 설정
    user_permissions = models.ManyToManyField(
        Permission,
        related_name="custom_user_permissions_set",  # 사용자와 권한의 관계에서 사용하는 이름
        blank=True,  # 빈 권한을 허용
    )

    class Meta:
        verbose_name = "user"  # 관리자 화면에 표시될 이름
        verbose_name_plural = "users"  # 관리자 화면에 표시될 복수형 이름
        permissions = [
            # 사용자 정의 권한을 여기에 추가할 수 있습니다.
        ]
        constraints = [
            models.UniqueConstraint(
                fields=["email"], name="unique_email"
            ),  # 이메일 중복 방지
            models.UniqueConstraint(
                fields=["username"], name="unique_username"
            ),  # 사용자 이름 중복 방지
        ]


class RefreshToken(models.Model):
    """
    리프레시 토큰 모델
    - 사용자와 관련된 리프레시 토큰을 저장하며, 토큰의 만료 여부를 확인합니다.
    """

    user = models.ForeignKey(
        settings.AUTH_USER_MODEL, on_delete=models.CASCADE
    )  # 사용자와의 외래키 관계 설정
    token = models.UUIDField(
        default=uuid.uuid4, editable=False, unique=True
    )  # 유니크한 UUID 토큰
    created_at = models.DateTimeField(auto_now_add=True)  # 토큰 생성 일자
    expires_at = models.DateTimeField()  # 토큰 만료 일자

    def is_expired(self):
        """
        리프레시 토큰이 만료되었는지 확인합니다.
        """
        return timezone.now() > self.expires_at

    class Meta:
        verbose_name = "refresh token"  # 관리자 화면에 표시될 이름
        verbose_name_plural = "refresh tokens"  # 관리자 화면에 표시될 복수형 이름
        constraints = [
            models.UniqueConstraint(
                fields=["token"], name="unique_refresh_token"
            ),  # 리프레시 토큰 중복 방지
        ]
