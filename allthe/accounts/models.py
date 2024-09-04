import uuid

from django.conf import settings
from django.contrib.auth.models import AbstractUser
from django.contrib.auth.models import BaseUserManager
from django.contrib.auth.models import Group
from django.contrib.auth.models import Permission
from django.db import models
from django.utils import timezone

from .managers import CustomUserManager


class User(AbstractUser):
    """
    사용자 모델
    """

    email = models.EmailField(unique=True)
    social_provider = models.CharField(
        max_length=100,
        choices=[
            ("kakao", "카카오"),
            ("naver", "네이버"),
            ("google", "구글"),
        ],
        blank=True,
        null=True,
    )
    username = models.CharField(max_length=150, blank=True, null=True, unique=True)
    created_at = models.DateTimeField(default=timezone.now)

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
    phone_number = models.CharField(max_length=255, blank=True, null=True)
    social_id = models.CharField(max_length=255, blank=True, null=True)
    refresh_token = models.CharField(max_length=255, blank=True, null=True)
    points = models.IntegerField(default=0)

    USERNAME_FIELD = "email"
    REQUIRED_FIELDS = ["username"]

    objects = CustomUserManager()

    groups = models.ManyToManyField(
        Group,
        related_name="custom_user_set",
        blank=True,
    )
    user_permissions = models.ManyToManyField(
        Permission,
        related_name="custom_user_permissions_set",
        blank=True,
    )

    class Meta:
        verbose_name = "user"
        verbose_name_plural = "users"
        constraints = [
            models.UniqueConstraint(fields=["email"], name="unique_email"),
            models.UniqueConstraint(fields=["username"], name="unique_username"),
        ]


class VerificationCode(models.Model):
    email = models.EmailField(unique=True)
    code = models.CharField(max_length=6)
    expires_at = models.DateTimeField()

    def __str__(self):
        return f"{self.email} - {self.code}"


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
    objects=models.Manager()
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


class CustomUserManager(BaseUserManager):
    def create_superuser(self, email, username, password=None, **extra_fields):
        extra_fields.setdefault("is_staff", True)
        extra_fields.setdefault("is_superuser", True)

        if extra_fields.get("is_staff") is not True:
            raise ValueError("Superuser must have is_staff=True.")
        if extra_fields.get("is_superuser") is not True:
            raise ValueError("Superuser must have is_superuser=True.")

        return self.create_user(email, username, password, **extra_fields)

    def create_user(self, email, username, password=None, **extra_fields):
        if not email:
            raise ValueError("The Email field must be set")
        email = self.normalize_email(email)
        user = self.model(email=email, username=username, **extra_fields)
        user.set_password(password)
        user.save(using=self._db)
        return user
