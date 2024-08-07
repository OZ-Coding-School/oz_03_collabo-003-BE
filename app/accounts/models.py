from django.contrib.auth.models import AbstractUser, Group, Permission
from django.db import models
from django.utils import timezone
import uuid
from .managers import CustomUserManager
from django.conf import settings

class User(AbstractUser):
    email = models.EmailField(unique=True)  # Ensure unique email
    provider = models.CharField(max_length=100)  # Authentication provider (e.g., Google, Facebook)
    username = models.CharField(max_length=150, blank=True, null=True, unique=True)
    created_at = models.DateTimeField(default=timezone.now)  # Timestamp with default value of now

    USERNAME_FIELD = "email"
    REQUIRED_FIELDS = []  # No additional fields are required for creating a superuser

    objects = CustomUserManager()  # Use the custom user manager

    # Update related_name to avoid clashes
    groups = models.ManyToManyField(
        Group,
        related_name='custom_user_set',
        blank=True,
    )
    user_permissions = models.ManyToManyField(
        Permission,
        related_name='custom_user_permissions_set',
        blank=True,
    )

    class Meta:
        verbose_name = "user"
        verbose_name_plural = "users"
        permissions = [
            # Add any custom permissions here
        ]
        constraints = [
            models.UniqueConstraint(fields=['email'], name='unique_email'),
            models.UniqueConstraint(fields=['username'], name='unique_username'),
        ]

class RefreshToken(models.Model):
    user = models.ForeignKey(settings.AUTH_USER_MODEL, on_delete=models.CASCADE)
    token = models.UUIDField(default=uuid.uuid4, editable=False, unique=True)
    created_at = models.DateTimeField(auto_now_add=True)
    expires_at = models.DateTimeField()

    def is_expired(self):
        """
        Check if the refresh token is expired.
        """
        return timezone.now() > self.expires_at

    class Meta:
        verbose_name = "refresh token"
        verbose_name_plural = "refresh tokens"
        constraints = [
            models.UniqueConstraint(fields=['token'], name='unique_refresh_token'),
        ]
