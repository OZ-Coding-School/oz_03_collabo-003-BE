from accounts.models import User
from django.db import models


class Notice(models.Model):
    title = models.CharField(max_length=255)
    content = models.TextField()
    created_at = models.DateTimeField(auto_now_add=True)
    updated_at = models.DateTimeField(auto_now=True)

    def __str__(self):
        return self.title


class Popup(models.Model):
    title = models.CharField(max_length=255)
    content = models.TextField()
    position = models.CharField(max_length=255)
    created_at = models.DateTimeField(auto_now_add=True)
    updated_at = models.DateTimeField(auto_now=True)

    def __str__(self):
        return self.title


class Admin(models.Model):
    email = models.CharField(max_length=255, unique=True)
    password = models.CharField(max_length=255)
    name = models.CharField(max_length=255)
    role = models.CharField(
        max_length=20,
        choices=[
            ("manager", "관리자"),
            ("editor", "에디터"),
        ],
        default="editor",
    )
    created_at = models.DateTimeField(auto_now_add=True)
    updated_at = models.DateTimeField(auto_now=True)

    def __str__(self):
        return self.name


class PointHistory(models.Model):
    user = models.ForeignKey(User, on_delete=models.CASCADE)
    amount = models.IntegerField()
    action = models.CharField(
        max_length=10,
        choices=[
            ("add", "적립"),
            ("subtract", "차감"),
        ],
    )
    description = models.CharField(max_length=255, blank=True, null=True)
    created_at = models.DateTimeField(auto_now_add=True)

    def __str__(self):
        return f"{self.user} - {self.amount} 포인트 {self.get_action_display()}"


class WithdrawRequest(models.Model):
    user = models.ForeignKey(User, on_delete=models.CASCADE)
    amount = models.IntegerField()
    bank = models.CharField(max_length=255)
    account_number = models.CharField(max_length=255)
    account_holder = models.CharField(max_length=255)
    status = models.CharField(
        max_length=20,
        choices=[
            ("pending", "대기 중"),
            ("completed", "완료"),
            ("rejected", "거절"),
        ],
        default="pending",
    )
    created_at = models.DateTimeField(auto_now_add=True)
    updated_at = models.DateTimeField(auto_now=True)

    def __str__(self):
        return f"{self.user} - {self.amount}원 출금 요청 ({self.get_status_display()})"
