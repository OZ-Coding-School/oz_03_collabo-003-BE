from accounts.models import User
from django.db import models


class Payment(models.Model):
    user = models.ForeignKey(User, on_delete=models.CASCADE)
    amount = models.DecimalField(max_digits=10, decimal_places=2)
    status = models.CharField(
        max_length=255,
        choices=[
            ("pending", "결제 대기"),
            ("paid", "결제 완료"),
            ("failed", "결제 실패"),
        ],
        default="pending",
    )
    transaction_id = models.CharField(max_length=255)
    created_at = models.DateTimeField(auto_now_add=True)
    updated_at = models.DateTimeField(auto_now=True)
