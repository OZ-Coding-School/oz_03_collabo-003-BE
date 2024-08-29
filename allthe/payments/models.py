from accounts.models import User
from django.db import models


class Payment(models.Model):
    user = models.ForeignKey(User, on_delete=models.CASCADE)
    imp_uid = models.CharField(max_length=255)
    # 원래 금액
    original_amount = models.DecimalField(max_digits=10, decimal_places=2)
    # 실 결제 금액
    paid_amount = models.DecimalField(max_digits=10, decimal_places=2)
    # 할인금액
    discount_amount = models.DecimalField(max_digits=10, decimal_places=2, default=0.00)
    # 할인율(백분율 형태)
    discount_rate = models.DecimalField(max_digits=5, decimal_places=2, default=0.00)
    status = models.CharField(
        max_length=255,
        choices=[
            ("pending", "결제 대기"),
            ("paid", "결제 완료"),
            ("failed", "결제 실패"),
        ],
        default="pending",
    )
    created_at = models.DateTimeField(auto_now_add=True)
    updated_at = models.DateTimeField(auto_now=True)

    def save(self, *args, **kwargs):
        # 할인 적용 후 실제 결제 금액을 계산
        self.paid_amount = self.original_amount - self.discount_amount
        super().save(*args, **kwargs)
