from django.db import models

class Category(models.Model):
    """
    카테고리 모델
    카테고리의 기본 정보를 저장합니다.
    """
    name = models.CharField(max_length=255)
    parent = models.ForeignKey('self', null=True, blank=True, on_delete=models.CASCADE)
    created_at = models.DateTimeField(auto_now_add=True)
    updated_at = models.DateTimeField(auto_now=True)

    def __str__(self):
        return self.name