from accounts.models import User
from contents.models import Content
from django.db import models


class AnalysisRequest(models.Model):
    client = models.ForeignKey(
        User, on_delete=models.CASCADE, related_name="analysis_requests_as_client"
    )
    analyst = models.ManyToManyField(
        User,
        # null=True,
        blank=True,
        related_name="analysis_requests_as_analyst",
    )
    content_id = models.ForeignKey(Content, on_delete=models.CASCADE)
    status = models.CharField(
        max_length=20,
        choices=[
            ("PENDING", "대기 중"),
            ("ACCEPTED", "수락됨"),
            ("COMPLETED", "완료됨"),
        ],
        default="PENDING",
    )
    requirements = models.TextField(null=True, blank=True)  # 요구 사항
    completed_at = models.DateTimeField(null=True, blank=True)
    created_at = models.DateTimeField(auto_now_add=True)
    updated_at = models.DateTimeField(auto_now=True)


class AnalysisReport(models.Model):
    request = models.OneToOneField(AnalysisRequest, on_delete=models.CASCADE)
    file = models.FileField(upload_to="reports/")
    created_at = models.DateTimeField(auto_now_add=True)


class Analyst(models.Model):
    user = models.OneToOneField(
        User, on_delete=models.CASCADE, related_name="analyst_profile"
    )
    analyst_image = models.ImageField(
        upload_to="analyst_photos/", blank=True, null=True
    )
    intro = models.TextField(blank=True, null=True)
    merit = models.TextField(blank=True, null=True)
    summary = models.TextField(blank=True, null=True)

    def __str__(self):
        return f"{self.user.username} - Analyst Profile"
