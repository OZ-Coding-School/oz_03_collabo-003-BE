from accounts.models import User
from django.db import models


class Category(models.Model):
    name = models.CharField(max_length=255)
    parent = models.ForeignKey(
        "self",
        on_delete=models.CASCADE,
        null=True,
        blank=True,
        related_name="subcategories",
    )

    def __str__(self):
        return self.name


class Content(models.Model):
    user = models.ForeignKey(User, on_delete=models.CASCADE)
    title = models.CharField(max_length=255)
    content = models.TextField()
    main_category = models.TextField()
    semi_category = models.TextField()
    thumbnail = models.ImageField(upload_to="images/", blank=True, null=True)
    site_url = models.CharField(max_length=255)
    site_description = models.TextField(blank=True, null=True)
    is_analyzed = models.BooleanField(default=False)
    created_at = models.DateTimeField(auto_now_add=True)
    updated_at = models.DateTimeField(auto_now=True)

    # 새로운 필드 추가
    views_count = models.PositiveIntegerField(default=0)  # 조회수
    likes_count = models.PositiveIntegerField(default=0)  # 찜수

    def __str__(self):
        return self.title

    def get_likes_count(self):
        return Like.objects.filter(content=self).count()

    def increment_views(self):
        self.views_count += 1
        self.save()


class ContentImage(models.Model):
    content = models.ForeignKey(
        Content, on_delete=models.CASCADE, blank=True, null=True, related_name="images"
    )
    file = models.ImageField(upload_to="images/", blank=True, null=True)
    uploaded_at = models.DateTimeField(auto_now_add=True)


class Review(models.Model):
    user = models.ForeignKey(User, on_delete=models.CASCADE)
    content = models.ForeignKey(
        Content, on_delete=models.CASCADE, related_name="reviews"
    )
    rating = models.IntegerField()
    comment = models.TextField()
    created_at = models.DateTimeField(auto_now_add=True)
    updated_at = models.DateTimeField(auto_now=True)


class Like(models.Model):
    user = models.ForeignKey(User, on_delete=models.CASCADE)
    content = models.ForeignKey(Content, on_delete=models.CASCADE)
    created_at = models.DateTimeField(auto_now_add=True)

    class Meta:
        unique_together = ("user", "content")


class QnA(models.Model):
    user = models.ForeignKey(User, on_delete=models.CASCADE)
    content = models.ForeignKey(Content, on_delete=models.CASCADE)
    parent = models.ForeignKey("self", on_delete=models.CASCADE, null=True, blank=True)
    text = models.TextField()
    created_at = models.DateTimeField(auto_now_add=True)
    updated_at = models.DateTimeField(auto_now=True)

    def is_question(self):
        return self.parent is None  # 질문인지 여부 확인

    def __str__(self):
        return self.text


class Image(models.Model):
    content = models.ForeignKey(
        Content, on_delete=models.CASCADE, null=True, blank=True
    )
    url = models.CharField(max_length=255)
    created_at = models.DateTimeField(auto_now_add=True)
