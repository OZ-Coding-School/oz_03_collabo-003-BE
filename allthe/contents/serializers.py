from rest_framework import serializers

from .models import Content
from .models import Like
from .models import Review


# 콘텐츠 시리얼라이저
class ContentsSerializer(serializers.ModelSerializer):
    class Meta:
        model = Content
        fields = "__all__"


class ReviewSerializer(serializers.ModelSerializer):
    class Meta:
        model = Review
        fields = [
            "id",
            "content",
            "user",
            "rating",
            "comment",
            "created_at",
            "updated_at",
        ]


class LikeSerializer(serializers.ModelSerializer):
    class Meta:
        model = Like
        fields = ["user", "content", "created_at"]
