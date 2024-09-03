from rest_framework import serializers

from .models import Content
from .models import ContentImage
from .models import Like
from .models import QnA
from .models import Review


class QnASerializer(serializers.ModelSerializer):
    answers = serializers.SerializerMethodField()  # 답변 목록을 가져오기 위한 필드

    class Meta:
        model = QnA
        fields = "__all__"

    def get_answers(self, obj):
        if obj.is_question():  # 질문일 경우에만 답변 가져오기
            answers = QnA.objects.filter(parent=obj)
            return QnASerializer(answers, many=True).data
        return None


class ContentImageSerializer(serializers.ModelSerializer):
    class Meta:
        model = ContentImage
        fields = "__all__"


class ContentSerializer(serializers.ModelSerializer):
    average_rating = serializers.SerializerMethodField()
    views_count = serializers.IntegerField()
    likes_count = serializers.IntegerField()

    class Meta:
        model = Content
        fields = [
            "id",
            "title",
            "content",
            "main_category",
            "semi_category",
            "thumbnail",
            "site_url",
            "site_description",
            "is_analyzed",
            "created_at",
            "updated_at",
            "views_count",
            "likes_count",
            "average_rating",
            # 기타 필드들
        ]

    def get_average_rating(self, obj):
        reviews = Review.objects.filter(content=obj)
        if reviews.exists():
            return reviews.aggregate(average_rating=models.Avg("rating"))[
                "average_rating"
            ]
        return 0


# 콘텐츠 시리얼라이저
class ContentsSerializer(serializers.ModelSerializer):
    images = ContentImageSerializer(many=True, read_only=True)
    qna = QnASerializer(many=True, read_only=True)  # 콘텐츠에 포함된 Q&A

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
