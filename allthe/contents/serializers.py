from rest_framework import serializers
from .models import Content

#콘텐츠 시리얼라이저
class ContentsSerializer(serializers.ModelSerializer):
    class Meta:
        model = Content
        fields = "__all__"