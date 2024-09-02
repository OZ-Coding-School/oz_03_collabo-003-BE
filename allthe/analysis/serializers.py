from accounts.serializers import UserSerializer
from contents.serializers import ContentsSerializer
from rest_framework import serializers

from .models import AnalysisReport
from .models import AnalysisRequest
from .models import Analyst
from .models import User


# 분석 요청 시리얼라이저 상세 조회
class AnalysisRequestSerializerDetail(serializers.ModelSerializer):
    client = UserSerializer(read_only=True)
    analyst = UserSerializer(read_only=True, many=True)
    content_id = ContentsSerializer(read_only=True)
    analyst_count = serializers.SerializerMethodField()

    class Meta:
        model = AnalysisRequest
        fields = "__all__"

    def get_analyst_count(self, obj):
        # analyst 필드의 총 개수를 반환
        return obj.analyst.count()


class AnalysisRequestSerializerList(serializers.ModelSerializer):
    client = UserSerializer(read_only=True)
    content_id = ContentsSerializer(read_only=True)

    class Meta:
        model = AnalysisRequest
        fields = "__all__"


# 분석 요청 post. list반환
class AnalysisRequestSerializer(serializers.ModelSerializer):
    class Meta:
        model = AnalysisRequest
        fields = "__all__"


# 분석 보고서 시리얼라이저
class AnalysisReportSerializer(serializers.ModelSerializer):
    request = AnalysisRequestSerializer()  # 의뢰 정보 포함

    class Meta:
        model = AnalysisReport
        fields = "__all__"


# 분석가 시리얼라이저
class AnalystSerializer(serializers.ModelSerializer):
    user_id = serializers.CharField(source="user.id", read_only=True)
    user_email = serializers.CharField(source="user.email", read_only=True)
    user_name = serializers.CharField(source="user.username", read_only=True)

    class Meta:
        model = Analyst
        fields = "__all__"
