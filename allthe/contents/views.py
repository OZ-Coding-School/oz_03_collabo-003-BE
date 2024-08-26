from django.shortcuts import render
from drf_yasg import openapi
from drf_yasg.utils import swagger_auto_schema
from rest_framework import status
from rest_framework.permissions import IsAuthenticated
from rest_framework.response import Response
from rest_framework.views import APIView

from .models import Content
from .models import Image
from .serializers import ContentsSerializer


# 콘텐츠 업로드(post), 모든 콘텐츠 list(get)
class UploadContent(APIView):
    permission_classes = [IsAuthenticated]  # 인증된 사용자만 접근 허용

    @swagger_auto_schema(
        request_body=openapi.Schema(
            type=openapi.TYPE_OBJECT,
            properties={
                "title": openapi.Schema(type=openapi.TYPE_STRING),
                "content": openapi.Schema(type=openapi.TYPE_STRING),
                "category": openapi.Schema(type=openapi.TYPE_STRING),
                "site_url": openapi.Schema(type=openapi.TYPE_STRING),
                "site_description": openapi.Schema(
                    type=openapi.TYPE_STRING, default=""
                ),
                "is_analyzed": openapi.Schema(type=openapi.TYPE_BOOLEAN, default=False),
                "images": openapi.Schema(
                    type=openapi.TYPE_ARRAY,
                    items=openapi.Schema(type=openapi.TYPE_FILE),
                    description="Upload multiple images",
                    default=[],
                ),
            },
        ),
        responses={
            status.HTTP_201_CREATED: ContentsSerializer,
            status.HTTP_400_BAD_REQUEST: openapi.Response("Bad Request"),
        },
        operation_summary="Upload new content with images",
        operation_description="This endpoint allows users to upload new content with multiple images. Only non-analyst users can upload content.",
    )
    def post(self, request):
        # 요청한 사용자가 의뢰자인지 확인
        if request.user.role == "analyst":
            return Response(
                {"error": "분석가는 콘텐츠를 업로드할 수 없습니다."},
                status=status.HTTP_403_FORBIDDEN,
            )

        # 요청 데이터에서 콘텐츠 정보를 가져옴
        data = request.data.copy()  # request.data는 ImmutableMultiValueDict이므로 복사
        data["user"] = request.user.id  # 사용자 ID를 추가

        # 콘텐츠의 기본 정보 저장
        content_serializer = ContentsSerializer(data=data, partial=True)
        if content_serializer.is_valid():
            # 콘텐츠 인스턴스 저장
            content = content_serializer.save()

            # 이미지 처리
            image_files = request.FILES.getlist("images")
            for image_file in image_files:
                # Image 모델에 이미지 저장
                image = Image.objects.create(file=image_file)
                # Content 모델과 연결
                content.images.add(image)

            return Response(content_serializer.data, status=status.HTTP_201_CREATED)

        return Response(content_serializer.errors, status=status.HTTP_400_BAD_REQUEST)

    @swagger_auto_schema(
        responses={
            status.HTTP_200_OK: ContentsSerializer(many=True),
            status.HTTP_401_UNAUTHORIZED: openapi.Response("Unauthorized"),
        },
        operation_summary="List all content",
        operation_description="Retrieve a list of all content objects. Only authenticated users can access this endpoint.",
    )
    def get(self, request):
        # 모든 콘텐츠 객체 가져오기
        contents = Content.objects.all()
        serializer = ContentsSerializer(contents, many=True)
        return Response(serializer.data, status=status.HTTP_200_OK)
