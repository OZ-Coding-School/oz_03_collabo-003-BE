from rest_framework import serializers
from rest_framework import status
from rest_framework.permissions import IsAuthenticated
from rest_framework.response import Response
from rest_framework.views import APIView
from drf_yasg import openapi
from drf_yasg.utils import swagger_auto_schema
from django.db import models
from accounts.models import User
from .models import Content, Review, Like
from .models import Image
from .serializers import ContentsSerializer, ReviewSerializer, LikeSerializer


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
    

# 콘텐츠 수정(PATCH) API
class UpdateContent(APIView):
    permission_classes = [IsAuthenticated]  # 인증된 사용자만 접근 허용
#APIView를 상속받아 UpdateContent 클래스를 정의
    @swagger_auto_schema(
        request_body=openapi.Schema( #request_body를 사용하여 요청 데이터의 형식
            type=openapi.TYPE_OBJECT,
            properties={
                "title": openapi.Schema(type=openapi.TYPE_STRING, description="Title of the content"),
                "content": openapi.Schema(type=openapi.TYPE_STRING, description="Content body"),
                "category": openapi.Schema(type=openapi.TYPE_STRING, description="Category of the content"),
                "site_url": openapi.Schema(type=openapi.TYPE_STRING, description="Site URL related to the content"),
                "site_description": openapi.Schema(type=openapi.TYPE_STRING, description="Description of the site"),
                "is_analyzed": openapi.Schema(type=openapi.TYPE_BOOLEAN, description="Is the content analyzed"),
                "images": openapi.Schema(
                    type=openapi.TYPE_ARRAY,
                    items=openapi.Schema(type=openapi.TYPE_FILE),
                    description="Upload multiple images",
                    default=[],
                ),
            },
        ),
        responses={ #responses를 사용하여 다양한 응답 상태 코드에 대한 설명을 추가
            status.HTTP_200_OK: ContentsSerializer,
            status.HTTP_400_BAD_REQUEST: openapi.Response("Bad Request"),
            status.HTTP_404_NOT_FOUND: openapi.Response("Content Not Found"),
            status.HTTP_403_FORBIDDEN: openapi.Response("Forbidden"),
        },
        operation_summary="Update existing content",
        operation_description="This endpoint allows users to update an existing content object. Only non-analyst users can update content.",
    )
    def patch(self, request, pk): #pk를 URL 경로에서 받아 콘텐츠를 검색
        # 콘텐츠 객체 가져오기
        try:
            content = Content.objects.get(pk=pk)
        except Content.DoesNotExist:
            #콘텐츠가 존재하지 않으면 404 Not Found 응답을 반환
            return Response({"error": "콘텐츠를 찾을 수 없습니다."}, status=status.HTTP_404_NOT_FOUND)

        # 요청한 사용자가 의뢰자인지 확인
        if request.user.role == "analyst":
            return Response(
                #요청 사용자의 역할을 확인하여 권한이 없으면 403 Forbidden 응답을 반환
                {"error": "분석가는 콘텐츠를 수정할 수 없습니다."},
                status=status.HTTP_403_FORBIDDEN,
            )

        # 요청 데이터에서 콘텐츠 정보를 가져옴
        data = request.data.copy()  # request.data는 ImmutableMultiValueDict이므로 복사

        # 콘텐츠의 기본 정보 수정
        content_serializer = ContentsSerializer(content, data=data, partial=True)
        if content_serializer.is_valid():
            # 콘텐츠 인스턴스 저장
            updated_content = content_serializer.save()

            # 이미지 처리
            if 'images' in request.FILES:
                image_files = request.FILES.getlist("images")
                for image_file in image_files:
                    # Image 모델에 이미지 저장
                    image = Image.objects.create(file=image_file)
                    # Content 모델과 연결
                    updated_content.images.add(image)

            return Response(content_serializer.data, status=status.HTTP_200_OK)

        return Response(content_serializer.errors, status=status.HTTP_400_BAD_REQUEST)
    

# 콘텐츠 삭제(DELETE) API
class DeleteContent(APIView):
    #APIView를 상속받아 DeleteContent 클래스를 정의
    permission_classes = [IsAuthenticated]  # 인증된 사용자만 접근 허용

    @swagger_auto_schema(
        responses={
            status.HTTP_204_NO_CONTENT: openapi.Response("Content Deleted"),
            status.HTTP_404_NOT_FOUND: openapi.Response("Content Not Found"),
            status.HTTP_403_FORBIDDEN: openapi.Response("Forbidden"),
        },
        operation_summary="Delete existing content",
        operation_description="This endpoint allows users to delete an existing content object. Only non-analyst users can delete content.",
    )
    def delete(self, request, pk):
        # 콘텐츠 객체 가져오기
        try:
            content = Content.objects.get(pk=pk)
        except Content.DoesNotExist:
            return Response({"error": "콘텐츠를 찾을 수 없습니다."}, status=status.HTTP_404_NOT_FOUND)

        # 요청한 사용자가 의뢰자인지 확인
        if request.user.role == "analyst":
            return Response(
                {"error": "분석가는 콘텐츠를 삭제할 수 없습니다."},
                status=status.HTTP_403_FORBIDDEN,
            )

        # 콘텐츠 객체 삭제
        content.delete()
        #콘텐츠 객체를 삭제하고 204 No Content 응답을 반환
        return Response(status=status.HTTP_204_NO_CONTENT)
    

class AddReview(APIView):
    permission_classes = [IsAuthenticated]  # 인증된 사용자만 접근 허용

    @swagger_auto_schema(
        request_body=ReviewSerializer,
        responses={
            status.HTTP_201_CREATED: ReviewSerializer,
            status.HTTP_400_BAD_REQUEST: openapi.Response("Bad Request"),
            status.HTTP_404_NOT_FOUND: openapi.Response("Content Not Found"),
            status.HTTP_403_FORBIDDEN: openapi.Response("Forbidden"),
        },
        operation_summary="Add a review to a content",
        operation_description="This endpoint allows authenticated users to add a review to a specific content. Users can provide a rating and comment.",
    )
    def post(self, request, content_id):
        try:
            content = Content.objects.get(pk=content_id)
        except Content.DoesNotExist:
            return Response({"error": "콘텐츠를 찾을 수 없습니다."}, status=status.HTTP_404_NOT_FOUND)

        data = request.data.copy()
        data["user"] = request.user.id
        data["content"] = content_id

        serializer = ReviewSerializer(data=data)
        if serializer.is_valid():
            serializer.save()
            return Response(serializer.data, status=status.HTTP_201_CREATED)

        return Response(serializer.errors, status=status.HTTP_400_BAD_REQUEST)
    

class UpdateReview(APIView):
    permission_classes = [IsAuthenticated]

    @swagger_auto_schema(
        request_body=ReviewSerializer,
        responses={
            status.HTTP_200_OK: ReviewSerializer,
            status.HTTP_400_BAD_REQUEST: openapi.Response("Bad Request"),
            status.HTTP_403_FORBIDDEN: openapi.Response("Forbidden"),
            status.HTTP_404_NOT_FOUND: openapi.Response("Review Not Found"),
        },
        operation_summary="Update a review",
        operation_description="This endpoint allows authenticated users to update their own review or admins to update any review. Users can modify the rating and comment.",
    )
    def put(self, request, review_id):
        try:
            review = Review.objects.get(pk=review_id)
        except Review.DoesNotExist:
            return Response({"error": "리뷰를 찾을 수 없습니다."}, status=status.HTTP_404_NOT_FOUND)
        
        # 본인 리뷰 또는 관리자인 경우만 수정 가능
        if request.user != review.user and not request.user.is_staff:
            return Response({"error": "본인 리뷰만 수정할 수 있습니다."}, status=status.HTTP_403_FORBIDDEN)

        data = request.data
        serializer = ReviewSerializer(review, data=data, partial=True)
        if serializer.is_valid():
            serializer.save()
            return Response(serializer.data, status=status.HTTP_200_OK)

        return Response(serializer.errors, status=status.HTTP_400_BAD_REQUEST)
    

class DeleteReview(APIView):
    permission_classes = [IsAuthenticated]

    @swagger_auto_schema(
        responses={
            status.HTTP_204_NO_CONTENT: openapi.Response("No Content"),
            status.HTTP_403_FORBIDDEN: openapi.Response("Forbidden"),
            status.HTTP_404_NOT_FOUND: openapi.Response("Review Not Found"),
        },
        operation_summary="Delete a review",
        operation_description="This endpoint allows authenticated users to delete their own review or admins to delete any review.",
    )
    def delete(self, request, review_id):
        try:
            review = Review.objects.get(pk=review_id)
        except Review.DoesNotExist:
            return Response({"error": "리뷰를 찾을 수 없습니다."}, status=status.HTTP_404_NOT_FOUND)

        # 본인 리뷰 또는 관리자인 경우만 삭제 가능
        if request.user != review.user and not request.user.is_staff:
            return Response({"error": "본인 리뷰만 삭제할 수 있습니다."}, status=status.HTTP_403_FORBIDDEN)

        review.delete()
        return Response(status=status.HTTP_204_NO_CONTENT)

#콘텐츠 찜하기 api
class Wishlist(models.Model):
    user = models.ForeignKey(User, on_delete=models.CASCADE)
    content = models.ForeignKey(Content, on_delete=models.CASCADE)
    created_at = models.DateTimeField(auto_now_add=True)

    class Meta:
        unique_together = ('user', 'content')  # 같은 사용자가 동일 콘텐츠를 중복 찜할 수 없도록 설정

    def __str__(self):
        return f'{self.user} - {self.content}'
    

class ToggleLike(APIView):
    permission_classes = [IsAuthenticated]

    @swagger_auto_schema(
        request_body=openapi.Schema(
            type=openapi.TYPE_OBJECT,
            properties={
                'content_id': openapi.Schema(type=openapi.TYPE_INTEGER, description='ID of the content to be liked/unliked')
            }
        ),
        responses={
            status.HTTP_200_OK: LikeSerializer,
            status.HTTP_400_BAD_REQUEST: openapi.Response('Bad Request'),
        },
        operation_summary='Add or remove content from likes',
        operation_description='Add or remove a specific content from the likes. If the content is already liked, it will be unliked. Otherwise, it will be liked.',
    )
    def post(self, request):
        content_id = request.data.get('content_id')
        if not content_id:
            return Response({"error": "Content ID is required."}, status=status.HTTP_400_BAD_REQUEST)

        try:
            content = Content.objects.get(pk=content_id)
        except Content.DoesNotExist:
            return Response({"error": "Content not found."}, status=status.HTTP_404_NOT_FOUND)

        # Check if the content is already liked by the user
        like, created = Like.objects.get_or_create(user=request.user, content=content)

        if not created:
            # Item already liked, remove it
            like.delete()
            return Response({"message": "Content removed from likes."}, status=status.HTTP_200_OK)

        # New item liked
        return Response({"message": "Content added to likes."}, status=status.HTTP_200_OK)

class LikedContentList(APIView):
    permission_classes = [IsAuthenticated]

    @swagger_auto_schema(
        responses={
            status.HTTP_200_OK: LikeSerializer(many=True),
            status.HTTP_400_BAD_REQUEST: openapi.Response('Bad Request'),
        },
        operation_summary='List all liked content',
        operation_description='Retrieve a list of all content items liked by the user.',
    )
    def get(self, request):
        liked_items = Like.objects.filter(user=request.user)
        serializer = LikeSerializer(liked_items, many=True)
        return Response(serializer.data, status=status.HTTP_200_OK)