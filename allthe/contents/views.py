import os
import uuid

import boto3
import jwt
from accounts.authentication import CookieAuthentication
from accounts.models import User
from django.conf import settings
from django.db import models
from drf_yasg import openapi
from drf_yasg.utils import swagger_auto_schema
from rest_framework import serializers
from rest_framework import status
from rest_framework.exceptions import AuthenticationFailed
from rest_framework.permissions import BasePermission
from rest_framework.permissions import IsAuthenticated
from rest_framework.response import Response
from rest_framework.views import APIView

from .models import Content
from .models import ContentImage
from .models import Image
from .models import Like
from .models import QnA
from .models import Review
from .serializers import ContentSerializer
from .serializers import ContentsSerializer
from .serializers import LikeSerializer
from .serializers import QnASerializer
from .serializers import ReviewSerializer

bucket_name = "allthe"
s3 = boto3.client(
    "s3",
    endpoint_url="https://kr.object.ncloudstorage.com",
    aws_access_key_id=os.getenv("NCP_Access_Key"),
    aws_secret_access_key=os.getenv("NCP_Secret_Key"),
)


# # Authentication Code
# class CookieAuthentication(BasePermission):
#     def has_permission(self, request, view):
#         """
#         쿠키 기반 인증을 수행하는 권한 클래스
#         - 요청의 쿠키에서 JWT 토큰을 추출하고, 이를 검증하여 사용자 인증을 수행합니다.
#         """
#         token = request.COOKIES.get("jwt")
#         if not token:
#             return False

#         try:
#             # JWT 토큰 디코딩 및 검증
#             payload = jwt.decode(token, settings.SECRET_KEY, algorithms=["HS256"])
#             request.user = User.objects.get(id=payload["id"])
#             return True
#         except jwt.ExpiredSignatureError:
#             raise AuthenticationFailed("Token has expired.")
#         except jwt.InvalidTokenError:
#             raise AuthenticationFailed("Invalid token.")
#         except User.DoesNotExist:
#             raise AuthenticationFailed("User not found.")


# 콘텐츠 업로드(post), 모든 콘텐츠 list(get)
class UploadContent(APIView):
    permission_classes = [IsAuthenticated]  # 권한 클래스만 포함
    authentication_classes = [CookieAuthentication]  # 인증 클래스 추가

    def post(self, request):
        data = request.data.copy()
        user = request.user
        data["user"] = user.id

        thumbnail = request.FILES.get("thumbnail")
        if thumbnail:
            thumbnail_id = str(uuid.uuid4())
            file_extension = thumbnail.name.split(".")[-1]
            thumbnail_name = f"{thumbnail_id}.{file_extension}"
            thumbnail_s3_key = f"thumbnails/{thumbnail_name}"
            try:
                s3.upload_fileobj(thumbnail.file, bucket_name, thumbnail_s3_key)
                s3.put_object_acl(
                    ACL="public-read", Bucket=bucket_name, Key=thumbnail_s3_key
                )
                data[
                    "thumbnail"
                ] = f"https://kr.object.ncloudstorage.com/{bucket_name}/{thumbnail_s3_key}"
            except Exception as e:
                print(e)
                return Response({"error": str(e)}, status=status.HTTP_400_BAD_REQUEST)

        serializer = ContentSerializer(data=data, context={"request": request})
        if serializer.is_valid():
            content = serializer.save()

            # 요청 파일에서 이미지를 추출하여 ContentImage 모델에 저장
            images = request.FILES.getlist("images")
            for image in images:
                image_id = str(uuid.uuid4())
                file_extension = image.name.split(".")[-1]
                image_name = f"{image_id}.{file_extension}"
                s3_key = f"images/{image_name}"
                ContentImage.objects.create(
                    content=content,
                    file=f"https://kr.object.ncloudstorage.com/{bucket_name}/{s3_key}",
                )
                try:
                    s3.upload_fileobj(image.file, bucket_name, s3_key)
                    s3.put_object_acl(ACL="public-read", Bucket=bucket_name, Key=s3_key)
                except Exception as e:
                    print(e)
                    return Response({"error": str(e)}, status=400)

            # Content 객체를 다시 직렬화하여 반환
            content_serializer = ContentSerializer(content)
            return Response(content_serializer.data, status=status.HTTP_201_CREATED)

        return Response(serializer.errors, status=status.HTTP_400_BAD_REQUEST)

    def get(self, request):
        contents = Content.objects.all()
        serializer = ContentSerializer(contents, many=True)
        return Response(serializer.data, status=status.HTTP_200_OK)


# 콘텐츠 수정(PATCH) API
class UpdateContent(APIView):
    permission_classes = [IsAuthenticated]
    authentication_classes = [CookieAuthentication]

    def put(self, request, pk):
        try:
            content = Content.objects.get(id=pk)
        except Content.DoesNotExist:
            return Response({"error": "Content not found"}, status=status.HTTP_404_NOT_FOUND)

        # 기존 콘텐츠를 업데이트할 데이터
        data = request.data.copy()
        data["user"] = request.user.id
        
        # 수정할 썸네일 처리
        thumbnail = request.FILES.get("thumbnail")
        if thumbnail:
            thumbnail_id = str(uuid.uuid4())
            file_extension = thumbnail.name.split(".")[-1]
            thumbnail_name = f"{thumbnail_id}.{file_extension}"
            thumbnail_s3_key = f"thumbnails/{thumbnail_name}"
            try:
                s3.upload_fileobj(thumbnail.file, bucket_name, thumbnail_s3_key)
                s3.put_object_acl(
                    ACL="public-read", Bucket=bucket_name, Key=thumbnail_s3_key
                )
                data["thumbnail"] = f"https://kr.object.ncloudstorage.com/{bucket_name}/{thumbnail_s3_key}"
            except Exception as e:
                print(e)
                return Response({"error": str(e)}, status=status.HTTP_400_BAD_REQUEST)

        # 기존 콘텐츠 업데이트
        serializer = ContentSerializer(content, data=data, partial=True, context={"request": request})
        if serializer.is_valid():
            updated_content = serializer.save()

            # 기존 이미지 삭제 및 새 이미지 저장
            ContentImage.objects.filter(content=updated_content).delete()
            images = request.FILES.getlist("images")
            for image in images:
                image_id = str(uuid.uuid4())
                file_extension = image.name.split(".")[-1]
                image_name = f"{image_id}.{file_extension}"
                s3_key = f"images/{image_name}"
                try:
                    s3.upload_fileobj(image.file, bucket_name, s3_key)
                    s3.put_object_acl(ACL="public-read", Bucket=bucket_name, Key=s3_key)
                    ContentImage.objects.create(
                        content=updated_content,
                        file=f"https://kr.object.ncloudstorage.com/{bucket_name}/{s3_key}",
                    )
                except Exception as e:
                    print(e)
                    return Response({"error": str(e)}, status=status.HTTP_400_BAD_REQUEST)

            content_serializer = ContentSerializer(updated_content)
            return Response(content_serializer.data, status=status.HTTP_200_OK)

        return Response(serializer.errors, status=status.HTTP_400_BAD_REQUEST)


# 콘텐츠 삭제(DELETE) API
class DeleteContent(APIView):
    # APIView를 상속받아 DeleteContent 클래스를 정의
    permission_classes = [IsAuthenticated]  # 권한 클래스만 포함
    authentication_classes = [CookieAuthentication]  # 인증 클래스 추가

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
            return Response(
                {"error": "콘텐츠를 찾을 수 없습니다."},
                status=status.HTTP_404_NOT_FOUND,
            )

        # 요청한 사용자가 의뢰자인지 확인
        if request.user.role == "analyst":
            return Response(
                {"error": "분석가는 콘텐츠를 삭제할 수 없습니다."},
                status=status.HTTP_403_FORBIDDEN,
            )

        # 콘텐츠 객체 삭제
        content.delete()
        # 콘텐츠 객체를 삭제하고 204 No Content 응답을 반환
        return Response(status=status.HTTP_204_NO_CONTENT)


class AddReview(APIView):
    permission_classes = [IsAuthenticated]  # 권한 클래스만 포함
    authentication_classes = [CookieAuthentication]  # 인증 클래스 추가

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
            return Response(
                {"error": "콘텐츠를 찾을 수 없습니다."},
                status=status.HTTP_404_NOT_FOUND,
            )

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
    authentication_classes = [CookieAuthentication]  # 필요하다면 추가

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
            return Response(
                {"error": "리뷰를 찾을 수 없습니다."}, status=status.HTTP_404_NOT_FOUND
            )

        # 본인 리뷰 또는 관리자인 경우만 수정 가능
        if request.user != review.user and not request.user.is_staff:
            return Response(
                {"error": "본인 리뷰만 수정할 수 있습니다."},
                status=status.HTTP_403_FORBIDDEN,
            )

        data = request.data
        serializer = ReviewSerializer(review, data=data, partial=True)
        if serializer.is_valid():
            serializer.save()
            return Response(serializer.data, status=status.HTTP_200_OK)

        return Response(serializer.errors, status=status.HTTP_400_BAD_REQUEST)


class DeleteReview(APIView):
    permission_classes = [IsAuthenticated]
    authentication_classes = [CookieAuthentication]  # 필요하다면 추가

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
            return Response(
                {"error": "리뷰를 찾을 수 없습니다."}, status=status.HTTP_404_NOT_FOUND
            )

        # 본인 리뷰 또는 관리자인 경우만 삭제 가능
        if request.user != review.user and not request.user.is_staff:
            return Response(
                {"error": "본인 리뷰만 삭제할 수 있습니다."},
                status=status.HTTP_403_FORBIDDEN,
            )

        review.delete()
        return Response(status=status.HTTP_204_NO_CONTENT)


# 콘텐츠 찜하기 api
class Wishlist(models.Model):
    user = models.ForeignKey(User, on_delete=models.CASCADE)
    content = models.ForeignKey(Content, on_delete=models.CASCADE)
    created_at = models.DateTimeField(auto_now_add=True)

    class Meta:
        unique_together = (
            "user",
            "content",
        )  # 같은 사용자가 동일 콘텐츠를 중복 찜할 수 없도록 설정

    def __str__(self):
        return f"{self.user} - {self.content}"


class ToggleLike(APIView):
    permission_classes = [IsAuthenticated]
    authentication_classes = [CookieAuthentication]  # 필요하다면 추가

    @swagger_auto_schema(
        request_body=openapi.Schema(
            type=openapi.TYPE_OBJECT,
            properties={
                "content_id": openapi.Schema(
                    type=openapi.TYPE_INTEGER,
                    description="ID of the content to be liked/unliked",
                )
            },
        ),
        responses={
            status.HTTP_200_OK: LikeSerializer,
            status.HTTP_400_BAD_REQUEST: openapi.Response("Bad Request"),
        },
        operation_summary="Add or remove content from likes",
        operation_description="Add or remove a specific content from the likes. If the content is already liked, it will be unliked. Otherwise, it will be liked.",
    )
    def post(self, request):
        content_id = request.data.get("content_id")
        if not content_id:
            return Response(
                {"error": "Content ID is required."}, status=status.HTTP_400_BAD_REQUEST
            )

        try:
            content = Content.objects.get(pk=content_id)
        except Content.DoesNotExist:
            return Response(
                {"error": "Content not found."}, status=status.HTTP_404_NOT_FOUND
            )

        # Check if the content is already liked by the user
        like, created = Like.objects.get_or_create(user=request.user, content=content)

        if not created:
            # Item already liked, remove it
            like.delete()
            return Response(
                {"message": "Content removed from likes."}, status=status.HTTP_200_OK
            )

        # New item liked
        return Response(
            {"message": "Content added to likes."}, status=status.HTTP_200_OK
        )


class LikedContentList(APIView):
    permission_classes = [IsAuthenticated]
    authentication_classes = [CookieAuthentication]  # 필요하다면 추가

    @swagger_auto_schema(
        responses={
            status.HTTP_200_OK: LikeSerializer(many=True),
            status.HTTP_400_BAD_REQUEST: openapi.Response("Bad Request"),
        },
        operation_summary="List all liked content",
        operation_description="Retrieve a list of all content items liked by the user.",
    )
    def get(self, request):
        liked_items = Like.objects.filter(user=request.user)
        serializer = LikeSerializer(liked_items, many=True)
        return Response(serializer.data, status=status.HTTP_200_OK)


# QnA 목록을 조회
class QnAList(APIView):
    permission_classes = [IsAuthenticated]
    authentication_classes = [CookieAuthentication]  # 필요하다면 추가

    def get(self, request, content_id):
        # URL에서 콘텐츠 ID 가져오기
        queryset = QnA.objects.filter(
            content_id=content_id, parent__isnull=True
        )  # 해당 콘텐츠의 질문만 필터링
        serializer = QnASerializer(queryset, many=True)
        return Response(serializer.data, status=status.HTTP_200_OK)


# QnA 생성
class QnACreate(APIView):
    permission_classes = [IsAuthenticated]
    authentication_classes = [CookieAuthentication]  # 필요하다면 추가

    def post(self, request, format=None):
        data = request.data.copy()  # 요청 데이터 복사
        user = request.user  # JWT 토큰으로부터 인증된 사용자 가져오기

        # 답변 생성 시 콘텐츠의 작성자를 확인
        parent_id = data.get("parent")
        if parent_id is None:
            # 질문인 경우
            data["user"] = user.id
        else:
            # 답변인 경우
            parent = QnA.objects.filter(id=parent_id).first()
            if parent is None:
                return Response(
                    {"error": "Parent question not found."},
                    status=status.HTTP_400_BAD_REQUEST,
                )

            # 콘텐츠 작성자를 확인
            content = parent.content
            if content.user != user:
                return Response(
                    {"error": "You are not authorized to answer this question."},
                    status=status.HTTP_403_FORBIDDEN,
                )

            data["user"] = user.id
            data["parent"] = parent_id

        serializer = QnASerializer(data=data)
        if serializer.is_valid():
            serializer.save()
            return Response(serializer.data, status=status.HTTP_201_CREATED)
        return Response(serializer.errors, status=status.HTTP_400_BAD_REQUEST)
