# category/views.py
from common.decorators import admin_required
from drf_yasg import openapi
from drf_yasg.utils import swagger_auto_schema
from rest_framework import status
from rest_framework.response import Response
from rest_framework.views import APIView

from .models import Category
from .serializers import CategorySerializer


class CategoryView(APIView):
    """
    카테고리 관련 API 뷰
    카테고리 생성, 수정, 삭제 기능을 제공합니다.
    """

    @swagger_auto_schema(
        operation_description="새로운 카테고리 추가",
        request_body=openapi.Schema(
            type=openapi.TYPE_OBJECT,
            properties={
                "name": openapi.Schema(
                    type=openapi.TYPE_STRING, description="카테고리 이름"
                ),
            },
        ),
        responses={
            201: openapi.Response(
                description="카테고리 생성 성공",
                examples={"application/json": {"id": 1, "name": "새로운 카테고리"}},
            ),
            400: "잘못된 요청",
            401: "인증 실패",
            403: "권한 없음",
        },
    )
    @admin_required
    def post(self, request):
        """
        새로운 카테고리를 생성합니다.
        """
        name = request.data.get("name")
        if not name:
            return Response(
                {"error": "이름은 필수입니다."}, status=status.HTTP_400_BAD_REQUEST
            )

        category = Category.objects.create(name=name)
        return Response(
            {"id": category.id, "name": category.name}, status=status.HTTP_201_CREATED
        )

    @swagger_auto_schema(
        operation_description="기존 카테고리 삭제",
        responses={
            200: openapi.Response(
                description="카테고리 삭제 성공",
                examples={
                    "application/json": {"message": "카테고리가 삭제되었습니다."}
                },
            ),
            404: "카테고리를 찾을 수 없음",
            401: "인증 실패",
            403: "권한 없음",
        },
    )
    @admin_required
    def delete(self, request, category_id):
        """
        지정된 카테고리를 삭제합니다.
        """
        try:
            category = Category.objects.get(id=category_id)
            category.delete()
            return Response(
                {"message": "카테고리가 삭제되었습니다."}, status=status.HTTP_200_OK
            )
        except Category.DoesNotExist:
            return Response(
                {"error": "카테고리를 찾을 수 없습니다."},
                status=status.HTTP_404_NOT_FOUND,
            )

    @swagger_auto_schema(
        operation_description="카테고리 수정",
        request_body=openapi.Schema(
            type=openapi.TYPE_OBJECT,
            properties={
                "name": openapi.Schema(
                    type=openapi.TYPE_STRING, description="수정할 카테고리 이름"
                ),
            },
        ),
        responses={
            200: openapi.Response(
                description="카테고리 수정 성공",
                examples={"application/json": {"id": 1, "name": "수정된 카테고리"}},
            ),
            400: "잘못된 요청",
            401: "인증 실패",
            403: "권한 없음",
            404: "카테고리를 찾을 수 없음",
        },
    )
    @admin_required
    def put(self, request, category_id):
        """
        지정된 카테고리의 정보를 수정합니다.
        """
        try:
            category = Category.objects.get(id=category_id)
        except Category.DoesNotExist:
            return Response(
                {"error": "카테고리를 찾을 수 없습니다."},
                status=status.HTTP_404_NOT_FOUND,
            )

        name = request.data.get("name")
        if not name:
            return Response(
                {"error": "이름은 필수입니다."}, status=status.HTTP_400_BAD_REQUEST
            )

        category.name = name
        category.save()
        return Response(
            {"id": category.id, "name": category.name}, status=status.HTTP_200_OK
        )


class SubCategoryView(APIView):
    """
    하위 카테고리 관련 API 뷰
    하위 카테고리 생성 및 삭제 기능을 제공합니다.
    """

    @swagger_auto_schema(
        operation_description="하위 카테고리 추가",
        request_body=openapi.Schema(
            type=openapi.TYPE_OBJECT,
            properties={
                "name": openapi.Schema(
                    type=openapi.TYPE_STRING, description="하위 카테고리 이름"
                ),
            },
        ),
        responses={
            201: openapi.Response(
                description="하위 카테고리 생성 성공",
                examples={
                    "application/json": {
                        "id": 2,
                        "name": "하위 카테고리",
                        "parentId": 1,
                    }
                },
            ),
            400: "잘못된 요청",
            401: "인증 실패",
            403: "권한 없음",
            404: "부모 카테고리를 찾을 수 없음",
        },
    )
    @admin_required
    def post(self, request, category_id):
        """
        지정된 카테고리의 하위 카테고리를 생성합니다.
        """
        name = request.data.get("name")
        if not name:
            return Response(
                {"error": "이름은 필수입니다."}, status=status.HTTP_400_BAD_REQUEST
            )

        try:
            parent_category = Category.objects.get(id=category_id)
        except Category.DoesNotExist:
            return Response(
                {"error": "부모 카테고리를 찾을 수 없습니다."},
                status=status.HTTP_404_NOT_FOUND,
            )

        subcategory = Category.objects.create(name=name, parent=parent_category)
        return Response(
            {
                "id": subcategory.id,
                "name": subcategory.name,
                "parentId": parent_category.id,
            },
            status=status.HTTP_201_CREATED,
        )

    @swagger_auto_schema(
        operation_description="하위 카테고리 삭제",
        responses={
            200: openapi.Response(
                description="하위 카테고리 삭제 성공",
                examples={
                    "application/json": {"message": "하위 카테고리가 삭제되었습니다."}
                },
            ),
            404: "카테고리를 찾을 수 없음",
            401: "인증 실패",
            403: "권한 없음",
        },
    )
    @admin_required
    def delete(self, request, category_id, subcategory_id):
        """
        지정된 하위 카테고리를 삭제합니다.
        """
        try:
            subcategory = Category.objects.get(id=subcategory_id, parent_id=category_id)
            subcategory.delete()
            return Response(
                {"message": "하위 카테고리가 삭제되었습니다."},
                status=status.HTTP_200_OK,
            )
        except Category.DoesNotExist:
            return Response(
                {"error": "하위 카테고리를 찾을 수 없습니다."},
                status=status.HTTP_404_NOT_FOUND,
            )

    @swagger_auto_schema(
        operation_description="하위 카테고리 수정",
        request_body=openapi.Schema(
            type=openapi.TYPE_OBJECT,
            properties={
                "name": openapi.Schema(
                    type=openapi.TYPE_STRING, description="수정할 하위 카테고리 이름"
                ),
            },
        ),
        responses={
            200: openapi.Response(
                description="하위 카테고리 수정 성공",
                examples={
                    "application/json": {
                        "id": 2,
                        "name": "수정된 하위 카테고리",
                        "parentId": 1,
                    }
                },
            ),
            400: "잘못된 요청",
            401: "인증 실패",
            403: "권한 없음",
            404: "카테고리를 찾을 수 없음",
        },
    )
    @admin_required
    def put(self, request, category_id, subcategory_id):
        """
        지정된 하위 카테고리의 정보를 수정합니다.
        """
        try:
            subcategory = Category.objects.get(id=subcategory_id, parent_id=category_id)
        except Category.DoesNotExist:
            return Response(
                {"error": "하위 카테고리를 찾을 수 없습니다."},
                status=status.HTTP_404_NOT_FOUND,
            )

        name = request.data.get("name")
        if not name:
            return Response(
                {"error": "이름은 필수입니다."}, status=status.HTTP_400_BAD_REQUEST
            )

        subcategory.name = name
        subcategory.save()
        return Response(
            {
                "id": subcategory.id,
                "name": subcategory.name,
                "parentId": subcategory.parent_id,
            },
            status=status.HTTP_200_OK,
        )


class CategoryListView(APIView):
    """
    카테고리 목록 조회 API 뷰
    모든 카테고리와 그에 속한 하위 카테고리 목록을 제공합니다.
    """

    @swagger_auto_schema(
        operation_description="모든 카테고리 조회",
        responses={
            200: openapi.Response(
                description="카테고리 조회 성공",
                examples={
                    "application/json": [
                        {
                            "id": 1,
                            "name": "업무 툴",
                            "subcategories": [{"id": 2, "name": "업무효율화"}],
                        }
                    ]
                },
            ),
        },
    )
    def get(self, request):
        """
        모든 카테고리와 그에 속한 하위 카테고리 목록을 반환합니다.
        """
        categories = Category.objects.filter(parent=None)
        result = []
        for category in categories:
            subcategories = Category.objects.filter(parent=category)
            result.append(
                {
                    "id": category.id,
                    "name": category.name,
                    "subcategories": [
                        {"id": sub.id, "name": sub.name} for sub in subcategories
                    ],
                }
            )
        return Response(result, status=status.HTTP_200_OK)


class CategoryDetailView(APIView):
    """
    카테고리 목록 조회 API
    특정 카테고리와 그에 속한 하위 카테고리 목록을 제공합니다.
    """

    @swagger_auto_schema(
        operation_description="특정 카테고리 조회",
        responses={
            200: openapi.Response(
                description="카테고리 조회 성공", schema=CategorySerializer
            ),
        },
    )
    def get(self, request, category_id):
        try:
            category = Category.objects.get(id=category_id)
            serializer = CategorySerializer(category)
            return Response(serializer.data)
        except Category.DoesNotExist:
            return Response({"error": "해당 카테고리가 존재하지 않습니다."}, status=404)
