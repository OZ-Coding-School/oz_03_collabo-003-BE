# category/urls.py
from django.urls import path

from .views import CategoryDetailView
from .views import CategoryListView
from .views import CategoryView
from .views import SubCategoryView

urlpatterns = [
    # 카테고리 수정 및 삭제
    path("<int:category_id>", CategoryView.as_view(), name="category-detail"),
    # 하위 카테고리 생성
    path(
        "subcategories/<int:category_id>",
        SubCategoryView.as_view(),
        name="subcategory-create",
    ),
    # 카테고리 목록 조회
    path("list", CategoryListView.as_view(), name="category-list"),
    # 카테고리 목록 조회2
    path("detail/<int:category_id>/", CategoryDetailView.as_view()),
]
