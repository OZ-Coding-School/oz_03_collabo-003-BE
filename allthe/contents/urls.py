from django.urls import path
from .views import UploadContent, UpdateContent, DeleteContent, AddReview, UpdateReview, DeleteReview, ToggleLike, LikedContentList

urlpatterns = [
    path('upload-content/', UploadContent.as_view(), name='upload_content'),
    path('update-content/<int:pk>/', UpdateContent.as_view(), name='update_content'),
    path('delete-content/<int:pk>/', DeleteContent.as_view(), name='delete_content'),
    path('add-review/<int:content_id>/', AddReview.as_view(), name='add_review'),
    path('update-review/<int:review_id>/', UpdateReview.as_view(), name='update_review'),
    path('delete-review/<int:review_id>/', DeleteReview.as_view(), name='delete_review'),
     path('like/', ToggleLike.as_view(), name='toggle_like'),
    path('liked-content/', LikedContentList.as_view(), name='liked_content_list'),
]
