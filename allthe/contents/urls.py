from django.urls import path

from .views import AddReview
from .views import DeleteContent
from .views import DeleteReview
from .views import LikedContentList
from .views import QnACreate
from .views import QnAList
from .views import ToggleLike
from .views import UpdateContent
from .views import UpdateReview
from .views import UploadContent

urlpatterns = [
    path("upload-content/", UploadContent.as_view(), name="upload_content"),
    path("update-content/<int:pk>/", UpdateContent.as_view(), name="update_content"),
    path("delete-content/<int:pk>/", DeleteContent.as_view(), name="delete_content"),
    path("add-review/<int:content_id>/", AddReview.as_view(), name="add_review"),
    path(
        "update-review/<int:review_id>/", UpdateReview.as_view(), name="update_review"
    ),
    path(
        "delete-review/<int:review_id>/", DeleteReview.as_view(), name="delete_review"
    ),
    path("like/", ToggleLike.as_view(), name="toggle_like"),
    path("liked-content/", LikedContentList.as_view(), name="liked_content_list"),
    path("<int:content_id>/qna/", QnAList.as_view(), name="qna-list"),
    path("qna/", QnACreate.as_view(), name="qna-create"),
]
