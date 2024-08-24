from django.urls import path

from .views import UploadContent

urlpatterns = [
    path("", UploadContent.as_view()),
]
