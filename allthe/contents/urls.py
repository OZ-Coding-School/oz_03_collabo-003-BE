from .views import UploadContent

from django.urls import path

urlpatterns = [
    path('', UploadContent.as_view()),
]