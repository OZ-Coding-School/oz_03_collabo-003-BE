from django.urls import path

from .views import AcceptAnalysisRequest
from .views import AcceptedAnalystsList
from .views import AnalysisRequestDetail
from .views import AnalysisRequestList
from .views import AnalystAcceptedRequestsList
from .views import CheckAnalysisReport
from .views import SelectAnalyst
from .views import UploadAnalysisReport
from .views import AnalysisRequest

urlpatterns = [
    path("", AnalysisRequest.as_view()),
    path("list", AnalysisRequestList.as_view()),
    path("<int:pk>", AnalysisRequestDetail.as_view()),
    path("accept/<int:pk>", AcceptAnalysisRequest.as_view()),
    path("client", AnalysisRequestList.as_view()),
    path("accepted/<int:pk>", AcceptedAnalystsList.as_view()),
    path("select/<int:pk>", SelectAnalyst.as_view()),
    path("analyst", AnalystAcceptedRequestsList.as_view()),
    path("report", UploadAnalysisReport.as_view()),
    path("report/<int:pk>", CheckAnalysisReport.as_view()),
]
