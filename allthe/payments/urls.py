from django.urls import include
from django.urls import path
from drf_yasg import openapi
from drf_yasg.views import get_schema_view
from rest_framework import permissions

from .views import PortOneRefund
from .views import VerifyPayment
from .views import payment_form

# Swagger 및 Redoc 설정
schema_view = get_schema_view(
    openapi.Info(
        title="결제 API",
        default_version="v1",
        description="결제 시스템을 위한 API 문서",
        terms_of_service="https://www.google.com/policies/terms/",
        contact=openapi.Contact(email="contact@yourapi.local"),
        license=openapi.License(name="BSD License"),
    ),
    public=True,
    permission_classes=(permissions.AllowAny,),
)

urlpatterns = [
    path("verify/", VerifyPayment.as_view(), name="verify_payment"),
    path("payment-form/", payment_form, name="payment_form"),
    path("refund/", PortOneRefund.as_view(), name="portone_payment_refund"),
    # Swagger 문서 URL
    path(
        "swagger/",
        schema_view.with_ui("swagger", cache_timeout=0),
        name="schema-swagger-ui",
    ),
    # Redoc 문서 URL
    path("redoc/", schema_view.with_ui("redoc", cache_timeout=0), name="schema-redoc"),
]
