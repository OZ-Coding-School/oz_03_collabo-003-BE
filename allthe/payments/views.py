import logging
import os

import requests
from django.contrib.auth.models import User
from django.db import transaction
from dotenv import load_dotenv
from drf_yasg import openapi
from drf_yasg.utils import swagger_auto_schema
from rest_framework import status
from rest_framework.response import Response
from rest_framework.views import APIView

from .models import Payment
from .serializers import PaymentSerializer

logger = logging.getLogger(__name__)

# .env 파일 경로를 지정
load_dotenv()
PORTONE_APP_KEY = os.getenv("PORTONE_APP_KEY")
PORTONE_SECRET = os.getenv("PORTONE_SECRET")
PORTONE_CHANNEL_KEY = os.getenv("PORTONE_CHANNEL_KEY")


class VerifyPayment(APIView):
    @swagger_auto_schema(
        request_body=PaymentSerializer,
        responses={
            200: openapi.Response(
                description="결제 검증 성공",
                examples={"application/json": {"success": True}},
            ),
            400: openapi.Response(
                description="잘못된 요청",
                examples={"application/json": {"error": "오류 메시지", "details": {}}},
            ),
        },
    )
    def post(self, request):
        # 요청 데이터 로깅
        logger.info("요청 데이터: %s", request.data)

        token_url = "https://api.iamport.kr/users/getToken"
        data = {
            "imp_key": PORTONE_APP_KEY,  # 환경 변수에서 가져온 앱 키
            "imp_secret": PORTONE_SECRET,  # 환경 변수에서 가져온 비밀 키
        }

        try:
            # 트랜잭션 블록 시작
            with transaction.atomic():
                # 토큰 요청
                response = requests.post(token_url, data=data)
                response_data = response.json()
                logger.info("토큰 응답: %s", response_data)

                if response.status_code != 200:
                    return Response(
                        {
                            "error": "토큰을 얻는 데 실패했습니다.",
                            "details": response_data,
                        },
                        status=status.HTTP_400_BAD_REQUEST,
                    )

                access_token = response_data["response"]["access_token"]
                if not access_token:
                    return Response(
                        {"error": "토큰이 없습니다."},
                        status=status.HTTP_400_BAD_REQUEST,
                    )

                # 요청 데이터 유효성 검증
                serializer = PaymentSerializer(data=request.data)
                if serializer.is_valid():
                    data = serializer.validated_data
                    imp_uid = data.get("imp_uid")
                    original_amount = data.get("paid_amount")

                    # 결제 검증을 위한 요청
                    headers = {"Authorization": f"Bearer {access_token}"}
                    response = requests.get(
                        f"https://api.iamport.kr/payments/{imp_uid}", headers=headers
                    )
                    result = response.json()
                    logger.info("결제 검증 결과: %s", result)

                    if (
                        result["code"] == 0
                        and result["response"]["status"] == "paid"
                        and result["response"]["amount"] == float(original_amount)
                    ):
                        user = request.user
                        payment = Payment(
                            user=user,  # 사용자 객체
                            imp_uid=imp_uid,  # 결제 고유 ID
                            original_amount=original_amount,  # 결제 금액
                            status="paid",  # 결제 상태
                        )
                        payment.save()
                        return Response({"success": True}, status=status.HTTP_200_OK)
                    else:
                        # 결제 검증 실패 시 결제 취소 요청
                        cancel_response = requests.post(
                            "https://api.iamport.kr/payments/cancel",
                            headers={"Authorization": f"Bearer {access_token}"},
                            data={
                                "imp_uid": imp_uid,  # 결제 고유 ID
                                "reason": "결제 검증 실패",  # 결제 취소 사유
                            },
                        )
                        cancel_result = cancel_response.json()
                        logger.info("결제 취소 결과: %s", cancel_result)

                        return Response(
                            {"success": False, "error": result["message"]},
                            status=status.HTTP_400_BAD_REQUEST,
                        )
                return Response(serializer.errors, status=status.HTTP_400_BAD_REQUEST)
        except Exception as e:
            # 전체 API 호출 중 에러 발생 시 결제 취소 요청
            logger.error("에러 발생: %s", str(e))
            if "access_token" in locals():
                # 로컬 변수가 존재하면 결제 취소 시도
                cancel_response = requests.post(
                    "https://api.iamport.kr/payments/cancel",
                    headers={"Authorization": f"Bearer {access_token}"},
                    data={
                        "imp_uid": request.data.get("imp_uid", ""),  # 결제 고유 ID
                        "reason": "전체 API 호출 중 에러 발생",  # 결제 취소 사유
                    },
                )
                cancel_result = cancel_response.json()
                logger.info("결제 취소 결과 (에러 발생): %s", cancel_result)
            return Response(
                {"error": "전체 API 호출 중 에러가 발생했습니다.", "details": str(e)},
                status=status.HTTP_500_INTERNAL_SERVER_ERROR,
            )


class PortOneRefund(APIView):
    @swagger_auto_schema(
        operation_description="Get a refund token and process a refund request.",
        responses={
            200: openapi.Response(
                description="Refund processed successfully",
                examples={
                    "application/json": {
                        "info": {
                            "status": "success",
                            "message": "Refund processed successfully",
                        }
                    }
                },
            ),
            400: openapi.Response(
                description="Error occurred",
                examples={
                    "application/json": {
                        "error": "Failed to obtain access token",
                        "details": "Detailed error message",
                    }
                },
            ),
        },
    )
    def get(self, request):
        # Token request URL
        token_url = "https://api.iamport.kr/users/getToken"
        data = {"imp_key": PORTONE_APP_KEY, "imp_secret": PORTONE_SECRET}

        # POST request to obtain the token
        response = requests.post(token_url, data=data)
        response_data = response.json()

        print("Token response:", response_data)

        if response.status_code != 200:
            return Response(
                {"error": "Failed to obtain access token", "details": response_data},
                status=status.HTTP_400_BAD_REQUEST,
            )

        access_token = response_data["response"]["access_token"]
        if not access_token:
            return Response(
                {"error": "No access token received"},
                status=status.HTTP_400_BAD_REQUEST,
            )

        # Process the refund request
        url = f"https://api.iamport.kr/payments/cancel"
        headers = {"Authorization": f"Bearer {access_token}"}
        response = requests.post(url, headers=headers, data=request.data)
        info = response.json()

        return Response({"info": info}, status=status.HTTP_200_OK)


from django.shortcuts import render


def payment_form(request):
    return render(request, "create_payment.html")
