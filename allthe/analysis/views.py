from accounts.models import User
from drf_yasg import openapi
from drf_yasg.utils import swagger_auto_schema
from rest_framework import status
from rest_framework.permissions import IsAuthenticated
from rest_framework.response import Response
from rest_framework.views import APIView

from .models import AnalysisReport
from .models import AnalysisRequest
from .models import Analyst
from .serializers import AnalysisReportSerializer
from .serializers import AnalysisRequestSerializer
from .serializers import AnalysisRequestSerializerDetail
from .serializers import AnalysisRequestSerializerList
from .serializers import AnalystSerializer
from .serializers import UserSerializer


# 의뢰요청(post), 의뢰목록(get)
class AnalysisRequestList(APIView):
    permission_classes = [IsAuthenticated]  # 인증된 사용자만 접근 허용

    @swagger_auto_schema(
        request_body=AnalysisRequestSerializer,
        responses={
            status.HTTP_201_CREATED: AnalysisRequestSerializer,
            status.HTTP_400_BAD_REQUEST: openapi.Response("Bad Request"),
        },
        operation_summary="Create a new analysis request",
        operation_description="Allows clients to create a new analysis request. Only users with 'CLIENT' role can access this endpoint.",
    )
    def post(self, request):
        # 요청한 사용자가 의뢰자인지 확인
        if request.user.role != "client":
            return Response(
                {"error": "의뢰자만 분석 요청을 업로드할 수 있습니다."},
                status=status.HTTP_403_FORBIDDEN,
            )

        # 요청 데이터에서 콘텐츠 정보를 가져옴
        data = request.data.copy()  # request.data는 ImmutableMultiValueDict이므로 복사
        data["client"] = request.user.id  # 사용자 ID를 추가

        # 요청 데이터로부터 시리얼라이저를 생성
        serializer = AnalysisRequestSerializer(data=data)
        if serializer.is_valid():
            serializer.save()  # 요청한 사용자 정보를 의뢰자로 설정
            return Response(serializer.data, status=status.HTTP_201_CREATED)
        return Response(serializer.errors, status=status.HTTP_400_BAD_REQUEST)

    @swagger_auto_schema(
        manual_parameters=[
            openapi.Parameter(
                name="status",
                in_=openapi.IN_QUERY,
                type=openapi.TYPE_STRING,
                description="Filter requests by status",
                required=False,
            ),
        ],
        responses={
            status.HTTP_200_OK: AnalysisRequestSerializerDetail(many=True),
            status.HTTP_401_UNAUTHORIZED: openapi.Response("Unauthorized"),
        },
        operation_summary="List all analysis requests",
        operation_description="Retrieve a list of all analysis requests. You can filter by status using the 'status' query parameter. Only authenticated users can access this endpoint.",
    )
    def get(self, request):
        # 요청 상태에 따라 조회할 수 있도록 추가
        status_filter = request.GET.get("status")

        # 요청이 있을 경우 status로 필터링
        if status_filter:
            requests = AnalysisRequest.objects.filter(status=status_filter)
        else:
            # status 파라미터가 없을 경우 모든 의뢰를 조회
            requests = AnalysisRequest.objects.all()
        serializer = AnalysisRequestSerializerDetail(requests, many=True)
        return Response(serializer.data)


# 특정 의뢰의 상세 정보를 조회
class AnalysisRequestDetail(APIView):
    permission_classes = [IsAuthenticated]  # 인증된 사용자만 접근 허용

    @swagger_auto_schema(
        responses={
            status.HTTP_200_OK: AnalysisRequestSerializerDetail,
            status.HTTP_404_NOT_FOUND: openapi.Response("Not Found"),
        },
        operation_summary="Get Analysis Request Details",
        operation_description="Retrieve the details of a specific analysis request by its ID.",
        manual_parameters=[
            openapi.Parameter(
                name="pk",
                in_=openapi.IN_PATH,
                description="ID of the analysis request to retrieve",
                type=openapi.TYPE_INTEGER,
                required=True,
            ),
        ],
    )
    def get(self, request, pk):
        # 의뢰 객체를 조회
        try:
            request_obj = AnalysisRequest.objects.get(pk=pk)
        except AnalysisRequest.DoesNotExist:
            return Response(status=status.HTTP_404_NOT_FOUND)

        serializer = AnalysisRequestSerializerDetail(request_obj)
        return Response(serializer.data)


# 분석가가 의뢰를 수락
class AcceptAnalysisRequest(APIView):
    permission_classes = [IsAuthenticated]  # 인증된 사용자만 접근 허용

    @swagger_auto_schema(
        operation_summary="Accept an analysis request",
        operation_description="This endpoint allows an analyst to accept an analysis request. Only users with the role 'ANALYST' can accept requests. The request can only be accepted if its status is 'PENDING'.",
        responses={
            status.HTTP_200_OK: openapi.Response(
                description="Request successfully accepted",
                examples={"application/json": {"status": "요청이 수락되었습니다."}},
            ),
            status.HTTP_400_BAD_REQUEST: openapi.Response(
                description="Bad Request - The request cannot be accepted.",
                examples={"application/json": {"error": "이미 매칭된 요청입니다."}},
            ),
            status.HTTP_403_FORBIDDEN: openapi.Response(
                description="Forbidden - The user does not have permission to accept the request.",
                examples={"application/json": {"error": "분석가만 의뢰를 수락할 수 있습니다."}},
            ),
            status.HTTP_404_NOT_FOUND: openapi.Response(
                description="Not Found - The request does not exist.",
            ),
        },
        manual_parameters=[
            openapi.Parameter(
                name="pk",
                in_=openapi.IN_PATH,
                description="ID of the analysis request to accept",
                type=openapi.TYPE_INTEGER,
                required=True,
            )
        ],
    )
    def post(self, request, pk):
        # 요청한 사용자가 분석가인지 확인
        if request.user.role != "analyst":
            return Response(
                {"error": "분석가만 의뢰를 수락할 수 있습니다."},
                status=status.HTTP_403_FORBIDDEN,
            )

        # 의뢰 객체를 조회
        try:
            request_obj = AnalysisRequest.objects.get(pk=pk)
        except AnalysisRequest.DoesNotExist:
            return Response(status=status.HTTP_404_NOT_FOUND)

        # 의뢰 상태가 'PENDING'일 때만 수락 가능
        if request_obj.status != "PENDING":
            return Response(
                {"error": "이미 매칭된 요청입니다."}, status=status.HTTP_400_BAD_REQUEST
            )

        request_obj.analyst.add(request.user)  # 의뢰에 분석가를 추가
        request_obj.save()

        return Response({"status": "요청이 수락되었습니다."})


# 의뢰자별 분석 요청 목록 리스트
class AnalysisRequestList(APIView):
    permission_classes = [IsAuthenticated]  # 인증된 사용자만 접근 허용

    @swagger_auto_schema(
        operation_summary="Get analysis requests by client",
        operation_description="This endpoint allows clients to get a list of their own analysis requests. The list is filtered based on the client who made the request.",
        responses={
            status.HTTP_200_OK: AnalysisRequestSerializerDetail(many=True),
            status.HTTP_403_FORBIDDEN: openapi.Response(
                description="Forbidden - Only clients can access their own analysis requests.",
                examples={
                    "application/json": {"error": "의뢰자만 자신의 분석 요청 목록을 조회할 수 있습니다."}
                },
            ),
        },
    )
    def get(self, request):
        # 요청한 사용자가 의뢰자인지 확인
        if request.user.role != "client":
            return Response(
                {"error": "의뢰자만 자신의 분석 요청 목록을 조회할 수 있습니다."},
                status=status.HTTP_403_FORBIDDEN,
            )

        # 의뢰자에 해당하는 분석 요청 목록 조회
        requests = AnalysisRequest.objects.filter(client=request.user)
        serializer = AnalysisRequestSerializerDetail(requests, many=True)

        return Response(serializer.data)


class AcceptedAnalystsList(APIView):
    permission_classes = [IsAuthenticated]  # 인증된 사용자만 접근 허용

    @swagger_auto_schema(
        responses={
            status.HTTP_200_OK: UserSerializer(many=True),
            status.HTTP_403_FORBIDDEN: openapi.Response(description="접근 권한이 없는 경우"),
            status.HTTP_404_NOT_FOUND: openapi.Response(
                description="의뢰 요청이 존재하지 않는 경우"
            ),
        },
        operation_summary="조회된 분석가 목록",
        operation_description="의뢰자가 본인의 의뢰를 수락한 분석가 목록을 조회합니다. 의뢰자만 접근할 수 있습니다.",
    )
    def get(self, request, pk):
        # 요청한 사용자가 의뢰자인지 확인
        if request.user.role != "client":
            return Response(
                {"error": "의뢰자만 수락한 분석가 목록을 조회할 수 있습니다."},
                status=status.HTTP_403_FORBIDDEN,
            )

        # 의뢰 객체를 조회
        try:
            request_obj = AnalysisRequest.objects.get(pk=pk)
        except AnalysisRequest.DoesNotExist:
            return Response(status=status.HTTP_404_NOT_FOUND)

        # 요청한 사용자가 의뢰자일 때만 접근 허용
        if request_obj.client != request.user:
            return Response({"error": "권한이 없습니다."}, status=status.HTTP_403_FORBIDDEN)

        # 수락한 분석가 목록 조회
        analysts = request_obj.analyst.all()
        serializer = UserSerializer(analysts, many=True)
        return Response(serializer.data)


# 의뢰자가 분석가 선택
class SelectAnalyst(APIView):
    permission_classes = [IsAuthenticated]  # 인증된 사용자만 접근 허용

    @swagger_auto_schema(
        request_body=openapi.Schema(
            type=openapi.TYPE_OBJECT,
            properties={
                "analyst_id": openapi.Schema(
                    type=openapi.TYPE_INTEGER, description="선택된 분석가의 ID"
                ),
            },
            required=["analyst_id"],
        ),
        responses={
            status.HTTP_200_OK: openapi.Response(
                description="분석가와 매칭됨",
                examples={"application/json": {"status": "분석가와 매칭되었습니다."}},
            ),
            status.HTTP_403_FORBIDDEN: openapi.Response(
                description="접근 권한이 없는 경우",
                examples={"application/json": {"error": "의뢰자만 분석가를 선택할 수 있습니다."}},
            ),
            status.HTTP_400_BAD_REQUEST: openapi.Response(
                description="잘못된 요청",
                examples={"application/json": {"error": "선택된 분석가의 ID를 제공해야 합니다."}},
            ),
            status.HTTP_404_NOT_FOUND: openapi.Response(
                description="의뢰 요청이나 분석가가 존재하지 않는 경우",
                examples={"application/json": {"error": "선택된 분석가가 존재하지 않습니다."}},
            ),
        },
        operation_summary="분석가 선택 및 매칭",
        operation_description="의뢰자가 분석가를 선택하여 매칭할 수 있습니다. 의뢰자는 상태가 'PENDING'인 의뢰에 대해 분석가를 선택할 수 있으며, 기존의 분석가는 모두 제거되고 선택된 분석가만 남게 됩니다.",
    )
    def post(self, request, pk):
        # 요청한 사용자가 의뢰자인지 확인
        if request.user.role != "client":
            return Response(
                {"error": "의뢰자만 분석가를 선택할 수 있습니다."},
                status=status.HTTP_403_FORBIDDEN,
            )

        # 요청한 사용자가 분석가를 선택할 수 있는 권한이 있는지 확인
        if "analyst_id" not in request.data:
            return Response(
                {"error": "선택된 분석가의 ID를 제공해야 합니다."},
                status=status.HTTP_400_BAD_REQUEST,
            )

        analyst_id = request.data["analyst_id"]

        # 의뢰 객체를 조회
        try:
            request_obj = AnalysisRequest.objects.get(pk=pk)
        except AnalysisRequest.DoesNotExist:
            return Response(status=status.HTTP_404_NOT_FOUND)

        # 요청 상태가 'PENDING'일 때만 분석가 선택 가능
        if request_obj.status != "PENDING":
            return Response(
                {"error": "매칭 진행중인 요청입니다."},
                status=status.HTTP_400_BAD_REQUEST,
            )

        # 선택된 분석가 객체를 조회
        try:
            selected_analyst = User.objects.get(pk=analyst_id)
        except User.DoesNotExist:
            return Response(
                {"error": "선택된 분석가가 존재하지 않습니다."},
                status=status.HTTP_404_NOT_FOUND,
            )

        # 기존의 분석가를 모두 제거하고 선택된 분석가만 남김
        request_obj.analyst.set([selected_analyst])
        request_obj.status = "ACCEPTED"  # 상태를 'ACCEPTED'로 변경
        request_obj.save()

        return Response({"status": "분석가와 매칭되었습니다."})


# 분석가와 매칭된 분석 요청 목록
class AnalystAcceptedRequestsList(APIView):
    permission_classes = [IsAuthenticated]  # 인증된 사용자만 접근 허용

    @swagger_auto_schema(
        responses={
            status.HTTP_200_OK: openapi.Response(
                description="수락된 분석 요청 목록 조회 성공",
                schema=AnalysisRequestSerializerList(many=True),
            ),
            status.HTTP_403_FORBIDDEN: openapi.Response(
                description="권한 부족",
                examples={"application/json": {"error": "권한이 없습니다."}},
            ),
        },
        operation_summary="분석가가 수락한 분석 요청 목록 조회",
        operation_description="`status`가 `ACCEPTED`이고 `analyst` 필드에 현재 사용자가 포함된 분석 요청 목록을 조회합니다.",
    )
    def get(self, request):
        # 요청한 사용자가 분석가인지 확인
        if request.user.role != "analyst":
            return Response(
                {"error": "분석가만 접근할 수 있습니다."},
                status=status.HTTP_403_FORBIDDEN,
            )

        # 분석가와 매칭된 분석 요청 목록을 조회
        analysis_requests = AnalysisRequest.objects.filter(
            status="ACCEPTED", analyst=request.user
        )

        serializer = AnalysisRequestSerializerList(analysis_requests, many=True)
        return Response(serializer.data)


# 분석가가 분석 보고서 업로드
class UploadAnalysisReport(APIView):
    permission_classes = [IsAuthenticated]  # 인증된 사용자만 접근 허용

    @swagger_auto_schema(
        request_body=openapi.Schema(
            type=openapi.TYPE_OBJECT,
            properties={
                "request": openapi.Schema(
                    type=openapi.TYPE_INTEGER,
                    description="The ID of the analysis request",
                ),
                "report": openapi.Schema(
                    type=openapi.TYPE_FILE, description="The report file"
                ),
            },
            required=["request", "report"],
        ),
        responses={
            status.HTTP_201_CREATED: AnalysisReportSerializer,
            status.HTTP_400_BAD_REQUEST: openapi.Response(
                description="Bad Request",
                examples={
                    "application/json": {
                        "error": "Invalid data or report already exists for this request."
                    }
                },
            ),
            status.HTTP_404_NOT_FOUND: openapi.Response(
                description="Analysis request not found",
                examples={"application/json": {"error": "Analysis request not found."}},
            ),
            status.HTTP_403_FORBIDDEN: openapi.Response(
                description="Permission denied",
                examples={
                    "application/json": {"error": "Only analysts can upload reports."}
                },
            ),
        },
        operation_summary="Upload an analysis report",
        operation_description="This endpoint allows analysts to upload a report for a specific analysis request. The request must be accepted by the analyst before the report can be uploaded.",
    )
    def post(self, request):
        # 요청한 사용자가 분석가인지 확인
        if request.user.role != "analyst":
            return Response(
                {"error": "Only analysts can upload reports."},
                status=status.HTTP_403_FORBIDDEN,
            )

        # 요청 데이터에서 의뢰 ID와 보고서 파일을 가져옴
        request_id = request.data.get("request")
        report_file = request.FILES.get("report")  # 필드 이름 수정

        if not request_id or not report_file:
            return Response(
                {"error": "Request ID and report file are required."},
                status=status.HTTP_400_BAD_REQUEST,
            )

        # 의뢰 객체를 조회
        try:
            analysis_request = AnalysisRequest.objects.get(pk=request_id)
        except AnalysisRequest.DoesNotExist:
            return Response(
                {"error": "Analysis request not found."},
                status=status.HTTP_404_NOT_FOUND,
            )

        # 의뢰 상태가 'ACCEPTED'인 경우만 보고서 업로드 가능
        if analysis_request.status != "ACCEPTED":
            return Response(
                {"error": "Report can only be uploaded for accepted requests."},
                status=status.HTTP_400_BAD_REQUEST,
            )

        # 기존에 보고서가 있는 경우 확인
        if AnalysisReport.objects.filter(request=analysis_request).exists():
            return Response(
                {"error": "A report already exists for this request."},
                status=status.HTTP_400_BAD_REQUEST,
            )

        # 보고서 생성 및 저장
        report = AnalysisReport(
            request=analysis_request, report=report_file
        )  # 필드 이름 수정
        report.save()

        # 의뢰 상태를 'COMPLETED'로 변경
        analysis_request.status = "COMPLETED"
        analysis_request.save()

        serializer = AnalysisReportSerializer(report)
        return Response(serializer.data, status=status.HTTP_201_CREATED)


class CheckAnalysisReport(APIView):
    permission_classes = [IsAuthenticated]  # 인증된 사용자만 접근 허용

    @swagger_auto_schema(
        manual_parameters=[
            openapi.Parameter(
                name="pk",
                in_=openapi.IN_PATH,
                type=openapi.TYPE_INTEGER,
                description="분석 요청의 ID",
            ),
        ],
        responses={
            status.HTTP_200_OK: AnalysisReportSerializer,
            status.HTTP_404_NOT_FOUND: openapi.Response(
                description="보고서 또는 요청이 존재하지 않음",
                examples={"application/json": {"error": "분석 보고서 또는 요청을 찾을 수 없습니다."}},
            ),
            status.HTTP_403_FORBIDDEN: openapi.Response(
                description="권한이 없음",
                examples={"application/json": {"error": "이 보고서를 조회할 권한이 없습니다."}},
            ),
        },
        operation_summary="분석 보고서 조회",
        operation_description="이 엔드포인트는 의뢰자가 자신의 분석 요청에 대한 보고서를 조회할 수 있도록 합니다. 보고서는 의뢰자가 요청한 경우에만 접근할 수 있습니다.",
    )
    def get(self, request, pk):
        # 요청한 사용자가 의뢰자인지 확인
        if request.user.role != "client":
            return Response(
                {"error": "의뢰자만 보고서를 조회할 수 있습니다."},
                status=status.HTTP_403_FORBIDDEN,
            )

        # 의뢰 객체를 조회
        try:
            analysis_request = AnalysisRequest.objects.get(pk=pk)
        except AnalysisRequest.DoesNotExist:
            return Response(
                {"error": "분석 요청을 찾을 수 없습니다."},
                status=status.HTTP_404_NOT_FOUND,
            )

        # 요청한 사용자가 의뢰자일 때만 접근 허용
        if analysis_request.client != request.user:
            return Response(
                {"error": "이 보고서를 조회할 권한이 없습니다."},
                status=status.HTTP_403_FORBIDDEN,
            )

        # 의뢰에 대한 보고서를 조회
        try:
            report = AnalysisReport.objects.get(request=analysis_request)
        except AnalysisReport.DoesNotExist:
            return Response(
                {"error": "분석 보고서를 찾을 수 없습니다."},
                status=status.HTTP_404_NOT_FOUND,
            )

        serializer = AnalysisReportSerializer(report)
        return Response(serializer.data)


# 분석가 리스트 조회 및 생성 뷰
class AnalystListCreate(APIView):
    permission_classes = [IsAuthenticated]  # 인증된 사용자만 접근 허용

    @swagger_auto_schema(
        operation_description="모든 분석가 목록을 조회하거나 새 분석가를 생성합니다.",
        responses={200: AnalystSerializer(many=True), 201: AnalystSerializer},
    )
    def get(self, request):
        # 모든 분석가 객체를 조회
        analysts = Analyst.objects.all()
        serializer = AnalystSerializer(analysts, many=True)
        return Response(serializer.data, status=status.HTTP_200_OK)

    @swagger_auto_schema(
        request_body=AnalystSerializer,
        responses={201: AnalystSerializer},
    )
    def post(self, request):
        # 요청한 사용자가 분석가인지 확인
        if request.user.role != "analyst":
            return Response(
                {"error": "Only analysts can make profile."},
                status=status.HTTP_403_FORBIDDEN,
            )
        # 새 분석가 객체를 생성
        serializer = AnalystSerializer(data=request.data)
        if serializer.is_valid():
            # 현재 사용자를 프로필 생성자(user)로 설정
            serializer.validated_data["user"] = request.user
            serializer.save()
            return Response(serializer.data, status=status.HTTP_201_CREATED)
        return Response(serializer.errors, status=status.HTTP_400_BAD_REQUEST)


# 특정 분석가의 상세 조회, 업데이트 및 삭제 뷰
class AnalystDetail(APIView):
    permission_classes = [IsAuthenticated]  # 인증된 사용자만 접근 허용

    def get_object(self, pk):
        try:
            return Analyst.objects.get(user=pk)
        except Analyst.DoesNotExist:
            return None

    @swagger_auto_schema(
        operation_description="특정 ID의 분석가를 조회합니다.",
        responses={200: AnalystSerializer, 404: "Not found"},
    )
    def get(self, request, pk):
        analyst = Analyst.objects.get(user=pk)
        if analyst is not None:
            serializer = AnalystSerializer(analyst)
            return Response(serializer.data, status=status.HTTP_200_OK)
        return Response({"detail": "Not found."}, status=status.HTTP_404_NOT_FOUND)

    @swagger_auto_schema(
        request_body=AnalystSerializer,
        responses={200: AnalystSerializer, 404: "Not found"},
    )
    def put(self, request, pk):
        analyst = Analyst.objects.get(user=pk)
        if analyst is not None:
            # 프로필 소유자인지 확인
            if analyst.user != request.user:
                return Response(
                    {"detail": "You do not have permission to edit this profile."},
                    status=status.HTTP_403_FORBIDDEN,
                )

            serializer = AnalystSerializer(analyst, data=request.data, partial=True)
            if serializer.is_valid():
                serializer.save()
                return Response(serializer.data, status=status.HTTP_200_OK)
            return Response(serializer.errors, status=status.HTTP_400_BAD_REQUEST)
        return Response({"detail": "Not found."}, status=status.HTTP_404_NOT_FOUND)

    @swagger_auto_schema(
        responses={204: "No content", 404: "Not found"},
    )
    def delete(self, request, pk, *args, **kwargs):
        analyst = self.get_object(pk)
        if analyst is not None:
            # 프로필 소유자인지 확인
            if analyst.user != request.user:
                return Response(
                    {"detail": "You do not have permission to delete this profile."},
                    status=status.HTTP_403_FORBIDDEN,
                )

            analyst.delete()
            return Response(status=status.HTTP_204_NO_CONTENT)
        return Response({"detail": "Not found."}, status=status.HTTP_404_NOT_FOUND)
