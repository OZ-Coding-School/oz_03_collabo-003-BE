from django.contrib.auth import get_user_model
from rest_framework import serializers

from .models import RefreshToken
from .models import User

User = get_user_model()


class UserSerializer(serializers.ModelSerializer):
    """
    사용자 직렬화기
    - 사용자 모델을 직렬화하고 유효성 검사를 수행합니다.
    - 사용자 정보를 JSON 형태로 변환하거나 JSON 데이터를 사용자 모델 인스턴스로 변환합니다.
    """

    class Meta:
        model = User
        fields = [
            "id",
            "email",
            "username",
            "password",
            "social_provider",
            "role",
            "business_number",
            "phone_number",
            "social_id",
            "points",
        ]
        extra_kwargs = {
            "password": {"write_only": True},
            "email": {"required": True},
            "username": {"required": True, "allow_blank": False},
        }

    def validate(self, data):
        """
        데이터 유효성 검사
        - 비밀번호 길이 검사: 비밀번호는 최소 8자 이상이어야 합니다.
        - 이메일 중복 검사: 제공된 이메일이 이미 사용 중인지 확인합니다.
        - 사용자 이름 중복 검사: 제공된 사용자 이름이 이미 사용 중인지 확인합니다.
        """
        password = data.get("password")
        if password and len(password) < 8:
            raise serializers.ValidationError(
                {"password": "Password must be at least 8 characters long."}
            )

        email = data.get("email")
        if email and User.objects.filter(email=email).exists():
            raise serializers.ValidationError({"email": "This email is already taken."})

        username = data.get("username")
        if username and User.objects.filter(username=username).exists():
            raise serializers.ValidationError(
                {"username": "This username is already taken."}
            )

        return data

    def create(self, validated_data):
        """
        사용자 생성
        - 유효성 검사를 통과한 데이터를 사용하여 새로운 사용자 인스턴스를 생성합니다.
        - 비밀번호는 해싱하여 저장합니다.
        """
        password = validated_data.pop("password", None)
        user = User(**validated_data)
        if password:
            user.set_password(password)
        user.save()
        return user


class RefreshTokenSerializer(serializers.ModelSerializer):
    """
    리프레시 토큰 직렬화기
    - 리프레시 토큰 정보를 직렬화합니다.
    """

    class Meta:
        model = RefreshToken
        fields = ["user", "token", "created_at", "expires_at"]
        read_only_fields = ["token", "created_at"]

    def validate(self, data):
        """
        리프레시 토큰 유효성 검사
        """
        if data["expires_at"] <= timezone.now():
            raise serializers.ValidationError({"expires_at": "Token has expired."})
        return data


class PasswordResetRequestSerializer(serializers.Serializer):
    """
    비밀번호 재설정 요청 직렬화기
    - 사용자가 비밀번호 재설정을 요청할 때 이메일 주소를 수집합니다.
    """

    email = serializers.EmailField()


class PasswordResetConfirmSerializer(serializers.Serializer):
    """
    비밀번호 재설정 확인 직렬화기
    - 사용자가 비밀번호 재설정을 할때 새로운 이메일을 수집합니다."
    """

    token = serializers.CharField(required=True)
    new_password = serializers.CharField(write_only=True, min_length=8)


# 닉네임 중복 검사
class UsernameCheckSerializer(serializers.Serializer):
    username = serializers.CharField(max_length=150)


class EmailSerializer(serializers.Serializer):
    """
    이메일 주소를 직렬화하는 직렬화기
    - 사용자가 인증 코드를 요청할 때 이메일 주소를 수집합니다.
    """

    email = serializers.EmailField()
