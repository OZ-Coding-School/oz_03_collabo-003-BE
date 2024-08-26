from django.contrib.auth import get_user_model
from rest_framework import serializers

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
        ]
        extra_kwargs = {
            "password": {
                "write_only": True
            },  # 비밀번호는 읽기 전용 필드로 설정하여 반환되지 않음
            "email": {"required": True},  # 이메일 필드는 필수 입력 사항
            "username": {
                "required": False,
                "allow_blank": True,
            },  # 사용자 이름은 선택 사항이며 공백 허용
        }

    # 사용자 데이터를 검증
    def validate(self, data):
        """
        데이터 유효성 검사
        - 비밀번호 길이 검사: 비밀번호는 최소 8자 이상이어야 합니다.
        - 이메일 중복 검사: 제공된 이메일이 이미 사용 중인지 확인합니다.
        """
        # 비밀번호 길이 검사
        password = data.get("password")
        if password and len(password) < 8:
            raise serializers.ValidationError(
                {"password": "Password must be at least 8 characters long."}
            )

        # 이메일 중복성 검사
        email = data.get("email")
        if email and User.objects.filter(email=email).exists():
            raise serializers.ValidationError({"email": "This email is already taken."})

        # 닉네임 중복성 검사
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
        password = validated_data.pop(
            "password", None
        )  # 비밀번호를 유효성 검사 후 제거
        username = validated_data.get("username")
        if not username:
            # 사용자 이름이 제공되지 않은 경우 기본 사용자 이름 생성
            username = self.generate_default_username(validated_data["email"])
        user = User(**validated_data, username=username)
        if password:
            user.set_password(password)  # 비밀번호 해싱
        user.save()
        return user

    def generate_default_username(self, email):
        """
        기본 사용자 이름 생성
        - 이메일을 기반으로 기본 사용자 이름을 생성합니다.
        """
        return email.split("@")[0]


class PasswordResetRequestSerializer(serializers.Serializer):
    """
    비밀번호 재설정 요청 직렬화기
    - 사용자가 비밀번호 재설정을 요청할 때 이메일 주소를 수집합니다.
    """

    email = serializers.EmailField()


class PasswordResetConfirmSerializer(serializers.Serializer):
    """
    비밀번호 재설정 확인 직렬화기
    - 비밀번호 재설정 과정에서 새로운 비밀번호를 받기 위한 직렬화기입니다.
    """

    password = serializers.CharField(write_only=True, min_length=8)


# 닉네임 중복 검사
class UsernameCheckSerializer(serializers.Serializer):
    username = serializers.CharField(max_length=150)
