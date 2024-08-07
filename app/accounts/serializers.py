from django.contrib.auth import get_user_model
from rest_framework import serializers

User = get_user_model()

class UserSerializer(serializers.ModelSerializer):
    class Meta:
        model = User
        fields = [
            "id",
            "email",
            "username",
            "password",
        ]
        extra_kwargs = {
            "password": {"write_only": True},
            "email": {"required": True},
            "username": {"required": False, "allow_blank": True},
        }

    def validate(self, data):
        password = data.get("password")
        if password and len(password) < 8:
            raise serializers.ValidationError({"password": "Password must be at least 8 characters long."})

        email = data.get("email")
        if email and User.objects.filter(email=email).exists():
            raise serializers.ValidationError({"email": "이미 존재하는 이메일입니다."})
        
        return data

    def create(self, validated_data):
        password = validated_data.pop("password", None)
        username = validated_data.get("username")
        if not username:
            username = self.generate_default_username(validated_data["email"])
        user = User(**validated_data, username=username)
        if password:
            user.set_password(password)
        user.save()
        return user

    def generate_default_username(self, email):
        return email.split('@')[0]



# 비밀번호를 찾기 위해 이메일 요구
class PasswordResetRequestSerializer(serializers.Serializer):
    email = serializers.EmailField()

# 비밀번호를 새로 설정하기 위해 토큰과 새 비밀번호 요구
class PasswordResetConfirmSerializer(serializers.Serializer):
    password = serializers.CharField(write_only=True, min_length=8)
