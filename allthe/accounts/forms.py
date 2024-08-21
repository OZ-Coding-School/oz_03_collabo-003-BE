from django import forms

from .models import User


class UserProfileForm(forms.ModelForm):
    """
    사용자 프로필 폼
    - `User` 모델의 인스턴스를 기반으로 사용자 프로필을 생성 및 수정할 수 있는 폼을 정의합니다.
    """

    class Meta:
        model = User
        fields = ["email", "provider", "password"]
        # `User` 모델의 `email`, `provider`, `password` 필드를 폼에 포함시킵니다.

        widgets = {
            "password": forms.PasswordInput(),  # 비밀번호 필드를 비밀번호 입력 위젯으로 렌더링합니다.
        }
