from django.contrib.auth.models import BaseUserManager


class CustomUserManager(BaseUserManager):
    # 일반 사용자 생성 메서드
    def create_user(self, nickname, email, password=None, **extra_fields):
        # 이메일 필드가 설정되지 않은 경우 예외 발생
        if not email:
            raise ValueError("The Email field must be set")

        # 이메일을 정규화하여 저장
        email = self.normalize_email(email)

        # 사용자 인스턴스 생성
        user = self.model(nickname=nickname, email=email, **extra_fields)

        # 비밀번호 설정 (해시화)
        user.set_password(password)

        # 사용자 인스턴스 데이터베이스에 저장
        user.save(using=self._db)

        return user  # 생성된 사용자 반환

    # 슈퍼유저 생성 메서드
    def create_superuser(self, nickname, email, password=None, **extra_fields):
        # 기본적으로 is_staff 및 is_superuser 필드를 True로 설정
        extra_fields.setdefault("is_staff", True)
        extra_fields.setdefault("is_superuser", True)

        # 슈퍼유저는 is_staff가 True여야 함
        if extra_fields.get("is_staff") is not True:
            raise ValueError("Superuser must have is_staff=True.")

        # 슈퍼유저는 is_superuser가 True여야 함
        if extra_fields.get("is_superuser") is not True:
            raise ValueError("Superuser must have is_superuser=True.")

        # 슈퍼유저 생성 메서드를 호출하여 사용자 생성
        return self.create_user(nickname, email, password, **extra_fields)
