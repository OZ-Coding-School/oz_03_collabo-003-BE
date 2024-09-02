"""
Django settings for allthe project.

Generated by 'django-admin startproject' using Django 5.1.

For more information on this file, see
https://docs.djangoproject.com/en/5.1/topics/settings/

For the full list of settings and their values, see
https://docs.djangoproject.com/en/5.1/ref/settings/
"""

import os
from pathlib import Path

from django.conf import settings
from dotenv import load_dotenv

load_dotenv()

# Build paths inside the project like this: BASE_DIR / 'subdir'.
BASE_DIR = Path(__file__).resolve().parent.parent


# Quick-start development settings - unsuitable for production
# See https://docs.djangoproject.com/en/5.1/howto/deployment/checklist/

# SECURITY WARNING: keep the secret key used in production secret!
SECRET_KEY = "django-insecure-&!0y$4(o$ynya*^2zft%_el3mf)_-8489w*^s*tb%9*_u)w!jo"

# SECURITY WARNING: don't run with debug turned on in production!
DEBUG = True

ALLOWED_HOSTS = [
    "localhost",
    "127.0.0.1",
    "223.130.128.216",
    "api.allthe.live",
    "api.allthe.shop",
    "api.allthe.store",
]

AUTH_USER_MODEL = "accounts.User"
# Application definition
CUSTOM_APPS = [
    "rest_framework",
    "rest_framework_simplejwt",
    "drf_yasg",
    "accounts",
    "contents",
    "analysis",
    "payments",
    "admin_panel",
    "common",
    # 소셜로그인
    "django.contrib.sites",
    "rest_framework.authtoken",
    "corsheaders",
    "storages",
]

DEFAULT_APPS = [
    "django.contrib.admin",
    "django.contrib.auth",
    "django.contrib.contenttypes",
    "django.contrib.sessions",
    "django.contrib.messages",
    "django.contrib.staticfiles",
]

INSTALLED_APPS = DEFAULT_APPS + CUSTOM_APPS

# NCP Object Storage와의 연결을 위한 설정
DEFAULT_FILE_STORAGE = "storages.backends.s3boto3.S3Boto3Storage"
STATICFILES_STORAGE = "storages.backends.s3boto3.S3Boto3Storage"

# NCP Object Storage 관련 설정
AWS_ACCESS_KEY_ID = os.getenv("NCP_Access_Key")  # NCP Access Key
AWS_SECRET_ACCESS_KEY = os.getenv("NCP_Secret_Key")  # NCP Secret Key
print(AWS_ACCESS_KEY_ID)
AWS_STORAGE_BUCKET_NAME = "allthe"  # NCP 버킷 이름

# 커스텀 도메인 설정 (optional)
AWS_S3_CUSTOM_DOMAIN = f"kr.object.ncloudstorage.com/{AWS_STORAGE_BUCKET_NAME}"

# 미디어 파일과 정적 파일의 URL 설정
MEDIA_URL = f"https://{AWS_S3_CUSTOM_DOMAIN}/media/"
STATIC_URL = f"https://{AWS_S3_CUSTOM_DOMAIN}/static/"

# 파일 업로드 경로 설정
MEDIA_ROOT = ""
STATIC_ROOT = ""


REST_FRAMEWORK = {
    "DEFAULT_AUTHENTICATION_CLASSES": (
        "rest_framework_simplejwt.authentication.JWTAuthentication",
        #'rest_framework.authentication.TokenAuthentication',
    ),
}

MIDDLEWARE = [
    "django.middleware.security.SecurityMiddleware",
    "corsheaders.middleware.CorsMiddleware",
    "django.contrib.sessions.middleware.SessionMiddleware",
    "django.middleware.common.CommonMiddleware",
    "django.middleware.csrf.CsrfViewMiddleware",
    "django.contrib.auth.middleware.AuthenticationMiddleware",
    "django.contrib.messages.middleware.MessageMiddleware",
    "django.middleware.clickjacking.XFrameOptionsMiddleware",
]


ROOT_URLCONF = "allthe.urls"

TEMPLATES = [
    {
        "BACKEND": "django.template.backends.django.DjangoTemplates",
        "DIRS": [],
        "APP_DIRS": True,
        "OPTIONS": {
            "context_processors": [
                "django.template.context_processors.debug",
                "django.template.context_processors.request",
                "django.contrib.auth.context_processors.auth",
                "django.contrib.messages.context_processors.messages",
            ],
        },
    },
]

WSGI_APPLICATION = "allthe.wsgi.application"


# Database
# https://docs.djangoproject.com/en/5.1/ref/settings/#databases

DATABASES = {
    "default": {
        "ENGINE": os.getenv("DB_ENGINE"),
        "NAME": os.getenv("DB_NAME"),
        "USER": os.getenv("DB_USER"),
        "PASSWORD": os.getenv("DB_PASSWORD"),
        "HOST": os.getenv("DB_HOST"),
        "PORT": os.getenv("DB_PORT"),
        "OPTIONS": {
            "options": "-c search_path=allthe",  # 사용할 스키마 이름으로 변경
            # NCP는 public 스키마를 지원하지 않기 때문에 allthe 스키마 생성 후 사용
        },
    }
}

# Password validation
# https://docs.djangoproject.com/en/5.1/ref/settings/#auth-password-validators

AUTH_PASSWORD_VALIDATORS = [
    {
        "NAME": "django.contrib.auth.password_validation.UserAttributeSimilarityValidator",
    },
    {
        "NAME": "django.contrib.auth.password_validation.MinimumLengthValidator",
    },
    {
        "NAME": "django.contrib.auth.password_validation.CommonPasswordValidator",
    },
    {
        "NAME": "django.contrib.auth.password_validation.NumericPasswordValidator",
    },
]


# Internationalization
# https://docs.djangoproject.com/en/5.1/topics/i18n/

LANGUAGE_CODE = "en-us"

TIME_ZONE = "UTC"

USE_I18N = True

USE_TZ = True


# Static files (CSS, JavaScript, Images)
# https://docs.djangoproject.com/en/5.1/howto/static-files/

STATIC_URL = "static/"

# Default primary key field type
# https://docs.djangoproject.com/en/5.1/ref/settings/#default-auto-field

DEFAULT_AUTO_FIELD = "django.db.models.BigAutoField"


# Swagger 설정 추가 (선택 사항)
SWAGGER_SETTINGS = {
    "DEFAULT_AUTO_SCHEMA_CLASS": "drf_yasg.inspectors.SwaggerAutoSchema",
}

EMAIL_BACKEND = "django.core.mail.backends.smtp.EmailBackend"
EMAIL_HOST = "smtp.gmail.com"  # Gmail SMTP 서버 주소
EMAIL_PORT = 587  # Gmail SMTP 포트
EMAIL_USE_TLS = True  # TLS 사용 여부
EMAIL_USE_SSL = False  # SSL 사용 여부
EMAIL_HOST_USER = "hancycle585@gmail.com"  # 이메일 서버 로그인용 이메일 주소
EMAIL_HOST_PASSWORD = "awvt ujct gvsu ahlm"  # 이메일 서버 로그인용 비밀번호
DEFAULT_FROM_EMAIL = EMAIL_HOST_USER  # 이메일 발신자 주소

CORS_ALLOW_CREDENTIALS = True
CORS_ALLOWED_ORIGINS = [
    "http://localhost:3000",  # 실제 요청이 발생하는 클라이언트 도메인 추가
    "http://127.0.0.1:3000",
    "http://localhost:5173",
    "https://localhost:3000",  # 실제 요청이 발생하는 클라이언트 도메인 추가
    "https://127.0.0.1:3000",
    "https://localhost:5173",
    "https://allthe.store",  # 추가
]
CORS_ALLOW_METHODS = [
    "DELETE",
    "GET",
    "OPTIONS",
    "PATCH",
    "POST",
    "PUT",
]
CORS_ALLOW_HEADERS = [
    "accept",
    "accept-encoding",
    "authorization",
    "content-type",
    "dnt",
    "origin",
    "user-agent",
    "x-csrftoken",
    "x-requested-with",
]


SITE_ID = 1

from datetime import timedelta

SIMPLE_JWT = {
    "ACCESS_TOKEN_LIFETIME": timedelta(days=7),
    "REFRESH_TOKEN_LIFETIME": timedelta(days=30),
    "ROTATE_REFRESH_TOKENS": False,
    "BLACKLIST_AFTER_ROTATION": True,
    "ALGORITHM": "HS256",
    "SIGNING_KEY": SECRET_KEY,
    "VERIFYING_KEY": None,
    "AUTH_HEADER_TYPES": ("Bearer",),
    "USER_ID_FIELD": "id",
    "USER_ID_CLAIM": "user_id",
    "AUTH_TOKEN_CLASSES": ("rest_framework_simplejwt.tokens.AccessToken",),
    "TOKEN_TYPE_CLAIM": "token_type",
}
