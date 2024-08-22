# Python 이미지를 기반으로 빌드
FROM python:3.11-slim-buster

# 작업 디렉토리 설정
WORKDIR /app

# requirements.txt 파일 복사 및 패키지 설치
COPY requirements.txt requirements.txt
RUN pip install --no-cache-dir -r requirements.txt

# 프로젝트 파일 복사
COPY . .

# 서버 실행 명령어
CMD ["python", "manage.py", "runserver"]