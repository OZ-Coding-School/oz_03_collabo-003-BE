#!/bin/bash

# 1. 작업 디렉토리 설정
cd /path/to/your/project  # Django 프로젝트가 위치한 디렉토리로 변경

# 2. 필요한 경우 Docker 이미지 pull (선택 사항)
# docker-compose pull

# 3. 기존 컨테이너 중지 및 삭제
docker-compose down

# 4. 마이그레이션 실행
docker-compose run --rm web python manage.py migrate

# 5. 정적 파일 수집
docker-compose run --rm web python manage.py collectstatic --noinput

# 6. 컨테이너 실행 (백그라운드 모드)
docker-compose up -d