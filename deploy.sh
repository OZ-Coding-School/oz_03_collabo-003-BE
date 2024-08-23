#!/bin/bash

DOCKER_IMAGE_NAME=$1  # Docker 이미지 이름 받아오기

# 1. 기존 컨테이너 중지 및 삭제
docker-compose down

# 2. Docker 이미지 pull (선택 사항)
# docker pull $DOCKER_IMAGE_NAME  # 필요한 경우 Docker 이미지를 레지스트리에서 pull

# 3. Docker 이미지 태그 변경 (선택 사항)
# docker tag $DOCKER_IMAGE_NAME your-image-name:latest  # 필요한 경우 Docker 이미지 태그 변경

# 4. 마이그레이션 실행
docker-compose run --rm web python manage.py migrate

# 5. 정적 파일 수집
docker-compose run --rm web python manage.py collectstatic --noinput

# 6. 컨테이너 실행 (백그라운드 모드)
docker-compose up -d