#!/bin/bash

DOCKER_IMAGE_NAME=$1  # Docker 이미지 이름 받아오기

# 컨테이너 중지 및 삭제
docker-compose down

# Docker 이미지 태그 변경 (필요한 경우)
docker tag $DOCKER_IMAGE_NAME allthe:latest  # allthe로 변경

# 컨테이너 실행
docker-compose up -d