#!/bin/bash
set -e

CONTAINER_NAME="ics-threat-feeds-app"
IMAGE_NAME="ics-threat-feeds-app-image"
PORT="80"

# build the container image
docker build -t $IMAGE_NAME .

# stop and remove old container if it exists
if docker ps -a --format '{{.Names}}' | grep -q "^$CONTAINER_NAME$"; then
    docker stop $CONTAINER_NAME
    docker rm $CONTAINER_NAME
fi

# run the container
docker run -d \
    --name $CONTAINER_NAME \
    -p $PORT:8080 \
    --restart unless-stopped \
    --cap-drop=ALL \
    --cap-add=NET_BIND_SERVICE \
    --security-opt no-new-privileges \
    $IMAGE_NAME
