DOCKER_DB=brilliance/certificate-db

default: build
db-docker:
	docker build -t ${DOCKER_DB} -f ./script/docker/Dockerfile.db .
.PHONY: db-docker
