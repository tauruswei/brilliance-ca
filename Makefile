DOCKER_DB=brilliance/certificate-db
BINARY=bin/brilliance-ca
DOCKER_TAG=brilliance/brilliance-ca

# 构建brilliance-ca
brilliance-ca:
	 #go build -tags '!cnccgm' -o ${BINARY} -mod vendor
	 go build -o ${BINARY} -mod vendor
default: build

# DB 镜像
db-docker:
	docker build -t ${DOCKER_DB} -f ./script/docker/Dockerfile.db .
.PHONY: db-docker

# brilliance-ca 镜像
docker:
	docker build -t ${DOCKER_TAG} -f ./script/docker/Dockerfile .
.PHONY: docker