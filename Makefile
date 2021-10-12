DOCKER_DB=brilliance/certificate-db
BINARY=bin/brilliance-ca
DOCKER_TAG=brilliance/brilliance-ca

# 构建brilliance-ca
brilliance-ca:
	 #go build -tags '!cnccgm' -o ${BINARY} -mod vendor
	go build -a -ldflags '-extldflags "-static"' -o ${BINARY} -mod vendor
	#go build -o ${BINARY} -mod vendor
default: build

# DB 镜像
db-docker:
	docker build -t ${DOCKER_DB} -f ./script/docker/Dockerfile.db .
.PHONY: db-docker

# brilliance-ca 镜像
docker:
	#docker build -t ${DOCKER_TAG} -f ./script/docker/Dockerfile .
	#docker buildx build --platform linux/amd64,linux/arm64 -t tauruswei/arm-platform-test-brilliance-ca --push -f ./script/docker/Dockerfile .
	#docker buildx build --platform linux/amd64,linux/arm64 -t tauruswei/arm-platform-test-brilliance-ca -o type=image -f ./script/docker/Dockerfile .
	docker buildx build --platform linux/arm64 -t tauruswei/arm-platform-test-brilliance-ca --output=type=docker -f ./script/docker/Dockerfile .
	#docker buildx build --platform linux/arm64 -t tauruswei/arm-platform-test-brilliance-ca --output type=oci,dest=./output -f ./script/docker/Dockerfile
.PHONY: docker

