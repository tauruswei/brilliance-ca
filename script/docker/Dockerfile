# 编译
FROM golang:1.13 as builder
ENV TZ=Asia/Shanghai
RUN ln -snf /usr/share/zoneinfo/$TZ /etc/localtime && echo $TZ > /etc/timezone
ADD . /go/src/brilliance/brilliance-ca/
WORKDIR /go/src/brilliance/brilliance-ca
#RUN cp ./libs/* /usr/lib
#RUN cp ./libs/* . && cp ./librenhangapi.so /usr/lib/ && cp ./RHVerifyAPI.h /usr/lib && cp ./libltdl.so.7 /usr/lib && \
#dpkg -i *.deb && cp -r ./third_party/http1 /usr/local/go/src/net/
RUN make brilliance-ca

FROM --platform=$TARGETPLATFORM alpine:latest
RUN apk add -U tzdata && cp /usr/share/zoneinfo/Asia/Shanghai /etc/localtime && apk del tzdata
RUN mkdir /lib64 && ln -s /lib/libc.musl-x86_64.so.1 /lib64/ld-linux-x86-64.so.2
COPY --from=builder /go/src/brilliance/brilliance-ca/bin/brilliance-ca /usr/local/bin
COPY --from=builder /go/src/brilliance/brilliance-ca/config  /opt/brilliance/brilliance-ca/config
WORKDIR /opt/brilliance/brilliance-ca
ENTRYPOINT ["brilliance-ca"]