FROM alpine:latest AS builder
RUN apk update && apk upgrade && \
    apk --no-cache add alpine-sdk clang cmake libmicrohttpd-dev libuv-dev jansson-dev
COPY *.c *.h CMakeLists.txt /opt/code/
WORKDIR /opt/code/build/
RUN cmake -DCMAKE_BUILD_TYPE=Release .. && make

FROM alpine:latest
RUN apk update && apk upgrade && \
    apk --no-cache add libmicrohttpd libuv jansson
WORKDIR /
COPY --from=builder /opt/code/build/server /
ENTRYPOINT [ "/server" ]
EXPOSE 8888
CMD [ "8888" ]