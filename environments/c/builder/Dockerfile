ARG BUILDER_IMAGE=fission/builder

FROM ${BUILDER_IMAGE}

FROM alpine:latest

RUN apk update && apk upgrade && \
    apk --no-cache add alpine-sdk clang cmake

COPY --from=0 /builder /builder
ADD build.sh /usr/local/bin/build

