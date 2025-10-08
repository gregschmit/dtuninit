FROM alpine:latest

RUN apk update && apk upgrade
RUN apk add --no-cache \
    clang \
    cmake \
    build-base \
    git \
    gdb \
    libbpf-dev \
    linux-headers \
    vim \
    zlib-static \
    zstd-static

WORKDIR /app
COPY . .

CMD ["/bin/sh"]
