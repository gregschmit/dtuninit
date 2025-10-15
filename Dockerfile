FROM alpine:latest

ENV CROSS_PKGS="clang libbpf-dev linux-headers lld zlib-static zstd-static"
ENV PKGS="make cmake git gdb vim $CROSS_PKGS"

RUN apk update && apk upgrade
RUN apk add --no-cache $PKGS

# Setup a sysroot for cross compilation on x86_64.
RUN [ "$(apk --print-arch)" != "x86_64" ] && \
    mkdir -p /sysroot/x86_64/etc/apk && \
    cp /etc/apk/repositories /sysroot/x86_64/etc/apk/ && \
    apk --arch x86_64 --root /sysroot/x86_64 --allow-untrusted --initdb add --no-cache $CROSS_PKGS || true

# # Setup a sysroot for cross compilation on aarch64.
RUN [ "$(apk --print-arch)" != "aarch64" ] && \
    mkdir -p /sysroot/aarch64/etc/apk && \
    cp /etc/apk/repositories /sysroot/aarch64/etc/apk/ && \
    apk --arch aarch64 --root /sysroot/aarch64 --allow-untrusted --initdb add --no-cache $CROSS_PKGS || true

WORKDIR /app
COPY . .

CMD ["/bin/sh"]
