FROM alpine:latest

ENV PACKAGES="make clang cmake git gdb libbpf-dev linux-headers lld vim zlib-static zstd-static"

RUN apk update && apk upgrade
RUN apk add --no-cache $PACKAGES

# Setup a sysroot for cross compilation on x86_64.
RUN [ "$(apk --print-arch)" != "x86_64" ] && \
    mkdir -p /sysroot/x86_64/etc/apk && \
    cp /etc/apk/repositories /sysroot/x86_64/etc/apk/ && \
    apk --arch x86_64 --root /sysroot/x86_64 --allow-untrusted --initdb add --no-cache $PACKAGES || true

# # Setup a sysroot for cross compilation on aarch64.
RUN [ "$(apk --print-arch)" != "aarch64" ] && \
    mkdir -p /sysroot/aarch64/etc/apk && \
    cp /etc/apk/repositories /sysroot/aarch64/etc/apk/ && \
    apk --arch aarch64 --root /sysroot/aarch64 --allow-untrusted --initdb add --no-cache $PACKAGES || true

WORKDIR /app
COPY . .

CMD ["/bin/sh"]
