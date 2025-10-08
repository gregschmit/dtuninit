VERSION = $(shell git describe --dirty 2>/dev/null)
OPT_LEVEL ?= 3
BPF_DEBUG ?= 0
COMMON_CFLAGS = -g -Wall -DVERSION=\"$(VERSION)\" -DBPF_DEBUG=$(BPF_DEBUG)

# Since we have to use clang for BPF, use it for everything.
CC = clang

# This probably shouldn't ever change, since it uses host endianness which is typically little, and
# that's also the endianness for most target architectures, but this could be set to `bpfel` or
# `bpfeb` if we need to target a different endianness from the host.
BPF_TARGET ?= bpf

BPF_CFLAGS = $(COMMON_CFLAGS) -target $(BPF_TARGET)
BPF_CFLAGS += -I/usr/include/x86_64-linux-gnu

USR_TARGET ?=
USR_LIBS = -lbpf -lelf -lz -lzstd
USR_CFLAGS = $(COMMON_CFLAGS) $(if $(USR_TARGET),-target $(USR_TARGET),)
USR_CFLAGS += -Iexternal
# USR_CFLAGS += -I/usr/include/x86_64-linux-gnu
# USR_CFLAGS += -I/usr/include/aarch64-linux-gnu
USR_SRCS = \
	src/shared.c \
	$(wildcard src/dtuninit/*.c) \
	$(wildcard src/dtuninit/bpf_state/*.c)
USR_OBJS = $(USR_SRCS:.c=.o)

ifeq ($(STATIC),1)
	USR_LIBS += -static
endif

.PHONY: all
all: dtuninit_bpf.o dtuninit

JSON_DIR = external/cJSON
JSON_LIB = external/cJSON.o
$(JSON_LIB):
	cp $(JSON_DIR)/cJSON.h external/
	$(CC) -O$(OPT_LEVEL) -c $(JSON_DIR)/cJSON.c -o $@

$(USR_OBJS): %.o: %.c
	$(CC) $(USR_CFLAGS) -O$(OPT_LEVEL) -c $< -o $@

dtuninit_bpf.o: src/dtuninit_bpf/main.c
	$(CC) $(BPF_CFLAGS) -O$(OPT_LEVEL) -c $^ -o $@

dtuninit: $(JSON_LIB) $(USR_OBJS)
	$(CC) $(USR_CFLAGS) -O$(OPT_LEVEL) $^ -o $@ $(USR_LIBS)

dev: dtuninit_bpf.o dtuninit
	sudo ./dtuninit -d -C ./dtuninit_clients

.PHONY: static
static:
	$(MAKE) all STATIC=1

.PHONY: cross
cross:
	# Assume aarch64 for now.
	$(MAKE) all USR_TARGET=aarch64-linux-gnu

.PHONY: docker_build
docker_build:
	docker build -t dtuninit .

.PHONY: docker_run
docker_run: docker_build
	docker run -it --rm -v .:/app dtuninit /bin/sh

.PHONY: build
build: docker_build
	docker run -it --rm -v .:/app dtuninit make -B

.PHONY: build_static
build_static: docker_build
	docker run -it --rm -v .:/app dtuninit make -B static

# TODO: Get clang-tidy working.
# .PHONY: tidy
# tidy:
# 	clang-tidy -checks='misc-include-cleaner' src/dtuninit_bpf/main.c -- -target bpf $(CFLAGS)
# 	clang-tidy -checks='misc-include-cleaner' src/dtuninit/main.c -- $(CFLAGS)

.PHONY: clean
clean:
	rm -f dtuninit_bpf.o dtuninit
	find src -type f -name "*.o" | xargs rm -f
	rm -f external/*.o external/*.h external/*.a
	rm -rf external/*_build
