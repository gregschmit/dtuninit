VERSION = $(shell git describe --dirty 2>/dev/null)

# Build Environment Tracking
#
# The specified build environment variables will be tracked and we will ensure targets are rebuilt
# when any of these change. We use conditional assignment so blank indicates to use the default
# value. This is useful in the Docker environment.
#
# This works by computing the current state, comparing it to the old state from the file, and if
# they differ, adding `-B` to the `MAKEFLAGS`. The current state is written to the file for the next
# build.
OPT_LEVEL := $(if $(strip $(OPT_LEVEL)),$(strip $(OPT_LEVEL)),3)
BPF_DEBUG := $(if $(strip $(BPF_DEBUG)),$(strip $(BPF_DEBUG)),0)
BPF_TARGET := $(if $(strip $(BPF_TARGET)),$(strip $(BPF_TARGET)),bpf)
STATIC := $(if $(strip $(STATIC)),$(if $(filter 0,$(STATIC)),,1),)
CROSS := $(if $(strip $(CROSS)),$(strip $(CROSS)),)
UBUS := $(if $(strip $(UBUS)),$(if $(filter 0,$(UBUS)),,1),1)
BUILDENV = .buildenv
BUILDENV_VARS = OPT_LEVEL BPF_DEBUG BPF_TARGET STATIC CROSS UBUS
BUILDENV_STATE = $(foreach v,$(BUILDENV_VARS),$(v)=$($(v)))
BUILDENV_STATE_OLD = $(shell [ -f $(BUILDENV) ] && cat $(BUILDENV))
ifneq ($(BUILDENV_STATE),$(BUILDENV_STATE_OLD))
  # Test if old state was blank, and print different message.
  ifeq ($(strip $(BUILDENV_STATE_OLD)),)
    $(info New build environment; forcing rebuild...)
  else
    $(info Build environment changed; forcing rebuild...)
  endif
  MAKEFLAGS += -B
  $(shell echo "$(BUILDENV_STATE)" > $(BUILDENV))
endif

# Initialize build variables.
COMMON_CFLAGS = -g -O$(OPT_LEVEL) -Wall
CFLAGS = $(COMMON_CFLAGS) -DVERSION=\"$(VERSION)\" -Iexternal
LDFLAGS =
LDLIBS = -lbpf

# Since we have to use Clang for BPF, use it for everything.
CC = clang
LDFLAGS += -fuse-ld=lld

# Submodules that use CMake should use some common flags.
CMAKE_COMMON = \
  -DCMAKE_C_COMPILER=clang \
  -DCMAKE_BUILD_TYPE=Release \
  -DCMAKE_LINKER_TYPE=LLD

BPF_CFLAGS = $(COMMON_CFLAGS) -DBPF_DEBUG=$(BPF_DEBUG) -target $(BPF_TARGET)

# Static linking support.
ifeq ($(STATIC), 1)
  STATIC_ONOFF = ON
  SHARED_ONOFF = OFF
  LDFLAGS += -static
  LDLIBS += -lelf -lz -lzstd
else
  STATIC_ONOFF = OFF
  SHARED_ONOFF = ON
endif

# Cross-compilation support.
ifeq ($(CROSS),)
  # No cross-compilation.
else ifeq ($(CROSS),aarch64)
  CFLAGS += --sysroot /sysroot/aarch64 -target aarch64-alpine-linux-musl
else ifeq ($(CROSS),x86_64)
  CFLAGS += --sysroot /sysroot/x86_64 -target x86_64-alpine-linux-musl
else
  $(error CROSS must be "aarch64" or "x86_64")
endif

# Ubus support.
ifeq ($(UBUS),1)
  CFLAGS += -DUBUS -I$(UBUS_INSTALL_DIR)/include
  LDFLAGS += -L$(UBUS_INSTALL_DIR)/lib
  LDLIBS += -lubus
endif

.PHONY: all
all: dtuninit_bpf.o dtuninit

# External: cJSON
# We use this library internally even though `ubus` requires `json-c` because it's fast, simple, and
# if we are compiling without `ubus` support, then we get to skip using CMake entirely. Also,
# `json-c` has two headers (`debug.h` and `arraylist.h`) that aren't namespaced that could conflict
# with our code or other libraries we might someday want to use in this project. No idea why they
# haven't namespaced those two headers like they do with all the others (e.g., `json_util.h`). We
# also always compile to an object file to directly link (equivalent to static linking).
JSON_DIR = external/cJSON
JSON_LIB = external/cJSON.o
$(JSON_LIB):
	cp $(JSON_DIR)/cJSON.h external/
	$(CC) $(CFLAGS) -c $(JSON_DIR)/cJSON.c -o $@

# External: json-c (needed by libubox)
JSONC_DIR = external/json-c
JSONC_BUILD_DIR = $(JSONC_DIR)_build
JSONC_INSTALL_DIR = $(JSONC_DIR)_install
JSONC_LIB = $(JSONC_INSTALL_DIR)/lib/libjson-c.$(if $(STATIC),a,so)
$(JSONC_LIB):
	rm -rf $(JSONC_BUILD_DIR)
	rm -rf $(JSONC_INSTALL_DIR)
	mkdir -p $(JSONC_BUILD_DIR)
	cmake -B $(JSONC_BUILD_DIR) -S $(JSONC_DIR) $(CMAKE_COMMON) \
		-DCMAKE_INSTALL_PREFIX=$(JSONC_INSTALL_DIR) \
		-DBUILD_STATIC_LIBS=$(STATIC_ONOFF) \
		-DBUILD_SHARED_LIBS=$(SHARED_ONOFF)
	cmake --build $(JSONC_BUILD_DIR)
	cmake --install $(JSONC_BUILD_DIR)

# External: libubox (needed by ubus)
UBOX_DIR = external/libubox
UBOX_BUILD_DIR = $(UBOX_DIR)_build
UBOX_INSTALL_DIR = $(UBOX_DIR)_install
UBOX_LIB = $(UBOX_INSTALL_DIR)/lib/libubox.$(if $(STATIC),a,so)
$(UBOX_LIB): $(JSONC_LIB)
	rm -rf $(UBOX_BUILD_DIR)
	rm -rf $(UBOX_INSTALL_DIR)
	mkdir -p $(UBOX_BUILD_DIR)
	cmake -B $(UBOX_BUILD_DIR) -S $(UBOX_DIR) $(CMAKE_COMMON) \
		-DCMAKE_PREFIX_PATH=$(PWD)/$(JSONC_INSTALL_DIR) \
		-DCMAKE_INSTALL_PREFIX=$(UBOX_INSTALL_DIR) \
		-DBUILD_LUA=OFF \
		-DBUILD_EXAMPLES=OFF
	cmake --build $(UBOX_BUILD_DIR)
	cmake --install $(UBOX_BUILD_DIR)

# External: ubus
UBUS_DIR = external/ubus
UBUS_BUILD_DIR = $(UBUS_DIR)_build
UBUS_INSTALL_DIR = $(UBUS_DIR)_install
UBUS_LIB = $(UBUS_INSTALL_DIR)/lib/libubus.$(if $(STATIC),a,so)
$(UBUS_LIB): $(UBOX_LIB)
	rm -rf $(UBUS_BUILD_DIR)
	rm -rf $(UBUS_INSTALL_DIR)
	mkdir -p $(UBUS_BUILD_DIR)
	cmake -B $(UBUS_BUILD_DIR) -S $(UBUS_DIR) $(CMAKE_COMMON) \
		-DCMAKE_PREFIX_PATH="$(PWD)/$(JSONC_INSTALL_DIR);$(PWD)/$(UBOX_INSTALL_DIR)" \
		-DCMAKE_INSTALL_PREFIX=$(UBUS_INSTALL_DIR) \
		-DBUILD_STATIC=$(STATIC_ONOFF) \
		-DBUILD_LUA=OFF \
		-DBUILD_EXAMPLES=OFF
	cmake --build $(UBUS_BUILD_DIR)
	cmake --install $(UBUS_BUILD_DIR)

dtuninit_bpf.o: src/dtuninit_bpf/main.c
	$(CC) $(BPF_CFLAGS) -c src/dtuninit_bpf/main.c -o $@

USR_SRCS = \
  src/shared.c \
  $(wildcard src/dtuninit/*.c) \
  $(wildcard src/dtuninit/bpf_state/*.c) \
  $(if $(UBUS),src/dtuninit/bpf_state/watch/ubus.c)
USR_OBJS = $(USR_SRCS:.c=.o)
dtuninit: $(JSON_LIB) $(if $(UBUS), $(UBUS_LIB)) $(USR_OBJS)
	$(CC) $(CFLAGS) $^ -o $@ $(LDFLAGS) $(LDLIBS)

dev: dtuninit_bpf.o dtuninit
	sudo ./dtuninit -d -C ./dtuninit_clients.json

.PHONY: docker_build
docker_build:
	docker build -t dtuninit .

.PHONY: docker_run
docker_run: docker_build
	docker run -it --rm -v .:/app dtuninit /bin/sh

.PHONY: build
build: docker_build
	docker run -it --rm -v .:/app \
		-e OPT_LEVEL=$(OPT_LEVEL) \
		-e BPF_DEBUG=$(BPF_DEBUG) \
		-e BPF_TARGET=$(BPF_TARGET) \
		-e STATIC=$(STATIC) \
		-e CROSS=$(CROSS) \
		-e UBUS=$(UBUS) \
		dtuninit make

# TODO: Get clang-tidy working.
# .PHONY: tidy
# tidy:
# 	clang-tidy -checks='misc-include-cleaner' src/dtuninit_bpf/main.c -- -target bpf $(CFLAGS)
# 	clang-tidy -checks='misc-include-cleaner' src/dtuninit/main.c -- $(CFLAGS)

.PHONY: clean
clean:
	rm -f dtuninit_bpf.o dtuninit $(BUILDENV)
	find src -type f -name "*.o" | xargs rm -f
	rm -f external/*.h external/*.o external/*.a external/*.so*
	rm -rf external/*_build external/*_install
