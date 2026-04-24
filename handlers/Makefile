CLANG ?= clang

ARCH := $(shell uname -m)

ifeq ($(ARCH),x86_64)
    ASM_INC := /usr/include/x86_64-linux-gnu
    ARCH_FLAGS := -D__TARGET_ARCH_x86 -D__x86_64__
else ifeq ($(ARCH),aarch64)
    ASM_INC := /usr/include/aarch64-linux-gnu
    ARCH_FLAGS := -D__TARGET_ARCH_arm64 -D__aarch64__
else
    ASM_INC := /usr/include
    ARCH_FLAGS :=
endif

CFLAGS := -O3 -g -target bpf -mcpu=v3 -fno-stack-protector \
          -Wall -Wno-unused-value \
          -I. -I/usr/include -I$(ASM_INC) -I/usr/include/bpf \
          $(ARCH_FLAGS)

OBJS := gre_handler.o esp_handler.o sctp_handler.o

.PHONY: all clean

all: $(OBJS)

gre_handler.o: gre_handler.c xdp_slot_ctx.h
	$(CLANG) $(CFLAGS) -c $< -o $@

esp_handler.o: esp_handler.c xdp_slot_ctx.h
	$(CLANG) $(CFLAGS) -c $< -o $@

sctp_handler.o: sctp_handler.c xdp_slot_ctx.h
	$(CLANG) $(CFLAGS) -c $< -o $@

clean:
	rm -f $(OBJS)
