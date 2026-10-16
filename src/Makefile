# Builds the daemon (l2dns6rw) and its BPF program (l2dns6rw.bpf.o).
# The OpenWrt package passes the toolchain and bpf.mk's clang, target, strip
# tool and headers; a host build finds libbpf through pkg-config.
CC ?= cc
CPPFLAGS ?=
CFLAGS ?= -O2
LDFLAGS ?=
# libbpf headers are not -Wpedantic clean, so they are included as system headers.
LIBBPF_CFLAGS ?= $(patsubst -I%,-isystem %,$(shell pkg-config --cflags-only-I libbpf 2>/dev/null))
BPF_CLANG ?= clang
BPF_TARGET ?= bpfel
BPF_STRIP ?=
BPF_INCLUDES ?= $(LIBBPF_CFLAGS)
VERSION ?= unknown
OBJECT_DIR ?= build

WARNINGS := -Wall -Wextra -Wpedantic -Wformat=2 -Wshadow -Wconversion -Werror
SOURCES := main.c options.c dns.c events.c program.c netlink.c log.c
OBJECTS := $(SOURCES:%.c=$(OBJECT_DIR)/%.o)
TARGET := $(OBJECT_DIR)/l2dns6rw
BPF_OBJECT := $(OBJECT_DIR)/l2dns6rw.bpf.o

all: $(TARGET) $(BPF_OBJECT)

$(TARGET): $(OBJECTS)
	$(CC) $(LDFLAGS) -o $@ $(OBJECTS) -lbpf

$(OBJECT_DIR)/%.o: %.c
	@mkdir -p $(@D)
	$(CC) -I$(CURDIR) -D_GNU_SOURCE -DPROGRAM_VERSION='"$(VERSION)"' $(CPPFLAGS) $(LIBBPF_CFLAGS) $(CFLAGS) $(WARNINGS) -std=c11 -MMD -MP -c -o $@ $<

# Kernel BPF objects carry BTF for libbpf, but not the DWARF debug sections.
# bpf-include holds headers that replace the target's, for the program only.
$(BPF_OBJECT): l2dns6rw.bpf.c l2dns6rw-bpf.h bpf-include/asm/byteorder.h
	@mkdir -p $(@D)
	$(BPF_CLANG) -O2 -g -target $(BPF_TARGET) -I$(CURDIR) -I$(CURDIR)/bpf-include $(BPF_INCLUDES) -Wall -Wextra -Werror -c -o $@ $<
	$(if $(BPF_STRIP),$(BPF_STRIP) --strip-debug $@)
	@# LLVM 20+ compiles code it proves unreachable to a call of the __bpf_trap
	@# kfunc; loading it needs kernel BTF, which OpenWrt kernels do not ship.
	@if grep -q __bpf_trap $@; then echo "$@ references __bpf_trap" >&2; rm -f $@; exit 1; fi

clean:
	$(RM) -r $(OBJECT_DIR)

.PHONY: all clean
-include $(OBJECTS:.o=.d)
