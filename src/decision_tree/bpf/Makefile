# SPDX-License-Identifier: (GPL-2.0 OR BSD-2-Clause)

LLVM_VERSION ?= -7 #update with correct LLVM / clang version
LLVM := $(shell clang$(LLVM_VERSION) --version)
CLANG_FLAGS ?= -W -Wall \
	-Wno-compare-distinct-pointer-types

SRCS=$(wildcard *.c)
OBJS=$(patsubst %.c,%.o,$(SRCS))
Q ?= @

INCLUDE_DIRS ?= -Iheaders/

%.o: %.c
	@echo "\tLLVM CC $@"
	$(Q) clang$(LLVM_VERSION) $(INCLUDE_DIRS) -O2 -emit-llvm -c $< $(CLANG_FLAGS) -o $(patsubst %.o,%.llvm,$@)
	$(Q) llc$(LLVM_VERSION) -march=bpf -filetype=obj -o $@ $(patsubst %.o,%.llvm,$@)
	$(Q) rm $(patsubst %.o,%.llvm,$@)

ifeq ($(LLVM),)
all:
	$(warning Install LLVM to compile BPF sources)
else
all: $(OBJS)
endif

clean:
	rm -f *.llvm
	rm -f *.o

.PHONY: all clean
