#
# Leaf makefile for EBPF programs
#

EBPFCC ?= clang-5.0
EBPFCCFLAGS ?= -ffreestanding -I ./ -I $(TOPDIR)/ebpf/include -O2 -target bpf

EBPFDEPFLAGS = -MT $@ -MMD -MP -MF $*.Bd

EBPFOBJS := $(addsuffix .ebpf, $(basename $(EBPFSRCS)))
EBPFDEPS := $(addsuffix .Bd, $(basename $(EBPFSRCS)))

%.ebpf: %.c
	$(EBPFCC) $(EBPFDEPFLAGS) $(EBPFCCFLAGS) -c $^ -o $@

.PHONY: clean distclean check

all: $(EBPFOBJS)

clean:
	rm -f $(EBPFDEPS) $(EBPFOBJS)

-include $(EBPFDEPS)
