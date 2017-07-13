# Makefile for yamldl test-suite
TOPDIR := .

TOPTARGETS := all clean

SUBDIRS := $(wildcard */.)

$(TOPTARGETS): $(SUBDIRS)

$(SUBDIRS):
	$(MAKE) -C $@ TOPDIR=$(TOPDIR)/.. $(MAKECMDGOALS)

.PHONY: $(TOPTARGETS) $(SUBDIRS)

.DEFAULT:
	@echo "Nothing to do for $@"

