# Makefile for yamldl test-suite
TOPDIR ?= $(realpath .)/..

TOPTARGETS := clean check validate genyamls

SUBDIRS := $(wildcard */.)

$(TOPTARGETS): $(SUBDIRS)

$(SUBDIRS):
	$(MAKE) -C $@ TOPDIR=$(TOPDIR) $(MAKECMDGOALS)

.PHONY: $(TOPTARGETS) $(SUBDIRS)

.DEFAULT:
	@echo "Nothing to do for $@"

