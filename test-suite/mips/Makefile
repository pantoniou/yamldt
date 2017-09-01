TOPDIR ?= $(realpath .)/../..

TOPTARGETS := all clean check validate genyamls

SUBDIRS := $(wildcard */.)

$(TOPTARGETS): $(SUBDIRS)

$(SUBDIRS):
	$(MAKE) -C $@ TOPDIR=$(TOPDIR) $(MAKECMDGOALS)

.PHONY: $(TOPTARGETS) $(SUBDIRS)
