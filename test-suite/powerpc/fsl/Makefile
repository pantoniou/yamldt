TOPDIR ?= ../../..

# Note that -@ needs those blacklisted
# they have symbol reordering differences
# BLACKLIST := p1021mds p1022rdk p1024rdb_32b p1024rdb_36b
BLACKLIST :=

BOARDS := $(shell ls *.dts)
include $(TOPDIR)/test-suite/Makefile.inc
