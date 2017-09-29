TOPDIR ?= ../..
BOARDS := $(shell ls *.dts)
include $(TOPDIR)/test-suite/Makefile.inc

.PHONY: validate-dts

validate-dts: $(SCHEMA) $(YDTCDTBS)
