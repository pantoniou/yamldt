TOPDIR ?= ../..
BOARDS := $(shell ls *.dts)

# VALIDATE ?= $(if $(findstring validate-dts, $(MAKECMDGOALS)), 1)

include $(TOPDIR)/test-suite/Makefile.inc

.PHONY: validate-dts

validate-dts: $(SCHEMA) $(YDTCDTBS)
