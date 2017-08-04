AUTOMAKE_OPTIONS = foreign
ACLOCAL_AMFLAGS = -I m4

CFLAGS = -Wall -ggdb -O2 -Os
include_HEADERS =

AM_YFLAGS = -d

bin_PROGRAMS = yamldt intexpr

yamldt_SOURCES = yamldt.c yamldt.h list.h fdt.h libfdt_env.h \
		 tree.c tree.h \
		 dtbgen.c dtbgen.h \
		 yamlgen.c yamlgen.h \
		 nullgen.c nullgen.h \
		 nullcheck.c nullcheck.h \
		 dtbcheck.c dtbcheck.h \
		 utils.c utils.h \
		 syexpr.c syexpr.h \
		 base64.c base64.h
yamldt_LDADD = -lm
if HAVE_LIBYAML
yamldt_LDADD += -lyaml
endif

intexpr_SOURCES = intexpr.c \
		  syexpr.c syexpr.h \
		  utils.c utils.h 

AM_MAKEFLAGS = DTC=@DTC@ \
	       YAMLDT=@abs_top_builddir@/yamldt \
	       EBPFRUN=@abs_top_builddir@/ebpfrun \
	       TOPDIR=@abs_top_srcdir@

bin_PROGRAMS += ebpfrun

ebpfrun_SOURCES = ebpfrun.c \
		  ebpf.c ebpf.h \
		  utils.c utils.h

SUBDIRS = . port

if RUN_DTC
SUBDIRS += test-suite
endif

if RUN_EBPFCC

bin_PROGRAMS += ebpfcompile

ebpfcompile_SOURCES = ebpfcompile.c \
		      ebpf.c ebpf.h \
		      utils.c utils.h

SUBDIRS += ebpf
endif
