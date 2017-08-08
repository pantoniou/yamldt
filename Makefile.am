AUTOMAKE_OPTIONS = foreign
ACLOCAL_AMFLAGS = -I m4

CFLAGS = -Wall -ggdb -O2 -Os
include_HEADERS =

AM_YFLAGS = -d

bin_PROGRAMS = yamldt intexpr

yamldt_CFLAGS = $(LIBYAML_CFLAGS) $(LIBELF_CFLAGS) 
yamldt_SOURCES = yamldt.c \
		 dt.c dt.h \
		 list.h fdt.h libfdt_env.h \
		 tree.c tree.h \
		 dtbgen.c dtbgen.h \
		 yamlgen.c yamlgen.h \
		 nullgen.c nullgen.h \
		 nullcheck.c nullcheck.h \
		 dtbcheck.c dtbcheck.h \
		 utils.c utils.h \
		 syexpr.c syexpr.h \
		 base64.c base64.h
yamldt_LDADD = -lm $(LIBYAML_LIBS)

intexpr_SOURCES = intexpr.c \
		  syexpr.c syexpr.h \
		  utils.c utils.h 

AM_MAKEFLAGS = DTC=@DTC@ \
	       YAMLDT=@abs_top_builddir@/yamldt \
	       EBPFRUN=@abs_top_builddir@/ebpfrun \
	       EBPFCC=@EBPFCC@ \
	       TOPDIR=@abs_top_srcdir@

SUBDIRS = . port

if RUN_EBPFCC
SUBDIRS += ebpf
endif

if EXEC_EBPF

bin_PROGRAMS += ebpfrun ebpfcompile

ebpfrun_CFLAGS = $(LIBELF_CFLAGS) $(LIBYAML_CFLAGS)
ebpfrun_SOURCES = ebpfrun.c \
		  ebpf.c ebpf.h \
		  utils.c utils.h \
		  dt.c dt.h \
		  tree.c tree.h \
		  list.h fdt.h libfdt_env.h \
		  yamlgen.c yamlgen.h \
		  nullgen.c nullgen.h \
		  nullcheck.c nullcheck.h \
		  syexpr.c syexpr.h \
		  base64.c base64.h
ebpfrun_LDADD = -lm $(LIBYAML_LIBS)

ebpfcompile_CFLAGS = $(LIBELF_CFLAGS)
ebpfcompile_SOURCES = ebpfcompile.c \
		      ebpf.c ebpf.h \
		      utils.c utils.h

endif

if RUN_DTC
SUBDIRS += test-suite
endif
