AUTOMAKE_OPTIONS = foreign
ACLOCAL_AMFLAGS = -I m4

CFLAGS = -Wall -ggdb -O2 -Os
include_HEADERS =

AM_YFLAGS = -d

bin_PROGRAMS = yamldt intexpr

yamldt_SOURCES = yamldt.c yamldt.h list.h fdt.h libfdt_env.h \
		 tree.c tree.h \
		 dtb.c dtb.h \
		 utils.c utils.h \
		 syexpr.c syexpr.h
yamldt_LDADD = -lm
if HAVE_LIBYAML
yamldt_LDADD += -lyaml
endif

intexpr_SOURCES = intexpr.c \
		  syexpr.c syexpr.h \
		  utils.c utils.h 

AM_MAKEFLAGS = DTC=@DTC@ YAMLDT=@abs_top_builddir@/yamldt TOPDIR=@abs_top_srcdir@

SUBDIRS = . port

if RUN_DTC
SUBDIRS += test-suite
endif
