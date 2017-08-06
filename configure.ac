#                                               -*- Autoconf -*-
# Process this file with autoconf to produce a configure script.

#AC_PREREQ(2.60)
m4_include(m4/version.m4)
AC_INIT(yamldt, m4_defn([VERSION_NUMBER]), panto@antoniou-consulting.com)
AC_CONFIG_MACRO_DIR([m4])
AC_REVISION([VERSION_NUMBER])
AC_CONFIG_SRCDIR([yamldt.c])
AC_CONFIG_HEADER([config.h])
AM_INIT_AUTOMAKE([-Wall -Werror foreign])

# enable maintainer mode by default
AM_MAINTAINER_MODE([enable])

# Checks for programs.
AC_PROG_CC
AC_PROG_INSTALL
AC_PROG_MAKE_SET

# Checks for libraries.
AM_PROG_LIBTOOL

# libyaml
LIBYAML_REQUIRED_VERSION=0.1
PKG_CHECK_MODULES(LIBYAML, yaml-0.1 >= $LIBYAML_REQUIRED_VERSION,[])

if $PKG_CONFIG --atleast-version "0.1" yaml-0.1 ; then
	AC_DEFINE([HAVE_LIBYAML_H], [], [Have libyaml])
	have_libyaml=true
else  
	have_libyaml=false
fi
AM_CONDITIONAL([HAVE_LIBYAML], [test x$have_libyaml = xtrue])

# check whether a dtc with yaml support is available
AC_MSG_CHECKING([for dtc with YAML support])
AC_PATH_PROGS_FEATURE_CHECK([DTC], [dtc],
	[[ echo '/dts-v1/; / { };' | \
	 	$ac_path_DTC -I dts -O yaml - -o - >/dev/null && \
           ac_cv_path_DTC=$ac_path_DTC ac_path_DTC_found=:]])
AC_SUBST([DTC], [$ac_cv_path_DTC])

# check if we can run DTC
AM_CONDITIONAL([RUN_DTC], [test x$ac_cv_path_DTC != x])
AM_COND_IF([RUN_DTC], [can_RUN_DTC=yes], [can_RUN_DTC=no])

if test x$can_RUN_DTC = xyes ;  then
	AC_MSG_RESULT([$ac_cv_path_DTC])
else
	AC_MSG_RESULT([not found])
fi

# libelf
LIBELF_REQUIRED_VERSION=0.8
PKG_CHECK_MODULES(LIBELF, libelf >= $LIBELF_REQUIRED_VERSION,[])

if $PKG_CONFIG --atleast-version "0.8" libelf ; then
	AC_DEFINE([HAVE_LIBELF_H], [], [Have libelf])
	have_libelf=true
else  
	have_libelf=false
fi
AM_CONDITIONAL([HAVE_LIBELF], [test x$have_libelf = xtrue])

# AC_CHECK_HEADERS([elf.h], [has_ELF_H=yes], [has_ELF_H=no])

AC_MSG_CHECKING([for ebpf compiler])
# eBPF compiler available?
AC_PATH_PROGS_FEATURE_CHECK([EBPFCC], [clang-5.0 clang-4.0 clang-3.9 clang],
	[[ echo 'unsigned long long entry(void *mem) { return 1; }' | \
	   $ac_path_EBPFCC 2>/dev/null -ffreestanding -x c -c -O2 -target bpf - -o /dev/null && \
           ac_cv_path_EBPFCC=$ac_path_EBPFCC ac_path_EBPFCC_found=:]])
AC_SUBST([EBPFCC], [$ac_cv_path_EBPFCC])

# check if we can run CLANG
AM_CONDITIONAL([RUN_EBPFCC], [test x$ac_cv_path_EBPFCC != x])
AM_COND_IF([RUN_EBPFCC], [can_RUN_EBPFCC=yes], [can_RUN_EBPFCC=no])

if test x$can_RUN_EBPFCC = xyes ;  then
	AC_MSG_RESULT([$ac_cv_path_EBPFCC])
else
	AC_MSG_RESULT([not found])
fi

# check if we can execute ebpf
AC_MSG_CHECKING([whether we can execute ebpf programs])
AM_CONDITIONAL([EXEC_EBPF], [test x$have_libelf = xtrue])
AM_COND_IF([EXEC_EBPF], [can_EXEC_EBPF=yes], [can_EXEC_EBPF=no])
AC_MSG_RESULT([$can_EXEC_EBPF])

# copy subdirs to allow foreign builds to work
cp_subdirs=
AM_CONDITIONAL([COPY_PORT], [ test x$srcdir != "x." ])
AM_COND_IF([COPY_PORT], [ cp_subdirs="${cp_subdirs} include port" ])

AM_CONDITIONAL([COPY_TESTS], [ test x$srcdir != "x." -a x$can_RUN_DTC = xyes ])
AM_COND_IF([COPY_TESTS], [ cp_subdirs="${cp_subdirs} test-suite"])

AC_CONFIG_COMMANDS_POST([\
	abs_srcdir=`cd $srcdir && pwd`; \
	if test "x$cp_subdirs" != x -a "x$abs_srcdir" != x ; then
		for subdir in $cp_subdirs; do \
			cp -as "${abs_srcdir}/${subdir}" "${subdir}"; \
		done; \
	fi; \
	])

AC_CONFIG_FILES([Makefile])
AC_OUTPUT
