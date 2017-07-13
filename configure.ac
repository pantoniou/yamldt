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

AC_MSG_CHECKING(for libyaml >= 0.1)
if $PKG_CONFIG --atleast-version "0.1" yaml-0.1 ; then
	AC_MSG_RESULT([found])
	AC_DEFINE([HAVE_LIBYAML_H], [], [Have libyaml])
	have_libyaml=true
else  
	AC_MSG_RESULT([not found])
	have_libyaml=false
fi
AM_CONDITIONAL([HAVE_LIBYAML], [test x$have_libyaml = xtrue])

AC_PATH_PROG([DTC], [dtc])

# check whether a dtc with yaml support is available
AC_PATH_PROGS_FEATURE_CHECK([DTC], [dtc],
	[[ echo '/dts-v1/; / { };' | $ac_path_DTC -I dts -O yaml - -o - && \
           ac_cv_path_DTC=$ac_path_DTC ac_path_DTC_found=:]])
AC_SUBST([DTC], [$ac_cv_path_DTC])

# check if we can run DTC
AM_CONDITIONAL([RUN_DTC], [test x$ac_cv_path_DTC != x])
AM_COND_IF([RUN_DTC], [can_RUN_DTC=yes], [can_RUN_DTC=no])

# copy subdirs to allow foreign builds to work
cp_subdirs=
AM_CONDITIONAL([COPY_PORT], [ test x$srcdir != "x." ])
AM_COND_IF([COPY_PORT], [ cp_subdirs="${cp_subdirs} include port" ])

AM_CONDITIONAL([COPY_TESTS], [ test x$srcdir != "x." -a x$can_RUN_DTC == xyes ])
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
