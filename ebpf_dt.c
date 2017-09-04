/*
 * ebpf_dt.c - EBPF + DT
 *
 * Verify and stuff
 *
 * (C) Copyright Pantelis Antoniou <pantelis.antoniou@konsulko.com>
 *
 * Redistribution and use in source and binary forms, with or without
 * modification, are permitted provided that the following conditions are
 * met:
 *
 *     (1) Redistributions of source code must retain the above copyright
 *     notice, this list of conditions and the following disclaimer.
 *
 *     (2) Redistributions in binary form must reproduce the above copyright
 *     notice, this list of conditions and the following disclaimer in
 *     the documentation and/or other materials provided with the
 *     distribution.
 *
 *     (3)The name of the author may not be used to
 *     endorse or promote products derived from this software without
 *     specific prior written permission.
 *
 * THIS SOFTWARE IS PROVIDED BY THE AUTHOR ``AS IS'' AND ANY EXPRESS OR
 * IMPLIED WARRANTIES, INCLUDING, BUT NOT LIMITED TO, THE IMPLIED
 * WARRANTIES OF MERCHANTABILITY AND FITNESS FOR A PARTICULAR PURPOSE ARE
 * DISCLAIMED. IN NO EVENT SHALL THE AUTHOR BE LIABLE FOR ANY DIRECT,
 * INDIRECT, INCIDENTAL, SPECIAL, EXEMPLARY, OR CONSEQUENTIAL DAMAGES
 * (INCLUDING, BUT NOT LIMITED TO, PROCUREMENT OF SUBSTITUTE GOODS OR
 * SERVICES; LOSS OF USE, DATA, OR PROFITS; OR BUSINESS INTERRUPTION)
 * HOWEVER CAUSED AND ON ANY THEORY OF LIABILITY, WHETHER IN CONTRACT,
 * STRICT LIABILITY, OR TORT (INCLUDING NEGLIGENCE OR OTHERWISE) ARISING
 * IN ANY WAY OUT OF THE USE OF THIS SOFTWARE, EVEN IF ADVISED OF THE
 * POSSIBILITY OF SUCH DAMAGE.
 */
#include "config.h"

#include <stdio.h>
#include <string.h>
#include <stdlib.h>
#include <unistd.h>
#include <errno.h>
#include <limits.h>
#include <ctype.h>
#include <time.h>
#include <stdbool.h>
#include <stdarg.h>
#include <inttypes.h>
#include <sys/types.h>
#include <sys/stat.h>
#include <unistd.h>
#include <assert.h>

#define _GNU_SOURCE
#include <getopt.h>

#include <libelf.h>

#include "list.h"
#include "utils.h"

#include "ebpf.h"

#include "tree.h"
#include "dt.h"

#include "ebpf_dt.h"

#define EXISTS 1
#define BADTYPE 2

uint64_t epbf_dt_lazy_func(uint64_t arg0, uint64_t arg1, uint64_t arg2,
			  uint64_t arg3, uint64_t arg4,
			  struct ebpf_ctx *ctx, const char *funcname)
{
	printf("Lazy function: %s(0x%" PRIx64 ", 0x%" PRIx64 ", 0x%" PRIx64  ", 0x%" PRIx64 ", 0x%" PRIx64 ")\n",
			funcname, arg0, arg1, arg2, arg3, arg4);

	return 0;
}

/* catch all for unresolved calls */
static uint64_t bpf_unresolved(uint64_t arg0, uint64_t arg1,
			     uint64_t arg2, uint64_t arg3,
			     uint64_t arg4, struct ebpf_ctx *ctx)
{
	fprintf(stderr, "ebpf error: Unresolved call at PC %u\n", ctx->pc);
	ctx->errcode = -EFAULT;
	return 0;
}

static uint64_t bpf_callback(uint64_t arg0, uint64_t arg1,
			     uint64_t arg2, uint64_t arg3,
			     uint64_t arg4, struct ebpf_ctx *ctx)
{
	printf("%s\n", __func__);

	return 0;
}

static uint64_t bpf_printf(uint64_t arg0, uint64_t arg1,
			     uint64_t arg2, uint64_t arg3,
			     uint64_t arg4, struct ebpf_ctx *ctx)
{
	const char *fmt = (void *)(intptr_t)arg0;
	const char *s;
	char c;
	int argsno, len;

	/* count instances of % (which are not escaped) */

	/* get length of string (negative on fault) */
	len = ebpf_strlen(ctx, fmt);
	if (len < 0)
		return ctx->errcode = len;

	argsno = 1;	/* fmt is the first */
	s = fmt;
	while ((c = *s++) != '\0') {
		if (c == '\\' && ((c = *s++) == '\0'))
			break;
		if (c == '%')
			argsno++;
	}
	if (argsno > 5)
		ctx->errcode = -EINVAL;
	if (ctx->errcode)
		return ctx->errcode;

	switch (argsno) {
	case 1:
		return puts(fmt);
	case 2:
		return printf(fmt, arg1);
	case 3:
		return printf(fmt, arg1, arg2);
	case 4:
		return printf(fmt, arg1, arg2, arg3);
	case 5:
		return printf(fmt, arg1, arg2, arg3, arg4);
	}

	return -1;
}

/* verify that the node is valid by comparing to each one in the tree */
struct node *get_and_verify_node(struct yaml_dt_state *dt, struct node *np, uint64_t ptr)
{
	struct node *child, *match;

	if ((intptr_t)np == (intptr_t)ptr)
		return np;

	for_each_child_of_node(np, child) {
		match = get_and_verify_node(dt, child, ptr);
		if (match)
			return match;
	}

	return NULL;
}

const char *get_and_verify_str(struct ebpf_ctx *ctx, uint64_t ptr)
{
	const char *str = (void *)(intptr_t)ptr;
	int len;

	len = ebpf_strlen(ctx, str);
	if (len < 0)
		return NULL;
	return str;
}

const char **get_and_verify_strv(struct ebpf_ctx *ctx, uint64_t ptr)
{
	const char **strv = (void *)(intptr_t)ptr;
	int i, len;
	const char *s;

	i = 0;
	for (;;) {
		/* verify load is possible */
		if (!ebpf_load_check(ctx, &strv[i], sizeof(*strv)))
			break;
		s = strv[i];

		/* NULL? final entry */
		if (!s)
			return strv;

		len = ebpf_strlen(ctx, s);
		if (len < 0)
			break;
		i++;
	}
	return NULL;
}

static uint64_t bpf_get_int(uint64_t arg0, uint64_t arg1,
			     uint64_t arg2, uint64_t arg3,
			     uint64_t arg4, struct ebpf_ctx *ctx)
{
	const struct ebpf_vm *vm = ctx->vm;
	struct yaml_dt_state *dt = ctx_to_dt(vm_to_ctx(vm));
	struct node *np = get_and_verify_node(dt, tree_root(to_tree(dt)), arg0);
	const char *name = (void *)(intptr_t)arg1;
	int namelen, err;
	char namebuf[NODE_FULLNAME_MAX];
	uint64_t flags = 0;
	uint64_t *flagsp = (void *)(intptr_t)arg2;
	unsigned long long v;

	if (!np)
		return ctx->errcode = -EINVAL;

	namelen = ebpf_strlen(ctx, name);
	if (namelen < 0)
		return ctx->errcode = namelen;

	if (!ebpf_store_check(ctx, flagsp, sizeof(*flagsp)))
		return ctx->errcode = -EFAULT;

	ebpf_debug(vm, "%s %s name=%s\n", __func__,
		dn_fullname(np, namebuf, sizeof(namebuf)),
		name);

	v = dt_get_int(dt, np, name, 0, 0, &err);
	if (err) {
		if (dt_get_rcount(dt, np, name, 0))
			flags |= BADTYPE;
		v = 0;
	} else
		flags |= EXISTS;

	*flagsp = flags;

	return (uint64_t)v;
}

static uint64_t bpf_get_bool(uint64_t arg0, uint64_t arg1,
			     uint64_t arg2, uint64_t arg3,
			     uint64_t arg4, struct ebpf_ctx *ctx)
{
	const struct ebpf_vm *vm = ctx->vm;
	struct yaml_dt_state *dt = ctx_to_dt(vm_to_ctx(vm));
	struct node *np = get_and_verify_node(dt, tree_root(to_tree(dt)), arg0);
	const char *name = (void *)(intptr_t)arg1;
	int namelen, ret;
	char namebuf[NODE_FULLNAME_MAX];
	uint64_t flags = 0;
	uint64_t *flagsp = (void *)(intptr_t)arg2;

	if (!np)
		return ctx->errcode = -EINVAL;

	namelen = ebpf_strlen(ctx, name);
	if (namelen < 0)
		return ctx->errcode = namelen;

	if (!ebpf_store_check(ctx, flagsp, sizeof(*flagsp)))
		return ctx->errcode = -EFAULT;

	ebpf_debug(vm, "%s %s name=%s\n", __func__,
		dn_fullname(np, namebuf, sizeof(namebuf)),
		name);

	ret = dt_get_bool(dt, np, name, 0, 0);
	if (ret < 0) {
		if (dt_get_rcount(dt, np, name, 0))
			flags |= BADTYPE;
		ret = false;
	} else
		flags |= EXISTS;

	*flagsp = flags;

	return (uint64_t)ret;
}

static uint64_t bpf_get_str(uint64_t arg0, uint64_t arg1,
			     uint64_t arg2, uint64_t arg3,
			     uint64_t arg4, struct ebpf_ctx *ctx)
{
	const struct ebpf_vm *vm = ctx->vm;
	struct yaml_dt_state *dt = ctx_to_dt(vm_to_ctx(vm));
	struct node *np = get_and_verify_node(dt, tree_root(to_tree(dt)), arg0);
	const char *name = (void *)(intptr_t)arg1;
	int namelen, err;
	char namebuf[NODE_FULLNAME_MAX];
	uint64_t flags = 0;
	bool *flagsp = (void *)(intptr_t)arg2;
	const char *str;

	if (!np)
		return ctx->errcode = -EINVAL;

	namelen = ebpf_strlen(ctx, name);
	if (namelen < 0)
		return ctx->errcode = namelen;

	if (!ebpf_store_check(ctx, flagsp, sizeof(*flagsp)))
		return ctx->errcode = -EFAULT;

	ebpf_debug(vm, "%s %s name=%s\n", __func__,
		dn_fullname(np, namebuf, sizeof(namebuf)),
		name);

	str = dt_get_string(dt, np, name, 0, 0);
	if (!str) {
		if (dt_get_rcount(dt, np, name, 0))
			flags |= BADTYPE;
	} else {
		flags |= EXISTS;

		/* open window to the pointed string */
		err = ebpf_open_memory_window(ctx, str, strlen(str) + 1);
		if (err)
			return ctx->errcode = -ENOMEM;
	}

	*flagsp = flags;

	ebpf_debug(vm, "v = \"%s\"\n", str);

	return (uint64_t)(intptr_t)str;
}

static uint64_t bpf_get_strseq(uint64_t arg0, uint64_t arg1,
			     uint64_t arg2, uint64_t arg3,
			     uint64_t arg4, struct ebpf_ctx *ctx)
{
	const struct ebpf_vm *vm = ctx->vm;
	struct yaml_dt_state *dt = ctx_to_dt(vm_to_ctx(vm));
	struct node *np = get_and_verify_node(dt, tree_root(to_tree(dt)), arg0);
	const char *name = (void *)(intptr_t)arg1;
	uint64_t flags = 0;
	uint64_t *flagsp = (void *)(intptr_t)arg2;
	int namelen, i, count ,err;
	char namebuf[NODE_FULLNAME_MAX];
	const char *s;
	const char **strv;

	if (!np || !name)
		return ctx->errcode = -EINVAL;

	namelen = ebpf_strlen(ctx, name);
	if (namelen < 0)
		return ctx->errcode = namelen;

	if (!ebpf_store_check(ctx, flagsp, sizeof(*flagsp)))
		return ctx->errcode = -EFAULT;

	ebpf_debug(vm, "%s %s name=%s\n", __func__,
		dn_fullname(np, namebuf, sizeof(namebuf)),
		name);

	/* get number of strings that the property contains */
	count = 0;
	while (dt_get_string(dt, np, name, 0, count))
		count++;

	/* if no strings are found return nothing */
	if (count == 0) {
		if (dt_get_rcount(dt, np, name, 0))
			flags |= BADTYPE;
		strv = NULL;
	} else {

		flags |= EXISTS;

		/* allocate a strv array */
		strv = ebpf_alloc(ctx, false, sizeof(*strv) * (count + 1));
		if (!strv)
			return ctx->errcode = -ENOMEM;

		/* now fill it in */
		for (i = 0; i < count; i++) {
			s = dt_get_string(dt, np, name, 0, i);
			assert(s);

			/* open window to the pointed string */
			err = ebpf_open_memory_window(ctx, s, strlen(s) + 1);
			if (err)
				return ctx->errcode = -ENOMEM;
			strv[i] = s;
		}
		strv[i] = NULL;
	}

	*flagsp = flags;

	for (i = 0; i < count; i++)
		ebpf_debug(vm, "v[%d] = \"%s\"\n", i, strv[i]);

	return (uint64_t)(intptr_t)strv;
}

static uint64_t bpf_streq(uint64_t arg0, uint64_t arg1,
			     uint64_t arg2, uint64_t arg3,
			     uint64_t arg4, struct ebpf_ctx *ctx)
{
	struct ebpf_vm *vm = ctx->vm;
	const char *str1 = get_and_verify_str(ctx, arg0);
	const char *str2 = get_and_verify_str(ctx, arg1);

	if (!str1 || !str2)
		return ctx->errcode = -EINVAL;

	ebpf_debug(vm, "%s %s %s\n", __func__, str1, str2);

	return !strcmp(str1, str2);
}

static uint64_t bpf_anystreq(uint64_t arg0, uint64_t arg1,
			     uint64_t arg2, uint64_t arg3,
			     uint64_t arg4, struct ebpf_ctx *ctx)
{
	struct ebpf_vm *vm = ctx->vm;
	const char **strv = get_and_verify_strv(ctx, arg0);
	const char *str = get_and_verify_str(ctx, arg1);

	if (!strv || !str)
		return ctx->errcode = -EINVAL;

	ebpf_debug(vm, "%s\n", __func__);

	while (*strv) {
		if (!strcmp(*strv, str))
			return 1;
		strv++;
	}

	return 0;
}

static uint64_t bpf_get_parent(uint64_t arg0, uint64_t arg1,
			       uint64_t arg2, uint64_t arg3,
			       uint64_t arg4, struct ebpf_ctx *ctx)
{
	const struct ebpf_vm *vm = ctx->vm;
	struct yaml_dt_state *dt = ctx_to_dt(vm_to_ctx(vm));
	struct node *np = get_and_verify_node(dt, tree_root(to_tree(dt)), arg0);
	const char *name = (void *)(intptr_t)arg1;
	int namelen;
	char namebuf[NODE_FULLNAME_MAX];

	if (!np)
		return ctx->errcode = -EINVAL;

	namelen = ebpf_strlen(ctx, name);
	if (namelen < 0)
		return ctx->errcode = namelen;

	ebpf_debug(vm, "%s %s name=%s\n", __func__,
		dn_fullname(np, namebuf, sizeof(namebuf)),
		name);

	return (uint64_t)(intptr_t)np->parent;
}

static uint64_t bpf_get_intseq(uint64_t arg0, uint64_t arg1,
			     uint64_t arg2, uint64_t arg3,
			     uint64_t arg4, struct ebpf_ctx *ctx)
{
	const struct ebpf_vm *vm = ctx->vm;
	struct yaml_dt_state *dt = ctx_to_dt(vm_to_ctx(vm));
	struct node *np = get_and_verify_node(dt, tree_root(to_tree(dt)), arg0);
	const char *name = (void *)(intptr_t)arg1;
	int64_t *countp = (void *)(intptr_t)arg2;
	uint64_t flags = 0;
	uint64_t *flagsp = (void *)(intptr_t)arg3;
	int namelen, i, count, err;
	char namebuf[NODE_FULLNAME_MAX];
	int64_t *intp = NULL;

	if (!np || !name)
		return ctx->errcode = -EINVAL;

	namelen = ebpf_strlen(ctx, name);
	if (namelen < 0)
		return ctx->errcode = namelen;

	if (!ebpf_store_check(ctx, countp, sizeof(*countp)))
		return ctx->errcode = -EFAULT;

	if (!ebpf_store_check(ctx, flagsp, sizeof(*flagsp)))
		return ctx->errcode = -EFAULT;

	ebpf_debug(vm, "%s %s name=%s\n", __func__,
		dn_fullname(np, namebuf, sizeof(namebuf)),
		name);

	count = dt_get_rcount(dt, np, name, 0);

	/* if nothing is found return nothing */
	if (count == 0)
		goto err_out;

	/* get number of ints that the property contains */
	for (i = 0; i < count; i++) {
		(void)dt_get_int(dt, np, name, 0, i, &err);
		if (err < 0) {
			flags |= BADTYPE;
			count = 0;
			goto err_out;
		}
			
		count++;
	}

	/* allocate a int array */
	intp = ebpf_alloc(ctx, false, sizeof(*intp) * count);
	if (!intp)
		return ctx->errcode = -ENOMEM;

	/* now fill it in */
	for (i = 0; i < count; i++) {
		intp[i] = dt_get_int(dt, np, name, 0, i, &err);
		assert(err == 0);
	}
	flags |= EXISTS;

err_out:

	*countp = count;
	*flagsp = flags;

	for (i = 0; intp && i < count; i++)
		ebpf_debug(vm, "v[%d] = %llu\n", i, intp[i]);

	return (uint64_t)(intptr_t)intp;
}

const struct ebpf_callback bpf_dt_cb[] = {
	[0] = {
		.name = "unresolved",
		.func = bpf_unresolved,
	},
	[1] = {
		.name = "callback",
		.func = bpf_callback,
	},
	[2] = {
		.name = "bpf_printf",
		.func = bpf_printf,
	},
	[3] = {
		.name = "get_int",
		.func = bpf_get_int,
	},
	[4] = {
		.name = "get_bool",
		.func = bpf_get_bool,
	},
	[5] = {
		.name = "get_str",
		.func = bpf_get_str,
	},
	[6] = {
		.name = "get_strseq",
		.func = bpf_get_strseq,
	},
	[7] = {
		.name = "streq",
		.func = bpf_streq,
	},
	[8] = {
		.name = "streq",
		.func = bpf_anystreq,
	},
	[9] = {
		.name = "get_parent",
		.func = bpf_get_parent,
	},
	[10] = {
		.name = "get_intseq",
		.func = bpf_get_intseq,
	},
	{ NULL, NULL }
};
