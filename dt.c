/*
 * dt.c - parser methods
 *
 * YAML to DTB generator
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
#define _GNU_SOURCE
#include "config.h"

#include <stdio.h>
#include <string.h>
#include <stdlib.h>
#include <unistd.h>
#include <dirent.h>
#include <errno.h>
#include <ctype.h>
#include <sys/types.h>
#include <sys/stat.h>
#include <sys/mman.h>
#include <unistd.h>
#include <time.h>
#include <stdbool.h>
#include <stdarg.h>
#include <assert.h>
#include <limits.h>

#include <getopt.h>

#include "utils.h"
#include "syexpr.h"
#include "base64.h"

#include "dt.h"

#include "nullgen.h"
#include "nullcheck.h"
#include "yamlgen.h"

#define DEFAULT_COMPILER "clang-5.0"
#define DEFAULT_CFLAGS "-x c -ffreestanding -target bpf -O2 -c -o - -"
#define DEFAULT_TAGS "!filter,!ebpf"

static const char *get_builtin_tag(const char *tag)
{
	static const char *tags[] = {
		"!anchor",
		"!pathref",
		"!int",
		"!bool",
		"!str",
		"!null",
		"!int",
		"!uint",
		"!int8",
		"!uint8",
		"!int16",
		"!uint16",
		"!int32",
		"!uint32",
		"!int64",
		"!uint64",
		"!char",
		"!base64",
	};

	int i;

	for (i = 0; i < ARRAY_SIZE(tags); i++)
		if (!strcmp(tag, tags[i]))
			return tags[i];

	return NULL;
}

static int parse_int(const char *str, int len, unsigned long long *valp,
		     bool *unsignedp, bool *hexp)
{
	int ret;
	sy_val_t val;
	struct sy_state state, *sy = &state;
	struct sy_config cfg;

	memset(&cfg, 0, sizeof(cfg));
	cfg.size = sy_workbuf_size_max(len);
	if (cfg.size > 4096)
		cfg.size = 4096;	/* do not allow pathological cases */
	cfg.workbuf = alloca(cfg.size);

	sy_init(sy, &cfg);

	assert(len > 0);
	ret = sy_eval(sy, str, len, &val);
	if (ret == 0) {
		*valp = val.v;
		*unsignedp = val.u;
		*hexp = val.x;
	}

	return ret;
}

static const char *is_int_tag(const char *tag)
{
	static const char *tags[] = {
		"!int",
		"!int",
		"!uint",
		"!int8",
		"!uint8",
		"!int16",
		"!uint16",
		"!int32",
		"!uint32",
		"!int64",
		"!uint64",
	};

	int i;

	for (i = 0; i < ARRAY_SIZE(tags); i++)
		if (!strcmp(tag, tags[i]))
			return tags[i];

	return NULL;
}

static bool int_val_in_range(const char *tag, unsigned long long val,
			     bool is_unsigned, bool is_hex)
{
	long long sval;
	bool sval_overflow;

	/* yes, I'm paranoid */
	assert(ULLONG_MAX >= UINT64_MAX);

	/* silently convert hex values to unsigned form */
	if (is_hex) {
		is_unsigned = true;
		if (!strcmp(tag,  "!int") || !strcmp(tag,  "!int32"))
			tag = "!uint";
		else if (!strcmp(tag,  "!int8"))
			tag = "!uint8";
		else if (!strcmp(tag,  "!int16"))
			tag = "!uint16";
		else if (!strcmp(tag,  "!int32"))
			tag = "!uint32";
		else if (!strcmp(tag,  "!int64"))
			tag = "!uint64";
	}

	sval = (long long)val;
	sval_overflow = is_unsigned && val > ULLONG_MAX;

	if (!strcmp(tag,  "!int") || !strcmp(tag,  "!int32"))
		return  (is_unsigned && val  <= INT32_MAX) ||
		       (!is_unsigned && sval >= INT32_MIN && sval <= INT32_MAX);

	if (!strcmp(tag, "!uint") || !strcmp(tag, "!uint32"))
		return val <= UINT32_MAX;

	if (!strcmp(tag, "!int8"))
		return  (is_unsigned && val  <= INT8_MAX) ||
		       (!is_unsigned && sval >= INT8_MIN && sval <= INT8_MAX);

	if (!strcmp(tag, "!uint8"))
		return val <= UINT8_MAX;

	if (!strcmp(tag, "!int16"))
		return  (is_unsigned && val  <= INT16_MAX) ||
		       (!is_unsigned && sval >= INT16_MIN && sval <= INT16_MAX);

	if (!strcmp(tag, "!uint16"))
		return val <= UINT16_MAX;

	if (!strcmp(tag, "!int32"))
		return  (is_unsigned && val  <= INT32_MAX) ||
		       (!is_unsigned && sval >= INT32_MIN && sval <= INT32_MAX);

	if (!strcmp(tag, "!uint32"))
		return val <= UINT32_MAX;

	if (!strcmp(tag, "!int64"))
		return  (is_unsigned && val  <= INT64_MAX) ||
		       (!is_unsigned && sval >= INT64_MIN && sval <= INT64_MAX &&
			 !sval_overflow);

	if (!strcmp(tag, "!uint64"))
		return val <= UINT64_MAX;

	return false;
}

static bool uint_val_in_range(const char *tag, unsigned long long val,
				      bool is_hex)
{
	if ((long long)val < 0)
		return false;

	if (!strcmp(tag,  "!int") || !strcmp(tag,  "!int32"))
		tag = "!uint";
	else if (!strcmp(tag,  "!int8"))
		tag = "!uint8";
	else if (!strcmp(tag,  "!int16"))
		tag = "!uint16";
	else if (!strcmp(tag,  "!int32"))
		tag = "!uint32";
	else if (!strcmp(tag,  "!int64"))
		tag = "!uint64";

	return int_val_in_range(tag, val, true, is_hex);
}

static void dt_print_at_msg(struct yaml_dt_state *dt,
			    const struct dt_yaml_mark *m,
			    const char *type, const char *msg);

struct ref *
yaml_dt_ref_alloc(struct tree *t, enum ref_type type,
		const void *data, int len, const char *xtag, int size)
{
	struct yaml_dt_state *dt = to_dt(t);
	struct dt_ref *dt_ref;
	struct ref *ref;
	void *p;

	assert(size >= sizeof(*dt_ref));

	dt_ref = malloc(size);
	assert(dt_ref);
	memset(dt_ref, 0, size);

	ref = to_ref(dt_ref);

	p = malloc(len + 1);
	assert(p);
	memcpy(p, data, len);
	((char *)p)[len] = '\0';	/* and always terminate */

	dt_ref->alloc_data = p;

	ref->data = p;
	ref->len = len;

	if (xtag) {
		ref->xtag_builtin = get_builtin_tag(xtag);
		if (!ref->xtag_builtin) {
			ref->xtag = strdup(xtag);
			assert(ref->xtag);
		}
	}

	/* always mark for debugging */
	dt_ref->m = dt->current_mark;

	return ref;
}

void yaml_dt_ref_free(struct tree *t, struct ref *ref)
{
	struct dt_ref *dt_ref = to_dt_ref(ref);

	if (ref->xtag)
		free(ref->xtag);

	if (dt_ref->alloc_data)
		free(dt_ref->alloc_data);

	if (dt_ref->binary)
		free(dt_ref->binary);

	free(dt_ref);
}

struct property *yaml_dt_prop_alloc(struct tree *t, const char *name, int size)
{
	struct yaml_dt_state *dt = to_dt(t);
	struct dt_property *dt_prop;
	struct property *prop;

	assert(size >= sizeof(*dt_prop));
	dt_prop = malloc(size);
	assert(dt_prop);
	memset(dt_prop, 0, size);

	prop = to_property(dt_prop);

	prop->name = strdup(name);
	assert(prop->name);

	dt_prop->m = dt->current_mark;

	return prop;
}

void yaml_dt_prop_free(struct tree *t, struct property *prop)
{
	struct dt_property *dt_prop = to_dt_property(prop);

	free(prop->name);
	free(dt_prop);
}

struct label *yaml_dt_label_alloc(struct tree *t, const char *name, int size)
{
	struct yaml_dt_state *dt = to_dt(t);
	struct dt_label *dt_l;
	struct label *l;

	assert(size >= sizeof(*dt_l));
	dt_l = malloc(size);
	assert(dt_l);
	memset(dt_l, 0, size);

	l = to_label(dt_l);

	l->label = strdup(name);
	assert(l->label);

	dt_l->m = dt->current_mark;

	return l;
}

void yaml_dt_label_free(struct tree *t, struct label *l)
{
	struct dt_label *dt_l = to_dt_label(l);

	free(l->label);

	free(dt_l);
}

struct node *yaml_dt_node_alloc(struct tree *t, const char *name,
				const char *label, int size)
{
	struct yaml_dt_state *dt = to_dt(t);
	struct dt_node *dt_np;
	struct node *np;

	assert(size >= sizeof(*dt_np));
	dt_np = malloc(size);
	assert(dt_np);
	memset(dt_np, 0, size);

	np = to_node(dt_np);

	np->name = strdup(name);
	assert(np->name);

	dt_np->m = dt->current_mark;

	return np;
}

void yaml_dt_node_free(struct tree *t, struct node *np)
{
	struct dt_node *dt_np = to_dt_node(np);

	free(np->name);
	free(dt_np);
}

void yaml_dt_tree_debugf(struct tree *t, const char *fmt, ...)
{
	struct yaml_dt_state *dt;
	va_list ap;

	dt = to_dt(t);

	va_start(ap, fmt);
	if (dt->cfg.debug)
		vfprintf(stderr, fmt, ap);
	va_end(ap);
}

void yaml_dt_tree_error_at_node(struct tree *t, struct node *np,
				const char *fmt, ...)
{
	va_list ap;
	char str[1024];
	int len;

	va_start(ap, fmt);
	vsnprintf(str, sizeof(str) - 1, fmt, ap);
	va_end(ap);
	str[sizeof(str) - 1] = '\0';

	len = strlen(str);
	while (len > 1 && str[len - 1] == '\n')
		str[--len] = '\0';

	dt_print_at_msg(to_dt(t), &to_dt_node(np)->m, "error", str);
	to_dt(t)->error_flag = true;
}

void yaml_dt_tree_error_at_property(struct tree *t,
				    struct property *prop, const char *fmt, ...)
{
	va_list ap;
	char str[1024];
	int len;

	va_start(ap, fmt);
	vsnprintf(str, sizeof(str) - 1, fmt, ap);
	va_end(ap);
	str[sizeof(str) - 1] = '\0';

	len = strlen(str);
	while (len > 1 && str[len - 1] == '\n')
		str[--len] = '\0';

	dt_print_at_msg(to_dt(t), &to_dt_property(prop)->m, "error", str);
	to_dt(t)->error_flag = true;
}

void yaml_dt_tree_error_at_ref(struct tree *t,
			       struct ref *ref, const char *fmt, ...)
{
	va_list ap;
	char str[1024];
	int len;

	va_start(ap, fmt);
	vsnprintf(str, sizeof(str) - 1, fmt, ap);
	va_end(ap);
	str[sizeof(str) - 1] = '\0';

	len = strlen(str);
	while (len > 1 && str[len - 1] == '\n')
		str[--len] = '\0';

	dt_print_at_msg(to_dt(t), &to_dt_ref(ref)->m, "error", str);
	to_dt(t)->error_flag = true;
}

void yaml_dt_tree_error_at_label(struct tree *t,
			         struct label *l, const char *fmt, ...)
{
	va_list ap;
	char str[1024];
	int len;
	const struct dt_yaml_mark *m;

	va_start(ap, fmt);
	vsnprintf(str, sizeof(str) - 1, fmt, ap);
	va_end(ap);
	str[sizeof(str) - 1] = '\0';

	len = strlen(str);
	while (len > 1 && str[len - 1] == '\n')
		str[--len] = '\0';

	m = &to_dt_label(l)->m;
	if (dt_mark_is_unset(m))
		m = &to_dt_node(l->np)->m;
	dt_print_at_msg(to_dt(t), m, "error", str);
	to_dt(t)->error_flag = true;
}

static void dt_stream_start(struct yaml_dt_state *dt)
{
	/* initialize */
	if (dt->map_key) {
		free(dt->map_key);
		dt->map_key = NULL;
	}
	dt->depth = 0;
	dt->current_np = NULL;
	dt->current_prop = NULL;
	dt->prop_seq_depth = 0;
	dt->error_flag = false;
	dt->stream_ended = false;
}

static void dt_stream_end(struct yaml_dt_state *dt)
{
	if (dt->map_key) {
		free(dt->map_key);
		dt->map_key = NULL;
	}
	dt->current_np = NULL;
	if (dt->current_prop) {
		prop_free(to_tree(dt), dt->current_prop);
		dt->current_prop = NULL;
	}
	dt->stream_ended = false;
}

static void dt_document_start(struct yaml_dt_state *dt)
{
	if (dt->map_key) {
		free(dt->map_key);
		dt->map_key = NULL;
	}
	dt->current_np = tree_root(to_tree(dt));
}

static void dt_document_end(struct yaml_dt_state *dt)
{
	if (dt->map_key) {
		free(dt->map_key);
		dt->map_key = NULL;
	}
}

int dt_emitter_setup(struct yaml_dt_state *dt)
{
	if (!dt->emitter || !dt->emitter->eops || !dt->emitter->eops->setup)
		return 0;

	return dt->emitter->eops->setup(dt);
}

void dt_emitter_cleanup(struct yaml_dt_state *dt)
{
	if (!dt->emitter || !dt->emitter->eops || !dt->emitter->eops->cleanup)
		return;

	dt->emitter->eops->cleanup(dt);
}

int dt_emitter_emit(struct yaml_dt_state *dt)
{
	if (!dt->emitter || !dt->emitter->eops || !dt->emitter->eops->emit)
		return 0;

	return dt->emitter->eops->emit(dt);
}

int dt_checker_setup(struct yaml_dt_state *dt)
{
	if (!dt->checker || !dt->checker->cops || !dt->checker->cops->setup)
		return 0;

	return dt->checker->cops->setup(dt);
}

void dt_checker_cleanup(struct yaml_dt_state *dt)
{
	if (!dt->checker || !dt->checker->cops || !dt->checker->cops->cleanup)
		return;

	dt->checker->cops->cleanup(dt);
}

int dt_checker_check(struct yaml_dt_state *dt)
{
	if (!dt->checker || !dt->checker->cops || !dt->checker->cops->check)
		return 0;

	return dt->checker->cops->check(dt);
}

static struct yaml_dt_input *
dt_input_create(struct yaml_dt_state *dt, const char *file,
		struct yaml_dt_input *in_parent)
{
	struct yaml_dt_config *cfg = &dt->cfg;
	struct yaml_dt_input *in;
	char *s;
	size_t bufsz, nread, adv, filesz, alloc;
	FILE *fp;
	struct stat st;
	char *tmpfile = NULL;
	int flen, plen;
	char * const *pathv;

	if (strcmp(file, "-")) {
		fp = fopen(file, "rb");
		if (!fp) {
			/* try include path when we have a parent */
			if (!in_parent || !cfg->search_path || !cfg->search_path[0])
				return NULL;
			flen = strlen(file);
			if (!flen)
				return NULL;
			pathv = cfg->search_path;
			while (*pathv) {
				plen = strlen(*pathv);
				while (plen > 1 && (*pathv)[plen - 1] == '/')
					plen--;
				tmpfile = malloc(plen + 1 + flen + 1);
				assert(tmpfile);
				memcpy(tmpfile, *pathv, plen);
				tmpfile[plen] = '/';
				strcpy(tmpfile + plen + 1, file);
				fp = fopen(tmpfile, "rb");
				if (fp) {
					file = tmpfile;
					break;
				}
				pathv++;
			}
		}
	} else {
		file = "<stdin>";
		fp = stdin;
	}

	in = malloc(sizeof(*in));
	assert(in);

	memset(in, 0, sizeof(*in));
	in->name = strdup(file);
	assert(in->name);
	if (tmpfile)
		free(tmpfile);

	INIT_LIST_HEAD(&in->includes);

	/* get the file size if we can */
	filesz = 0;
	if (fstat(fileno(fp), &st) != -1 && S_ISREG(st.st_mode))
		filesz = st.st_size;

	/* for non regular files the advance is 64K */
	adv = filesz ? filesz : 64 * 1024;

	alloc = 0;
	do {
		if (in->size >= alloc) {
			alloc += adv;
			in->content = realloc(in->content, alloc + 1);
			assert(in->content);
		}

		s = in->content + in->size;
		bufsz = alloc - in->size;

		nread = fread(s, 1, bufsz, fp);
		if (nread <= 0 && ferror(fp))
			return NULL;
		in->size += nread;
		s[nread] = '\0';	/* always terminate with zero */

		/* avoid extra calls to fread */
		if (filesz && in->size >= filesz)
			break;

	} while (nread >= bufsz);

	/* trim */
	if (in->size && alloc != in->size) {
		in->content = realloc(in->content, in->size + 1);
		assert(in->content);
		/* always terminate with zero */
		*((char *)in->content + in->size) = '\0';
	}

	fclose(fp);

	in->parent = in_parent;
	list_add_tail(&in->node, !in->parent ? &dt->inputs : &in_parent->includes);

	dt_debug(dt, "%s: read %zd bytes\n", in->name, in->size);

	if (dt->dep_output)
		fprintf(dt->dep_output, " %s", in->name);

	return in;
}

static void dt_input_free(struct yaml_dt_state *dt, struct yaml_dt_input *in)
{
	struct yaml_dt_input *ini, *inin;

	list_for_each_entry_safe(ini, inin, &in->includes, node) {
		list_del(&ini->node);
		dt_input_free(dt, ini);
	}
	free(in->name);
	free(in->content);
	free(in);
}

static struct yaml_dt_span *
dt_span_create(struct yaml_dt_state *dt, const struct yaml_dt_input *in)
{
	struct yaml_dt_span *span;

	span = malloc(sizeof(*span));
	assert(span);

	memset(span, 0, sizeof(*span));
	span->in = in;

	/* default is with an empty span at current pos */
	span->m.start.index = dt->curr_input_pos;
	span->m.start.line = dt->curr_input_line;
	span->m.start.column = 0;
	span->m.end = span->m.start;
	span->start_pos = in->pos;
	span->end_pos = in->pos;

	list_add_tail(&span->node, &dt->spans);

	return span;
}

static void dt_span_free(struct yaml_dt_state *dt, struct yaml_dt_span *span)
{
	free(span);
}

static void dt_dts_debug(struct dts_state *ds, const char *fmt, ...)
		__attribute__ ((__format__ (__printf__, 2, 0)));

static void dt_dts_message(struct dts_state *ds, enum dts_message_type type,
		const struct dts_location *loc, const char *fmt, ...)
		__attribute__ ((__format__ (__printf__, 4, 0)));

#define dts_to_dt(_t) 	container_of(_t, struct yaml_dt_state, ds)

static void dt_dts_debug(struct dts_state *ds, const char *fmt, ...)
{
	struct yaml_dt_state *dt = dts_to_dt(ds);
	FILE *fp;
	char *buf, *s;
	size_t size;
	va_list ap;

	fp = open_memstream(&buf, &size);
	assert(fp);

	va_start(ap, fmt);
	vfprintf(fp, fmt, ap);
	va_end(ap);

	fclose(fp);

	/* strip trailing newlines */
	s = buf + size;
	while (s > buf && s[-1] == '\n')
		*--s = '\0';

	dt_debug(dt, "dts: %s\n", buf);
	free(buf);
}

static void dts_loc_to_yaml_mark(const struct dts_location *loc, struct dt_yaml_mark *m)
{
	m->start.index = loc->start_index;
	m->start.line = loc->start_line;
	m->start.column = loc->start_col - 1;
	m->end.index = loc->end_index;
	m->end.line = loc->end_line;
	m->end.column = loc->end_col;
}

static void dt_dts_message(struct dts_state *ds, enum dts_message_type type,
		const struct dts_location *loc, const char *fmt, ...)
{
	struct yaml_dt_state *dt = dts_to_dt(ds);
	struct dt_yaml_mark m;
	FILE *fp;
	char *buf, *s;
	size_t size;
	va_list ap;

	fp = open_memstream(&buf, &size);
	assert(fp);

	va_start(ap, fmt);
	vfprintf(fp, fmt, ap);
	va_end(ap);

	fclose(fp);

	/* strip trailing newlines */
	s = buf + size;
	while (s > buf && s[-1] == '\n')
		*--s = '\0';

	memset(&m, 0, sizeof(m));

	if (loc)
		dts_loc_to_yaml_mark(loc, &m);

	switch (type) {
	case dmt_info:
		dt_info(dt, "dts: %s\n", buf);
		break;
	case dmt_warning:
		dt_warning_at(dt, loc ? &m : NULL, "dts: %s\n", buf);
		break;
	case dmt_error:
		dt_error_at(dt, loc ? &m : NULL, "dts: %s\n", buf);
		break;
	}
	free(buf);
}

static int dt_dts_emit(struct dts_state *ds, int depth,
		enum dts_emit_type type, const struct dts_emit_data *data)
{
	char namebuf[NODE_FULLNAME_MAX];
	struct yaml_dt_state *dt = dts_to_dt(ds);
	struct dt_yaml_mark m;
	struct yaml_dt_input *in;
	struct yaml_dt_span *span;
	bool is_root;
	struct node *np, *npt;
	struct property *prop;
	struct ref *ref;
	struct label *l;
	bool found_existing;
	const char *name, *label;
	char *nname, *strunesc;
	const struct dts_property_item *pi;
	const struct dts_emit_item *ei;
	enum ref_type rt;
	int i, j, k, bits, lenunesc;
	const char *bits_tag, *tag;
	const char *refdata;
	int reflen;
	char bytebuf[4 + 1];	/* 0xFF */

	switch (type) {
	case det_separator:
	case det_comment:
	case det_preproc:
	case det_node_empty:
		/* nothing */
		break;
	case det_del_node:
		name = data->del_node->contents;
		np = dt->current_np;

		switch (data->del_node->atom) {
		case dea_name:

			if (!np)
				dt_fatal(dt, "can't delete node out of node context\n");

			if (!dt->current_np_ref) {
				npt = node_get_child_by_name(to_tree(dt),
							    np, name, 0);
				if (npt) {
					dt_debug(dt, "deleting child %s\n",
						dn_fullname(npt, &namebuf[0], sizeof(namebuf)));
					node_del(to_tree(dt), npt);
				}
			} else {
				prop = prop_alloc(to_tree(dt), name);
				prop->np = np;
				prop->is_delete = true;
				list_add_tail(&prop->node, &np->properties);
			}
			break;
		case dea_ref:
		case dea_pathref:
			if (dt->current_np)
				dt_fatal(dt, "ref/pathref delete in node context\n");

			/* for a ref prefix with '*' */
			if (data->del_node->atom == dea_ref) {
				nname = alloca(strlen(name) + 2);
				nname[0] = '*';
				strcpy(nname + 1, name);
				name = nname;
			};

			np = node_alloc(to_tree(dt), name, NULL);
			np->is_delete = true;

			dts_loc_to_yaml_mark(&data->del_node->loc,
					     &to_dt_node(np)->m);

			list_add_tail(&np->node, tree_ref_nodes(to_tree(dt)));

			dt_debug(dt, "adding delete ref %s\n", name);

			/* if we can apply the ref now, do it */
			if (tree_apply_single_ref_node(to_tree(dt), np,
				dt->cfg.object, dt->cfg.compatible)) {

				list_del(&np->node);
				node_free(to_tree(dt), np);
				np = NULL;
			}

			break;
		default:
			break;
		}
		break;
	case det_del_prop:
		name = data->del_node->contents;
		np = dt->current_np;
		/* only handle delete names */
		if (data->del_node->atom != dea_name)
			break;
		prop = prop_get_by_name(to_tree(dt), np, name, 0);
		if (prop) {
			prop_del(to_tree(dt), prop);
			break;
		}

		if (np && dt->current_np_ref) {
			prop = prop_alloc(to_tree(dt), name);
			prop->is_delete = true;
			prop->np = np;
			list_add_tail(&prop->node, &np->properties);
			break;
		}

		dt_fatal(dt, "failed to delete property %s\n", name);
		break;

	case det_include:
		if (data->include->atom != dea_string) {
			dts_error(ds, "bad include atom\n");
			return -1;
		}

		dt_debug(dt, "include %s\n", data->include->contents);
		assert(dt->curr_in);
		in = dt_input_create(dt, data->include->contents, dt->curr_in);
		if (!in) {
			dts_error_at(ds, &data->include->loc,
				"Unable to open include file \"%s\"\n",
				data->include->contents);
			return -1;
		}
		dt->curr_in = in;

		assert(dt->curr_span);
		span = dt_span_create(dt, in);
		assert(span);

		/* the end of this span is the start of the new one */
		dt->curr_span->m.end = span->m.start;

		dt->curr_span = span;

		break;

	case det_memreserve:

		np = tree_root(to_tree(dt));
		if (!np) {
			/* sigh, create root */
			np = node_alloc(to_tree(dt), "", NULL);

			/* mark as the last map */
			dts_loc_to_yaml_mark(&data->memreserves[0]->loc,
					&to_dt_node(np)->m);
			tree_set_root(to_tree(dt), np);
		}

		prop = prop_alloc(to_tree(dt), "/memreserve/");

		for (i = 0; i < 2; i++) {
			ref = ref_alloc(to_tree(dt), r_scalar,
					data->memreserves[i]->contents,
					strlen(data->memreserves[i]->contents),
					"!int64");
			ref->prop = prop;
			list_add_tail(&ref->node, &prop->refs);

			dts_loc_to_yaml_mark(&data->memreserves[i]->loc,
					     &to_dt_ref(ref)->m);
		}

		prop->np = np;
		list_add_tail(&prop->node, &np->properties);

		break;

	case det_node:
		name = data->pn.name->contents;

		dt_debug(dt, "node name=%s depth=%d\n", name, depth);

		is_root = data->pn.name->atom == dea_name && !strcmp(name, "/");

		dts_loc_to_yaml_mark(&data->pn.name->loc, &m);

		/* reference? */
		if (data->pn.name->atom == dea_ref || data->pn.name->atom == dea_pathref) {
			if (depth != 0)
				dt_fatal(dt, "ref with depth not 0 (%d)\n", depth);
		} else if (data->pn.name->atom != dea_name)
			dt_fatal(dt, "can't process unknown type of node\n");

		/* add one for the implicit root */
		if (!is_root)
			depth++;

		found_existing = false;
		np = dt->current_np;

		if (is_root) {
			np = tree_root(to_tree(dt));
			found_existing = !!np;
		} else if (np) {
			/* note that we match on deleted too */
			for_each_child_of_node_withdel(dt->current_np, np) {
				/* match on same name or root */
				if (!strcmp(name, np->name) ||
					(name[0] == '/' && np->name[0] == '\0')) {
					found_existing = true;
					/* resurrect? */
					if (np->deleted)
						np->deleted = false;
					break;
				}
			}
		}

		if (!found_existing) {

			/* tack on * on ref */
			if (data->pn.name->atom == dea_ref) {
				nname = alloca(strlen(name) + 2);
				nname[0] = '*';
				strcpy(nname + 1, name);
				name = nname;
			} else if (is_root)
				name = "";

			np = node_alloc(to_tree(dt), name, NULL);

			/* mark as the last map */
			to_dt_node(np)->m = m;

			if (data->pn.name->atom == dea_name) {
				if (!is_root) {
					np->parent = dt->current_np;
					list_add_tail(&np->node, &np->parent->children);
				} else
					tree_set_root(to_tree(dt), np);
			} else {
				np->parent = NULL;
				list_add_tail(&np->node, tree_ref_nodes(to_tree(dt)));
			}
		}

		dt_debug(dt, "%s node @%s\n",
				found_existing ? "using existing" : "creating",
				dn_fullname(np, namebuf, sizeof(namebuf)));

		dt->current_np = np;
		dt->depth = depth;

		if (data->pn.name->atom != dea_name)
			dt->current_np_ref = true;

		for (i = 0; i < data->pn.nr_labels; i++) {
			label = data->pn.labels[i]->contents;

			/* check if label is duplicate */
			npt = node_lookup_by_label(to_tree(dt), label, strlen(label));
			if (npt) {
				/* duplicate label on the same node is a NOP */
				if (npt == np)
					continue;
				/* in non-compatible mode we warn */
				if (!dt->cfg.compatible) {
					dt_warning_at(dt, &dt->current_mark,
						"node %s with duplicate label %s; removing\n",
						name, label);
					continue;
				}
				/* in compatible mode we allow it */
			}
			l = label_add_nolink(to_tree(dt), np, label);
			if (!l)
				break;

			/* mark the location of the label */
			dts_loc_to_yaml_mark(&data->pn.labels[i]->loc, &to_dt_label(l)->m);

			/* in compatible mode we add the label at the head */
			if (!dt->cfg.compatible)
				list_add_tail(&l->node, &np->labels);
			else
				list_add(&l->node, &np->labels);
		}
		break;

	case det_node_end:

		np = dt->current_np;
		assert(np);

		if (dt->current_np_ref && depth == 0) {
			dt->current_np_ref = false;

			if (tree_apply_single_ref_node(to_tree(dt), np,
				dt->cfg.object, dt->cfg.compatible)) {

				list_del(&np->node);
				node_free(to_tree(dt), np);
			}
			np = NULL;
		} else
			np = np->parent;

		if (dt->depth >= 1)
			dt->depth--;

		if (np)
			dt_debug(dt, "now at node @%s (depth=%d)\n",
					dn_fullname(np, namebuf, sizeof(namebuf)),
					dt->depth);
		else
			dt_debug(dt, "now outside node context\n");

		dt->current_np = np;
		break;

	case det_property:

		name = data->pn.name->contents;
		dts_loc_to_yaml_mark(&data->pn.name->loc, &m);

		np = dt->current_np;
		if (!np)
			dt_fatal(dt, "property when no node\n");

		found_existing = false;
		for_each_property_of_node_withdel(np, prop) {
			if (!strcmp(prop->name, name)) {
				found_existing = true;
				/* bring it back to life */
				if (prop->deleted) {
					prop->deleted = false;
					prop->is_delete = false;
				}
				break;
			}
		}
		if (!found_existing)
			prop = NULL;

		if (!prop)
			prop = prop_alloc(to_tree(dt), name);
		else
			prop_ref_clear(to_tree(dt), prop);
		assert(prop);

		to_dt_property(prop)->m = m;

		dt_debug(dt, "%s property %s at %s\n",
			found_existing ? "existing" : "new",
			prop->name[0] ? prop->name : "-",
			np ? dn_fullname(np, namebuf, sizeof(namebuf)) : "<NULL>");

		/* single (true) boolean value */
		if (!data->pn.nr_items) {
			ref = ref_alloc(to_tree(dt), r_scalar,
					"true", strlen("true"),
					NULL);
			ref->prop = prop;
			list_add_tail(&ref->node, &prop->refs);

			/* the ref mark is the name of the property */
			to_dt_ref(ref)->m = m;

		} else {

			for (k = 0; k < data->pn.nr_items; k++) {
				pi = data->pn.items[k];
				j = data->pn.items[k]->nr_elems;
				if (j > 0)
					ei = data->pn.items[k]->elems[0];
				else
					ei = NULL;


				bits = 0;
				/* emit bits */
				if (pi->bits)
					bits = atoi(pi->bits->contents);
				else if (ei && ei->atom == dea_byte)
					bits = 8;

				switch (bits) {
				case 8:
					bits_tag = "!int8";
					break;
				case 16:
					bits_tag = "!int16";
					break;
				case 32:
					bits_tag = "!int32";
					break;
				case 64:
					bits_tag = "!int64";
					break;
				default:
					bits_tag = NULL;
					break;
				}

				for (i = 0; i < j; i++) {
					ei = pi->elems[i];

					tag = NULL;
					rt = r_scalar;	/* default is scalar */

					/* default is using the same content */
					refdata = ei->contents;
					reflen = strlen(ei->contents);

					switch (ei->atom) {
					case dea_int:
					case dea_expr:
						tag = bits_tag;
						break;
					case dea_byte:
						tag = "!int8";
						/* tack on hex prefix if it's not there */
						if (reflen <= 2) {
							bytebuf[0] = '0';
							bytebuf[1] = 'x';
							memcpy(bytebuf + 2, refdata, reflen);
							bytebuf[2 + reflen] = '\0';
							refdata = bytebuf;
							reflen = strlen(bytebuf);
						}
						break;
					case dea_char:
						tag = "!char";
						break;
					case dea_string:
						tag = "!str";

						/* if something need to be unescaped do it */
						if (reflen != esc_strlen(refdata)) {
							lenunesc = esc_strlen(refdata);
							strunesc = alloca(lenunesc + 1);
							esc_getstr(refdata, strunesc, lenunesc + 1);
							refdata = strunesc;
							reflen = lenunesc;
						}
						break;
					case dea_stringref:
						tag = "!pathref";
						rt = r_path;
						break;
					case dea_ref:
					case dea_pathref:
						tag = "!anchor";
						rt = r_anchor;
						break;
					default:
						tag = NULL;
						break;
					}

					ref = ref_alloc(to_tree(dt), rt,
							refdata, reflen, tag);
					ref->prop = prop;
					list_add_tail(&ref->node, &prop->refs);

					/* track */
					dts_loc_to_yaml_mark(&ei->loc,
							&to_dt_ref(ref)->m);
				}
			}
		}

		if (!found_existing) {
			prop->np = np;
			list_add_tail(&prop->node, &np->properties);
		}

		break;
	default:
		break;
	}

	return 0;
}

static const struct dts_ops dt_dts_ops = {
	.debugf		= dt_dts_debug,
	.messagef	= dt_dts_message,
	.emit		= dt_dts_emit,
};

static bool dt_tag_exists(struct yaml_dt_state *dt, struct yaml_dt_input *in,
		const char *tag)
{
	const char *s, *start, *ls, *le, *p;
	int taglen = strlen(tag);

	start = in->content;

	/* NOTE content is always terminated by zero */
	/* so this is guaranteed to work */
	s = strstr(start, tag);
	if (!s)
		return false;

	/* okay, now find the line this is on */
	ls = memrchr(start, '\n', s - start);
	if (!ls)
		ls = start;
	else
		ls++;

	le = strchr(s, '\n');
	if (!le)
		le = start + in->size;

	p = ls;
	while (isspace(*p))
		p++;

	return (le - p >= taglen) && !memcmp(p, tag, taglen);
}

static bool dt_yaml_parse_dts(struct yaml_dt_state *dt, struct yaml_dt_input *in)
{
	struct yaml_dt_config *cfg = &dt->cfg;

	if (!strcmp(cfg->input_format, "yaml"))
		return false;

	if (!strcmp(cfg->input_format, "dts"))
		in->dts = true;
	else
		in->dts = dt_tag_exists(dt, in, "/dts-v1/");

	if (!in->dts)
		return false;

	/* turn on object mode if plugin tag exists */
	if (!cfg->object && dt_tag_exists(dt, in, "/plugin/"))
		cfg->object = true;

	return true;
}

static int dt_yaml_read_handler(void *data, unsigned char *buffer, size_t size, size_t *size_read)
{
	struct yaml_dt_state *dt = data;
	struct yaml_dt_config *cfg = &dt->cfg;
	struct yaml_dt_input *in;
	struct yaml_dt_span *span;
	const char *name;
	size_t nread, nlines;
	const char *s, *e, *le, *ss;
	bool addnl = false;

	if (size <= 0)
		return 0;

	in = dt->curr_in;
	span = dt->curr_span;
	if (in && in->pos >= in->size) {
		dt_debug(dt, "EOF at %s\n", in->name);
		dt->curr_input_file++;
		in = NULL;
		span = NULL;
	}

	/* have to read a file (that's not empty) */
	while (!in || !in->size || in->dts) {
		if (in && !in->size)
			dt->curr_input_file++;

		if (dt->curr_input_file >= cfg->input_file_count) {
			dt_debug(dt, "End of input\n");
			*size_read = 0;
			return 1;
		}
		name = cfg->input_file[dt->curr_input_file];
		dt_debug(dt, "reading %s\n", name);
		in = dt_input_create(dt, name, NULL);
		if (!in) {
			dt_info(dt, "Unable to read input file %s\n", name);
			return 0;
		}
		dt->curr_in = in;

		span = dt_span_create(dt, in);
		assert(span);

		dt->curr_span = span;

		/* TODO clean this up with input detection */
		if (dt_yaml_parse_dts(dt, in))
			dt->curr_input_file++;
	}

	nread = size;
	if (in->pos + nread > in->size)
		nread = in->size - in->pos;

	/* try to read at a line boundary */
	nlines = 0;
	ss = in->content + in->pos;
	s = ss;
	e = s + nread;
	while (s < e) {
		le = memchr(s, '\n', e - s);
		if (!le) {
			/* if we have at least one line break there */
			if (nlines > 0)
				nread = s - ss;
			else if (in->pos + nread >= in->size)
				addnl = true;
			break;
		}
		nlines++;
		s = le + 1;
	}

	memcpy(buffer, in->content + in->pos, nread);
	in->pos += nread;
	*size_read = nread;

	/* for when there's no newline at EOF */
	if (addnl && nread < size) {
		*(char *)(in->content + in->pos) = '\n';
		in->pos++;
		(*size_read)++;
		nlines++;
	}

	/* keep last */
	dt->last_input_pos = dt->curr_input_pos;
	dt->last_input_line = dt->curr_input_line;

	/* advance */
	dt->curr_input_pos += nread;
	dt->curr_input_line += nlines;

	return 1;
}

int dt_setup(struct yaml_dt_state *dt, struct yaml_dt_config *cfg,
	     struct yaml_dt_emitter *emitter, struct yaml_dt_checker *checker)
{
	int ret;

	memset(dt, 0, sizeof(*dt));
	INIT_LIST_HEAD(&dt->children);

	if (!yaml_parser_initialize(&dt->parser)) {
		fprintf(stderr, "Could not initialize the parser object\n");
		return -1;
	}

	memcpy(&dt->cfg, cfg, sizeof(*cfg));

	INIT_LIST_HEAD(&dt->inputs);
	INIT_LIST_HEAD(&dt->spans);

	/* no output file? if the emitter doesn't need it /dev/null */
	if (!dt->cfg.output_file)
		dt->cfg.output_file = "/dev/null";

	if (strcmp(dt->cfg.output_file, "-")) {
		dt->output = fopen(dt->cfg.output_file, "wb");
		if (!dt->output) {
			fprintf(stderr, "Failed to open %s for output\n",
					dt->cfg.output_file);
			return -1;
		}
	} else
		dt->output = stdout;

	if (dt->cfg.depname && strcmp(dt->cfg.depname, "-")) {
		dt->dep_output = fopen(dt->cfg.depname, "wa");
		if (!dt->dep_output) {
			fprintf(stderr, "Failed to open %s for dependencies\n",
					dt->cfg.depname);
			return -1;
		}
		fprintf(dt->dep_output, "%s:", dt->cfg.output_file);
	} else if (dt->cfg.depname)
		dt->dep_output = stdout;


	yaml_parser_set_encoding(&dt->parser, YAML_UTF8_ENCODING);
	yaml_parser_set_input(&dt->parser, dt_yaml_read_handler, dt);

	tree_init(to_tree(dt), emitter->tops);

	dt->emitter = emitter;

	ret = dt_emitter_setup(dt);
	if (ret) {
		fprintf(stderr, "Failed to setup emitter\n");
		return -1;
	}

	dt->checker = checker;

	ret = dt_checker_setup(dt);
	if (ret) {
		dt_emitter_cleanup(dt);
		fprintf(stderr, "Failed to setup checker\n");
		return -1;
	}

	dt_debug(dt, "Selected emitter: %s\n", emitter->name);
	dt_debug(dt, "Selected checker: %s\n", checker->name);

	return 0;
}

void files_in_dir_with_suffix(const char *name, const char *suffix, char **bufp, char *end)
{
	DIR *dir;
	struct dirent *entry;
	char path[PATH_MAX];
	int slen, len;

	dir = opendir(name);
	if (!dir)
		return;

	slen = strlen(suffix);
	while ((entry = readdir(dir)) != NULL) {

		snprintf(path, sizeof(path), "%s/%s", name,
				entry->d_name);
		len = strlen(path);

		if (entry->d_type != DT_DIR) {
			/* no spaces in filenames */
			if (strchr(entry->d_name, ' '))
				continue;

			/* limit reached */
			if (len < slen ||
				memcmp(path + len - slen, suffix, slen))
				continue;

			if (*bufp + len + 2 > end)
				return;

			memcpy(*bufp, path, len);
			*bufp += len;
			(*bufp)[0] = ' ';
			(*bufp)[1] = '\0';
			*bufp += 1;
		} else {
			if (strcmp(entry->d_name,  ".") == 0 ||
				strcmp(entry->d_name, "..") == 0)
				continue;
			files_in_dir_with_suffix(path, suffix, bufp, end);
		}
	}
	closedir(dir);
}

struct yaml_dt_state *dt_parse_single(struct yaml_dt_state *dt,
		const char *input, const char *output,
		const char *name)
{
	struct yaml_dt_state *sdt;
	struct yaml_dt_config cfg;
	char *argv[2];
	char dirname[PATH_MAX];
	char dirbuf[128 * 1024];	/* 128K limit on filenames */
	char *p;
	int i, err;

	sdt = malloc(sizeof(*sdt));
	assert(sdt);

	memset(&cfg, 0, sizeof(cfg));
	cfg.debug = dt->cfg.debug;
	cfg.color = dt->cfg.color;
	cfg.output_file = output ? output : "/dev/null";
	cfg.quiet = dt->cfg.quiet;
	cfg.input_format = "yaml";	/* by definition here */
	cfg.output_format = "yaml";
	/* we don't copy the other configuration params */

	/* directory mode */
	i = strlen(input);
	if (i > 0 && input[i-1] == '/') {
		strncpy(dirname, input, sizeof(dirname));
		dirname[sizeof(dirname) - 1] = '\0';
		dirname[i - 1] = '\0';
		dirbuf[0] = '\0';
		p = dirbuf;
		files_in_dir_with_suffix(dirname, ".yaml", &p, dirbuf + sizeof(dirbuf));

		if (strlen(dirbuf) == 0) {
			fprintf(stderr, "directory %s contains no yaml files\n",
					dirname);
			return NULL;
		}

		dt->alloc_argv = str_to_argv("", dirbuf);
		assert(dt->alloc_argv);
		cfg.input_file = dt->alloc_argv + 1;
		for (i = 0; dt->alloc_argv[i + 1]; i++)
			;
		cfg.input_file_count = i;

	} else if (!strchr(input, ' ') && !strchr(input, '\n')) {
		argv[0] = (char *)input;
		argv[1] = NULL;
		cfg.input_file = argv;
		cfg.input_file_count = 1;
	} else {
		dt->alloc_argv = str_to_argv("", input);
		assert(dt->alloc_argv);
		cfg.input_file = dt->alloc_argv + 1;
		for (i = 0; dt->alloc_argv[i + 1]; i++)
			;
		cfg.input_file_count = i;
	}

	err = dt_setup(sdt, &cfg, output ? &yaml_emitter : &null_emitter,
			   &null_checker);
	if (err)
		dt_fatal(dt, "Unable to setup single parser for %s -> %s\n",
				input, output ? output : "<NULL>");

	sdt->parent = dt;
	sdt->name = strdup(name);
	assert(sdt->name);
	list_add_tail(&sdt->node, &dt->children);

	err = dt_parse(sdt);
	if (err)
		dt_fatal(sdt, "Failed to parse single %s\n", input);

	err = sdt->error_flag;
	if (err) {
		dt_cleanup(sdt, sdt->error_flag);
		sdt = NULL;
	}

	return sdt;
}

void dt_cleanup(struct yaml_dt_state *dt, bool abnormal)
{
	struct yaml_dt_state *child, *childn;
	struct yaml_dt_input *in, *inn;
	struct yaml_dt_span *span, *spann;
	bool rm_file;

	list_for_each_entry_safe(child, childn, &dt->children, node)
		dt_cleanup(child, abnormal);

	if (dt->dts_initialized) {
		dts_cleanup(&dt->ds);
		dt->dts_initialized = false;
	}

	if (dt->map_key)
		free(dt->map_key);
	if (dt->current_prop)
		prop_free(to_tree(dt), dt->current_prop);

	tree_cleanup(to_tree(dt));

	dt_checker_cleanup(dt);
	dt_emitter_cleanup(dt);

	rm_file = abnormal && dt->output && dt->output != stdout &&
		  strcmp(dt->cfg.output_file, "-") &&
		  strcmp(dt->cfg.output_file, "/dev/null") &&
		  !dt->cfg.force;

	if (dt->current_event)
		yaml_event_delete(dt->current_event);

	list_for_each_entry_safe(span, spann, &dt->spans, node) {
		list_del(&span->node);
		dt_span_free(dt, span);
	}

	list_for_each_entry_safe(in, inn, &dt->inputs, node) {
		list_del(&in->node);
		dt_input_free(dt, in);
	}

	if (dt->output && dt->output != stdout)
		fclose(dt->output);

	if (dt->dep_output && dt->dep_output != stdout) {
		fputc('\n', dt->dep_output);
		fclose(dt->dep_output);
	}

	yaml_parser_delete(&dt->parser);
	fflush(stdout);

	if (dt->input_compiler_tag)
		free(dt->input_compiler_tag);

	if (dt->output_compiler_tag)
		free(dt->output_compiler_tag);

	if (rm_file)
		remove(dt->cfg.output_file);

	if (dt->alloc_argv)
		free(dt->alloc_argv);

	/* children are dynamically allocated so free accordingly */
	if (dt->parent) {
		list_del(&dt->node);
		dt->parent = NULL;
		free(dt->name);
		free(dt);
	}
}

static void finalize_current_property(struct yaml_dt_state *dt)
{
	char namebuf[NODE_FULLNAME_MAX];
	struct node *np, *child, *childn;
	struct property *prop;
	struct ref *ref, *refn;
	int nrefs, nnulls;

	if (!dt)
		return;

	/* if we have a current property finalize it */
	np = dt->current_np;
	prop = dt->current_prop;

	if (!np || !prop)
		return;

	dt->current_prop = NULL;
	dt_debug(dt, "finalizing property %s at %s\n",
			prop->name[0] ? prop->name : "-",
			dn_fullname(np, namebuf, sizeof(namebuf)));

	/* special case for completely empty tree marker */
	if (!strcmp(prop->name, "~")) {
		dt_debug(dt, "Deleting empty tree marker %s at %s\n",
				prop->name[0] ? prop->name : "-",
				dn_fullname(np, namebuf, sizeof(namebuf)));
		prop_free(to_tree(dt), prop);
		prop = NULL;

	} else {

		/* detect whether it's a delete property */
		nrefs = nnulls = 0;
		for_each_ref_of_property_safe(prop, ref, refn) {
			nrefs++;
			if ((!ref->xtag || !strcmp(ref->xtag, "!null")) &&
			((ref->len == 4 && !memcmp(ref->data, "null", 4)) ||
			(ref->len == 1 && *(char *)ref->data == '~')) )
				nnulls++;
		}

		if (nrefs == nnulls)
			prop->is_delete = true;

		if (!dt->current_prop_existed) {

			if (prop->is_delete && !dt->current_np_ref) {

				dt_debug(dt, "deleting property %s at %s\n",
						prop->name,
						dn_fullname(np, namebuf, sizeof(namebuf)));

				for_each_child_of_node_safe(np, child, childn) {
					if (strcmp(child->name, prop->name))
						continue;

					dt_debug(dt, "deleting child %s\n",
						dn_fullname(child, &namebuf[0], sizeof(namebuf)));

					node_del(to_tree(dt), child);
				}

				prop_free(to_tree(dt), prop);

			} else {
				dt_debug(dt, "appending property %s at %s\n",
						prop->name[0] ? prop->name : "-",
						dn_fullname(np, namebuf, sizeof(namebuf)));

				prop->np = np;
				list_add_tail(&prop->node, &np->properties);
			}

		} else {
			if (prop->is_delete) {
				dt_debug(dt, "deleting property %s at %s\n",
						prop->name,
						dn_fullname(np, namebuf, sizeof(namebuf)));

				prop_del(to_tree(dt), prop);

			} else
				dt_debug(dt, "updating property %s at %s\n",
					prop->name[0] ? prop->name : "-",
					dn_fullname(np, namebuf, sizeof(namebuf)));
		}
	}

	dt->current_prop_existed = false;

	if (dt->map_key)
		free(dt->map_key);
	dt->map_key = NULL;
}

static bool detect_and_split_int_array_ref(struct yaml_dt_state *dt, struct ref *ref)
{
	struct ref *refn;
	const char *s, *e, *se;
	int nest;
	unsigned long long val;
	bool is_hex, is_unsigned;
	int ret, i, count;
	const char **items;
	int *sizes;
	struct property *prop;

	/* don't try for too large items */
	if (ref->len > 1024)
		return false;

	s = ref->data;
	e = ref->data + ref->len;

	/* worse case allocation */
	items = alloca(sizeof(*items) * (ref->len + 1));
	sizes = alloca(sizeof(*items) * (ref->len + 1));

	count = 0;
	while (s < e) {
		while (isspace(*s))
			s++;
		if (*s == '(') {
			nest = 0;
			se = s;
			while (*se) {
				if (*se == '(')
					nest++;
				else if (*se == ')') {
					nest--;
					if (nest == 0) {
						se++;
						break;
					}
				}
				se++;
			}
			/* not a valid () expr */
			if (nest)
				return false;
		} else {
			se = s;
			while (*se && !isspace(*se))
				se++;
		}

		ret = parse_int(s, se - s, &val, &is_unsigned, &is_hex);
		if (ret)
			return false;

		items[count] = s;
		sizes[count] = se - s;

		s = se;
		count++;
	}

	if (count <= 1)
		return false;

	prop = ref->prop;

	/* TODO adjust position markers */
	for (i = 0; i < count; i++) {
		refn = ref_alloc(to_tree(dt), r_scalar, items[i], sizes[i], NULL);
		refn->prop = prop;
		list_add_tail(&refn->node, &prop->refs);
	}

	dt_debug(dt, "array used as scalar converted to scalar seq\n");

	ref_free(to_tree(dt), ref);

	return true;
}

static void append_to_current_property(struct yaml_dt_state *dt,
		yaml_event_t *event)
{
	struct node *np;
	struct property *prop;
	struct ref *ref;
	yaml_event_type_t type;
	char *tag, *xtag;
	char *p;
	int len;
	enum ref_type rt;
	const char *ref_label;
	int ref_label_len;
	char namebuf[NODE_FULLNAME_MAX];
	char *refname;
	int refnamelen;

	if (!dt || !event)
		return;
	type = event->type;

	np = dt->current_np;
	prop = dt->current_prop;

	assert(np);
	assert(prop);

	rt = -1;
	ref_label = NULL;
	ref_label_len = 0;
	xtag = NULL;
	tag = NULL;

	if (type == YAML_ALIAS_EVENT) {
		rt = r_anchor;
		ref_label = (char *)event->data.alias.anchor;
		ref_label_len = strlen(ref_label);

		xtag = "!anchor";
		tag = xtag;

	} else if (type == YAML_SCALAR_EVENT) {
		switch (event->data.scalar.style) {
		case YAML_PLAIN_SCALAR_STYLE:
			p = (char *)event->data.scalar.value;
			len = event->data.scalar.length;

			ref_label = p;
			ref_label_len = len;

			/* try to find implicitly a type */
			tag = (char *)event->data.scalar.tag;

			/* if no tag and we're on a tagged sequence */
			if (!tag && dt->prop_seq_depth > 0 &&
					dt->prop_seq_tag[dt->prop_seq_depth - 1])
				tag = dt->prop_seq_tag[dt->prop_seq_depth - 1];
			xtag = tag;

			/* everything scalar but pathref */
			rt = r_scalar;	/* default scalar */
			if (tag && !strcmp(tag, "!pathref"))
				rt = r_path;
			else if (tag && !strcmp(tag, "!anchor"))
				rt = r_anchor;

			break;
		case YAML_SINGLE_QUOTED_SCALAR_STYLE:
		case YAML_DOUBLE_QUOTED_SCALAR_STYLE:
		case YAML_LITERAL_SCALAR_STYLE:
		case YAML_FOLDED_SCALAR_STYLE:

			ref_label = (char *)event->data.scalar.value;
			ref_label_len = event->data.scalar.length;

			/* try to find implicitly a type */
			tag = (char *)event->data.scalar.tag;

			/* try to figure out if it's a single char */
			if (!tag && event->data.scalar.style == YAML_SINGLE_QUOTED_SCALAR_STYLE) {
				if (esc_strlen(ref_label) == 1)
					tag = "!char";
				else
					dt_warning_at(dt, &dt->current_mark,
						"single quoted string used as string\n");
			}

			xtag = tag ? tag : "!str";
			rt = r_scalar;

			break;
		case YAML_ANY_SCALAR_STYLE:
			dt_fatal(dt, "ANY_SCALAR not allowed\n");
		}
	} else
		dt_fatal(dt, "Illegal type to append\n");

	/* ref_label_len can be zero for an empty string */
	if (!ref_label || ref_label_len < 0)
		return;

	ref = ref_alloc(to_tree(dt), rt, ref_label,
			ref_label_len, xtag);

	/* 60 bytes for a display purposes should be enough */
	refnamelen = ref->len > 60 ? 60 : ref->len;
	refname = alloca(refnamelen + 1);
	memcpy(refname, ref->data, refnamelen);
	refname[refnamelen] = '\0';

	dt_debug(dt, "new ref \"%s%s\" @%s%s%s\n",
		refname, ref->len > refnamelen ? "..." : "",
		dn_fullname(np, namebuf, sizeof(namebuf)),
		np != tree_root(to_tree(dt)) ? "/" : "",
		prop->name[0] ? prop->name : "-");

	/* add the reference to the list */
	ref->prop = prop;
	list_add_tail(&ref->node, &prop->refs);

	if (event->data.scalar.style == YAML_PLAIN_SCALAR_STYLE &&
	    rt == r_scalar && !xtag)
		detect_and_split_int_array_ref(dt, ref);
}

static struct property *
property_prepare(struct yaml_dt_state *dt, yaml_event_t *event,
		 struct property *prop)
{
	struct dt_property *dt_prop;
	const char *name;

	if (!prop) {
		name = dt->map_key;
		if (!name)
			name = "";
		prop = prop_alloc(to_tree(dt), name);
	} else
		prop_ref_clear(to_tree(dt), prop);
	assert(prop);

	dt_debug(dt, "property prepared with name %s\n",
			prop->name[0] ? prop->name : "-");

	dt_prop = to_dt_property(prop);

	dt_prop->m = dt->current_mark;

	return prop;
}

static void process_yaml_event(struct yaml_dt_state *dt, yaml_event_t *event)
{
	yaml_event_type_t type = event->type;
	struct yaml_dt_span *span = dt->curr_span;
	struct node *np;
	struct property *prop;
	bool found_existing;
	char *label;
	struct label *l;
	char namebuf[NODE_FULLNAME_MAX];
	int len;
	const char *s;

	assert(!dt->current_event);
	dt->current_event = event;

	dt->current_mark.start = event->start_mark;
	dt->current_mark.end = event->end_mark;

	if (span && !span->in->dts) {
		span->m.end = event->end_mark;
		span->end_pos = span->start_pos +
				(span->m.end.index - span->m.start.index);
	}

	switch (type) {
	case YAML_NO_EVENT:
		break;
	case YAML_STREAM_START_EVENT:
		dt_debug(dt, "StSE\n");
		dt_stream_start(dt);
		break;
	case YAML_STREAM_END_EVENT:
		dt_debug(dt, "StEV\n");
		dt_stream_end(dt);
		break;
	case YAML_DOCUMENT_START_EVENT:
		dt_debug(dt, "DSE\n");
		dt_document_start(dt);
		break;
	case YAML_DOCUMENT_END_EVENT:
		dt_debug(dt, "DEE\n");
		dt_document_end(dt);
		break;

	case YAML_MAPPING_START_EVENT:
		dt_debug(dt, "MSE\n");

		/* if we have a current property finalize it */
		finalize_current_property(dt);

		label = (char *)event->data.mapping_start.anchor;

		/* creating root */
		if (!dt->map_key && dt->depth == 0) {

			np = tree_root(to_tree(dt));

			if (!np) {
				np = node_alloc(to_tree(dt), "", NULL);
				dt->current_np = np;
				tree_set_root(to_tree(dt), np);
			}

			dt->current_np = np;

			dt_debug(dt, "* creating root at depth %d\n",
				dt->depth);

			dt->depth++;
			break;
		}

		if (!dt->map_key) {
			dt_fatal(dt, "MAPPING start event, but without a previous VAL\n");
			break;
		}

		found_existing = false;
		if (dt->current_np) {
			/* note that we match on deleted too */
			for_each_child_of_node_withdel(dt->current_np, np) {
				/* match on same name or root */
				if (!strcmp(dt->map_key, np->name) ||
					(dt->map_key == '\0' && np->name[0] == '\0')) {
					found_existing = true;
					/* resurrect? */
					if (np->deleted)
						np->deleted = false;
					break;
				}
			}
		}

		if (found_existing) {
			if (label) {
				l = label_add_nolink(to_tree(dt), np, label);
				if (l) {
					/* in non compatible mode always insert to tail */
					/* in compatible mode; if the node is completely empty */
					if (!dt->cfg.compatible ||
						(list_empty(&np->children) &&
						 list_empty(&np->properties)))
						list_add_tail(&l->node, &np->labels);
					else
						list_add(&l->node, &np->labels);
				}
			}

			dt_debug(dt, "using existing node @%s%s%s\n",
					dn_fullname(np, namebuf, sizeof(namebuf)),
					label ? " label=" : "",
					label ? label : "");
		} else {
			if (label) {
				np = node_lookup_by_label(to_tree(dt), label,
						strlen(label));
				if (np) {
					/* in compatible mode we allow it */
					if (!dt->cfg.compatible) {
						dt_warning_at(dt, &dt->current_mark,
							"node %s with duplicate label %s; removing\n",
							dt->map_key, label);
						label = NULL;
						np = NULL;
					}
				}
			}

			np = node_alloc(to_tree(dt), dt->map_key, label);

			/* mark as the last map */
			to_dt_node(np)->m = dt->last_map_mark;

			dt_debug(dt, "creating node @%s%s%s\n",
					dn_fullname(np, namebuf, sizeof(namebuf)),
					label ? " label=" : "",
					label ? label : "");

		}

		free(dt->map_key);
		dt->map_key = NULL;

		if (dt->depth > 1 || !dt->current_np_ref) {
			dt_debug(dt, "normal node\n");
			if (!found_existing) {
				np->parent = dt->current_np;
				list_add_tail(&np->node, &np->parent->children);
			}
		} else {
			dt_debug(dt, "ref node\n");

			/* mark as the last map */
			to_dt_node(np)->m = dt->last_alias_mark;

			list_add_tail(&np->node, tree_ref_nodes(to_tree(dt)));
		}
		dt->current_np = np;

		dt_debug(dt, "* creating %s at depth %d\n",
			dn_fullname(np, namebuf, sizeof(namebuf)),
			dt->depth);

		dt->depth++;

		break;

	case YAML_MAPPING_END_EVENT:
		dt_debug(dt, "MEE\n");

		if (dt->depth == 0)
			dt_fatal(dt, "illegal MAPPING end event at depth 0\n");
		assert(dt->current_np);

		finalize_current_property(dt);

		if (dt->map_key)
			free(dt->map_key);
		dt->map_key = NULL;

		np = dt->current_np;

		dt_debug(dt, "* finished with %s at depth %d\n",
				dn_fullname(np, namebuf, sizeof(namebuf)),
				dt->depth - 1);

		dt->depth--;
		dt->current_np = np->parent;

		if (dt->current_np == NULL && dt->current_np_ref) {
			dt_debug(dt, "* out of ref context\n");

			/* if we can apply the ref now, do it */
			if (tree_apply_single_ref_node(to_tree(dt), np,
				dt->cfg.object, dt->cfg.compatible)) {

				list_del(&np->node);
				node_free(to_tree(dt), np);
				np = NULL;
			}

			dt->current_np = tree_root(to_tree(dt));
			dt->current_np_ref = false;
		}

		break;

	case YAML_SEQUENCE_START_EVENT:
		dt_debug(dt, "SSE\n");

		np = dt->current_np;

		prop = dt->current_prop;
		if (!prop && !dt->map_key) {
			dt->bare_seq++;
			dt_debug(dt, "No prop, no map key, bare_seq=%d\n",
					dt->bare_seq);

			if (!np) {
				np = node_alloc(to_tree(dt), "", NULL);
				dt->current_np = np;
				tree_set_root(to_tree(dt), np);
			}

			break;
		}

		if (!prop) {

			len = strlen(dt->map_key);
			if (dt->map_key &&
			    ((dt->map_key[0] == '/' && dt->map_key[len - 1] != '/') ||
				dt->map_key[0] == '*'))
				dt_fatal(dt, "Illegal sequence context\n");

			found_existing = false;
			assert(np);
			if (strcmp(dt->map_key, "/memreserve/")) {
				for_each_property_of_node_withdel(np, prop) {
					if (!strcmp(prop->name, dt->map_key)) {
						found_existing = true;
						/* bring it back to life */
						if (prop->deleted) {
							prop->deleted = false;
							prop->is_delete = false;
						}
						break;
					}
				}
			}
			if (!found_existing)
				prop = NULL;

			prop = property_prepare(dt, event, prop);

			dt_debug(dt, "%s property %s at %s [SEQ]\n",
				found_existing ? "existing" : "new",
				prop->name[0] ? prop->name : "-",
				np ? dn_fullname(np, namebuf, sizeof(namebuf)) : "<NULL>");

			dt->current_prop = prop;
			dt->current_prop_existed = found_existing;
		}
		dt_debug(dt, "sequence to prop '%s' (depth %d)%s%s\n",
			 prop->name[0] ? prop->name : "-",
			 dt->prop_seq_depth,
			 event->data.sequence_start.tag ? " tag=" : "",
			 event->data.sequence_start.tag ? (char *)event->data.sequence_start.tag : "");

		assert(dt->prop_seq_depth + 1 <= ARRAY_SIZE(dt->prop_seq_tag));

		/* free tag */
		if (event->data.sequence_start.tag) {
			dt->prop_seq_tag[dt->prop_seq_depth] = strdup((char *)event->data.sequence_start.tag);
			assert(dt->prop_seq_tag[dt->prop_seq_depth]);
		} else
			dt->prop_seq_tag[dt->prop_seq_depth] = NULL;

		dt->prop_seq_depth++;
		break;

	case YAML_SEQUENCE_END_EVENT:
		dt_debug(dt, "SEE\n");

		if (dt->bare_seq) {
			dt->bare_seq--;
			dt_debug(dt, "bare_seq=%d\n", dt->bare_seq);
			break;
		}

		assert(dt->prop_seq_depth > 0);
		assert(dt->current_prop);
		assert(dt->current_np);

		/* free tag */
		dt->prop_seq_depth--;

		if (dt->prop_seq_tag[dt->prop_seq_depth]) {
			free(dt->prop_seq_tag[dt->prop_seq_depth]);
			dt->prop_seq_tag[dt->prop_seq_depth] = NULL;
		}

		if (dt->prop_seq_depth == 0)
			finalize_current_property(dt);

		dt->bare_seq = false;

		break;

	case YAML_SCALAR_EVENT:
		dt_debug(dt, "SE\n");
		np = dt->current_np;
		prop = dt->current_prop;

		s = (char *)event->data.scalar.value;
		len = event->data.scalar.length;

		if (!dt->map_key && !dt->bare_seq) {
			if (!np) {
				/* in case of a corrupt file, make sure the output is sane */
				if (len > 40)
					len = 40;
				if (len > sizeof(namebuf) - 1)
					len = sizeof(namebuf) - 1;

				memcpy(namebuf, s, len);
				namebuf[len] = '\0';
				dt_fatal(dt, "Unexpected scalar %s (is this a YAML input file?)\n",
						namebuf);
			}

			/* TODO check event->data.scalar.style */

			dt->map_key = malloc(len + 1);
			assert(dt->map_key);
			memcpy(dt->map_key, s, len);
			dt->map_key[len] = '\0';

			/*
			 * due to the weird /memreserve/ stuff, there must not be
			 * a terminating /
			 */
			if (len > 1 && s[0] == '/' && s[len-1] != '/' ) {
				/* path reference key (path alias) */

				if (dt->depth != 1)
					dt_fatal(dt, "Bare references not allowed on non root level\n");
				if (dt->current_np_ref)
					dt_fatal(dt, "Can't do more than one level of ref\n");
				dt->current_np_ref = true;

				dt->last_alias_mark = dt->current_mark;

				dt_debug(dt, "next up is a ref to %s\n", dt->map_key);
			} else {
				/* normal map key */
				dt->last_map_mark = dt->current_mark;
			}

		} else {

			len = strlen(dt->map_key);
			if ((dt->map_key[0] == '/' && dt->map_key[len - 1] != '/') ||
			     dt->map_key[0] == '*') {
				if (dt->depth != 1)
					dt_fatal(dt, "Bare references not allowed on non root level\n");
				if (!dt->current_np_ref)
					dt_fatal(dt, "ref in scalar context\n");

				if (strcmp(s, "null") && strcmp(s, "~"))
					dt_fatal(dt, "only null values allowed\n");

				/* the only valid content is NULL */
				np = node_alloc(to_tree(dt), dt->map_key, NULL);
				np->is_delete = true;

				/* mark as the last alias */
				to_dt_node(np)->m = dt->last_alias_mark;

				list_add_tail(&np->node, tree_ref_nodes(to_tree(dt)));

				dt_debug(dt, "adding delete ref %s\n", dt->map_key);

				if (dt->map_key)
					free(dt->map_key);
				dt->map_key = NULL;

				/* if we can apply the ref now, do it */
				if (tree_apply_single_ref_node(to_tree(dt), np,
					dt->cfg.object, dt->cfg.compatible)) {

					list_del(&np->node);
					node_free(to_tree(dt), np);
					np = NULL;
				}

				dt_debug(dt, "* out of ref context\n");
				dt->current_np = tree_root(to_tree(dt));
				dt->current_np_ref = false;

				break;
			}

			if (!prop) {
				found_existing = false;
				/* memreserve is special; allow it to be present many times */
				if (dt->map_key && strcmp(dt->map_key, "/memreserve/")) {
					assert(np);
					for_each_property_of_node_withdel(np, prop) {
						if (!strcmp(prop->name, dt->map_key)) {
							found_existing = true;
							/* bring it back to life */
							if (prop->deleted) {
								prop->deleted = false;
								prop->is_delete = false;
							}
							break;
						}
					}
				}
				if (!found_existing)
					prop = NULL;
				prop = property_prepare(dt, event, prop);

				dt_debug(dt, "%s property %s at %s\n",
					found_existing ? "existing" : "new",
					prop->name[0] ? prop->name : "-",
					np ? dn_fullname(np, namebuf, sizeof(namebuf)) : "<NULL>");
				dt->current_prop = prop;
				dt->current_prop_existed = found_existing;
			}
			append_to_current_property(dt, event);

			if (dt->prop_seq_depth == 0)
				finalize_current_property(dt);
		}
		break;
	case YAML_ALIAS_EVENT:

		np = dt->current_np;
		assert(np);

		if (!dt->map_key) {
			if (dt->depth != 1)
				dt_fatal(dt, "Bare references not allowed on non root level\n");
			if (dt->current_np_ref)
				dt_fatal(dt, "Can't do more than one level of ref\n");
			dt->map_key = malloc(strlen((char *)event->data.alias.anchor) + 2);
			assert(dt->map_key);
			dt->map_key[0] = '*';
			strcpy(dt->map_key + 1, (char *)event->data.alias.anchor);
			dt->current_np_ref = true;

			dt->last_alias_mark = dt->current_mark;

			dt_debug(dt, "next up is a ref to %s\n", dt->map_key);

			break;
		}

		prop = dt->current_prop;

		if (!prop) {
			found_existing = false;
			if (dt->map_key) {
				for_each_property_of_node_withdel(np, prop) {
					if (!strcmp(prop->name, dt->map_key)) {
						found_existing = true;
						/* bring it back to life */
						if (prop->deleted) {
							prop->deleted = false;
							prop->is_delete = false;
						}
						break;
					}
				}
			}
			if (!found_existing)
				prop = NULL;
			prop = property_prepare(dt, event, prop);

			dt_debug(dt, "%s property %s at %s\n",
				found_existing ? "existing" : "new",
				prop->name[0] ? prop->name : "-",
				dn_fullname(np, namebuf, sizeof(namebuf)));
			dt->current_prop = prop;
			dt->current_prop_existed = found_existing;
		}
		append_to_current_property(dt, event);

		if (dt->prop_seq_depth == 0)
			finalize_current_property(dt);
		break;
	default:
		dt_fatal(dt, "unkonwn YAML type not allowed\n");
	}

	dt->current_event = NULL;
}

int dt_parse_yaml(struct yaml_dt_state *dt, yaml_token_type_t *token_type)
{
	struct yaml_dt_span *span = dt->curr_span;
	yaml_event_t event;
	struct dt_yaml_mark m;

	if (!yaml_parser_parse(&dt->parser, &event)) {
		m.start = m.end = dt->parser.problem_mark;
		span->m.end = m.end;
		span->end_pos = span->start_pos +
				(span->m.end.index - span->m.start.index);
		dt_error_at(dt, &m, "%s\n", dt->parser.problem);
		return -1;
	}

	process_yaml_event(dt, &event);

	*token_type = event.type;

	yaml_event_delete(&event);

	return 0;
}

int dt_parse_dts(struct yaml_dt_state *dt)
{
	struct yaml_dt_input *in = dt->curr_in;
	struct yaml_dt_span *span = dt->curr_span;
	int err, c;

	if (!in || !span || !in->dts)
		return 0;

	if (!dt->dts_initialized) {
		err = dts_setup(&dt->ds, in->name, 8, &dt_dts_ops);
		if (err)
			dt_fatal(dt, "Unable to setup DTS parser\n");
		dt->dts_initialized = true;
	}

	err = 0;
	while (!err && in->pos < in->size) {

		c = *((char *)in->content + in->pos);

		dt->curr_span_mark.start = span->m.end;
		/* mark the end of the span */
		span->m.end.index++;
		if (c == '\n') {
			span->m.end.line++;
			span->m.end.column = 0;
		} else
			span->m.end.column++;
		span->end_pos = span->start_pos + in->pos + 1;
		dt->curr_span_mark.end = span->m.end;

		err = dts_feed(&dt->ds, c);

		/* if no error, advance */
		if (!err) {
			in->pos++;
			dt->curr_input_pos++;
			if (c == '\n') {
				dt->curr_input_line++;
				dt->curr_input_column = 0;
			} else
				dt->curr_input_column++;
		}

		in = dt->curr_in;
		span = dt->curr_span;

		/* pop (creating spans on the way out) */
		while (in->pos >= in->size && in->parent) {
			in = in->parent;
			span = dt_span_create(dt, in);
			assert(span);
		}

		dt->curr_in = in;
		dt->curr_span = span;

	}

	if (!err)
		dts_feed(&dt->ds, EOF);

	return err;
}

int dt_parse(struct yaml_dt_state *dt)
{
	yaml_token_type_t token_type;
	int err;

	/* we must start with stream start */
	err = dt_parse_yaml(dt, &token_type);
	if (err || token_type != YAML_STREAM_START_TOKEN)
		dt_fatal(dt, "YAML parser not starting with stream start\n");

	do {
		dt_parse_dts(dt);

		err = dt_parse_yaml(dt, &token_type);
		if (err == 0 && token_type == YAML_STREAM_END_TOKEN)
			break;
	} while (err == 0);

	return dt->error_flag ? -1 : 0;
}

static void get_error_location(struct yaml_dt_state *dt,
			size_t idx,
		        char *filebuf, size_t filebufsize,
			char *linebuf, size_t linebufsize,
			size_t *linep)
{
	const struct yaml_dt_input *in;
	const struct yaml_dt_span *span;
	bool found;
	char *s, *ls, *le, *start, *end, *p, *pe;
	char *filep;
	int i, lines, lastline, filepsz, sz;
	char c;

	*filebuf = '\0';
	*linebuf = '\0';
	*linep = 0;

	/*
	fprintf(stderr, "looking for %zu at spans\n", idx);
	list_for_each_entry(span, &dt->spans, node) {
		fprintf(stderr, "%zu-%zu: %s %zu-%zu\n",
				span->m.start.index, span->m.end.index,
				span->in->name,
				span->start_pos, span->end_pos);
	}
	fprintf(stderr, "\n");
	*/

	/* first iterate over the regular input files */
	span = NULL;
	found = false;
	list_for_each_entry(span, &dt->spans, node) {
		if (idx >= span->m.start.index && idx < span->m.end.index) {
			found = true;
			break;
		}
	}

	/* not found? */
	if (!found) {
		fprintf(stderr, "Could not find corresponding span idx=%zu\n", idx);
		return;
	}
	in = span->in;

	start = in->content;
	end = start + in->size;

	s = start + span->start_pos + (idx - span->m.start.index);
	assert(s < end);

	/* get full line of the first marker */
	ls = memrchr(start, '\n', s - start);
	if (!ls)
		ls = start;
	else
		ls++;
	le = memchr(s, '\n', end - s);
	if (!le)
		le = end;

	sz = le - ls;
	if (sz > linebufsize - 1)
		sz = linebufsize  - 1;
	for (i = 0; i < sz; i++) {
		c = ls[i];
		if (isspace(c))
			c = ' ';
		linebuf[i] = c;
	}
	linebuf[sz] = '\0';

	/* work back, until we find a file marker or end */
	lines = 0;
	s = ls;
	filep = in->name;
	filepsz = strlen(in->name);
	if (s > start && s[-1] == '\n')
		s--;
	while (s > start) {
		ls = memrchr(start, '\n', s - start);
		if (!ls) {
			ls = start;
			p = ls;
		} else
			p = ls + 1;

		if (p[0] == '#' && isspace(p[1])) {
			p += 2;
			while (isspace(*p))
				p++;
			lastline = strtol(p, &pe, 10) - 1;
			if (pe > p && isspace(*pe)) {
				while (isspace(*pe))
					pe++;
				p = pe + 1;
				pe = strchr(p, '"');
				if (pe) {
					filep = p;
					filepsz = pe - p;
					lines += lastline;
					break;
				}
			}
		}

		s = ls;
		lines++;
	}
	sz = filepsz;
	if (sz > filebufsize - 1)
		sz = filebufsize - 1;
	memcpy(filebuf, filep, sz);
	filebuf[sz] = '\0';

	*linep = lines + 1;
}

void dt_fatal(struct yaml_dt_state *dt, const char *fmt, ...)
{
	va_list ap;
	char str[1024];
	int len;
	char linebuf[1024];
	char filebuf[PATH_MAX + 1];
	size_t line, column, end_line, end_column;
	const char *emph = "", *kind = "", *marker = "", *reset = "";

	if ((dt->cfg.color == -1 && isatty(STDERR_FILENO)) ||
	     dt->cfg.color == 1) {
		emph = WHITE;
		kind = RED;
		marker = GREEN;
		reset = RESET;
	}

	va_start(ap, fmt);
	vsnprintf(str, sizeof(str) - 1, fmt, ap);
	va_end(ap);
	str[sizeof(str) - 1] = '\0';

	len = strlen(str);
	while (len > 1 && str[len - 1] == '\n')
		str[--len] = '\0';

	if (!dt->stream_ended) {
		line = dt->current_mark.start.line;
		column = dt->current_mark.start.column;
		end_line = dt->current_mark.end.line;
		end_column = dt->current_mark.end.column;

		if (end_line != line)
			end_column = strlen(linebuf) + 1;

		get_error_location(dt, dt->current_mark.start.index,
				filebuf, sizeof(filebuf),
				linebuf, sizeof(linebuf),
				&line);

		fprintf(stderr, "%s%s:%zd:%zd: %s%s%s\n %s\n %*s%s^%s",
				emph, filebuf, line, column + 1,
				kind, str, reset,
				linebuf,
				(int)column, "", marker, reset);
		if (column > 0 && end_column > 0) {
			while (++column < end_column)
				fprintf(stderr, "~");
		}
		fprintf(stderr, "\n");
	} else
		fprintf(stderr, "%s\n", str);

	dt_stream_end(dt);
	dt_cleanup(dt, true);

	exit(EXIT_FAILURE);
}

static void dt_print_at_msg(struct yaml_dt_state *dt,
			    const struct dt_yaml_mark *m,
			    const char *type, const char *msg)
{
	char linebuf[1024];
	char filebuf[PATH_MAX + 1];
	size_t line, column, end_line, end_column;
	const char *emph = "", *kind = "", *marker = "", *reset = "";

	/* handle quiet */
	if (dt->cfg.quiet >= 3 ||
	    (dt->cfg.quiet >= 2 && !strcmp(type, "error")) ||
	    (dt->cfg.quiet >= 1 && !strcmp(type, "warning")))
		return;

	if ((dt->cfg.color == -1 && isatty(STDERR_FILENO)) || dt->cfg.color == 1) {
		emph = WHITE;
		if (!strcmp(type, "error"))
			kind = RED;
		else if (!strcmp(type, "warning"))
			kind = MAGENTA;
		else
			kind = YELLOW;
		marker = GREEN;
		reset = RESET;
	}

	/* if no mark, use the current one */
	if (!m)
		m = &dt->curr_span_mark;

	line = m->start.line;
	column = m->start.column;
	end_line = m->end.line;
	end_column = m->end.column;

	if (end_line != line)
		end_column = strlen(linebuf) + 1;

	get_error_location(dt, m->start.index,
			filebuf, sizeof(filebuf),
			linebuf, sizeof(linebuf),
			&line);

	fprintf(stderr, "%s%s:%zd:%zd: %s%s:%s %s%s\n %s\n %*s%s^",
			emph, filebuf, line, column + 1,
			kind, type, emph, msg, reset,
			linebuf, (int)column, "", marker);
	while (++column < end_column)
		fprintf(stderr, "~");
	fprintf(stderr, "%s\n", reset);
}

void dt_print_at(struct yaml_dt_state *dt,
		 const struct dt_yaml_mark *m,
		 const char *type, const char *fmt, ...)
{
	va_list ap;
	char str[1024];
	int len;

	va_start(ap, fmt);
	vsnprintf(str, sizeof(str) - 1, fmt, ap);
	va_end(ap);
	str[sizeof(str) - 1] = '\0';

	len = strlen(str);
	while (len > 1 && str[len - 1] == '\n')
		str[--len] = '\0';

	dt_print_at_msg(dt, m, type, str);
}

void dt_warning_at(struct yaml_dt_state *dt,
		   const struct dt_yaml_mark *m,
		   const char *fmt, ...)
{
	va_list ap;
	char str[1024];
	int len;

	va_start(ap, fmt);
	vsnprintf(str, sizeof(str) - 1, fmt, ap);
	va_end(ap);
	str[sizeof(str) - 1] = '\0';

	len = strlen(str);
	while (len > 1 && str[len - 1] == '\n')
		str[--len] = '\0';

	dt_print_at_msg(dt, m, "warning", str);
}

void dt_error_at(struct yaml_dt_state *dt,
		 const struct dt_yaml_mark *m,
		 const char *fmt, ...)
{
	va_list ap;
	char str[1024];
	int len;

	va_start(ap, fmt);
	vsnprintf(str, sizeof(str) - 1, fmt, ap);
	va_end(ap);
	str[sizeof(str) - 1] = '\0';

	len = strlen(str);
	while (len > 1 && str[len - 1] == '\n')
		str[--len] = '\0';

	dt_print_at_msg(dt, m, "error", str);
	dt->error_flag = true;
}

void dt_debug(struct yaml_dt_state *dt, const char *fmt, ...)
{
	va_list ap;

	if (!dt->cfg.debug || dt->cfg.quiet)
		return;

	va_start(ap, fmt);
	vfprintf(stderr, fmt, ap);
	va_end(ap);
}

void dt_info(struct yaml_dt_state *dt, const char *fmt, ...)
{
	va_list ap;

	if (dt->cfg.quiet)
		return;

	va_start(ap, fmt);
	vfprintf(stderr, fmt, ap);
	va_end(ap);
}

void dt_error(struct yaml_dt_state *dt, const char *fmt, ...)
{
	va_list ap;

	if (dt->cfg.quiet >= 2)
		return;

	va_start(ap, fmt);
	vfprintf(stderr, fmt, ap);
	va_end(ap);
}

int dt_resolve_ref(struct yaml_dt_state *dt, struct ref *ref)
{
	struct tree *t = to_tree(dt);
	struct node *np;
	struct property *prop;
	int ret, len;
	unsigned long long val = 0;
	bool is_unsigned;
	bool is_hex;
	bool is_int;
	const char *p;
	const char *xtag = NULL;
	const char *tag = NULL;
	void *bin_output;
	size_t bin_size;

	/* already resolved? */
	if (to_dt_ref(ref)->is_resolved)
		return 0;

	prop = ref->prop;
	assert(prop);

	/* get tag */
	xtag = ref->xtag;
	if (!xtag)
		xtag = ref->xtag_builtin;
	tag = xtag;

	switch (ref->type) {
	case r_anchor:
	case r_path:
		len = ref->len;
		p = ref->data;

		if (len > 0 && *p == '/')
			np = node_lookup_by_path(t, ref->data, ref->len);
		else
			np = node_lookup_by_label(t, ref->data, ref->len);
		if (!np && !dt->cfg.object)
			return -ENOENT;	/* not found */

		to_dt_ref(ref)->tag = ref->type == r_anchor ? "!anchor" :
							      "!pathref";

		/* object mode, just leave references here */
		if (!np)
			break;

		to_dt_ref(ref)->npref = np;
		to_dt_ref(ref)->is_resolved = true;
		break;

	case r_scalar:
		np = prop->np;
		assert(np);

		len = ref->len;
		p = ref->data;

		is_int = false;

		/* either an explict int tag or no tag and reasonable length */
		if ((tag && is_int_tag(tag)) ||
		    (!tag && len > 0 && len < 1024)) {

			ret = parse_int(p, len, &val, &is_unsigned, &is_hex);
			is_int = ret == 0;
		}

		/* TODO type checking/conversion here */
		if (!tag && is_int)
			tag = is_hex || is_unsigned ? "!uint" : "!int";
		else if (!tag && ((len == 4 && !memcmp(p,  "true", 4)) ||
		                  (len == 5 && !memcmp(p, "false", 5)) ))
			tag = "!bool";
		else if (!tag && (len == 0 ||
		                 (len == 4 && !memcmp(p, "null", 4)) ||
				 (len == 1 && *(char *)p == '~')) )
			tag = "!null";
		else if (!tag)
			tag = "!str";

		/* set tag here always */
		to_dt_ref(ref)->tag = tag;

		if (is_int_tag(tag)) {
			if (!is_int)
				return -EINVAL;
			if (!int_val_in_range(tag, val, is_unsigned, is_hex)) {
				if (!uint_val_in_range(tag, val, is_hex))
					return -ERANGE;
				dt_warning_at(dt, &to_dt_ref(ref)->m,
					"treating as unsigned\n");
			}

			to_dt_ref(ref)->is_int = true;
			to_dt_ref(ref)->is_hex = is_hex;
			to_dt_ref(ref)->is_unsigned = is_unsigned;
			to_dt_ref(ref)->val = val;
			to_dt_ref(ref)->is_builtin_tag = true;

		} else if (!strcmp(tag, "!str")) {
			to_dt_ref(ref)->is_str = true;
			to_dt_ref(ref)->is_builtin_tag = true;
		} else if (!strcmp(tag, "!bool")) {

			if (!((len == 4 && !memcmp(p,  "true", 4)) ||
			      (len == 5 && !memcmp(p, "false", 5))) )
				return -EINVAL;

			to_dt_ref(ref)->is_bool = true;
			to_dt_ref(ref)->val = (len == 4 && !memcmp(p,  "true", 4));
			to_dt_ref(ref)->is_builtin_tag = true;
		} else if (!strcmp(tag, "!null")) {
			to_dt_ref(ref)->is_null = true;
			to_dt_ref(ref)->is_builtin_tag = true;
		} else if (!strcmp(tag, "!char")) {
			val = esc_getc(&p);
			if ((int)val < 0 || val > INT32_MAX)
				return -EINVAL;
			to_dt_ref(ref)->val = val;
			to_dt_ref(ref)->is_builtin_tag = true;
		} else if (!strcmp(tag, "!base64")) {
			bin_output = base64_decode((const void *)p, len, &bin_size);
			if (!bin_output)
				return -EINVAL;

			to_dt_ref(ref)->binary = bin_output;
			to_dt_ref(ref)->binary_size = bin_size;
		} else
			to_dt_ref(ref)->is_builtin_tag = false;
		to_dt_ref(ref)->is_resolved = true;
		break;

	default:
		/* nothing */
		break;
	}

	return 0;
}

struct node *dt_get_node(struct yaml_dt_state *dt,
			    struct node *parent, const char *name,
			    int index)
{
	char namebuf[NODE_FULLNAME_MAX];
	struct node *np;

	if (!dt || !parent || !name)
		return NULL;

	np = node_get_child_by_name(to_tree(dt), parent, name, index);
	if (!np && dt->error_on_failed_get)
		dt_error_at(dt, &to_dt_node(parent)->m,
				"Unable to find child node %s#%d of %s\n",
				name, index,
				dn_fullname(parent, namebuf, sizeof(namebuf)));

	return np;
}

struct property *dt_get_property(struct yaml_dt_state *dt,
			    struct node *np, const char *name,
			    int index)
{
	char namebuf[NODE_FULLNAME_MAX];
	struct property *prop;

	if (!dt || !np || !name)
		return NULL;

	prop = prop_get_by_name(to_tree(dt), np, name, index);

	if (!prop && dt->error_on_failed_get)
		dt_error_at(dt, &to_dt_node(np)->m,
				"Unable to find property %s#%d of %s\n",
				name, index,
				dn_fullname(np, namebuf, sizeof(namebuf)));
	return prop;
}

struct ref *dt_get_ref(struct yaml_dt_state *dt,
		struct property *prop, int index)
{
	char namebuf[NODE_FULLNAME_MAX];
	struct ref *ref;

	if (!dt || !prop)
		return NULL;

	ref = ref_get_by_index(to_tree(dt), prop, index);

	if (!ref && dt->error_on_failed_get)
		dt_error_at(dt, &to_dt_property(prop)->m,
				"Unable to find ref #%d of prop %s of %s\n",
				index, prop->name,
				dn_fullname(prop->np, namebuf, sizeof(namebuf)));
	return ref;
}

int dt_get_rcount(struct yaml_dt_state *dt, struct node *np,
		  const char *name, int pindex)
{
	struct property *prop;
	int rindex;

	if (!dt || !np || !name)
		return 0;

	prop = dt_get_property(dt, np, name, pindex);
	if (!prop)
		return 0;
	rindex = 0;
	while (dt_get_ref(dt, prop, rindex))
		rindex++;
	return rindex;
}

const char *
dt_ref_string(struct yaml_dt_state *dt, struct ref *ref)
{
	if (!to_dt_ref(ref)->is_resolved)
		dt_resolve_ref(dt, ref);

	if (!to_dt_ref(ref)->is_resolved) {
		if (dt->error_on_failed_get)
			dt_error_at(dt, &to_dt_ref(ref)->m,
				"Failed to resolve\n");
		return NULL;
	}

	/* everything is a string, but warn if not evaluated as such */
	if (strcmp(to_dt_ref(ref)->tag, "!str"))
		dt_warning_at(dt, &to_dt_ref(ref)->m,
			"Retrieving as !str (%s)\n", to_dt_ref(ref)->tag);

	return ref->data;
}

const char *dt_get_string(struct yaml_dt_state *dt, struct node *np,
			  const char *name, int pindex, int rindex)
{
	struct property *prop;
	struct ref *ref;

	if (!dt || !np || !name)
		return NULL;

	prop = dt_get_property(dt, np, name, pindex);
	if (!prop)
		return NULL;
	ref = dt_get_ref(dt, prop, rindex);
	if (!ref)
		return NULL;

	return dt_ref_string(dt, ref);
}

unsigned long long dt_ref_int(struct yaml_dt_state *dt, struct ref *ref,
			      int *error)
{
	if (!to_dt_ref(ref)->is_resolved)
		dt_resolve_ref(dt, ref);

	if (!to_dt_ref(ref)->is_resolved) {
		if (dt->error_on_failed_get)
			dt_error_at(dt, &to_dt_ref(ref)->m,
				"resolve failed\n");
		return -1ULL;
	}

	/* can't retreive a non int tag */
	if (!is_int_tag(to_dt_ref(ref)->tag) || !to_dt_ref(ref)->is_int) {
		if (dt->error_on_failed_get)
			dt_error_at(dt, &to_dt_ref(ref)->m,
				"not !int (%s) ref\n", to_dt_ref(ref)->tag);
		return -1ULL;
	}

	if (error)
		*error = 0;

	return to_dt_ref(ref)->val;
}

unsigned long long dt_get_int(struct yaml_dt_state *dt, struct node *np,
			  const char *name, int pindex, int rindex, int *error)
{
	struct property *prop;
	struct ref *ref;

	if (error)
		*error = -1;

	if (!dt || !np || !name)
		return -1ULL;

	prop = dt_get_property(dt, np, name, pindex);
	if (!prop)
		return -1ULL;
	ref = dt_get_ref(dt, prop, rindex);
	if (!ref)
		return -1ULL;

	return dt_ref_int(dt, ref, error);
}

int dt_ref_bool(struct yaml_dt_state *dt, struct ref *ref)
{
	if (!to_dt_ref(ref)->is_resolved)
		dt_resolve_ref(dt, ref);

	if (!to_dt_ref(ref)->is_resolved) {
		if (dt->error_on_failed_get)
			dt_error_at(dt, &to_dt_ref(ref)->m,
				"resolve failed\n");
		return -1;
	}

	/* can't retreive a non int tag */
	if (strcmp(to_dt_ref(ref)->tag, "!bool") || !to_dt_ref(ref)->is_bool) {
		if (dt->error_on_failed_get)
			dt_error_at(dt, &to_dt_ref(ref)->m,
				"not !bool (%s) ref\n",
					to_dt_ref(ref)->tag);
		return -1;
	}

	return to_dt_ref(ref)->val ? 1 : 0;
}

int dt_get_bool(struct yaml_dt_state *dt, struct node *np,
		 const char *name, int pindex, int rindex)
{
	struct property *prop;
	struct ref *ref;

	if (!dt || !np || !name)
		return -1;

	prop = dt_get_property(dt, np, name, pindex);
	if (!prop)
		return -1;
	ref = dt_get_ref(dt, prop, rindex);
	if (!ref)
		return -1;

	return dt_ref_bool(dt, ref);
}

const void *dt_ref_binary(struct yaml_dt_state *dt, struct ref *ref,
			  size_t *binary_size)
{
	if (!to_dt_ref(ref)->is_resolved)
		dt_resolve_ref(dt, ref);

	if (!to_dt_ref(ref)->is_resolved) {
		if (dt->error_on_failed_get)
			dt_error_at(dt, &to_dt_ref(ref)->m,
				"Failed to resolve\n");
		return NULL;
	}

	if (binary_size)
		*binary_size = to_dt_ref(ref)->binary_size;

	return to_dt_ref(ref)->binary;
}

const void *dt_get_binary(struct yaml_dt_state *dt, struct node *np,
			  const char *name, int pindex, int rindex,
			  size_t *binary_size)
{
	struct property *prop;
	struct ref *ref;

	if (!dt || !np || !name)
		return NULL;

	prop = dt_get_property(dt, np, name, pindex);
	if (!prop)
		return NULL;
	ref = dt_get_ref(dt, prop, rindex);
	if (!ref)
		return NULL;

	return dt_ref_binary(dt, ref, binary_size);
}

struct node *dt_ref_noderef(struct yaml_dt_state *dt, struct ref *ref)
{
	if (!to_dt_ref(ref)->is_resolved)
		dt_resolve_ref(dt, ref);

	if (!to_dt_ref(ref)->is_resolved) {
		if (dt->error_on_failed_get)
			dt_error_at(dt, &to_dt_ref(ref)->m,
				"resolve failed\n");
		return NULL;
	}

	if (!to_dt_ref(ref)->npref) {
		if (dt->error_on_failed_get)
			dt_error_at(dt, &to_dt_ref(ref)->m,
				"Invalid node reference\n");
		return NULL;
	}
	return to_dt_ref(ref)->npref;
}

struct node *dt_get_noderef(struct yaml_dt_state *dt, struct node *np,
			     const char *name, int pindex, int rindex)
{
	struct property *prop;
	struct ref *ref;

	if (!dt || !np || !name)
		return NULL;

	prop = dt_get_property(dt, np, name, pindex);
	if (!prop)
		return NULL;
	ref = dt_get_ref(dt, prop, rindex);
	if (!ref)
		return NULL;

	return dt_ref_noderef(dt, ref);
}
