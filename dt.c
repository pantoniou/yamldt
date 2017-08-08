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
#include "config.h"

#include <stdio.h>
#include <string.h>
#include <stdlib.h>
#include <unistd.h>
#include <errno.h>
#include <ctype.h>
#include <sys/types.h>
#include <sys/stat.h>
#include <unistd.h>
#include <time.h>
#include <stdbool.h>
#include <stdarg.h>
#include <assert.h>
#include <limits.h>

#define _GNU_SOURCE
#include <getopt.h>

#include "utils.h"
#include "syexpr.h"

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

static bool int_val_in_range(const char *tag, unsigned long long val, bool is_unsigned,
			     bool is_hex)
{
	long long sval;
	bool sval_overflow;

	/* yes, I'm paranoid */
	assert(ULLONG_MAX >= UINT64_MAX);

	if (is_hex)
		is_unsigned = true;

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

	if (!strcmp(tag, "!uint8"))
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

	/* we could try to avoid the copy but.. it's easier for now to allocate */

	/* if (data < dt->input_content || data >= dt->input_content + dt->input_size) { */
		p = malloc(len + 1);
		assert(p);
		memcpy(p, data, len);
		((char *)p)[len] = '\0';	/* and always terminate */
	/* } else
		p = (void *)data; */

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
	struct yaml_dt_state *dt = to_dt(t);
	struct dt_ref *dt_ref = to_dt_ref(ref);
	void *p;

	if (ref->xtag)
		free(ref->xtag);

	p = (void *)ref->data;
	if (p < dt->input_content || p >= dt->input_content + dt->input_size)
		free(p);

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

static int read_input_file(struct yaml_dt_state *dt, const char *file)
{
	struct input *in;
	char *s, *e, *le;
	size_t bufsz, nread, currline, adv, filesz;
	FILE *fp;
	struct stat st;

	if (strcmp(file, "-")) {
		fp = fopen(file, "rb");
		if (!fp)
			return -1;
	} else {
		file = "<stdin>";
		fp = stdin;
	}

	in = malloc(sizeof(*in));
	assert(in);

	memset(in, 0, sizeof(*in));
	in->name = strdup(file);
	assert(in->name);
	in->start = dt->input_size;

	/* get the file size if we can */
	filesz = 0;
	if (fstat(fileno(fp), &st) != -1 && S_ISREG(st.st_mode))
		filesz = st.st_size;

	/* for non regular files the advance is 64K */
	adv = filesz ? filesz : 64 * 1024;

	do {
		if (dt->input_size >= dt->input_alloc) {
			dt->input_alloc += adv;
			dt->input_content = realloc(dt->input_content,
						    dt->input_alloc);
			assert(dt->input_content);
		}

		s = dt->input_content + in->start + in->size;
		bufsz = dt->input_alloc - dt->input_size;

		nread = fread(s, 1, bufsz, fp);
		if (nread <= 0 && ferror(fp))
			return -1;
		dt->input_size += nread;
		in->size += nread;

		/* avoid extra calls to fread */
		if (filesz && in->size >= filesz)
			break;

	} while (nread >= bufsz);

	dt_debug(dt, "%s: read %zd bytes @%zd\n",
			in->name, in->size, in->start);

	s = dt->input_content + in->start;
	e = s + in->size;

	in->start_line = dt->input_lines;

	currline = 0;
	while (s < e) {
		le = strchr(s, '\n');
		currline++;
		if (!le)
			break;
		s = le + 1;
	}

	in->lines = currline;
	dt->input_lines += currline;

	dt_debug(dt, "%s: has %zd lines starting at line @%zd\n",
			in->name, in->lines, in->start_line);

	list_add_tail(&in->node, &dt->inputs);

	fclose(fp);

	return 0;
}

static void append_input_marker(struct yaml_dt_state *dt, const char *marker)
{
	int len = strlen(marker);
	bool ignore_first_newline;
	char c, *s;

	s = dt->input_content + dt->input_size;
	ignore_first_newline = dt->input_size > 0 && *s != '\n' && *marker == '\n';

	if (dt->input_size + len > dt->input_alloc) {
		dt->input_alloc += len;
		dt->input_content = realloc(dt->input_content, dt->input_alloc);
		assert(dt->input_content);
	}
	memcpy(dt->input_content + dt->input_size, marker, len);
	dt->input_size += len;

	while ((c = *marker++) != '\0') {
		if (c == '\n' && !ignore_first_newline)
			dt->input_lines++;
		ignore_first_newline = false;
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

int dt_setup(struct yaml_dt_state *dt, struct yaml_dt_config *cfg,
	     struct yaml_dt_emitter *emitter, struct yaml_dt_checker *checker)
{
	int i, ret, len;
	char *s;

	memset(dt, 0, sizeof(*dt));
	INIT_LIST_HEAD(&dt->children);

	if (!yaml_parser_initialize(&dt->parser)) {
		fprintf(stderr, "Could not initialize the parser object\n");
		return -1;
	}

	memcpy(&dt->cfg, cfg, sizeof(*cfg));

	if (dt->cfg.compiler && dt->cfg.cflags && dt->cfg.compiler_tags) {
		s = strchr(cfg->compiler_tags, ',');
		if (!s) {
			fprintf(stderr, "compiler tags are bogus: %s\n",
					cfg->compiler_tags);
			return -1;
		}

		len = s - cfg->compiler_tags;
		dt->input_compiler_tag = malloc(len + 1);
		assert(dt->input_compiler_tag);
		memcpy(dt->input_compiler_tag, cfg->compiler_tags, len);
		dt->input_compiler_tag[len] = '\0';

		len = strlen(++s);
		dt->output_compiler_tag = malloc(len + 1);
		assert(dt->output_compiler_tag);
		memcpy(dt->output_compiler_tag, s, len);
		dt->output_compiler_tag[len] = '\0';
	}

	INIT_LIST_HEAD(&dt->inputs);

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

	for (i = 0; i < cfg->input_file_count; i++) {
		ret = read_input_file(dt, cfg->input_file[i]);
		if (ret == -1) {
			fprintf(stderr, "Could not initialize parser\n");
			return -1;
		}
		if (i < (cfg->input_file_count - 1))
			append_input_marker(dt, "---\n");
	}

	yaml_parser_set_input_string(&dt->parser, dt->input_content,
				     dt->input_size);

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

struct yaml_dt_state *dt_parse_single(struct yaml_dt_state *dt,
		const char *input, const char *output,
		const char *name)
{
	struct yaml_dt_state *sdt;
	struct yaml_dt_config cfg;
	char *argv[2];
	int err;

	sdt = malloc(sizeof(*sdt));
	assert(sdt);

	memset(&cfg, 0, sizeof(cfg));
	cfg.debug = dt->cfg.debug;
	cfg.output_file = output ? output : "/dev/null";

	argv[0] = (char *)input;
	argv[1] = NULL;
	cfg.input_file = argv;
	cfg.input_file_count = 1;

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
	struct input *in, *inn;
	bool rm_file;

	list_for_each_entry_safe(child, childn, &dt->children, node)
		dt_cleanup(child, abnormal);

	if (dt->map_key)
		free(dt->map_key);
	if (dt->current_prop)
		prop_free(to_tree(dt), dt->current_prop);

	tree_cleanup(to_tree(dt));

	dt_checker_cleanup(dt);
	dt_emitter_cleanup(dt);

	rm_file = abnormal && dt->output && dt->output != stdout &&
		  strcmp(dt->cfg.output_file, "-") &&
		  strcmp(dt->cfg.output_file, "/dev/null");

	if (dt->current_event)
		yaml_event_delete(dt->current_event);

	list_for_each_entry_safe(in, inn, &dt->inputs, node) {
		list_del(&in->node);
		free(in->name);
		free(in);
	}

	if (dt->output && dt->output != stdout)
		fclose(dt->output);

	yaml_parser_delete(&dt->parser);
	fflush(stdout);

	if (dt->input_compiler_tag)
		free(dt->input_compiler_tag);

	if (dt->output_compiler_tag)
		free(dt->output_compiler_tag);

	if (dt->input_content)
		free(dt->input_content);

	if (rm_file)
		remove(dt->cfg.output_file);

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
	struct node *np;
	struct property *prop;

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
		prop_del(to_tree(dt), prop);
	} else if (!dt->current_prop_existed) {

		dt_debug(dt, "appending property %s at %s\n",
				prop->name[0] ? prop->name : "-",
				dn_fullname(np, namebuf, sizeof(namebuf)));

		prop->np = np;
		list_add_tail(&prop->node, &np->properties);

	} else
		dt_debug(dt, "dangling property %s at %s\n",
				prop->name[0] ? prop->name : "-",
				dn_fullname(np, namebuf, sizeof(namebuf)));

	dt->current_prop_existed = false;

	if (dt->map_key)
		free(dt->map_key);
	dt->map_key = NULL;
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
			rt = tag && !strcmp(tag, "!pathref") ? r_path : r_scalar;

			break;
		case YAML_SINGLE_QUOTED_SCALAR_STYLE:
		case YAML_DOUBLE_QUOTED_SCALAR_STYLE:
		case YAML_LITERAL_SCALAR_STYLE:
		case YAML_FOLDED_SCALAR_STYLE:

			ref_label = (char *)event->data.scalar.value;
			ref_label_len = event->data.scalar.length;

			/* try to find implicitly a type */
			tag = (char *)event->data.scalar.tag;

			xtag = tag ? tag : "!str";
			rt = r_scalar;

			break;
		case YAML_ANY_SCALAR_STYLE:
			dt_fatal(dt, "ANY_SCALAR not allowed\n");
		}
	} else
		dt_fatal(dt, "Illegal type to append\n");

	if (ref_label && ref_label_len > 0) {

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
	}
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

static int process_yaml_event(struct yaml_dt_state *dt, yaml_event_t *event)
{
	struct node *np;
	struct property *prop;
	yaml_event_type_t type = event->type;
	bool found_existing;
	char *label;
	char namebuf[NODE_FULLNAME_MAX];
	int len;

	assert(!dt->current_event);
	dt->current_event = event;

	dt->current_mark.start = event->start_mark;
	dt->current_mark.end = event->end_mark;

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
		if (dt->current_np && !dt->cfg.late) {
			list_for_each_entry(np, &dt->current_np->children, node) {
				/* match on same name or root */
				if (!strcmp(dt->map_key, np->name) ||
					(dt->map_key == '\0' && np->name[0] == '\0')) {
					found_existing = true;
					break;
				}
			}
		}

		if (found_existing) {
			if (label)
				label_add(to_tree(dt), np, label);

			dt_debug(dt, "using existing node @%s%s%s\n",
					dn_fullname(np, namebuf, sizeof(namebuf)),
					label ? " label=" : "",
					label ? label : "");
		} else {
			if (label) {
				np = node_lookup_by_label(to_tree(dt), label,
						strlen(label));
				if (np)
					dt_fatal(dt, "Node %s with duplicate label %s\n",
							dt->map_key, label);
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

		dt_debug(dt, "* finished with %s at depth %d\n",
				dn_fullname(dt->current_np, namebuf, sizeof(namebuf)),
				dt->depth - 1);

		dt->depth--;
		dt->current_np = dt->current_np->parent;

		if (dt->current_np == NULL && dt->current_np_ref) {
			dt_debug(dt, "* out of ref context\n");
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
			found_existing = false;
			assert(np);
			list_for_each_entry(prop, &np->properties, node) {
				if (!strcmp(prop->name, dt->map_key)) {
					found_existing = true;
					break;
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

		if (!dt->map_key && !dt->bare_seq) {
			len = event->data.scalar.length;

			if (!np) {
				/* in case of a corrput file, make sure the output is sane */
				if (len > 40)
					len = 40;
				if (len > sizeof(namebuf) - 1)
					len = sizeof(namebuf) - 1;

				memcpy(namebuf, event->data.scalar.value, len);
				namebuf[len] = '\0';
				dt_fatal(dt, "Unexpected scalar %s (is this a YAML input file?)\n",
						namebuf);
			}

			/* TODO check event->data.scalar.style */
			dt->map_key = malloc(len + 1);
			assert(dt->map_key);
			memcpy(dt->map_key, event->data.scalar.value, len);
			dt->map_key[len] = '\0';

			dt->last_map_mark = dt->current_mark;

		} else {
			if (!prop) {
				found_existing = false;
				if (dt->map_key) {
					assert(np);
					list_for_each_entry(prop, &np->properties, node) {
						if (!strcmp(prop->name, dt->map_key)) {
							found_existing = true;
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
				list_for_each_entry(prop, &np->properties, node) {
					if (!strcmp(prop->name, dt->map_key)) {
						found_existing = true;
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
	return 0;
}

int dt_parse(struct yaml_dt_state *dt)
{
	yaml_event_t event;
	struct dt_yaml_mark m;
	int err;
	bool end;

	while (1) {

		if (!yaml_parser_parse(&dt->parser, &event)) {
			m.start = m.end = dt->parser.problem_mark;
			dt_error_at(dt, &m, "%s\n", dt->parser.problem);
			return -1;
		}

		err = process_yaml_event(dt, &event);
		if (err)
			dt_fatal(dt, "Error processing event: %d\n", err);

		end = event.type == YAML_STREAM_END_EVENT;

		yaml_event_delete(&event);

		if (end)
			break;
	}
	return 0;

	// return dt->error_flag ? -1 : 0;
}

static void get_error_location(struct yaml_dt_state *dt,
			size_t line, size_t column,
		        char *filebuf, size_t filebufsize,
			char *linebuf, size_t linebufsize,
			size_t *linep)
{
	char *s, *e, *ls, *le, *p, *pe;
	size_t currline;
	size_t lastline, tlastline;
	struct input *in;

	*filebuf = '\0';
	*linebuf = '\0';

	s = dt->input_content;
	e = dt->input_content + dt->input_size;

	currline = 0;
	ls = s;
	le = NULL;
	lastline = 0;
	while (ls < e && currline < line) {

		/* get file marker (if it exists) */
		p = ls;
		if (p[0] == '#' && isspace(p[1])) {
			p += 2;
			while (isspace(*p))
				p++;
			tlastline = strtol(p, &pe, 10);
			if (pe > p && isspace(*pe)) {
				while (isspace(*pe))
					pe++;
				p = pe + 1;
				pe = strchr(p, '"');
				if (pe) {
					lastline = tlastline;
					if ((pe - p) > (filebufsize - 1))
						pe = p + filebufsize - 1;
					memcpy(filebuf, p, pe - p);
					filebuf[pe - p] = '\0';
				}
			}
		} else
			lastline++;

		le = strchr(ls, '\n');
		if (!le)
			break;
		ls = le + 1;
		currline++;
	}

	if (ls < e && *ls) {
		le = strchr(ls, '\n');
		if (!le)
			le = ls + strlen(ls);

		if ((le - ls) > (linebufsize - 1))
			le = ls + linebufsize - 1;
		memcpy(linebuf, ls, le - ls);
		linebuf[le - ls] = '\0';
	}

	/* no markers? iterate in the input list */
	if (!*filebuf) {

		filebuf[0] = '\0';
		list_for_each_entry(in, &dt->inputs, node) {
			if (line >= in->start_line &&
			    line <= in->start_line + in->lines) {
				strncat(filebuf, in->name, filebufsize);
				lastline = line - in->start_line;
				break;
			}
		}
		filebuf[filebufsize - 1] = '\0';

		lastline++;
	}

	/* convert to presentation */
	*linep = lastline;
}

void dt_fatal(struct yaml_dt_state *dt, const char *fmt, ...)
{
	va_list ap;
	char str[1024];
	int len;
	char linebuf[1024];
	char filebuf[PATH_MAX + 1];
	size_t line, column, end_line, end_column;

	va_start(ap, fmt);
	vsnprintf(str, sizeof(str) - 1, fmt, ap);
	va_end(ap);
	str[sizeof(str) - 1] = '\0';

	len = strlen(str);
	while (len > 1 && str[len - 1] == '\n')
		str[--len] = '\0';

	line = dt->current_mark.start.line;
	column = dt->current_mark.start.column;
	end_line = dt->current_mark.end.line;
	end_column = dt->current_mark.end.column;

	get_error_location(dt, line, column,
			filebuf, sizeof(filebuf),
			linebuf, sizeof(linebuf),
			&line);

	if (end_line != line)
		end_column = strlen(linebuf) + 1;

	fprintf(stderr, "%s:%zd:%zd: %s\n %s\n %*s^",
			filebuf, line, column + 1,
			str, linebuf, (int)column, "");
	while (++column < end_column - 1)
		fprintf(stderr, "~");
	fprintf(stderr, "\n");

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

	line = m->start.line;
	column = m->start.column;
	end_line = m->end.line;
	end_column = m->end.column;

	get_error_location(dt, line, column,
			filebuf, sizeof(filebuf),
			linebuf, sizeof(linebuf),
			&line);

	if (end_line != line)
		end_column = strlen(linebuf) + 1;

	fprintf(stderr, "%s:%zd:%zd: %s: %s\n %s\n %*s^",
			filebuf, line, column + 1,
			type, msg, linebuf, (int)column, "");
	while (++column < end_column - 1)
		fprintf(stderr, "~");
	fprintf(stderr, "\n");
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

	if (!dt->cfg.debug)
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
		np = node_lookup_by_label(t, ref->data, ref->len);
		if (!np && !dt->cfg.object)
			return -ENOENT;	/* not found */

		to_dt_ref(ref)->tag = ref->type == r_anchor ? "!anchor" :
							      "!pathref";

		/* object mode, just leave references here */
		if (!np)
			break;

		to_dt_ref(ref)->npref = np;
		break;

	case r_scalar:
		np = prop->np;
		assert(np);

		len = ref->len;
		p = ref->data;

		/* try to parse as an int anyway */
		ret = parse_int(p, len, &val, &is_unsigned, &is_hex);
		is_int = ret == 0;

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
			if (!int_val_in_range(tag, val, is_unsigned, is_hex))
				return -ERANGE;

			to_dt_ref(ref)->is_int = true;
			to_dt_ref(ref)->is_hex = is_hex;
			to_dt_ref(ref)->is_unsigned = is_unsigned;
			to_dt_ref(ref)->val = val;
			to_dt_ref(ref)->is_builtin_tag = true;

		} else if (!strcmp(tag, "!str")) {
			to_dt_ref(ref)->is_str = true;
			to_dt_ref(ref)->is_builtin_tag = true;
		} else if (!strcmp(tag, "!bool")) {

			if (!(len == 4 && !memcmp(p,  "true", 4)) ||
			     (len == 5 && !memcmp(p, "false", 5)) )
				return -EINVAL;

			to_dt_ref(ref)->is_bool = true;
			to_dt_ref(ref)->val = (len == 4 && !memcmp(p,  "true", 4));
			to_dt_ref(ref)->is_builtin_tag = true;
		} else if (!strcmp(tag, "!null")) {
			to_dt_ref(ref)->is_null = true;
			to_dt_ref(ref)->is_builtin_tag = true;
		} else
			to_dt_ref(ref)->is_builtin_tag = false;
		break;

	default:
		/* nothing */
		break;
	}

	to_dt_ref(ref)->is_resolved = true;

	return 0;
}

struct node *dt_get_node(struct yaml_dt_state *dt,
			    struct node *parent, const char *name,
			    int index)
{
	char namebuf[NODE_FULLNAME_MAX];
	struct node *np;

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

	ref = ref_get_by_index(to_tree(dt), prop, index);

	if (!ref && dt->error_on_failed_get)
		dt_error_at(dt, &to_dt_property(prop)->m,
				"Unable to find ref #%d of prop %s of %s\n",
				index, prop->name,
				dn_fullname(prop->np, namebuf, sizeof(namebuf)));
	return ref;
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

	if (!to_dt_ref(ref)->is_resolved)
		dt_resolve_ref(dt, ref);

	if (!to_dt_ref(ref)->is_resolved) {
		if (dt->error_on_failed_get)
			dt_error_at(dt, &to_dt_ref(ref)->m,
				"Failed to resolve with getting %s property\n",
			name);
		return NULL;
	}

	/* everything is a string, but warn if not evaluated as such */
	if (strcmp(to_dt_ref(ref)->tag, "!str"))
		dt_warning_at(dt, &to_dt_ref(ref)->m,
			"Retrieving as !str (%s) at %s property\n",
			to_dt_ref(ref)->tag, name);

	return ref->data;
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

	if (!to_dt_ref(ref)->is_resolved)
		dt_resolve_ref(dt, ref);

	if (!to_dt_ref(ref)->is_resolved) {
		if (dt->error_on_failed_get)
			dt_error_at(dt, &to_dt_ref(ref)->m,
				"resolve failed ref #%d of %s#%d\n",
					rindex, name, pindex);
		return -1ULL;
	}

	/* can't retreive a non int tag */
	if (!is_int_tag(to_dt_ref(ref)->tag) || !to_dt_ref(ref)->is_int) {
		if (dt->error_on_failed_get)
			dt_error_at(dt, &to_dt_ref(ref)->m,
				"not !int (%s) ref #%d of %s#%d\n",
					to_dt_ref(ref)->tag, rindex,
					name, pindex);
		return -1ULL;
	}

	if (error)
		*error = 0;

	return to_dt_ref(ref)->val;
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

	if (!to_dt_ref(ref)->is_resolved)
		dt_resolve_ref(dt, ref);

	if (!to_dt_ref(ref)->is_resolved) {
		if (dt->error_on_failed_get)
			dt_error_at(dt, &to_dt_ref(ref)->m,
				"resolve failed ref #%d of %s#%d\n",
					rindex, name, pindex);
		return -1;
	}

	/* can't retreive a non int tag */
	if (strcmp(to_dt_ref(ref)->tag, "!bool") || !to_dt_ref(ref)->is_bool) {
		if (dt->error_on_failed_get)
			dt_error_at(dt, &to_dt_ref(ref)->m,
				"not !bool (%s) ref #%d of %s#%d\n",
					to_dt_ref(ref)->tag, rindex,
					name, pindex);
		return -1;
	}

	return to_dt_ref(ref)->val ? 1 : 0;
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

	if (!to_dt_ref(ref)->is_resolved)
		dt_resolve_ref(dt, ref);

	if (!to_dt_ref(ref)->is_resolved) {
		if (dt->error_on_failed_get)
			dt_error_at(dt, &to_dt_ref(ref)->m,
				"resolve failed ref #%d of %s#%d\n",
					rindex, name, pindex);
		return NULL;
	}

	if (!to_dt_ref(ref)->npref) {
		if (dt->error_on_failed_get)
			dt_error_at(dt, &to_dt_ref(ref)->m,
				"Invalid node reference ref #%d of %s#%d\n",
					rindex, name, pindex);
		return NULL;
	}
	return to_dt_ref(ref)->npref;
}
