/*
 * yamldt.c - main parser source
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

#define _GNU_SOURCE
#include <getopt.h>

#include "utils.h"
#include "syexpr.h"

#include "yamldt.h"

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

static struct ref *
yaml_dt_ref_alloc(struct tree *t, enum ref_type type,
		const void *data, int len, const char *xtag)
{
	struct yaml_dt_state *dt = to_dt(t);
	struct ref *ref;
	void *p;

	ref = malloc(sizeof(*ref));
	assert(ref);
	memset(ref, 0, sizeof(*ref));

	/* try to avoid copy if the pointer given is in read data */
	if (p < dt->input_file_contents || p >= dt->input_file_contents) {
		p = malloc(len);
		assert(p);
		memcpy(p, data, len);
	} else
		p = (void *)data;

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
	ref->line = dt->current_start_mark.line;
	ref->column = dt->current_start_mark.column;
	ref->end_line = dt->current_end_mark.line;
	ref->end_column = dt->current_end_mark.column;

	return ref;
}

static void yaml_dt_ref_free(struct tree *t, struct ref *ref)
{
	struct yaml_dt_state *dt = to_dt(t);
	void *p;

	if (ref->xtag)
		free(ref->xtag);

	p = (void *)ref->data;
	if (p < dt->input_file_contents || p >= dt->input_file_contents)
		free(p);

	memset(ref, 0, sizeof(*ref));
	free(ref);
}

static struct property *yaml_dt_prop_alloc(struct tree *t, const char *name)
{
	struct yaml_dt_state *dt = to_dt(t);
	struct property *prop;

	prop = malloc(sizeof(*prop));
	assert(prop);
	memset(prop, 0, sizeof(*prop));

	prop->name = strdup(name);
	assert(prop->name);

	prop->line = dt->current_start_mark.line;
	prop->column = dt->current_start_mark.column;
	prop->end_line = dt->current_end_mark.line;
	prop->end_column = dt->current_end_mark.column;

	return prop;
}

static void yaml_dt_prop_free(struct tree *t, struct property *prop)
{
	if (prop->data)
		free(prop->data);
	free(prop->name);
	memset(prop, 0, sizeof(*prop));
	free(prop);
}

static struct label *yaml_dt_label_alloc(struct tree *t, const char *name)
{
	struct label *l;

	l = malloc(sizeof(*l));
	assert(l);
	memset(l, 0, sizeof(*l));
	l->label = strdup(name);
	assert(l->label);

	return l;
}

static void yaml_dt_label_free(struct tree *t, struct label *l)
{
	free(l->label);
	memset(l, 0, sizeof(*l));
	free(l);
}

static struct device_node *yaml_dt_node_alloc(struct tree *t, const char *name,
					     const char *label)
{
	struct device_node *np;

	np = malloc(sizeof(*np));
	assert(np);
	memset(np, 0, sizeof(*np));

	np->name = strdup(name);
	assert(np->name);

	return np;
}

static void yaml_dt_node_free(struct tree *t, struct device_node *np)
{
	free(np->name);

	memset(np, 0, sizeof(*np));
	free(np);
}

static void yaml_dt_tree_debugf(struct tree *t, const char *fmt, ...)
		__attribute__ ((__format__ (__printf__, 2, 0)));

static void yaml_dt_tree_debugf(struct tree *t, const char *fmt, ...)
{
	struct yaml_dt_state *dt;
	va_list ap;

	dt = to_dt(t);

	va_start(ap, fmt);
	if (dt->debug)
		vfprintf(stderr, fmt, ap);
	va_end(ap);
}

static const struct tree_ops yaml_tree_ops = {
	.ref_alloc	= yaml_dt_ref_alloc,
	.ref_free	= yaml_dt_ref_free,
	.prop_alloc	= yaml_dt_prop_alloc,
	.prop_free	= yaml_dt_prop_free,
	.label_alloc	= yaml_dt_label_alloc,
	.label_free	= yaml_dt_label_free,
	.node_alloc	= yaml_dt_node_alloc,
	.node_free	= yaml_dt_node_free,
	.debugf		= yaml_dt_tree_debugf,
};

void dt_start(struct yaml_dt_state *dt)
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

	if (!dt->yaml)
		dtb_init(dt);
	else
		yaml_init(dt);
	tree_init(to_tree(dt), &yaml_tree_ops);
}

void dt_end(struct yaml_dt_state *dt)
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

	if (!dt->yaml)
		dtb_cleanup(dt);
	else
		yaml_cleanup(dt);
	tree_term(to_tree(dt));
}

static void read_whole_input_file(struct yaml_dt_state *dt)
{
	void *buf, *readbuf;
	size_t bufsz, nread, total;

	bufsz = 64 * 1024;	/* 64K default buffer */

	buf = malloc(bufsz);
	assert(buf);

	readbuf = NULL;
	total = 0;
	while ((nread = fread(buf, 1, bufsz, dt->input)) > 0) {
		if (nread < bufsz && !readbuf) {
			readbuf = buf;
			buf = NULL;
			total = nread;
			break;
		}
		readbuf = realloc(readbuf, total + nread);
		assert(readbuf);
		memcpy(readbuf + total, buf, nread);
		total += nread;
	}

	if (buf)
		free(buf);

	dt->input_file_contents = readbuf;
	dt->input_file_size = total;
}

int dt_setup(struct yaml_dt_state *dt,
		const char *input_file,
		const char *output_file,
		bool debug, bool compatible,
		bool yaml)
{
	memset(dt, 0, sizeof(*dt));

	dt->input_file = input_file;
	dt->output_file = output_file;
	dt->debug = debug;
	dt->compatible = compatible;
	dt->yaml = yaml;

	if (strcmp(dt->input_file, "-")) {
		dt->input = fopen(dt->input_file, "rb");
		if (!dt->input) {
			fprintf(stderr, "Failed to open %s for input\n",
					dt->input_file);
			return -1;
		}
	} else
		dt->input = stdin;

	if (strcmp(dt->output_file, "-")) {
		dt->output = fopen(dt->output_file, "wb");
		if (!dt->output) {
			fprintf(stderr, "Failed to open %s for output\n",
					dt->output_file);
			return -1;
		}
	} else
		dt->output = stdout;

	if (!yaml_parser_initialize(&dt->parser)) {
		fprintf(stderr, "Could not initialize the parser object\n");
		return -1;
	}
	read_whole_input_file(dt);
	yaml_parser_set_input_string(&dt->parser, dt->input_file_contents,
				     dt->input_file_size);

	return 0;
}

void dt_cleanup(struct yaml_dt_state *dt, bool abnormal)
{
	bool rm_file;

	rm_file = abnormal && dt->output && dt->output != stdout &&
		  strcmp(dt->output_file, "-");

	if (dt->current_event)
		yaml_event_delete(dt->current_event);

	if (dt->input && dt->input != stdin)
		fclose(dt->input);
	if (dt->output && dt->output != stdout)
		fclose(dt->output);

	yaml_parser_delete(&dt->parser);
	fflush(stdout);

	if (dt->input_file_contents)
		free(dt->input_file_contents);

	if (dt->buffer)
		free(dt->buffer);

	if (rm_file)
		remove(dt->output_file);

	memset(dt, 0, sizeof(*dt));
}

static void finalize_current_property(struct yaml_dt_state *dt)
{
	char namebuf[NODE_FULLNAME_MAX];
	struct device_node *np;
	struct property *prop;

	if (!dt)
		return;

	/* if we have a current property finalize it */
	np = dt->current_np;
	prop = dt->current_prop;

	if (!np || !prop)
		return;

	dt->current_prop = NULL;
	dt_debug(dt, "finalizing property %s at %s\n", prop->name,
			dn_fullname(np, namebuf, sizeof(namebuf)));

	/* special case for completely empty tree marker */
	if (!strcmp(prop->name, "~")) {
		dt_debug(dt, "Deleting empty tree marker %s at %s\n", prop->name,
				dn_fullname(np, namebuf, sizeof(namebuf)));
		prop_del(to_tree(dt), prop);
	} else if (!dt->current_prop_existed) {

		dt_debug(dt, "appending property %s at %s\n", prop->name,
				dn_fullname(np, namebuf, sizeof(namebuf)));

		prop->np = np;
		list_add_tail(&prop->node, &np->properties);
	} else
		dt_debug(dt, "dangling property %s at %s\n", prop->name,
				dn_fullname(np, namebuf, sizeof(namebuf)));

	dt->current_prop_existed = false;

	if (dt->map_key)
		free(dt->map_key);
	dt->map_key = NULL;
}

static void append_to_current_property(struct yaml_dt_state *dt,
		yaml_event_t *event)
{
	struct device_node *np;
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

			xtag = "!str";
			rt = r_scalar;

			break;
		case YAML_ANY_SCALAR_STYLE:
			dt_fatal(dt, "ANY_SCALAR not allowed\n");
		}
	} else
		dt_fatal(dt, "Illegal type to append\n");

	if (ref_label && ref_label_len > 0 && rt >= 0) {

		ref = ref_alloc(to_tree(dt), rt, ref_label,
				ref_label_len, xtag);

		dt_debug(dt, "new ref @%s%s%s\n",
			dn_fullname(np, namebuf, sizeof(namebuf)),
			np != tree_root(to_tree(dt)) ? "/" : "",
			prop->name);

		/* add the reference to the list */
		ref->prop = prop;
		ref->offset = -1;
		ref->np = NULL;
		list_add_tail(&ref->node, &prop->refs);
	}
}

static struct property *
property_prepare(struct yaml_dt_state *dt, yaml_event_t *event,
		 struct property *prop)
{
	if (!prop)
		prop = prop_alloc(to_tree(dt), dt->map_key);
	else
		prop_ref_clear(to_tree(dt), prop);
	assert(prop);

	prop->line = dt->current_start_mark.line;
	prop->column = dt->current_start_mark.column;
	prop->end_line = dt->current_end_mark.line;
	prop->end_column = dt->current_end_mark.column;

	return prop;
}

static int process_yaml_event(struct yaml_dt_state *dt, yaml_event_t *event)
{
	struct device_node *np;
	struct property *prop;
	yaml_event_type_t type = event->type;
	bool found_existing;
	char *label;
	char namebuf[NODE_FULLNAME_MAX];

	assert(!dt->current_event);
	dt->current_event = event;
	dt->current_start_mark = event->start_mark;
	dt->current_end_mark = event->end_mark;

	switch (type) {
	case YAML_NO_EVENT:
		break;
	case YAML_STREAM_START_EVENT:
		break;
	case YAML_STREAM_END_EVENT:
		break;
	case YAML_DOCUMENT_START_EVENT:
		dt_start(dt);
		break;
	case YAML_DOCUMENT_END_EVENT:
		if (!dt->yaml)
			dtb_emit(dt);
		else
			yaml_emit(dt);
		dt_end(dt);
		break;

	case YAML_MAPPING_START_EVENT:
		/* if we have a current property finalize it */
		finalize_current_property(dt);

		label = (char *)event->data.mapping_start.anchor;

		/* creating root */
		if (!dt->map_key && dt->depth == 0) {
			assert(!tree_root(to_tree(dt)));

			np = node_alloc(to_tree(dt), "", NULL);

			dt->current_np = np;
			tree_set_root(to_tree(dt), np);
		} else if (dt->map_key) {

			found_existing = false;
			if (dt->current_np) {
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

				np->line = dt->last_map_start_mark.line;
				np->column = dt->last_map_start_mark.column;
				np->end_line = dt->last_map_end_mark.line;
				np->end_column = dt->last_map_end_mark.column;

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

				np->line = dt->last_alias_start_mark.line;
				np->column = dt->last_alias_start_mark.column;
				np->end_line = dt->last_alias_end_mark.line;
				np->end_column = dt->last_alias_end_mark.column;

				list_add_tail(&np->node, tree_ref_nodes(to_tree(dt)));
			}
			dt->current_np = np;
		} else
			dt_fatal(dt, "MAPPING start event, but without a previous VAL\n");

		dt_debug(dt, "* creating %s at depth %d\n",
			dn_fullname(np, namebuf, sizeof(namebuf)),
			dt->depth);

		dt->depth++;

		break;

	case YAML_MAPPING_END_EVENT:
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
			if (dt->debug)
				printf("* out of ref context\n");
			dt->current_np = tree_root(to_tree(dt));
			dt->current_np_ref = false;
		}

		break;

	case YAML_SEQUENCE_START_EVENT:

		np = dt->current_np;
		assert(np);

		prop = dt->current_prop;
		if (!prop) {
			found_existing = false;
			list_for_each_entry(prop, &np->properties, node) {
				if (!strcmp(prop->name, dt->map_key)) {
					found_existing = true;
					break;
				}
			}
			if (!found_existing)
				prop = NULL;

			prop = property_prepare(dt, event, prop);

			if (dt->debug)
				printf("%s property %s at %s [SEQ]\n",
					found_existing ? "existing" : "new",
					prop->name, dn_fullname(np, namebuf, sizeof(namebuf)));

			dt->current_prop = prop;
			dt->current_prop_existed = found_existing;
		}
		if (dt->debug)
			printf("sequence to prop '%s' (depth %d)%s%s\n", prop->name,
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

		break;

	case YAML_SCALAR_EVENT:
		np = dt->current_np;

		if (!dt->map_key) {
			if (!np)
				dt_fatal(dt, "Unexpected scalar (is this a YAML input file?)\n");

			/* TODO check event->data.scalar.style */
			dt->map_key = malloc(event->data.scalar.length + 1);
			assert(dt->map_key);
			memcpy(dt->map_key, event->data.scalar.value, event->data.scalar.length);
			dt->map_key[event->data.scalar.length] = '\0';

			dt->last_map_start_mark = event->start_mark;
			dt->last_map_end_mark = event->end_mark;

		} else {
			assert(np);

			prop = dt->current_prop;

			if (!prop) {
				found_existing = false;
				list_for_each_entry(prop, &np->properties, node) {
					if (!strcmp(prop->name, dt->map_key)) {
						found_existing = true;
						break;
					}
				}
				if (!found_existing)
					prop = NULL;
				prop = property_prepare(dt, event, prop);

				if (dt->debug)
					printf("%s property %s at %s\n",
						found_existing ? "existing" : "new",
						prop->name, dn_fullname(np, namebuf, sizeof(namebuf)));
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

			dt->last_alias_start_mark = event->start_mark;
			dt->last_alias_end_mark = event->end_mark;

			if (dt->debug)
				printf("next up is a ref to %s\n", dt->map_key);

			break;
		}

		prop = dt->current_prop;

		if (!prop) {
			found_existing = false;
			list_for_each_entry(prop, &np->properties, node) {
				if (!strcmp(prop->name, dt->map_key)) {
					found_existing = true;
					break;
				}
			}
			if (!found_existing)
				prop = NULL;
			prop = property_prepare(dt, event, prop);

			if (dt->debug)
				printf("%s property %s at %s\n",
					found_existing ? "existing" : "new",
					prop->name, dn_fullname(np, namebuf, sizeof(namebuf)));
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

void dt_parse(struct yaml_dt_state *dt)
{
	yaml_event_t event;
	int err;
	bool end;

	while (1) {

		if (!yaml_parser_parse(&dt->parser, &event))
			dt_fatal(dt, "Parse error: %s\n", dt->parser.problem);

		err = process_yaml_event(dt, &event);
		if (err)
			dt_fatal(dt, "Error processing event: %d\n", err);

		end = event.type == YAML_STREAM_END_EVENT;

		yaml_event_delete(&event);

		if (end)
			break;
	}
}

static void get_error_location(struct yaml_dt_state *dt,
			size_t line, size_t column,
		        char *filebuf, size_t filebufsize,
			char *linebuf, size_t linebufsize,
			size_t *linep)
{
	char *s, *e, *ls, *le, *p, *pe;
	size_t curline;
	size_t lastline, tlastline;

	*filebuf = '\0';
	*linebuf = '\0';

	s = dt->input_file_contents;
	e = dt->input_file_contents + dt->input_file_size;

	curline = 0;
	ls = s;
	le = NULL;
	lastline = 0;
	while (ls < e && curline < line) {

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
		curline++;
	}

	if (*ls) {
		le = strchr(ls, '\n');
		if (!le)
			le = ls + strlen(ls);

		if ((le - ls) > (linebufsize - 1))
			le = ls + linebufsize - 1;
		memcpy(linebuf, ls, le - ls);
		linebuf[le - ls] = '\0';
	}

	/* no markers? */
	if (!*filebuf) {
		snprintf(filebuf, filebufsize, "%s",
				strcmp(dt->input_file, "-") ? dt->input_file : "<stdin>");
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

	line = dt->current_start_mark.line;
	column = dt->current_start_mark.column;
	end_line = dt->current_end_mark.line;
	end_column = dt->current_end_mark.column;

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

	dt_end(dt);
	dt_cleanup(dt, true);

	exit(EXIT_FAILURE);
}

static void dt_print_at_msg(struct yaml_dt_state *dt,
		 size_t line, size_t column,
		 size_t end_line, size_t end_column,
		 const char *type, const char *msg)
{
	char linebuf[1024];
	char filebuf[PATH_MAX + 1];

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
		 size_t line, size_t column,
		 size_t end_line, size_t end_column,
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

	dt_print_at_msg(dt, line, column, end_line, end_column, type, str);
}

void dt_warning_at(struct yaml_dt_state *dt,
		 size_t line, size_t column,
		 size_t end_line, size_t end_column,
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

	dt_print_at_msg(dt, line, column, end_line, end_column, "warning", str);
	dt->error_flag = true;
}

void dt_error_at(struct yaml_dt_state *dt,
		 size_t line, size_t column,
		 size_t end_line, size_t end_column,
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

	dt_print_at_msg(dt, line, column, end_line, end_column, "error", str);
	dt->error_flag = true;
}

void dt_debug(struct yaml_dt_state *dt, const char *fmt, ...)
{
	va_list ap;

	if (!dt->debug)
		return;

	va_start(ap, fmt);
	vfprintf(stderr, fmt, ap);
	va_end(ap);
}

static struct option opts[] = {
	{ "output",	required_argument, 0, 'o' },
	{ "debug",	no_argument, 0, 'd' },
	{ "compatible",	no_argument, 0, 'C' },
	{ "yaml",	no_argument, 0, 'y' },
	{ "help",	no_argument, 0, 'h' },
	{ "version",    no_argument, 0, 'v' },
	{0, 0, 0, 0}
};

static void help(void)
{
	printf("yamldt [options] <input-file>\n"
		" options are:\n"
		"   -o, --output	Output DTB or YAML file\n"
		"   -d, --debug		Debug messages\n"
		"   -y, --yaml		Generate YAML output\n"
		"   -C, --compatible	Bit exact compatibility mode\n"
		"   -h, --help		Help\n"
		"   -v, --version	Display version\n"
		);
}

int main(int argc, char *argv[])
{
	struct yaml_dt_state dt_state, *dt = &dt_state;
	int err;
	int cc, option_index = 0;
	const char *input_file = NULL;
	const char *output_file = NULL;
	bool debug = false, compatible = false, yaml = false;

	memset(dt, 0, sizeof(*dt));

	while ((cc = getopt_long(argc, argv,
			"o:Cydvh?", opts, &option_index)) != -1) {
		switch (cc) {
		case 'o':
			output_file = optarg;
			break;
		case 'd':
			debug = true;
			break;
		case 'C':
			compatible = true;
			break;
		case 'y':
			yaml = true;
			break;
		case 'v':
			printf("%s version %s\n", PACKAGE_NAME, VERSION);
			return 0;
		case 'h':
		case '?':
			help();
			return 0;
		}
	}

	if (!output_file) {
		fprintf(stderr, "Missing output file\n");
		return EXIT_FAILURE;
	}

	if (optind >= argc) {
		fprintf(stderr, "Missing input file argument\n");
		return EXIT_FAILURE;
	}
	input_file = argv[optind];

	err = dt_setup(dt, input_file, output_file, debug, compatible, yaml);
	if (err)
		return EXIT_FAILURE;

	dt_parse(dt);

	dt_cleanup(dt, dt->error_flag);

	return 0;
}
