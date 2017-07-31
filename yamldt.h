/*
 * yamldt.h - YAML DT header
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

#ifndef YAMLDT_H
#define YAMLDT_H

#include "config.h"

#include <stdint.h>
#include <sys/time.h>
#ifdef __linux__
#include <linux/limits.h>
#else
#include <limits.h>
#endif

#include <yaml.h>

#include "list.h"
#include "libfdt_env.h"
#include "fdt.h"

#include "tree.h"
#include "dtbgen.h"
#include "yamlgen.h"

/* should be enough */
#define YAMLDL_PROP_SEQ_TAG_DEPTH_MAX	128

struct dt_yaml_mark {
	yaml_mark_t start;
	yaml_mark_t end;
};

struct dt_node {
	struct node n;
	struct dt_yaml_mark m;
};
#define to_dt_node(_n) 	container_of(_n, struct dt_node, n)
#define to_node(_np)		(&(_np)->n)

struct dt_property {
	struct property p;
	struct dt_yaml_mark m;
};
#define to_dt_property(_p) 	container_of(_p, struct dt_property, p)
#define to_property(_prop)	(&(_prop)->p)

struct dt_ref {
	struct ref r;
	struct dt_yaml_mark m;
};
#define to_dt_ref(_r) 		container_of(_r, struct dt_ref, r)
#define to_ref(_ref)		(&(_ref)->r)

struct dt_label {
	struct label l;
	struct dt_yaml_mark m;
};
#define to_dt_label(_l) 	container_of(_l, struct dt_label, l)
#define to_label(_label)	(&(_label)->l)

struct yaml_dt_config {
	char * const *input_file;
	int input_file_count;
	const char *output_file;
	bool debug;
	bool compatible;
	bool yaml;
	bool late;
	bool object;
};

struct input {
	struct list_head node;
	char *name;
	size_t size;
	size_t start;
	size_t start_line;
	size_t lines;
};

struct yaml_dt_state {
	/* yaml parser state */
	bool debug;
	bool compatible;	/* bit exact mode */
	bool yaml;		/* generate YAML */
	bool late;		/* late resolution mode */
	bool object;		/* object mode */
	const char *output_file;
	FILE *output;
	void *input_content;
	size_t input_size;	/* including fake document markers */
	size_t input_alloc;
	size_t input_lines;
	struct list_head inputs;

	unsigned char *buffer;
	size_t buffer_pos;
	size_t buffer_read;
	size_t buffer_alloc;
	char current_file[PATH_MAX + 1];
	long current_line;
	long current_col;
	long global_line;
	bool last_was_marker;

	yaml_parser_t parser;
	yaml_event_t *current_event;
	struct dt_yaml_mark current_mark;
	struct dt_yaml_mark last_map_mark;
	struct dt_yaml_mark last_alias_mark;

	struct node *current_np;
	bool current_np_isref;
	struct property *current_prop;
	bool current_prop_existed; 
	char *map_key;
	int depth;
	int prop_seq_depth;
	char *prop_seq_tag[YAMLDL_PROP_SEQ_TAG_DEPTH_MAX];
	bool current_np_ref;

	bool error_flag;

	/* tree build state (initialized by the emitter) */
	struct tree tree;
	void *emitter_config;
	void *emitter_state;
};

#define to_dt(_t) 	container_of(_t, struct yaml_dt_state, tree)
#define to_tree(_dt)	(&(_dt)->tree)

void dt_debug(struct yaml_dt_state  *dt, const char *fmt, ...)
		__attribute__ ((__format__ (__printf__, 2, 0)));

void dt_fatal(struct yaml_dt_state  *dt, const char *fmt, ...)
		__attribute__ ((__format__ (__printf__, 2, 0)))
		__attribute__ ((noreturn));

void dt_print_at(struct yaml_dt_state *dt,
		 const struct dt_yaml_mark *m,
		 const char *type, const char *fmt, ...)
			__attribute__ ((__format__ (__printf__, 4, 0)));

void dt_error_at(struct yaml_dt_state *dt,
		 const struct dt_yaml_mark *m,
		 const char *fmt, ...)
			__attribute__ ((__format__ (__printf__, 3, 0)));

void dt_warning_at(struct yaml_dt_state *dt,
		   const struct dt_yaml_mark *m,
		   const char *fmt, ...)
		   __attribute__ ((__format__ (__printf__, 3, 0)));

/* common tree hooks (called by emitters) */
struct ref *yaml_dt_ref_alloc(struct tree *t, enum ref_type type,
			      const void *data, int len, const char *xtag);
void yaml_dt_ref_free(struct tree *t, struct ref *ref);

struct property *yaml_dt_prop_alloc(struct tree *t, const char *name);
void yaml_dt_prop_free(struct tree *t, struct property *prop);

struct label *yaml_dt_label_alloc(struct tree *t, const char *name);
void yaml_dt_label_free(struct tree *t, struct label *l);

struct node *yaml_dt_node_alloc(struct tree *t, const char *name,
				const char *label);
void yaml_dt_node_free(struct tree *t, struct node *np);

void yaml_dt_tree_debugf(struct tree *t, const char *fmt, ...)
		__attribute__ ((__format__ (__printf__, 2, 0)));

#endif
