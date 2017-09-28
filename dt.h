/*
 * dt.h - DT header for methods
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

#ifndef DT_H
#define DT_H

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

#include "dtsparser.h"

/* should be enough */
#define YAMLDL_PROP_SEQ_TAG_DEPTH_MAX	128

struct dt_yaml_mark {
	yaml_mark_t start;
	yaml_mark_t end;
};

static inline bool dt_mark_is_unset(const struct dt_yaml_mark *m)
{
	return m->start.index == 0 && m->end.index == 0;
}

struct dt_node {
	struct node n;
	struct dt_yaml_mark m;
};
#define to_dt_node(_n) 	container_of(_n, struct dt_node, n)
#define to_node(_np)	(&(_np)->n)

struct dt_property {
	struct property p;
	struct dt_yaml_mark m;
};
#define to_dt_property(_p) 	container_of(_p, struct dt_property, p)
#define to_property(_prop)	(&(_prop)->p)

struct dt_ref {
	struct ref r;
	struct dt_yaml_mark m;
	const char *tag;	/* tag after implicit resolve */
	unsigned long long val;
	bool is_int : 1;
	bool is_str : 1;
	bool is_bool : 1;
	bool is_null : 1;
	bool is_resolved : 1;
	bool is_builtin_tag : 1;
	bool is_hex : 1;
	bool is_unsigned : 1;
	struct node *npref;	/* r_anchor, r_path */
	const char *use_label;
	void *alloc_data;
	void *binary;		/* to avoid costly conversions */
	size_t binary_size;
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
	int color;
	bool save_temps;
	bool sort;
	bool force;
	char * const *search_path;

	/* for dtb & yaml */
	bool object;

	/* for dtb */
	bool compatible;
	bool symbols;
	bool force_boot_cpuid;
	unsigned int quiet;
	unsigned int reserve;
	unsigned int space;
	unsigned int align;
	unsigned int pad;
	unsigned int out_version;
	unsigned int boot_cpuid;
	const char *depname;
	const char *schema;
	const char *schema_save;
	const char *codegen;
	const char *input_format;
	const char *output_format;
	const char *phandle_format;
};

struct yaml_dt_input {
	struct list_head node;
	char *name;
	void *content;
	size_t size;
	size_t pos;

	struct yaml_dt_input *parent;
	struct list_head includes;

	bool dts;		/* set to true when DTS source */
};

struct yaml_dt_span {
	struct list_head node;
	const struct yaml_dt_input *in;
	size_t start_pos;
	size_t end_pos;
	struct dt_yaml_mark m;
};

struct yaml_dt_state;
struct yaml_dt_config;

struct yaml_dt_emitter_ops {
	int (*setup)(struct yaml_dt_state *dt);
	void (*cleanup)(struct yaml_dt_state *dt);
	int (*emit)(struct yaml_dt_state *dt);
};

struct yaml_dt_emitter {
	struct list_head node;
	const char *name;
	const char * const *suffixes;
	const struct tree_ops *tops;
	const struct yaml_dt_emitter_ops *eops;
};

struct yaml_dt_checker_ops {
	int (*setup)(struct yaml_dt_state *dt);
	void (*cleanup)(struct yaml_dt_state *dt);
	int (*check)(struct yaml_dt_state *dt);
};

struct yaml_dt_checker {
	struct list_head node;
	const char *name;
	const struct yaml_dt_checker_ops *cops;
};

struct yaml_dt_state {
	struct yaml_dt_state *parent;
	struct list_head node;
	char *name;
	struct list_head children;

	struct yaml_dt_config cfg;
	char *input_compiler_tag;
	char *output_compiler_tag;

	FILE *output;

	int curr_input_file;
	size_t curr_input_pos;
	size_t curr_input_line;
	size_t curr_input_column;
	size_t last_input_pos;
	size_t last_input_line;
	size_t last_input_column;

	struct yaml_dt_input *curr_in;
	struct list_head inputs;
	struct yaml_dt_span *curr_span;
	struct dt_yaml_mark curr_span_mark;
	struct list_head spans;

	char **alloc_argv;

	/* yaml parser state */
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
	int bare_seq;
	int bare_map;
	bool stream_ended;

	/* emitter data */
	bool error_on_failed_get;
	bool error_flag;

	/* tree build state (initialized by the emitter) */
	struct tree tree;
	const struct yaml_dt_emitter *emitter;
	void *emitter_state;
	void *emitter_cfg;

	const struct yaml_dt_checker *checker;
	void *checker_state;
	void *checker_cfg;

	/* dts parser */
	struct dts_state ds;
	bool dts_initialized;
	FILE *dep_output;
};

#define to_dt(_t) 	container_of(_t, struct yaml_dt_state, tree)
#define to_tree(_dt)	(&(_dt)->tree)

static inline bool dt_get_error_flag(struct yaml_dt_state *dt)
{
	return dt->error_flag;
}

static inline void dt_set_error_flag(struct yaml_dt_state *dt, bool error)
{
	dt->error_flag = error;
}

static inline bool dt_get_error_on_failed_get(struct yaml_dt_state *dt)
{
	return dt->error_on_failed_get;
}

static inline void dt_set_error_on_failed_get(struct yaml_dt_state *dt, bool error)
{
	dt->error_on_failed_get = error;
}

void dt_debug(struct yaml_dt_state  *dt, const char *fmt, ...)
		__attribute__ ((__format__ (__printf__, 2, 0)));

void dt_info(struct yaml_dt_state  *dt, const char *fmt, ...)
		__attribute__ ((__format__ (__printf__, 2, 0)));

void dt_error(struct yaml_dt_state  *dt, const char *fmt, ...)
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
			      const void *data, int len, const char *xtag,
			      int size);
void yaml_dt_ref_free(struct tree *t, struct ref *ref);

struct property *yaml_dt_prop_alloc(struct tree *t, const char *name,
				    int size);
void yaml_dt_prop_free(struct tree *t, struct property *prop);

struct label *yaml_dt_label_alloc(struct tree *t, const char *name,
				  int size);
void yaml_dt_label_free(struct tree *t, struct label *l);

struct node *yaml_dt_node_alloc(struct tree *t, const char *name,
				const char *label, int size);
void yaml_dt_node_free(struct tree *t, struct node *np);

void yaml_dt_tree_debugf(struct tree *t, const char *fmt, ...)
		__attribute__ ((__format__ (__printf__, 2, 0)));
void yaml_dt_tree_error_at_node(struct tree *t, struct node *np,
		const char *fmt, ...)
		__attribute__ ((__format__ (__printf__, 3, 0)));
void yaml_dt_tree_error_at_property(struct tree *t, struct property *prop,
		const char *fmt, ...)
		__attribute__ ((__format__ (__printf__, 3, 0)));
void yaml_dt_tree_error_at_ref(struct tree *t, struct ref *ref,
		const char *fmt, ...)
		__attribute__ ((__format__ (__printf__, 3, 0)));
void yaml_dt_tree_error_at_label(struct tree *t, struct label *l,
		const char *fmt, ...)
		__attribute__ ((__format__ (__printf__, 3, 0)));

int dt_setup(struct yaml_dt_state *dt, struct yaml_dt_config *cfg, 
	     struct yaml_dt_emitter *emitter, struct yaml_dt_checker *checker);
int dt_parse(struct yaml_dt_state *dt);
int dt_emitter_emit(struct yaml_dt_state *dt);
int dt_checker_check(struct yaml_dt_state *dt);
void dt_cleanup(struct yaml_dt_state *dt, bool abnormal);

struct yaml_dt_state *dt_parse_single(struct yaml_dt_state *dt,
		const char *input, const char *output, const char *name);
int dt_resolve_ref(struct yaml_dt_state *dt, struct ref *ref);

struct node *dt_get_node(struct yaml_dt_state *dt,
			    struct node *parent, const char *name,
			    int index);
struct property *dt_get_property(struct yaml_dt_state *dt,
			    struct node *np, const char *name,
			    int index);
struct ref *dt_get_ref(struct yaml_dt_state *dt,
		struct property *prop, int index);

int dt_get_rcount(struct yaml_dt_state *dt, struct node *np,
		  const char *name, int pindex);

const char *dt_ref_string(struct yaml_dt_state *dt, struct ref *ref);
const char *dt_get_string(struct yaml_dt_state *dt, struct node *np,
			  const char *name, int pindex, int rindex);

unsigned long long dt_ref_int(struct yaml_dt_state *dt, struct ref *ref,
			      int *error);
unsigned long long dt_get_int(struct yaml_dt_state *dt, struct node *np,
			  const char *name, int pindex, int rindex, int *error);

int dt_ref_bool(struct yaml_dt_state *dt, struct ref *ref);
int dt_get_bool(struct yaml_dt_state *dt, struct node *np,
		 const char *name, int pindex, int rindex);

const void *dt_ref_binary(struct yaml_dt_state *dt, struct ref *ref,
			  size_t *binary_size);
const void *dt_get_binary(struct yaml_dt_state *dt, struct node *np,
			  const char *name, int pindex, int rindex,
			  size_t *binary_size);

struct node *dt_ref_noderef(struct yaml_dt_state *dt, struct ref *ref);
struct node *dt_get_noderef(struct yaml_dt_state *dt, struct node *np,
			     const char *name, int pindex, int rindex);

#endif
