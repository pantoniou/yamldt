/*
 * dtsparser.h - General purpose DTS parser header
 *
 * Disects and emits DTS tokens
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

#ifndef DTSPARSER_H
#define DTSPARSER_H

enum file_state {
	s_start,
	s_headers,
	s_memreserves,
	s_slash,
	s_in_c_comment,
	s_in_cpp_comment,
	s_preproc,
	s_nodes_and_properties,
	s_nodes_and_properties_marker,
	s_node_ref,
	s_node_pathref,
	s_refnode_start,
	s_semicolon,
	s_property,
	s_string,
	s_string_ref,
	s_slash_directive,
	s_property_bits,
	s_array,
	s_byte,
	s_item_ref,
	s_item_expr,
	s_item_char,
	s_item_int,
	s_item_macro,
	s_item_macro_args,
	s_item_pathref,
	s_include,
	s_include_arg,
	s_node_del,
	s_node_del_ref,
	s_node_del_pathref,
	s_node_del_name,
	s_prop_del,
	s_prop_del_name,

	s_first = s_start,
	s_last = s_prop_del_name,
};

enum dts_message_type {
	dmt_info,
	dmt_warning,
	dmt_error,
};

enum dts_emit_atom {
	dea_int,
	dea_char,
	dea_expr,
	dea_byte,
	dea_string,
	dea_stringref,
	dea_name,
	dea_label,
	dea_ref,
	dea_pathref,
	dea_bits,
	dea_array_start,
	dea_array_end,
	dea_bytestring_start,
	dea_bytestring_end,
	dea_comment,

	dea_first_scalar = dea_int,
	dea_last_scalar = dea_stringref,
};

static inline bool is_scalar_atom(enum dts_emit_atom atom)
{
	return atom >= dea_int && atom <= dea_last_scalar;
}

static inline bool is_array_item_atom(enum dts_emit_atom atom)
{
	return atom == dea_int || atom == dea_char || atom == dea_expr ||
	       atom == dea_ref || atom == dea_pathref;
}

static inline bool is_bytestring_item_atom(enum dts_emit_atom atom)
{
	return atom == dea_byte;
}

static inline bool is_string_atom(enum dts_emit_atom atom)
{
	return atom == dea_string || atom == dea_stringref;
}

static inline bool is_seqstart_atom(enum dts_emit_atom atom)
{
	return atom == dea_array_start || atom == dea_bytestring_start;
}

struct dts_location {
	const char *filename;
	int start_line, start_col;
	int end_line, end_col;
};

struct dts_emit_item {
	enum dts_emit_atom atom;
	const char *contents;
	struct dts_location loc;
};

enum dts_emit_type {
	det_separator,
	det_comment,
	det_preproc,
	det_memreserve,
	det_property,
	det_node,
	det_include,
	det_incbin,
	det_del_node,
	det_del_prop,
	det_plugin,
	det_node_empty,	/* special marker for empty node */
};

struct dts_ops;

struct dts_property_item {
	const struct dts_emit_item *bits;
	int nr_elems;
	const struct dts_emit_item *elems[];
};

struct dts_emit_data {
	union {
		const struct dts_emit_item *comment;
		const struct dts_emit_item *preproc;
		const struct dts_emit_item *include;
		const struct dts_emit_item *memreserves[2];
		const struct dts_emit_item *del_node;
		const struct dts_emit_item *del_prop;
		struct {
			const struct dts_emit_item *name;
			int nr_labels;
			const struct dts_emit_item **labels;
			/* bellow only for prop */
			int nr_items;
			const struct dts_property_item **items;
		} pn;	/* prop node */
	};
};

struct dts_state {
	char *filename;

	struct acc_state acc_body;
	struct dts_location acc_loc;

	struct acc_state acc_comm;
	struct dts_location comm_loc;

	const struct dts_ops *ops;

	enum file_state fs;
	enum file_state pre_slash_fs;
	enum file_state pre_preproc_fs;
	bool start_root;
	bool refroot;
	int depth;
	bool node_empty;
	char last_c;
	int line;
	int col;
	int tabs;

	int expr_nest;

	int nr_items;
	struct list_head items;
};

struct dts_ops {
	void (*debugf)(struct dts_state *ds, const char *fmt, ...)
			__attribute__ ((__format__ (__printf__, 2, 0)));
	void (*messagef)(struct dts_state *ds, enum dts_message_type type,
			const struct dts_location *loc, const char *fmt, ...)
			__attribute__ ((__format__ (__printf__, 4, 0)));
	int (*emit)(struct dts_state *ds, int depth,
			enum dts_emit_type, const struct dts_emit_data *data);
};

#define dts_debug(_ds, _fmt, ...) \
	do { \
		if ((_ds)->ops->debugf) \
			(_ds)->ops->debugf((_ds), (_fmt), \
				##__VA_ARGS__); \
	} while(0)

#define dts_message(_ds, _type, _fmt, ...) \
	do { \
		if ((_ds)->ops->messagef) \
			(_ds)->ops->messagef((_ds), (_type), NULL, (_fmt), \
				##__VA_ARGS__); \
	} while(0)

#define dts_info(_ds, _fmt, ...) \
	dts_message(_ds, dmt_info, _fmt, ##__VA_ARGS__)

#define dts_warning(_ds, _fmt, ...) \
	dts_message(_ds, dmt_warning, _fmt, ##__VA_ARGS__)

#define dts_error(_ds, _fmt, ...) \
	dts_message(_ds, dmt_error, _fmt, ##__VA_ARGS__)

#define dts_message_at(_ds, _type, _loc, _fmt, ...) \
	do { \
		if ((_ds)->ops->messagef) \
			(_ds)->ops->messagef((_ds), (_type), (_loc), (_fmt), \
				##__VA_ARGS__); \
	} while(0)

#define dts_info_at(_ds, _loc, _fmt, ...) \
	dts_message_at(_ds, dmt_info, _loc, _fmt, ##__VA_ARGS__)

#define dts_warning_at(_ds, _loc, _fmt, ...) \
	dts_message_at(_ds, dmt_warning, _loc, _fmt, ##__VA_ARGS__)

#define dts_error_at(_ds, _loc, _fmt, ...) \
	dts_message_at(_ds, dmt_error, _loc, _fmt, ##__VA_ARGS__)

int dts_setup(struct dts_state *ds, const char *filename, int tabs,
		const struct dts_ops *ops);
void dts_cleanup(struct dts_state *ds);

int dts_feed(struct dts_state *ds, char c);
const char *dts_get_filename(struct dts_state *ds);
const char *dts_get_state(struct dts_state *ds);
int dts_get_line(struct dts_state *ds);
int dts_get_column(struct dts_state *ds);
int dts_get_token_line(struct dts_state *ds);
int dts_get_token_column(struct dts_state *ds);
;
#endif
