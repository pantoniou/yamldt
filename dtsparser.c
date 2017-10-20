/*
 * dtsparser.c - General purpose DTS parser
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
#include <assert.h>

#include "utils.h"
#include "list.h"

#include "dtsparser.h"

static inline bool ispropnodec(char c)
{
	return c == ',' || c == '.' || c == '_' || c == '+' || c == '*' ||
	       c == '#' || c == '?' || c == '@' || c == '-' || isalnum(c);
}

static inline bool ispathc(char c)
{
	return c == '/' || ispropnodec(c);
}

static inline bool islabelc(char c, bool first)
{
	return c == '_' || (first ? isalpha(c) : isalnum(c));
}

static inline bool ismacroc(char c, bool first)
{
	return islabelc(c, first);
}

static inline bool state_with_comments(enum file_state fs)
{
	return fs != s_slash && fs != s_slash_directive &&
	       fs != s_string && fs != s_item_char &&
	       fs != s_in_c_comment && fs != s_in_cpp_comment &&
	       fs != s_include_arg &&
	       fs != s_backslash && fs != s_backslash_space &&
	       fs != s_incbin_file;
}

static inline bool state_with_preproc(enum file_state fs)
{
	return state_with_comments(fs) && fs != s_hash && fs != s_preproc;
}

static inline bool is_valid_final_state(enum file_state fs)
{
	return fs == s_start || fs == s_headers || fs == s_nodes_and_properties;
}

static inline bool is_valid_preproc_state(enum file_state fs)
{
	return fs == s_start || fs == s_headers || fs == s_nodes_and_properties;
}

static const char *states_txt[] = {
	[s_start]			= "start",
	[s_headers]			= "headers",
	[s_memreserves]			= "memreserves",
	[s_slash]			= "slash",
	[s_in_c_comment]		= "in_c_comment",
	[s_in_cpp_comment]		= "in_cpp_comment",
	[s_preproc]			= "preproc",
	[s_hash]			= "hash",
	[s_backslash]			= "backslash",
	[s_backslash_space]		= "backslash_space",
	[s_nodes_and_properties]	= "nodes_and_properties",
	[s_nodes_and_properties_marker]	= "nodes_and_properties_marker",
	[s_node_ref]			= "node_ref",
	[s_node_pathref]		= "node_pathref",
	[s_refnode_start]		= "refnode_start",
	[s_semicolon]			= "semicolon",
	[s_property]			= "property",
	[s_string]			= "string",
	[s_string_ref]			= "string_ref",
	[s_slash_directive]		= "slash_directive",
	[s_property_bits]		= "property_bits",
	[s_array]			= "array",
	[s_byte]			= "byte",
	[s_item_ref]			= "item_ref",
	[s_item_expr]			= "item_expr",
	[s_item_char]			= "item_char",
	[s_item_int]			= "item_int",
	[s_item_macro]			= "item_macro",
	[s_item_macro_args]		= "item_macro_args",
	[s_item_pathref]		= "item_pathref",
	[s_include]			= "include",
	[s_include_arg]			= "include_arg",
	[s_node_del]			= "node_del",
	[s_node_del_ref]		= "node_del_ref",
	[s_node_del_pathref]		= "node_del_pathref",
	[s_node_del_name]		= "node_del_name",
	[s_prop_del]			= "prop_del",
	[s_prop_del_name]		= "prop_del_name",
	[s_prop_macro]			= "prop_macro",
	[s_prop_macro_args]		= "prop_macro_args",
	[s_incbin]			= "incbin",
	[s_incbin_arg]			= "incbin_arg",
	[s_incbin_file]			= "incbin_file",
	[s_incbin_file_comma]		= "incbin_file_comma",
	[s_incbin_offset]		= "incbin_offset",
	[s_incbin_offset_comma]		= "incbin_offset_comma",
	[s_incbin_size]			= "incbin_size",
	[s_incbin_end]			= "incbin_end",
};

struct dts_emit_list_item {
	struct list_head node;
	struct dts_emit_item item;
	char data[];
};

struct dts_property_list_item {
	struct list_head node;
	struct dts_property_item item;
};

static int (*states[])(struct dts_state *ds, char c);

static void reset_accumulator(struct dts_state *ds)
{
	acc_reset(&ds->acc_body);
	ds->acc_loc.filename = NULL;
}

static int accumulate(struct dts_state *ds, char c)
{
	int ret;

	if (acc_get_size(&ds->acc_body) == 0) {
		ds->acc_loc.filename = ds->filename;
		ds->acc_loc.start_index = ds->index;
		ds->acc_loc.start_line = ds->line;
		ds->acc_loc.start_col = ds->col;
	}
	ret = acc_add(&ds->acc_body, c);
	if (ret) {
		dts_error(ds, "out of memory\n");
		return -1;
	}

	ds->acc_loc.end_index = ds->index;
	ds->acc_loc.end_line = ds->line;
	ds->acc_loc.end_col = ds->col;
	return 0;
}

static const char *get_accumulator(struct dts_state *ds)
{
	return acc_get(&ds->acc_body);
}

static int get_accumulator_size(struct dts_state *ds)
{
	return acc_get_size(&ds->acc_body);
}

static void reset_comment_accumulator(struct dts_state *ds)
{
	acc_reset(&ds->acc_comm);
	ds->comm_loc.filename = NULL;
}

static int comment_accumulate(struct dts_state *ds, char c)
{
	int ret;

	if (acc_get_size(&ds->acc_comm) == 0) {
		ds->comm_loc.filename = ds->filename;
		ds->comm_loc.start_index = ds->index;
		ds->comm_loc.start_line = ds->line;
		ds->comm_loc.start_col = ds->col;
	}
	ret = acc_add(&ds->acc_comm, c);
	if (ret) {
		dts_error(ds, "out of memory\n");
		return -1;
	}
	ds->comm_loc.end_index = ds->index;
	ds->comm_loc.end_line = ds->line;
	ds->comm_loc.end_col = ds->col;
	return 0;
}

static const char *get_comment_accumulator(struct dts_state *ds)
{
	return acc_get(&ds->acc_comm);
}

static int get_comment_accumulator_size(struct dts_state *ds)
{
	return acc_get_size(&ds->acc_comm);
}

static void goto_state(struct dts_state *ds, enum file_state fs)
{
	if (fs != ds->fs)
		dts_debug(ds, "state change from %s -> %s\n",
				states_txt[ds->fs],
				states_txt[fs]);
	ds->fs = fs;
}

static int handle_comment(struct dts_state *ds, char c)
{
	if (c == '/') {
		ds->pre_slash_fs = ds->fs;
		goto_state(ds, s_slash);
		return 1;
	}
	if (c == '\\') {
		ds->pre_backslash_fs = ds->fs;
		goto_state(ds, s_backslash);
		return 1;
	}
	return 0;
}

static int handle_preproc(struct dts_state *ds, char c)
{
	if (c != '#')
		return 0;

	if (get_accumulator_size(ds))
		return 0;

	/* preproc or property name starting with # */
	ds->pre_preproc_fs = ds->fs;
	goto_state(ds, s_hash);
	reset_accumulator(ds);
	accumulate(ds, '#');
	return 1;
}

static int is_string_or_char_done(const char *buf, int len, char c, char termc)
{
	char *tbuf = alloca(len + 1 + 1);
	int elen;

	elen = esc_strlen(buf);

	if (c == termc && elen >= 0)
		return 1;

	strcpy(tbuf, buf);
	tbuf[len] = c;
	tbuf[len + 1] = '\0';
	len++;

	elen = esc_strlen(tbuf);

	return (elen >= 0 || elen == -2) ? 0 : -1;
}

static struct dts_emit_list_item *
item_from_accumulator(struct dts_state *ds, enum dts_emit_atom atom)
{
	char *p;
	int data_size;
	struct dts_emit_list_item *li;
	const char *buf = get_accumulator(ds);
	int len = get_accumulator_size(ds);

	data_size = len + 1 + ds->filename_len + 1;

	li = malloc(sizeof(*li) + data_size);
	if (!li) {
		dts_error(ds, "out of memory\n");
		return NULL;
	}

	p = li->data;
	li->item.atom = atom;
	li->item.contents = p;
	memcpy(p, buf, len);
	p += len;
	*p++ = '\0';
	li->item.loc.filename = p;
	memcpy(p, ds->filename, ds->filename_len);
	p += ds->filename_len;
	*p++ = '\0';
	li->item.loc.start_index = ds->acc_loc.start_index;
	li->item.loc.end_index = ds->acc_loc.end_index;
	li->item.loc.start_line = ds->acc_loc.start_line;
	li->item.loc.start_col = ds->acc_loc.start_col;
	li->item.loc.end_line = ds->acc_loc.end_line;
	li->item.loc.end_col = ds->acc_loc.end_col;

	list_add_tail(&li->node, &ds->items);

	return li;
}

static struct dts_emit_list_item *
item_from_comment_accumulator(struct dts_state *ds)
{
	char *p;
	int data_size;
	struct dts_emit_list_item *li;
	const char *buf = get_comment_accumulator(ds);
	int len = get_comment_accumulator_size(ds);

	data_size = len + 1 + ds->filename_len + 1;

	li = malloc(sizeof(*li) + data_size);
	if (!li) {
		dts_error(ds, "out of memory\n");
		return NULL;
	}

	p = li->data;
	li->item.atom = dea_comment;
	li->item.contents = p;
	memcpy(p, buf, len);
	p += len;
	*p++ = '\0';
	li->item.loc.filename = p;
	strcpy(p, ds->filename);
	memcpy(p, ds->filename, ds->filename_len);
	p += ds->filename_len;
	*p++ = '\0';
	li->item.loc.start_index = ds->comm_loc.start_index;
	li->item.loc.end_index = ds->comm_loc.end_index;
	li->item.loc.start_line = ds->comm_loc.start_line;
	li->item.loc.start_col = ds->comm_loc.start_col;
	li->item.loc.end_line = ds->comm_loc.end_line;
	li->item.loc.end_col = ds->comm_loc.end_col;

	list_add_tail(&li->node, &ds->items);

	return li;
}

static void reset_item_list(struct dts_state *ds)
{
	struct dts_emit_list_item *li, *lin;

	list_for_each_entry_safe(li, lin, &ds->items, node) {
		list_del(&li->node);
		free(li);
	}
}

static int dts_generate_property_items(struct dts_state *ds,
		struct list_head *lh)
{
	struct dts_emit_list_item *li, *lit, *li_bits;
	enum dts_emit_atom atom, end_atom;
	int nr_elems, size;
	bool found_end_atom;
	struct dts_property_list_item *pli;

	/* first count items */
	li_bits = NULL;
	list_for_each_entry(li, &ds->items, node) {
		atom = li->item.atom;

		/* skip comments completely */
		if (atom == dea_comment)
			continue;

		if (atom == dea_bits) {
			li_bits = li;

		} else if (is_string_atom(atom) || atom == dea_expr) {

			lit = li;

			/* count string items and check */
			nr_elems = 1;

			/* macros can't be grouped */
			if (atom != dea_expr) {
				list_for_each_entry_continue(li, &ds->items, node) {
					atom = li->item.atom;
					if (atom == dea_comment)
						continue;
					if (!is_string_atom(atom))
						break;
					nr_elems++;
				}
			}

			size = sizeof(*pli) +
			       sizeof(pli->item.elems[0]) * nr_elems;
			pli = malloc(size);
			if (!pli) {
				dts_error(ds, "out of memory");
				return -1;
			}
			pli->item.bits = NULL;
			pli->item.nr_elems = nr_elems;

			li = lit;
			nr_elems = 0;
			pli->item.elems[nr_elems++] = &li->item;
			if (nr_elems < pli->item.nr_elems) {
				list_for_each_entry_continue(li, &ds->items, node) {
					atom = li->item.atom;
					if (atom == dea_comment)
						continue;
					pli->item.elems[nr_elems++] = &li->item;
					if (nr_elems >= pli->item.nr_elems)
						break;
				}
			}

			list_add_tail(&pli->node, lh);

			li_bits = NULL;

		} else if (is_seqstart_atom(atom)) {

			end_atom = atom == dea_array_start ? dea_array_end : dea_bytestring_end;
			found_end_atom = false;
			nr_elems = 0;

			lit = li;

			/* count items and check */
			list_for_each_entry_continue(li, &ds->items, node) {
				atom = li->item.atom;
				if (atom == dea_comment)
					continue;
				if (atom == end_atom) {
					found_end_atom = true;
					break;
				}
				/* valid item? */
				if ((end_atom == dea_array_end &&
					is_array_item_atom(atom)) ||
				    (end_atom == dea_bytestring_end &&
					is_bytestring_item_atom(atom))) {
					nr_elems++;
				} else {
					dts_error_at(ds, &li->item.loc,
						     "bad array item\n");
					return -1;
				}
			}
			if (!found_end_atom) {
				dts_error(ds, "no property sequence end\n");
				return -1;
			}

			/* allocate property item */
			size = sizeof(*pli) +
			       sizeof(pli->item.elems[0]) * nr_elems;
			pli = malloc(size);
			if (!pli) {
				dts_error(ds, "out of memory");
				return -1;
			}
			pli->item.bits = li_bits ? &li_bits->item : NULL;
			pli->item.nr_elems = nr_elems;

			/* fill in now */
			li = lit;
			nr_elems = 0;
			list_for_each_entry_continue(li, &ds->items, node) {
				atom = li->item.atom;
				if (atom == dea_comment)
					continue;
				if (atom == end_atom)
					break;
				pli->item.elems[nr_elems++] = &li->item;
			}

			list_add_tail(&pli->node, lh);

			li_bits = NULL;
		}
	}

	return 0;
}

static int dts_emit(struct dts_state *ds, enum dts_emit_type type)
{
	struct dts_emit_list_item *li;
	struct dts_property_list_item *pli, *plin;
	struct dts_emit_data d;
	int i, ret = 0, depth;
	struct list_head pi_list;

	depth = ds->depth;
	if (!ds->refroot && ds->start_root && depth > 0)
		depth--;

	INIT_LIST_HEAD(&pi_list);

	switch (type) {
	case det_plugin:
		/* TODO */
		reset_item_list(ds);
		return 0;
	case det_del_node:
		d.del_node = NULL;
		list_for_each_entry(li, &ds->items, node) {
			if (li->item.atom != dea_comment) {
				d.del_node = &li->item;
				break;
			}
		}
		assert(d.del_node);
		break;
	case det_del_prop:
		d.del_prop = NULL;
		list_for_each_entry(li, &ds->items, node) {
			if (li->item.atom != dea_comment) {
				d.del_prop = &li->item;
				break;
			}
		}
		assert(d.del_prop);
		break;
	case det_include:
		d.include = NULL;
		list_for_each_entry(li, &ds->items, node) {
			if (li->item.atom == dea_string) {
				d.include = &li->item;
				break;
			}
		}
		assert(d.include);
		break;
	case det_comment:
		d.comment = NULL;
		if (!list_is_singular(&ds->items)) {
			dts_error(ds, "bad comment emit\n");
			return -1;
		}
		li = list_first_entry(&ds->items, typeof(*li), node);
		d.comment = &li->item;
		break;
	case det_preproc:
		d.preproc = NULL;
		list_for_each_entry(li, &ds->items, node) {
			if (li->item.atom == dea_string) {
				d.preproc = &li->item;
				break;
			}
		}
		assert(d.preproc);
		break;
	case det_separator:
	case det_node_empty:
	case det_node_end:
		break;
	case det_memreserve:
		d.memreserves[0] = NULL;
		d.memreserves[1] = NULL;
		i = 0;
		list_for_each_entry(li, &ds->items, node) {
			/* verify not more than two and is an int */
			if (i >= 2 || li->item.atom != dea_int) {
				dts_error_at(ds, &li->item.loc,
					     "bad /memreserve/\n");
				return -1;
			}
			d.memreserves[i++] = &li->item;
		}
		break;
	case det_node:
		d.pn.name = NULL;
		d.pn.nr_labels = 0;
		d.pn.labels = NULL;
		d.pn.nr_items = 0;
		d.pn.items = NULL;
		list_for_each_entry(li, &ds->items, node) {
			switch (li->item.atom) {
			case dea_comment:
				break;
			case dea_label:
				d.pn.nr_labels++;
				break;
			case dea_ref:
			case dea_name:
			case dea_pathref:
				/* impossible but verify */
				assert(!d.pn.name);
				d.pn.name = &li->item;
				break;
			default:
				dts_error_at(ds, &li->item.loc,
					     "bad node item \"%s\" (%d)\n",
					     li->item.contents, li->item.atom);
				return -1;
			}
		}
		/* impossible to get here with this NULL, but check */
		assert(d.pn.name);

		if (d.pn.nr_labels) {
			d.pn.labels = malloc(sizeof(d.pn.labels[0]) * d.pn.nr_labels);
			if (!d.pn.labels) {
				dts_error(ds, "out of memory");
				ret = -1;
				break;
			}
			i = 0;
			list_for_each_entry(li, &ds->items, node) {
				if  (li->item.atom == dea_label)
					d.pn.labels[i++] = &li->item;
			}
		}

		break;

	case det_incbin:
		d.incbin.property = NULL;
		d.incbin.filename = NULL;
		d.incbin.offset = NULL;
		d.incbin.size = NULL;
		list_for_each_entry(li, &ds->items, node) {
			if (li->item.atom == dea_name) {
				d.incbin.property = &li->item;
			} else if (li->item.atom == dea_string) {
				d.incbin.filename = &li->item;
			} else if (li->item.atom == dea_int) {
				if (!d.incbin.offset)
					d.incbin.offset = &li->item;
				else if (!d.incbin.size)
					d.incbin.size = &li->item;
			}
		}
		assert(d.incbin.property);
		assert(d.incbin.filename);
		break;

	case det_property:
		d.pn.name = NULL;
		d.pn.nr_labels = 0;
		d.pn.labels = NULL;
		d.pn.nr_items = 0;
		d.pn.items = NULL;
		list_for_each_entry(li, &ds->items, node) {
			if (li->item.atom == dea_name) {
				/* impossible but verify */
				assert(!d.pn.name);
				d.pn.name = &li->item;
			}
		}
		assert(d.pn.name);

		ret = dts_generate_property_items(ds, &pi_list);
		if (ret)
			break;

		/* count items */
		d.pn.nr_items = 0;
		list_for_each_entry(pli, &pi_list, node)
			d.pn.nr_items++;

		if (d.pn.nr_items == 0)
			break;

		d.pn.items = malloc(sizeof(d.pn.items[0]) * d.pn.nr_items);
		if (!d.pn.items) {
			dts_error(ds, "out of memory");
			ret = -1;
			break;
		}
		i = 0;
		list_for_each_entry(pli, &pi_list, node)
			d.pn.items[i++] = &pli->item;
		break;
	}

	if (!ret && ds->ops->emit)
		ret = ds->ops->emit(ds, depth, type, &d);

	if (type == det_property || type == det_node) {
		list_for_each_entry_safe(pli, plin, &pi_list, node) {
			list_del(&pli->node);
			free(pli);
		}
		if (d.pn.items)
			free(d.pn.items);
		if (d.pn.labels)
			free(d.pn.labels);
	}

	reset_item_list(ds);

	return ret;
}

static int start(struct dts_state *ds, char c)
{
	int ret;

	if (isspace(c)) {
		/* newline at start of line? it's meant to separate */
		if (ds->col == 1 && c == '\n') {
			ret = dts_emit(ds, det_separator);
			if (ret)
				return ret;
		}
		return 0;
	}

	/* it's a dtsi, no flags */
	if (c == '/') {
		ds->start_root = true;
		accumulate(ds, c);
		goto_state(ds, s_nodes_and_properties_marker);
		return 0;
	}

	if (c == '&') {
		ds->refroot = true;
		goto_state(ds, s_node_ref);
		return 0;
	}

	if (ispropnodec(c)) {
		ds->start_root = false;
		accumulate(ds, c);
		goto_state(ds, s_nodes_and_properties);
		return 0;
	}

	dts_error(ds, "File flags expected (but missing)\n");
	return -1;
}

static int headers(struct dts_state *ds, char c)
{
	int ret;

	/* ignore ; */
	if (c == ';')
		return 0;

	if (isspace(c)) {
		/* newline at start of line? it's meant to separate */
		if (ds->col == 1 && c == '\n') {
			ret = dts_emit(ds, det_separator);
			if (ret)
				return ret;
		}
		return 0;
	}

	goto_state(ds, s_nodes_and_properties);
	return states[ds->fs](ds, (char)c);
}

static int memreserves(struct dts_state *ds, char c)
{
	const char *buf;
	struct dts_emit_list_item *li;
	int ret;

	if (isspace(c) || c == ';') {
		if (get_accumulator_size(ds) > 0) {
			buf = get_accumulator(ds);
			if (!get_accumulator_size(ds)) {
				dts_error(ds, "bad memreserve item %s\n", buf);
				return -1;
			}
			dts_debug(ds, "memreserve: %s\n", buf);
			li = item_from_accumulator(ds, dea_int);
			if (!li)
				return -1;
			reset_accumulator(ds);
		}
		if (c == ';') {
			ret = dts_emit(ds, det_memreserve);
			if (ret)
				return ret;
			goto_state(ds, s_headers);
		}
		return 0;
	}

	if (isxdigit(c) || ((c == 'x' || c == 'X') &&
			    !strcmp(get_accumulator(ds), "0"))) {
		accumulate(ds, c);
		return 0;
	}

	dts_error(ds, "Bad /memreserve/ character %c\n", c);
	return -1;
}

static int slash(struct dts_state *ds, char c)
{
	if (c == '/' || c == '*') {
		comment_accumulate(ds, '/');
		comment_accumulate(ds, c);
		goto_state(ds, c == '/' ? s_in_cpp_comment : s_in_c_comment);
		return 0;
	}

	accumulate(ds, '/');
	switch (ds->pre_slash_fs) {
	case s_start:
		/* / encountered */
		if (isspace(c)) {
			ds->start_root = true;
			goto_state(ds, s_nodes_and_properties);
			break;
		}
		if (c == '{') {
			ds->start_root = true;
			goto_state(ds, s_nodes_and_properties_marker);
			break;
		}
		if (!isalpha(c)) {
			dts_error(ds, "expecting /dts-v1/ but missing\n");
			return -1;
		}
		goto_state(ds, s_slash_directive);
		break;
	case s_headers:
		if (isalpha(c))
			goto_state(ds, s_slash_directive);
		else if (isspace(c)) {
			ds->start_root = true;
			goto_state(ds, s_nodes_and_properties);
		} else if (c == '{') {
			ds->start_root = true;
			goto_state(ds, s_nodes_and_properties_marker);
		} else {
			dts_error(ds, "bad headers '%c'\n", c);
			return -1;
		}
		break;
	case s_property:
		if (!isalpha(c)) {
			dts_error(ds, "expecting /bits/ directive\n");
			return -1;
		}
		goto_state(ds, s_slash_directive);
		break;
	case s_nodes_and_properties:
		/* not a directive, it's / again */
		if (get_accumulator_size(ds) == 1 && isspace(c)) {
			ds->start_root = true;
			goto_state(ds, ds->pre_slash_fs);
			break;
		}
		if (c == '{') {
			ds->start_root = true;
			goto_state(ds, s_nodes_and_properties_marker);
			break;
		}

		if (!isalpha(c)) {
			dts_error(ds, "bad slash directive\n");
			return -1;
		}
		goto_state(ds, s_slash_directive);
		break;
	default:
		goto_state(ds, ds->pre_slash_fs);
		break;
	}

	/* and pass to old state */
	return states[ds->fs](ds, (char)c);
}

static inline bool is_top_level_comment(struct dts_state *ds)
{
	enum file_state fs = ds->pre_slash_fs;

	return fs == s_headers || fs == s_start || fs == s_nodes_and_properties;
}

static int in_c_comment(struct dts_state *ds, char c)
{
	const char *buf;
	struct dts_emit_list_item *li;
	int ret;

	comment_accumulate(ds, c);
	if (ds->last_c != '*' || c != '/')
		return 0;

	if (get_comment_accumulator_size(ds) < 4)
		return 0;

	buf = get_comment_accumulator(ds);
	dts_debug(ds, "c comment: %s\n", buf);
	li = item_from_comment_accumulator(ds);
	if (!li)
		return -1;
	/* emit when we're a top level comment */
	if (is_top_level_comment(ds)) {
		ret = dts_emit(ds, det_comment);
		if (ret)
			return ret;
	}
	reset_comment_accumulator(ds);
	goto_state(ds, ds->pre_slash_fs);

	return 0;
}

static int in_cpp_comment(struct dts_state *ds, char c)
{
	const char *buf;
	struct dts_emit_list_item *li;
	int ret;

	if (c != '\n' || ds->last_c == '\\') {
		comment_accumulate(ds, c);
		return 0;
	}
	buf = get_comment_accumulator(ds);
	dts_debug(ds, "c++ comment: %s\n", buf);
	li = item_from_comment_accumulator(ds);
	if (!li)
		return -1;
	/* emit when we're a top level comment */
	if (is_top_level_comment(ds)) {
		ret = dts_emit(ds, det_comment);
		if (ret)
			return ret;
	}
	reset_comment_accumulator(ds);
	goto_state(ds, ds->pre_slash_fs);

	return 0;
}

static int preproc(struct dts_state *ds, char c)
{
	const char *buf;
	struct dts_emit_list_item *li;
	int ret;

	if (c != '\n') {
		accumulate(ds, c);
		return 0;
	}
	buf = get_accumulator(ds);

	if (is_valid_preproc_state(ds->pre_preproc_fs)) {
		dts_debug(ds, "preproc directive: %s\n", buf);
		li = item_from_accumulator(ds, dea_string);
		if (!li)
			return -1;
		ret = dts_emit(ds, det_preproc);
		if (ret)
			return ret;
	} else
		dts_debug(ds, "suppressed preproc directive: %s\n", buf);
	reset_accumulator(ds);

	/* mark that we've found preprocessor directives so macros possible */
	ds->found_preproc = true;
	goto_state(ds, ds->pre_preproc_fs);
	return 0;
}

static int hash(struct dts_state *ds, char c)
{
	/* those must be escaped */
	static const char *preproc_commands[] = {
		"if",
		"ifdef",
		"ifndef",
		"else",
		"elif",
		"endif",
		"define",
		"include",
		"error",
		"warning",
		"pragma",
		"line",
		NULL,
	};
	const char *s;
	const char **ss;
	const char *buf;

	if (isalpha(c)) {
		accumulate(ds, c);
		return 0;
	}

	buf = get_accumulator(ds);
	dts_debug(ds, "hash: %s\n", buf);

	/* if a match, it's a preprocessor command */
	ss = preproc_commands;
	while ((s = *ss++)) {
		if (!strcmp(s, buf + 1)) {
			accumulate(ds, c);
			goto_state(ds, s_preproc);
			return 0;
		}
	}

	/* some form of line marker (# N ... ) */
	if (get_accumulator_size(ds) == 1 && isspace(c)) {
		accumulate(ds, c);
		goto_state(ds, s_preproc);
		return 0;
	}


	/* nope it's something else; pass it along */
	goto_state(ds, ds->pre_preproc_fs);
	return states[ds->fs](ds, (char)c);
}

static int backslash(struct dts_state *ds, char c)
{
	if (c == '\n') {
		goto_state(ds, s_backslash_space);
		return 0;
	}

	/* and pass to old state */
	goto_state(ds, ds->pre_backslash_fs);
	return states[ds->fs](ds, (char)c);
}

static int backslash_space(struct dts_state *ds, char c)
{
	/* remove leading spaces (but not newlines) */
	if (isspace(c) && c != '\n')
		return 0;

	/* continuation of backslash */
	if (c == '\\') {
		goto_state(ds, s_backslash);
		return 0;
	}

	/* anything else pass to old state */
	goto_state(ds, ds->pre_backslash_fs);
	return states[ds->fs](ds, (char)c);
}

static int nodes_and_properties_marker_common(struct dts_state *ds, char c)
{
	const char *buf;
	struct dts_emit_list_item *li;
	int ret;

	switch (c) {
	case ':':
		buf = get_accumulator(ds);
		dts_debug(ds, "label: \"%s\"\n", buf);
		li = item_from_accumulator(ds, dea_label);
		if (!li)
			return -1;
		reset_accumulator(ds);
		goto_state(ds, s_nodes_and_properties);
		return 1;
	case '=':
	case ';':
		ds->node_empty = false;
		buf = get_accumulator(ds);
		if (c == '=')
			dts_debug(ds, "property: \"%s\"\n", buf);
		else
			dts_debug(ds, "boolean: %s=true\n", buf);
		li = item_from_accumulator(ds, dea_name);
		if (!li)
			return -1;
		reset_accumulator(ds);
		if (c == ';') {
			/* boolean (it's going to be nothing but name) */
			ret = dts_emit(ds, det_property);
			if (ret)
				return ret;
			goto_state(ds, s_nodes_and_properties);
		} else
			goto_state(ds, s_property);
		return 1;
	case '{':
		if (!get_accumulator_size(ds)) {
			dts_error(ds, "missing node name\n");
			return -1;
		}
		buf = get_accumulator(ds);
		dts_debug(ds, "new node: \"%s\" depth %d\n", buf, ds->depth);
		li = item_from_accumulator(ds, dea_name);
		if (!li)
			return -1;
		ret = dts_emit(ds, det_node);
		if (ret)
			return ret;
		reset_accumulator(ds);
		ds->depth++;
		ds->node_empty = true;
		goto_state(ds, s_nodes_and_properties);
		return 1;
	case '}':
		if (ds->depth == 0) {
			dts_error(ds, "bad node nesting\n");
			return -1;
		}
		ds->depth--;
		dts_debug(ds, "pop node: depth %d\n",
					ds->depth);
		if (ds->node_empty) {
			if (ds->refroot || ds->depth > 0)
				dts_emit(ds, det_node_empty);
			ds->node_empty = false;
		}
		if (ds->depth == 0) {
			ds->refroot = false;
			ds->start_root = false;
		}
		dts_emit(ds, det_node_end);
		goto_state(ds, s_semicolon);
		return 1;
	}

	return 0;
}

static int nodes_and_properties(struct dts_state *ds, char c)
{
	int ret;

	/* ignore leading space */
	if (get_accumulator_size(ds) == 0 && isspace(c)) {
		/* newline at start of line? it's meant to separate */
		if (ds->col == 1 && c == '\n') {
			ret = dts_emit(ds, det_separator);
			if (ret)
				return ret;
		}
		return 0;
	}

	if (isspace(c)) {
		goto_state(ds, s_nodes_and_properties_marker);
		return 0;
	}

	/* root only */
	if (c == '/') {
		ds->start_root = true;
		accumulate(ds, c);
		goto_state(ds, s_nodes_and_properties_marker);
		return 0;
	}

	if (c == '&') {
		if (ds->depth != 0) {
			dts_error(ds, "bad non-root refnode\n");
			return -1;
		}
		ds->refroot = true;
		goto_state(ds, s_node_ref);
		return 0;
	}

	ret = nodes_and_properties_marker_common(ds, c);
	if (ret < 0)
		return ret;

	/* state change */
	if (ret > 0)
		return 0;

	if (ispropnodec(c)) {
		accumulate(ds, c);
		return 0;
	}

	dts_error(ds, "bad node/property char '%c'\n", c);
	return -1;
}

static int nodes_and_properties_marker(struct dts_state *ds, char c)
{
	int ret;

	if (isspace(c))
		return 0;

	ret = nodes_and_properties_marker_common(ds, c);
	if (ret < 0)
		return ret;

	/* state change */
	if (ret > 0)
		return 0;

	dts_error(ds, "bad property/node start char '%c'\n", c);
	return -1;
}

static int node_ref(struct dts_state *ds, char c)
{
	const char *buf;
	struct dts_emit_list_item *li;
	int ret;

	/* if first character is left bracket then it's a path ref */
	if (get_accumulator_size(ds) == 0 && c == '{') {
		goto_state(ds, s_node_pathref);
		return 0;
	}
	if (isspace(c) || c == '{') {

		buf = get_accumulator(ds);
		dts_debug(ds, "ref node: &%s depth %d\n", buf, ds->depth);
		li = item_from_accumulator(ds, dea_ref);
		if (!li)
			return -1;
		reset_accumulator(ds);

		if (c == '{') {
			ret = dts_emit(ds, det_node);
			if (ret)
				return ret;
			ds->depth++;
			ds->node_empty = true;
			goto_state(ds, s_nodes_and_properties);
		} else
			goto_state(ds, s_refnode_start);

		return 0;
	}
	if (islabelc(c, get_accumulator_size(ds) == 0)) {
		accumulate(ds, c);
		return 0;
	}
	dts_error(ds, "bad ref character '%c'\n", c);
	return -1;
}

static int node_pathref(struct dts_state *ds, char c)
{
	struct dts_emit_list_item *li;
	const char *buf;

	if (c == '}') {
		buf = get_accumulator(ds);
		dts_debug(ds, "node pathref &{%s}\n", buf);
		li = item_from_accumulator(ds, dea_pathref);
		if (!li)
			return -1;
		reset_accumulator(ds);
		goto_state(ds, s_refnode_start);
		return 0;
	}

	if (ispathc(c)) {
		accumulate(ds, c);
		return 0;
	}
	dts_error(ds, "bad pathref character '%c'\n", c);
	return -1;
}

static int refnode_start(struct dts_state *ds, char c)
{
	int ret;

	if (isspace(c))
		return 0;

	if (c == '{') {
		ret = dts_emit(ds, det_node);
		if (ret)
			return ret;
		ds->depth++;
		ds->node_empty = true;
		goto_state(ds, s_nodes_and_properties);
		return 0;
	}

	dts_error(ds, "bad node ref start character '%c'\n", c);
	return -1;
}

static int semicolon(struct dts_state *ds, char c)
{
	if (isspace(c))
		return 0;

	if (c == ';') {
		goto_state(ds, s_nodes_and_properties);
		return 0;
	}
	dts_error(ds, "Expected semicolon, got '%c'\n", c);
	return -1;
}

static int property(struct dts_state *ds, char c)
{
	struct dts_emit_list_item *li;
	int ret;

	if (isspace(c))
		return 0;

	switch (c) {
	case ',':
		/* ignore commas */
		return 0;
	case '"':
		reset_accumulator(ds);
		goto_state(ds, s_string);
		return 0;
	case '<':
		reset_accumulator(ds);
		li = item_from_accumulator(ds, dea_array_start);
		if (!li)
			return -1;
		goto_state(ds, s_array);
		return 0;
	case '[':
		reset_accumulator(ds);
		li = item_from_accumulator(ds, dea_bytestring_start);
		if (!li)
			return -1;
		goto_state(ds, s_byte);
		return 0;
	case ';':
		ret = dts_emit(ds, det_property);
		if (ret)
			return ret;
		reset_accumulator(ds);
		goto_state(ds, s_nodes_and_properties);
		return 0;
	case '&':
		reset_accumulator(ds);
		goto_state(ds, s_string_ref);
		return 0;
	}

	if (ismacroc(c, true)) {
		accumulate(ds, c);
		goto_state(ds, s_prop_macro);
		return 0;
	}

	dts_error(ds, "bad property item start '%c'\n", c);
	return -1;
}

static int string(struct dts_state *ds, char c)
{
	const char *buf;
	int len;
	struct dts_emit_list_item *li;

	buf = get_accumulator(ds);
	len = get_accumulator_size(ds);
	switch (is_string_or_char_done(buf, len, c, '"')) {
	case -1:
		dts_error(ds, "bad string \"%s%c\"\n", buf, c);
		return -1;
	case 0:
		accumulate(ds, c);
		break;
	case 1:
		dts_debug(ds, "string \"%s\"\n", buf);
		li = item_from_accumulator(ds, dea_string);
		if (!li)
			return -1;
		reset_accumulator(ds);
		goto_state(ds, s_property);
		break;
	}

	return 0;
}

static int string_ref(struct dts_state *ds, char c)
{
	const char *buf;
	struct dts_emit_list_item *li;
	int ret;

	if (isspace(c) || c == ';' || c == ',') {
		buf = get_accumulator(ds);
		dts_debug(ds, "string-ref &%s\n", buf);
		li = item_from_accumulator(ds, dea_stringref);
		if (!li)
			return -1;
		reset_accumulator(ds);
		if (c == ';') {
			ret = dts_emit(ds, det_property);
			if (ret)
				return ret;
			goto_state(ds, s_nodes_and_properties);
		} else
			goto_state(ds, s_property);
		return 0;
	}
	if (ispropnodec(c)) {
		accumulate(ds, c);
		return 0;
	}
	dts_error(ds, "bad string ref char '%c'\n", c);
	return -1;
}

static int slash_directive(struct dts_state *ds, char c)
{
	const char *buf;
	int ret = 0;

	if (c == ';') {
		goto_state(ds, ds->pre_slash_fs);
		return 0;
	}

	if (isspace(c) || c == '{') {
		dts_error(ds, "bad directive\n");
		return -1;
	}

	accumulate(ds, c);
	if (c != '/')
		return 0;

	buf = get_accumulator(ds);
	dts_debug(ds, "slash-directive: %s\n", buf);

	switch (ds->pre_slash_fs) {
	case s_start:
		if (!strcmp(buf, "/dts-v1/")) {
			goto_state(ds, s_headers);
			break;
		}
		if (!strcmp(buf, "/include/")) {
			goto_state(ds, s_include);
			break;
		}
		if (!strcmp(buf, "/memreserve/")) {
			goto_state(ds, s_memreserves);
			break;
		}
		dts_error(ds, "Expected /dts-v1/ got %s\n", buf);
		ret = -1;
		break;
	case s_headers:
		if (!strcmp(buf, "/plugin/"))
			break;
		if (!strcmp(buf, "/memreserve/")) {
			goto_state(ds, s_memreserves);
			break;
		}
		if (!strcmp(buf, "/include/")) {
			goto_state(ds, s_include);
			break;
		}
		dts_error(ds, "Bad /keyword/ %s\n", buf);
		ret = -1;
		break;
	case s_property:
		if (!strcmp(buf, "/bits/")) {
			goto_state(ds, s_property_bits);
			break;
		}
		if (!strcmp(buf, "/incbin/")) {
			goto_state(ds, s_incbin);
			break;
		}
		dts_error(ds, "Illegal %s property directive\n", buf);
		ret = -1;
		break;
	case s_nodes_and_properties:
		if (!strcmp(buf, "/delete-property/")) {
			goto_state(ds, s_prop_del);
			break;
		}
		if (!strcmp(buf, "/delete-node/")) {
			goto_state(ds, s_node_del);
			break;
		}
		if (!strcmp(buf, "/include/")) {
			goto_state(ds, s_include);
			break;
		}
		goto_state(ds, ds->pre_slash_fs);
		break;
	default:
		goto_state(ds, ds->pre_slash_fs);
		break;
	}

	reset_accumulator(ds);

	return ret;
}

static int property_bits(struct dts_state *ds, char c)
{
	const char *buf;
	struct dts_emit_list_item *li;
	int bits;

	/* ignore leading space */
	if (get_accumulator_size(ds) == 0 && isspace(c))
		return 0;

	/* array prefix or space */
	if (c == '<' || isspace(c)) {
		buf = get_accumulator(ds);
		dts_debug(ds, "bits: %s\n", buf);
		bits = atoi(buf);
		if (bits != 8 && bits != 16 && bits != 32 && bits != 64) {
			dts_error(ds, "Bad /bits/ value %s\n", buf);
			return -1;
		}
		li = item_from_accumulator(ds, dea_bits);
		if (!li)
			return -1;
		reset_accumulator(ds);
		if (c == '<') {
			li = item_from_accumulator(ds, dea_array_start);
			if (!li)
				return -1;
			goto_state(ds, s_array);
		} else
			goto_state(ds, s_property);
		return 0;
	}

	/* a number only */
	if (isxdigit(c) || ((c == 'x' || c == 'X') &&
			    !strcmp(get_accumulator(ds), "0"))) {
		accumulate(ds, c);
		return 0;
	}
	dts_error(ds, "Bad /bits/ character %c\n", c);
	return -1;
}

static int array(struct dts_state *ds, char c)
{
	struct dts_emit_list_item *li;

	if (c == '>' && ds->last_c != '\\') {
		li = item_from_accumulator(ds, dea_array_end);
		if (!li)
			return -1;
		goto_state(ds, s_property);
		return 0;
	}

	/* remove whitespace */
	if (isspace(c))
		return 0;

	if (c == '&') {
		goto_state(ds, s_item_ref);
		return 0;
	}
	if (c == '(') {
		ds->expr_nest = 1;
		goto_state(ds, s_item_expr);
		return 0;
	}
	if (c == '\'') {
		goto_state(ds, s_item_char);
		return 0;
	}
	if (isdigit(c)) {
		accumulate(ds, c);
		goto_state(ds, s_item_int);
		return 0;
	}
	/* only do fancy macro stuff when preprocessor found */
	if (ismacroc(c, true)) {
		accumulate(ds, c);
		goto_state(ds, s_item_macro);
		return 0;
	}

	dts_error(ds, "Bad array item character %c\n", c);
	return -1;
}

static int byte(struct dts_state *ds, char c)
{
	const char *buf;
	int len, ret = 0;
	struct dts_emit_list_item *li;

	if (c == ']') {
		if (get_accumulator_size(ds) > 0) {
			buf = get_accumulator(ds);
			dts_debug(ds, "byte [%s]\n", buf);
			li = item_from_accumulator(ds, dea_byte);
			if (!li)
				return -1;
			reset_accumulator(ds);
		}
		li = item_from_accumulator(ds, dea_bytestring_end);
		if (!li)
			return -1;
		goto_state(ds, s_property);
		return 0;
	}

	if (isspace(c)) {
		len = get_accumulator_size(ds);
		ret = 0;
		switch (len) {
		case 0:
			/* nothing, leading whitespace */
			break;
		case 1:
			dts_error(ds, "bad byte expr\n");
			ret = -1;
			break;
		case 2:
			buf = get_accumulator(ds);
			dts_debug(ds, "byte [%s]\n", buf);
			li = item_from_accumulator(ds, dea_byte);
			if (!li)
				return -1;
			reset_accumulator(ds);
			break;
		}

		if (ret)
			return ret;
	}

	if (isspace(c))
		return 0;

	if (!isxdigit(c)) {
		dts_error(ds, "bad byte char '%c'\n", c);
		return -1;
	}
	accumulate(ds, c);

	/* split bytestream into 2 char byte items */
	len = get_accumulator_size(ds);
	if (len == 2) {
		buf = get_accumulator(ds);
		dts_debug(ds, "byte [%s]\n", buf);
		li = item_from_accumulator(ds, dea_byte);
		if (!li)
			return -1;
		reset_accumulator(ds);
	}

	return 0;
}

static int item_ref(struct dts_state *ds, char c)
{
	const char *buf;
	struct dts_emit_list_item *li;

	/* if first character is left bracket then it's a path ref */
	if (get_accumulator_size(ds) == 0 && c == '{') {
		goto_state(ds, s_item_pathref);
		return 0;
	}
	if (isspace(c) || c == '>') {
		buf = get_accumulator(ds);
		dts_debug(ds, "item ref &%s\n", buf);
		li = item_from_accumulator(ds, dea_ref);
		if (!li)
			return -1;
		reset_accumulator(ds);
		if (c == '>') {
			li = item_from_accumulator(ds, dea_array_end);
			if (!li)
				return -1;
			goto_state(ds, s_property);
		} else
			goto_state(ds, s_array);
		return 0;
	}
	if (islabelc(c, get_accumulator_size(ds) == 0)) {
		accumulate(ds, c);
		return 0;
	}
	dts_error(ds, "bad ref character '%c'\n", c);
	return -1;
}

static int item_pathref(struct dts_state *ds, char c)
{
	const char *buf;
	struct dts_emit_list_item *li;

	if (c == '}') {
		buf = get_accumulator(ds);
		dts_debug(ds, "item pathref &{%s}\n", buf);
		li = item_from_accumulator(ds, dea_pathref);
		if (!li)
			return -1;
		reset_accumulator(ds);
		goto_state(ds, s_array);
		return 0;
	}

	if (ispathc(c)) {
		accumulate(ds, c);
		return 0;
	}
	dts_error(ds, "bad pathref character '%c'\n", c);
	return -1;
}

static int item_expr(struct dts_state *ds, char c)
{
	const char *buf;
	struct dts_emit_list_item *li;

	if (c == ')') {
		if (ds->expr_nest == 0) {
			dts_error(ds, "bad expression\n");
			return -1;
		}
		ds->expr_nest--;
		if (ds->expr_nest == 0) {
			buf = get_accumulator(ds);
			dts_debug(ds, "item expr %s\n", buf);
			li = item_from_accumulator(ds, dea_expr);
			if (!li)
				return -1;
			reset_accumulator(ds);
			goto_state(ds, s_array);
		} else
			accumulate(ds, c);
		return 0;
	}

	if (c == '(') {
		accumulate(ds, c);
		ds->expr_nest++;
		return 0;
	}
	/* convert all spaces to actual space (handle weird spacing) */
	if (isspace(c))
		c = ' ';

	accumulate(ds, c);
	return 0;
}

static int item_char(struct dts_state *ds, char c)
{
	const char *buf;
	int len;
	struct dts_emit_list_item *li;

	buf = get_accumulator(ds);
	len = get_accumulator_size(ds);
	switch (is_string_or_char_done(buf, len, c, '\'')) {
	case -1:
		dts_error(ds, "bad char item '%s%c'\n", buf, c);
		return -1;
	case 0:
		accumulate(ds, c);
		break;
	case 1:
		dts_debug(ds, "char '%s'\n", buf);
		li = item_from_accumulator(ds, dea_char);
		if (!li)
			return -1;
		reset_accumulator(ds);
		goto_state(ds, s_array);
		break;
	}
	return 0;
}

static int item_int(struct dts_state *ds, char c)
{
	const char *buf;
	struct dts_emit_list_item *li;

	if (c == '>' || isspace(c)) {
		buf = get_accumulator(ds);
		if (!get_accumulator_size(ds)) {
			dts_error(ds, "bad int item %s\n", buf);
			return -1;
		}
		li = item_from_accumulator(ds, dea_int);
		if (!li)
			return -1;
		dts_debug(ds, "int %s\n", buf);
		reset_accumulator(ds);
		if (c == '>') {
			li = item_from_accumulator(ds, dea_array_end);
			if (!li)
				return -1;
		}
		goto_state(ds, c == '>' ? s_property : s_array);
		return 0;
	}

	if (isxdigit(c) || ((c == 'x' || c == 'X') &&
			    !strcmp(get_accumulator(ds), "0"))) {
		accumulate(ds, c);
		return 0;
	}

	dts_error(ds, "bad int item char '%c'\n", c);
	return -1;
}

static int item_macro(struct dts_state *ds, char c)
{
	const char *buf;
	struct dts_emit_list_item *li;

	if (c == '>' || isspace(c)) {
		buf = get_accumulator(ds);
		dts_debug(ds, "item expr (define)  %s\n", buf);
		li = item_from_accumulator(ds, dea_expr);
		if (!li)
			return -1;
		reset_accumulator(ds);
		if (c == '>') {
			li = item_from_accumulator(ds, dea_array_end);
			if (!li)
				return -1;
		}
		goto_state(ds, c == '>' ? s_property : s_array);
		return 0;
	}
	if (c != '(' && !ismacroc(c, false)) {
		dts_error(ds, "bad macro char '%c'\n", c);
		return -1;
	}
	accumulate(ds, c);
	if (c == '(') {
		ds->expr_nest = 1;
		goto_state(ds, s_item_macro_args);
		return 0;
	}
	return 0;
}

static int item_macro_args(struct dts_state *ds, char c)
{
	const char *buf;
	struct dts_emit_list_item *li;

	if (c == ')') {
		if (ds->expr_nest == 0) {
			dts_error(ds, "bad expression\n");
			return -1;
		}
		accumulate(ds, c);
		ds->expr_nest--;
		if (ds->expr_nest == 0) {
			buf = get_accumulator(ds);
			dts_debug(ds, "item expr (macro with args) %s\n", buf);
			li = item_from_accumulator(ds, dea_expr);
			if (!li)
				return -1;
			reset_accumulator(ds);
			goto_state(ds, s_array);
		}
		return 0;
	}

	if (c == '(') {
		accumulate(ds, c);
		ds->expr_nest++;
		return 0;
	}

	if (c == '\n' && ds->last_c != '\\') {
		dts_error(ds, "bad macro expansion\n");
		return -1;
	}

	/* convert all spaces to actual space (handle weird spacing) */
	if (isspace(c))
		c = ' ';

	accumulate(ds, c);
	return 0;
}

static int include(struct dts_state *ds, char c)
{
	/* ignore leading spaces */
	if (isspace(c))
		return 0;

	if (c == '"') {
		goto_state(ds, s_include_arg);
		return 0;
	}
	dts_error(ds, "Bad include directive\n");
	return -1;
}

static int include_arg(struct dts_state *ds, char c)
{
	const char *buf;
	struct dts_emit_list_item *li;
	int len, ret;

	buf = get_accumulator(ds);
	len = get_accumulator_size(ds);
	switch (is_string_or_char_done(buf, len, c, '"')) {
	case -1:
		dts_error(ds, "bad include \"%s%c\"\n", buf, c);
		return -1;
	case 0:
		accumulate(ds, c);
		break;
	case 1:
		dts_debug(ds, "include: \"%s\"\n", buf);
		li = item_from_accumulator(ds, dea_string);
		if (!li)
			return -1;
		reset_accumulator(ds);
		ret = dts_emit(ds, det_include);
		if (ret)
			return ret;
		goto_state(ds, ds->pre_slash_fs);
		break;
	}
	return 0;
}

static int node_del(struct dts_state *ds, char c)
{
	/* ignore leading spaces */
	if (isspace(c))
		return 0;

	if (c == '&') {
		goto_state(ds, s_node_del_ref);
		return 0;
	}

	if (ispropnodec(c)) {
		accumulate(ds, c);
		goto_state(ds, s_node_del_name);
		return 0;
	}

	dts_error(ds, "bad /delete-node/ directive\n");
	return -1;
}

static int node_del_ref(struct dts_state *ds, char c)
{
	const char *buf;
	struct dts_emit_list_item *li;
	int ret;

	/* if first character is left bracket then it's a path ref */
	if (get_accumulator_size(ds) == 0 && c == '{') {
		goto_state(ds, s_node_del_pathref);
		return 0;
	}
	if (isspace(c) || c == ';') {
		buf = get_accumulator(ds);
		dts_debug(ds, "node-del ref &%s\n", buf);
		li = item_from_accumulator(ds, dea_ref);
		if (!li)
			return -1;
		reset_accumulator(ds);
		ret = dts_emit(ds, det_del_node);
		if (ret)
			return ret;
		if (c == ';')
			goto_state(ds, s_nodes_and_properties);
		else
			goto_state(ds, s_semicolon);
		return 0;
	}
	if (islabelc(c, get_accumulator_size(ds) == 0)) {
		accumulate(ds, c);
		return 0;
	}
	dts_error(ds, "bad node del ref character '%c'\n", c);
	return -1;
}

static int node_del_pathref(struct dts_state *ds, char c)
{
	const char *buf;
	struct dts_emit_list_item *li;
	int ret;

	if (c == '}') {
		buf = get_accumulator(ds);
		dts_debug(ds, "node-del pathref &{%s}\n", buf);
		li = item_from_accumulator(ds, dea_pathref);
		if (!li)
			return -1;
		reset_accumulator(ds);
		ret = dts_emit(ds, det_del_node);
		if (ret)
			return ret;
		goto_state(ds, s_semicolon);
		return 0;
	}

	if (ispathc(c)) {
		accumulate(ds, c);
		return 0;
	}
	dts_error(ds, "bad node del pathref character '%c'\n", c);
	return -1;
}

static int node_del_name(struct dts_state *ds, char c)
{
	const char *buf;
	struct dts_emit_list_item *li;
	int ret;

	if (isspace(c) || c == ';') {
		buf = get_accumulator(ds);
		dts_debug(ds, "node-del name %s\n", buf);
		li = item_from_accumulator(ds, dea_name);
		if (!li)
			return -1;
		reset_accumulator(ds);
		ret = dts_emit(ds, det_del_node);
		if (ret)
			return ret;
		if (c == ';') {
			goto_state(ds, s_nodes_and_properties);
		} else
			goto_state(ds, s_semicolon);
		return 0;
	}
	if (ispropnodec(c)) {
		accumulate(ds, c);
		return 0;
	}
	dts_error(ds, "bad name char '%c'\n", c);
	return -1;
}

static int prop_del(struct dts_state *ds, char c)
{
	/* ignore leading spaces */
	if (isspace(c))
		return 0;

	if (ispropnodec(c)) {
		accumulate(ds, c);
		goto_state(ds, s_prop_del_name);
		return 0;
	}

	dts_error(ds, "bad /delete-property/ directive\n");
	return -1;
}

static int prop_del_name(struct dts_state *ds, char c)
{
	const char *buf;
	struct dts_emit_list_item *li;
	int ret;

	if (isspace(c) || c == ';') {
		buf = get_accumulator(ds);
		dts_debug(ds, "prop-del name %s\n", buf);
		li = item_from_accumulator(ds, dea_name);
		if (!li)
			return -1;
		reset_accumulator(ds);
		ret = dts_emit(ds, det_del_prop);
		if (ret)
			return ret;
		if (c == ';') {
			goto_state(ds, s_nodes_and_properties);
		} else
			goto_state(ds, s_semicolon);
		return 0;
	}
	if (ispropnodec(c)) {
		accumulate(ds, c);
		return 0;
	}
	dts_error(ds, "bad name char '%c'\n", c);
	return -1;
}

static int prop_macro(struct dts_state *ds, char c)
{
	const char *buf;
	struct dts_emit_list_item *li;
	int ret;

	if (c == ';' || c == ',' || isspace(c)) {
		buf = get_accumulator(ds);
		dts_debug(ds, "prop expr (define) %s\n", buf);
		li = item_from_accumulator(ds, dea_expr);
		if (!li)
			return -1;
		reset_accumulator(ds);
		if (c == ';') {
			ret = dts_emit(ds, det_property);
			if (ret)
				return ret;
			goto_state(ds, s_nodes_and_properties);
		} else
			goto_state(ds, s_property);
		return 0;
	}
	if (c != '(' && !ismacroc(c, false)) {
		dts_error(ds, "bad macro char '%c'\n", c);
		return -1;
	}
	accumulate(ds, c);
	if (c == '(') {
		ds->expr_nest = 1;
		goto_state(ds, s_prop_macro_args);
		return 0;
	}
	return 0;
}

static int prop_macro_args(struct dts_state *ds, char c)
{
	const char *buf;
	struct dts_emit_list_item *li;

	if (c == ')') {
		if (ds->expr_nest == 0) {
			dts_error(ds, "bad expression\n");
			return -1;
		}
		accumulate(ds, c);
		ds->expr_nest--;
		if (ds->expr_nest == 0) {
			buf = get_accumulator(ds);
			dts_debug(ds, "prop expr (macro with args) %s\n", buf);
			li = item_from_accumulator(ds, dea_expr);
			if (!li)
				return -1;
			reset_accumulator(ds);
			goto_state(ds, s_property);
		}
		return 0;
	}

	if (c == '(') {
		accumulate(ds, c);
		ds->expr_nest++;
		return 0;
	}

	if (c == '\n' && ds->last_c != '\\') {
		dts_error(ds, "bad macro expansion\n");
		return -1;
	}

	accumulate(ds, c);
	return 0;
}

static int incbin(struct dts_state *ds, char c)
{
	if (isspace(c))
		return 0;
	if (c != '(') {
		dts_error(ds, "Expecting ( got %s\n", c);
		return -1;
	}
	goto_state(ds, s_incbin_arg);
	return 0;
}

static int incbin_arg(struct dts_state *ds, char c)
{
	if (isspace(c))
		return 0;
	if (c == '"') {
		reset_accumulator(ds);
		goto_state(ds, s_incbin_file);
		return 0;
	}
	dts_error(ds, "Expecting \" got %s\n", c);
	return -1;
}

static int incbin_file(struct dts_state *ds, char c)
{
	struct dts_emit_list_item *li;
	const char *buf;
	int len;

	buf = get_accumulator(ds);
	len = get_accumulator_size(ds);
	switch (is_string_or_char_done(buf, len, c, '"')) {
	case -1:
		dts_error(ds, "bad string \"%s%c\"\n", buf, c);
		return -1;
	case 0:
		accumulate(ds, c);
		break;
	case 1:
		dts_debug(ds, "incbin file \"%s\"\n", buf);
		li = item_from_accumulator(ds, dea_string);
		if (!li)
			return -1;
		reset_accumulator(ds);
		goto_state(ds, s_incbin_file_comma);
		break;
	}

	return 0;
}

static int incbin_file_comma(struct dts_state *ds, char c)
{
	if (isspace(c))
		return 0;
	if (c == ',') {
		goto_state(ds, s_incbin_offset);
		return 0;
	}
	if (c == ')') {
		dts_emit(ds, det_incbin);
		goto_state(ds, s_semicolon);
		return 0;
	}
	dts_error(ds, "expecting either , or ) got %s\n", c);
	return -1;
}

static int incbin_offset(struct dts_state *ds, char c)
{
	const char *buf;
	struct dts_emit_list_item *li;

	if (isspace(c) || c == ',') {
		if (!get_accumulator_size(ds)) {
			if (c == ',') {
				dts_error(ds, "missing offset\n");
				return -1;
			}
			return 0;
		}
		buf = get_accumulator(ds);
		li = item_from_accumulator(ds, dea_int);
		if (!li)
			return -1;
		dts_debug(ds, "incbin offset %s\n", buf);
		reset_accumulator(ds);
		goto_state(ds, c == ',' ? s_incbin_size :
				s_incbin_offset_comma);
		return 0;
	}

	if (isxdigit(c) || ((c == 'x' || c == 'X') &&
			    !strcmp(get_accumulator(ds), "0"))) {
		accumulate(ds, c);
		return 0;
	}

	dts_error(ds, "bad incbin offset char '%c'\n", c);
	return -1;
}

static int incbin_offset_comma(struct dts_state *ds, char c)
{
	if (isspace(c))
		return 0;
	if (c == ',') {
		goto_state(ds, s_incbin_size);
		return 0;
	}
	dts_error(ds, "expecting , got %s\n", c);
	return -1;
}

static int incbin_size(struct dts_state *ds, char c)
{
	const char *buf;
	struct dts_emit_list_item *li;

	if (isspace(c) || c == ')') {
		if (!get_accumulator_size(ds)) {
			if (c == ')') {
				dts_error(ds, "missing size\n");
				return -1;
			}
			return 0;
		}
		buf = get_accumulator(ds);
		li = item_from_accumulator(ds, dea_int);
		if (!li)
			return -1;
		dts_debug(ds, "incbin size %s\n", buf);
		reset_accumulator(ds);
		dts_emit(ds, det_incbin);
		goto_state(ds, c == ')' ? s_semicolon :
				s_incbin_end);
		return 0;
	}

	if (isxdigit(c) || ((c == 'x' || c == 'X') &&
			    !strcmp(get_accumulator(ds), "0"))) {
		accumulate(ds, c);
		return 0;
	}

	dts_error(ds, "bad incbin size char '%c'\n", c);
	return -1;
}

static int incbin_end(struct dts_state *ds, char c)
{
	if (isspace(c))
		return 0;
	if (c == ')') {
		goto_state(ds, s_semicolon);
		return 0;
	}
	dts_error(ds, "expecting ) goto '%c'\n", c);
	return -1;
}

static int (*states[])(struct dts_state *ds, char c) = {
	[s_start] 			= start,
	[s_headers]			= headers,
	[s_memreserves]			= memreserves,
	[s_slash]			= slash,
	[s_in_c_comment]		= in_c_comment,
	[s_in_cpp_comment]		= in_cpp_comment,
	[s_preproc]			= preproc,
	[s_hash]			= hash,
	[s_backslash]			= backslash,
	[s_backslash_space]		= backslash_space,
	[s_nodes_and_properties]	= nodes_and_properties,
	[s_nodes_and_properties_marker]	= nodes_and_properties_marker,
	[s_node_ref]			= node_ref,
	[s_node_pathref]		= node_pathref,
	[s_refnode_start]		= refnode_start,
	[s_semicolon]			= semicolon,
	[s_property]			= property,
	[s_string]			= string,
	[s_string_ref]			= string_ref,
	[s_slash_directive]		= slash_directive,
	[s_property_bits]		= property_bits,
	[s_array]			= array,
	[s_byte]			= byte,
	[s_item_ref]			= item_ref,
	[s_item_expr]			= item_expr,
	[s_item_char]			= item_char,
	[s_item_int]			= item_int,
	[s_item_macro]			= item_macro,
	[s_item_macro_args]		= item_macro_args,
	[s_item_pathref]		= item_pathref,
	[s_include]			= include,
	[s_include_arg]			= include_arg,
	[s_node_del]			= node_del,
	[s_node_del_ref]		= node_del_ref,
	[s_node_del_pathref]		= node_del_pathref,
	[s_node_del_name]		= node_del_name,
	[s_prop_del]			= prop_del,
	[s_prop_del_name]		= prop_del_name,
	[s_prop_macro]			= prop_macro,
	[s_prop_macro_args]		= prop_macro_args,
	[s_incbin]			= incbin,
	[s_incbin_arg]			= incbin_arg,
	[s_incbin_file]			= incbin_file,
	[s_incbin_file_comma]		= incbin_file_comma,
	[s_incbin_offset]		= incbin_offset,
	[s_incbin_offset_comma]		= incbin_offset_comma,
	[s_incbin_size]			= incbin_size,
	[s_incbin_end]			= incbin_end,
	NULL
};

int dts_setup(struct dts_state *ds, const char *filename, int tabs,
	      bool debug, const struct dts_ops *ops)
{
	if (!ops)
		return -1;

	memset(ds, 0, sizeof(*ds));

	acc_setup(&ds->acc_body);
	acc_setup(&ds->acc_comm);

	if (filename == NULL)
		filename = "<stdin>";
	ds->filename = strdup(filename);
	ds->filename_len = strlen(ds->filename);
	ds->fs = s_start;
	ds->last_c = 0;
	ds->index = 0;
	ds->line = 1;
	ds->col = 1;
	ds->tabs = tabs;
	ds->debug = debug;

	ds->ops = ops;

	INIT_LIST_HEAD(&ds->items);

	return 0;
}

void dts_cleanup(struct dts_state *ds)
{
	if (ds->filename)
		free(ds->filename);
	acc_cleanup(&ds->acc_body);
	acc_cleanup(&ds->acc_comm);
}

int dts_feed(struct dts_state *ds, int c)
{
	int ret = 0;

	if (ds->fs < s_first || ds->fs > s_last) {
		dts_error(ds, "internal error (bad state)\n");
		return -1;
	}

	if (c == EOF) {
		if (ds->depth != 0 || !is_valid_final_state(ds->fs)) {
			dts_error(ds, "unexpected EOF on %s/%d\n",
				dts_get_state(ds), ds->depth);
			return -1;
		}
		dts_debug(ds, "end of file: %s\n", ds->filename);
		return 0;
	}

	ret = 0;
	if (state_with_comments(ds->fs))
		ret = handle_comment(ds, c);

	if (!ret && state_with_preproc(ds->fs))
		ret = handle_preproc(ds, c);

	if (!ret)
		ret = states[ds->fs](ds, c);

	if (ret < 0)
		return ret;

	ds->last_c = c;
	ds->index++;
	if (c == '\n') {
		ds->line++;
		ds->col = 1;
	} else
		ds->col++;

	return 0;
}

const char *dts_get_filename(struct dts_state *ds)
{
	return ds->filename;
}

const char *dts_get_state(struct dts_state *ds)
{
	return states_txt[ds->fs];
}

int dts_get_index(struct dts_state *ds)
{
	return ds->index;
}

int dts_get_line(struct dts_state *ds)
{
	return ds->line;
}

int dts_get_column(struct dts_state *ds)
{
	return ds->col;
}

int dts_get_token_index(struct dts_state *ds)
{
	return ds->acc_loc.start_index;
}

int dts_get_token_line(struct dts_state *ds)
{
	return ds->acc_loc.start_line;
}

int dts_get_token_column(struct dts_state *ds)
{
	return ds->acc_loc.start_col;
}
