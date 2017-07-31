/*
 * yamlgen.c - YAML generation
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
#include <time.h>
#include <stdbool.h>
#include <assert.h>
#include <alloca.h>
#include <limits.h>

#include "utils.h"
#include "syexpr.h"

#include "yamldt.h"

static int parse_int(const char *str, int len, unsigned long long *valp,
		     bool *unsignedp, bool *hexp)
{
	int ret;
	sy_val_t val;
	struct sy_state state, *sy = &state;
	struct sy_config cfg;

	memset(&cfg, 0, sizeof(cfg));
	cfg.size = sy_workbuf_size_max(len);
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

static void ref_output_single(struct yaml_dt_state *dt, struct ref *ref, int depth)
{
	struct node *np;
	struct property *prop;
	struct label *l;
	int ret, len;
	unsigned long long val = 0;
	bool is_unsigned;
	bool is_hex;
	bool is_int;
	const char *p;
	const char *xtag = NULL;
	const char *tag = NULL;
	char namebuf[NODE_FULLNAME_MAX];

	prop = ref->prop;
	assert(prop);

	/* get tag */
	xtag = ref->xtag;
	if (!xtag)
		xtag = ref->xtag_builtin;
	tag = xtag;

	switch (ref->type) {
	case r_anchor:
		np = node_lookup_by_label(to_tree(dt),
				ref->data, ref->len);
		if (!np && !dt->object) {
			fprintf(stderr, "object=%s\n", dt->object ? "true" : "false");

			strncat(namebuf, ref->data, sizeof(namebuf) - 1);
			namebuf[sizeof(namebuf) - 1] = '\0';
			dt_error_at(dt, ref->line, ref->column,
				    ref->end_line, ref->end_column,
				    "Can't resolve reference to label %s\n",
				    namebuf);
			return;
		}

		/* object mode, just leave references here */
		if (!np && dt->object) {
			fputc('*', dt->output);
			fwrite(ref->data, ref->len, 1, dt->output);
			break;
		}

		/* if not the first label, switch it to the first */
		l = list_first_entry(&np->labels, struct label, node);
		if (strlen(l->label) != ref->len ||
		    memcmp(l->label, ref->data, ref->len)) {
			strncat(namebuf, ref->data, sizeof(namebuf) - 1);
			namebuf[sizeof(namebuf) - 1] = '\0';
			dt_warning_at(dt, ref->line, ref->column,
				    ref->end_line, ref->end_column,
				    "Switching label %s to label %s\n",
				    namebuf, l->label);
		}

		fprintf(dt->output, "*%s", l->label);
		break;

	case r_path:
		np = node_lookup_by_label(to_tree(dt),
				ref->data, ref->len);
		if (!np && !dt->object) {
			strncat(namebuf, ref->data, sizeof(namebuf) - 1);
			namebuf[sizeof(namebuf) - 1] = '\0';
			dt_error_at(dt, ref->line, ref->column,
				    ref->end_line, ref->end_column,
				    "Can't resolve reference to label %s\n",
				    namebuf);
			return;
		}

		/* object mode, just leave references here */
		if (!np && dt->object) {
			fputs("!pathref ", dt->output);
			fwrite(ref->data, ref->len, 1, dt->output);
			break;
		}

		/* if not the first label, switch it to the first */
		l = list_first_entry(&np->labels, struct label, node);
		if (strlen(l->label) != ref->len ||
		    memcmp(l->label, ref->data, ref->len)) {
			strncat(namebuf, ref->data, sizeof(namebuf) - 1);
			namebuf[sizeof(namebuf) - 1] = '\0';
			dt_warning_at(dt, ref->line, ref->column,
				    ref->end_line, ref->end_column,
				    "Switching label %s to label %s\n",
				    namebuf, l->label);
		}

		fprintf(dt->output, "!pathref %s", l->label);
		break;

	case r_scalar:
		np = prop->np;
		assert(np);

		len = ref->len;
		p = ref->data;

		/* try to parse as an int anyway */
		ret = parse_int(p, len, &val, &is_unsigned, &is_hex);
		is_int = ret == 0;

		/* output explicit tag (which is not a string) */
		if (xtag && strcmp(xtag, "!str"))
			fprintf(dt->output, "%s ", xtag);

		/* TODO type checking/conversion here */
		if (!tag && is_int) {
			tag = is_hex || is_unsigned ? "!uint" : "!int";
		} else if (!tag && ((len == 4 && !memcmp(p,  "true", 4)) ||
		                  (len == 5 && !memcmp(p, "false", 5)) ))
			tag = "!bool";
		else if (!tag && (len == 0 ||
		                 (len == 4 && !memcmp(p, "null", 4)) ||
				 (len == 1 && *(char *)p == '~')) )
			tag = "!null";
		else if (!tag)
			tag = "!str";

		if (is_int_tag(tag)) {
			if (!is_int) {
				dt_error_at(dt, ref->line, ref->column,
					ref->end_line, ref->end_column,
						"Invalid integer syntax\n");
				return;
			}
			if (!int_val_in_range(tag, val, is_unsigned, is_hex)) {
				dt_error_at(dt, ref->line, ref->column,
					ref->end_line, ref->end_column,
						"Integer out of range%s%s\n",
						is_unsigned ? " unsigned" : "",
						is_hex ? " hex" : "");
				return;
			}

			if (is_hex)
				fprintf(dt->output, "0x%llx", val);
			else if (is_unsigned)
				fprintf(dt->output, "%llu", val);
			else
				fprintf(dt->output, "%lld", (long long)val);

		} else if (!strcmp(tag, "!str")) {
			fputc('"', dt->output);
			fwrite(ref->data, ref->len, 1, dt->output);
			fputc('"', dt->output);
		} else if (!strcmp(tag, "!bool")) {
			fwrite(ref->data, ref->len, 1, dt->output);
		} else if (!strcmp(tag, "!null")) {
			fwrite(ref->data, ref->len, 1, dt->output);
		} else {
			fwrite(ref->data, ref->len, 1, dt->output);
			dt_warning_at(dt, ref->line, ref->column,
				ref->end_line, ref->end_column,
				"Unknown tag %s\n", tag);
		}

		break;

	default:
		/* nothing */
		break;
	}
}


void __yaml_flatten_node(struct yaml_dt_state *dt,
			 struct node *np, int depth)
{
	struct node *child;
	struct property *prop;
	struct ref *ref;
	struct label *l = NULL;
	int outcount, count, i;

	if (depth > 0) {
		fprintf(dt->output, "%*s%s:", (depth - 1) * 2, "",
				np->name);

		/* output only first label */
		list_for_each_entry(l, &np->labels, node) {
			fprintf(dt->output, " &%s", l->label);
			break;
		}
		fputc('\n', dt->output);
	}

	outcount = 0;
	list_for_each_entry(prop, &np->properties, node) {
		outcount++;

		fprintf(dt->output, "%*s", depth * 2, "");
		if (prop->name[0] != '#')
			fprintf(dt->output, "%s:", prop->name);
		else
			fprintf(dt->output, "\"%s\":", prop->name);

		count = 0;
		list_for_each_entry(ref, &prop->refs, node) {
			if (ref->type == r_seq_start ||
			    ref->type == r_seq_end)
				continue;
			count++;
		}

		if (count > 1)
			fputs(" [", dt->output);

		i = 0;
		list_for_each_entry(ref, &prop->refs, node) {

			if (ref->type == r_seq_start ||
			    ref->type == r_seq_end)
				continue;

			if (i > 0)
				fputc(',', dt->output);
			fputc(' ', dt->output);

			if (ref->type == r_null)
				fputc('~', dt->output);
			else
				ref_output_single(dt, ref, depth);
			i++;
		}

		if (count > 1)
			fputs(" ]", dt->output);

		fputc('\n', dt->output);
	}

	list_for_each_entry(child, &np->children, node)
		outcount++;

	/* "~: ~" for an empty tree without props or children */
	if (outcount == 0)
		fprintf(dt->output, "%*s~: ~\n", depth * 2, "");

	list_for_each_entry(child, &np->children, node)
		__yaml_flatten_node(dt, child, depth + 1);

	/* multiple labels to same node; spit out only the labels */
	if (l && depth > 0) {
		list_for_each_entry_continue(l, &np->labels, node) {
			fprintf(dt->output, "%*s# %s: &%s { }\n", (depth - 1) * 2, "",
					np->name, l->label);
		}
	}
}

static void yaml_flatten_node(struct yaml_dt_state *dt)
{
	__yaml_flatten_node(dt, tree_root(to_tree(dt)), 0);
}

static void yaml_apply_ref_nodes(struct yaml_dt_state *dt)
{
	struct node *np, *npn, *npref;
	struct list_head *ref_nodes = tree_ref_nodes(to_tree(dt));

	list_for_each_entry_safe(np, npn, ref_nodes, node) {

		npref = node_lookup_by_label(to_tree(dt), np->name + 1,
				strlen(np->name + 1));

		if (!npref && !dt->object)
			dt_error_at(dt, np->line, np->column,
				np->end_line, np->end_column,
				"reference to unknown label %s\n",
				np->name + 1);

		if (npref)
			tree_apply_ref_node(to_tree(dt), npref, np);

		/* free everything now */
		if (npref || !dt->object) {
			list_del(&np->node);
			node_free(to_tree(dt), np);
		}
	}

	if (!dt->object)
		return;

	/* move all remaining unref nodes to root */
	list_for_each_entry_safe(np, npn, ref_nodes, node) {

		if (tree_root(to_tree(dt))) {
			list_del(&np->node);
			np->parent = tree_root(to_tree(dt));
			list_add_tail(&np->node, &np->parent->children);
		} else
			node_free(to_tree(dt), np);
	}
}

void yaml_init(struct yaml_dt_state *dt)
{
	/* nothing */
}

void yaml_cleanup(struct yaml_dt_state *dt)
{
	/* nothing */
}

void yaml_emit(struct yaml_dt_state *dt)
{
	yaml_apply_ref_nodes(dt);
	yaml_flatten_node(dt);
}
