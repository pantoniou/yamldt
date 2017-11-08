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
#include "base64.h"

#include "dt.h"

#include "yamlgen.h"

static struct ref *yaml_ref_alloc(struct tree *t, enum ref_type type,
				 const void *data, int len, const char *xtag)
{
	return yaml_dt_ref_alloc(t, type, data, len, xtag,
			sizeof(struct dt_ref));
}

static void yaml_ref_free(struct tree *t, struct ref *ref)
{
	yaml_dt_ref_free(t, ref);
}

static struct property *yaml_prop_alloc(struct tree *t, const char *name)
{
	return yaml_dt_prop_alloc(t, name, sizeof(struct dt_property));
}

static void yaml_prop_free(struct tree *t, struct property *prop)
{
	yaml_dt_prop_free(t, prop);
}

static struct label *yaml_label_alloc(struct tree *t, const char *name)
{
	return yaml_dt_label_alloc(t, name, sizeof(struct dt_label));
}

static void yaml_label_free(struct tree *t, struct label *l)
{
	yaml_dt_label_free(t, l);
}

static struct node *yaml_node_alloc(struct tree *t, const char *name,
				   const char *label)
{
	return yaml_dt_node_alloc(t, name, label, sizeof(struct dt_node));
}

static void yaml_node_free(struct tree *t, struct node *np)
{
	yaml_dt_node_free(t, np);
}

static const struct tree_ops yaml_tree_ops = {
	.ref_alloc		= yaml_ref_alloc,
	.ref_free		= yaml_ref_free,
	.prop_alloc		= yaml_prop_alloc,
	.prop_free		= yaml_prop_free,
	.label_alloc		= yaml_label_alloc,
	.label_free		= yaml_label_free,
	.node_alloc		= yaml_node_alloc,
	.node_free		= yaml_node_free,
	.debugf			= yaml_dt_tree_debugf,
	.msg_at_node		= yaml_dt_tree_msg_at_node,
	.msg_at_property	= yaml_dt_tree_msg_at_property,
	.msg_at_ref		= yaml_dt_tree_msg_at_ref,
	.msg_at_label		= yaml_dt_tree_msg_at_label,
};

static void ref_output_single(struct tree *t, FILE *fp,
			      struct ref *ref, bool object,
			      bool json, int depth)
{
	struct yaml_dt_state *dt = to_dt(t);
	struct node *np;
	struct property *prop;
	struct label *l;
	int err;
	unsigned long long val = 0;
	const char *xtag = NULL;
	const char *tag = NULL;
	char *refname;
	int refnamelen;
	const char *s, *e;
	char c2buf[C2STR_BUF_MAX];

	prop = ref->prop;
	assert(prop);

	/* get tag */
	xtag = ref->xtag;
	if (!xtag)
		xtag = ref->xtag_builtin;
	tag = xtag;

	/* 60 bytes for a display purposes should be enough */
	refnamelen = ref->len > 60 ? 60 : ref->len;
	refname = alloca(refnamelen + 1);
	memcpy(refname, ref->data, refnamelen);
	refname[refnamelen] = '\0';

	err = dt_resolve_ref(dt, ref);
	if (err != 0) {
		if (ref->type == r_anchor || ref->type == r_path) {
			tree_error_at_ref(to_tree(dt), ref,
				"Can't resolve reference to %s %s\n",
				refname[0] == '/' ? "path" : "label",
				refname);
			return;
		}
		if (err == -EINVAL) {
			tree_error_at_ref(to_tree(dt), ref, "Invalid %s\n",
				refname);
			return;
		}
		if (err == -ERANGE) {
			tree_error_at_ref(to_tree(dt), ref, "Invalid range on %s\n",
				refname);
			return;
		}
	}

	switch (ref->type) {
	case r_anchor:
	case r_path:
		np = to_dt_ref(ref)->npref;

		/* object mode, just leave references here */
		if (!np) {
			if (!json) {
				if (ref->type == r_anchor)
					fputc('*', fp);
				else
					fputs("!pathref ", fp);
				fwrite(ref->data, ref->len, 1, fp);
			} else {
				fprintf(fp, "[ \"\\f%s\", \"",
						ref->type == r_anchor ?
						"!anchor" : "!pathref");
				fwrite(ref->data, ref->len, 1, fp);
				fputs("\" ]", fp);
			}
			break;
		}

		/* empty list; pathref to node with no label */
		if (list_empty(&np->labels)) {
			tree_error_at_ref(to_tree(dt), ref,
				"Can't resolve reference to %s %s\n",
				refname[0] == '/' ? "path" : "label",
				refname);
			break;
		}

		/* if not the first label, switch it to the first */
		l = list_first_entry(&np->labels, struct label, node);
		if (strlen(l->label) != ref->len ||
		    memcmp(l->label, ref->data, ref->len)) {
			tree_debug(t, "Switching label %s to label %s\n",
				    refname, l->label);
		}

		if (!json) {
			if (ref->type == r_anchor)
				fprintf(fp, "*%s", l->label);
			else
				fprintf(fp, "!pathref %s", l->label);
		} else {
			fprintf(fp, "[ \"\\f%s\", \"%s\" ]",
					ref->type == r_anchor ?
					"!anchor" : "!pathref",
					l->label);
		}
		break;

	case r_scalar:
		tag = to_dt_ref(ref)->tag;

		/* output explicit tag (which is not a string) */
		if (!json && xtag && strcmp(xtag, "!str"))
			fprintf(fp, "%s ", xtag);

		val = to_dt_ref(ref)->val;
		if (to_dt_ref(ref)->is_int) {
			if (!json) {
				if (to_dt_ref(ref)->is_hex) {
					if (!strcmp(tag, "!int8") || !strcmp(tag, "!uint8"))
						fprintf(fp, "0x%llx", val & 0xff);
					else if (!strcmp(tag, "!int16") || !strcmp(tag, "!uint16"))
						fprintf(fp, "0x%llx", val & 0xffff);
					else if (!strcmp(tag, "!int32") || !strcmp(tag, "!uint32"))
						fprintf(fp, "0x%llx", val & 0xffffffff);
					else
						fprintf(fp, "0x%llx", val);
				} else if (to_dt_ref(ref)->is_unsigned)
					fprintf(fp, "%llu", val);
				else
					fprintf(fp, "%lld", (long long)val);
			} else {
				if (xtag && strcmp(xtag, "!int32"))
					fprintf(fp, "[ \"\\f%s\", ", tag);
				if (to_dt_ref(ref)->is_unsigned)
					fprintf(fp, "%llu", val);
				else
					fprintf(fp, "%lld", (long long)val);
				if (xtag && strcmp(xtag, "!int32"))
					fputs(" ]", fp);
			}

		} else if (!strcmp(tag, "!bool")) {
			fputs(val ? "true" : "false", fp);
		} else if (!strcmp(tag, "!null")) {
			if (!json)
				fputc('~', fp);
			else
				fputs("null", fp);
		} else {

			if (strcmp(tag, "!str"))
				tree_debug(t, "Non builtin tag %s: %s\n",
						tag, refname);

			if (json && tag && strcmp(tag, "!str"))
				fprintf(fp, "[ \"\\f%s\", ", tag);

			/* no newlines? easy */
			if (!memchr(ref->data, '\n', ref->len)) {
				fputc('"', fp);
				fwrite(ref->data, ref->len, 1, fp);
				fputc('"', fp);
			} else if (!json) {
				fputs("|+", fp);
				s = ref->data;
				while (s && s < (char *)ref->data + ref->len) {
					e = memchr(s, '\n', (char *)ref->data + ref->len - s);
					if (!e)
						e = ref->data + ref->len;
					fprintf(fp, "\n%*s", (depth + 1) * 2, "");
					fwrite(s, e - s, 1, fp);
					s = e < ((char *)ref->data + ref->len) ? e + 1 : NULL;
				}
			} else {
				fputc('"', fp);
				s = ref->data;
				while (s && s < (char *)ref->data + ref->len)
					fputs(c2str(*s++, c2buf, sizeof(c2buf)), fp);
				fputc('"', fp);
			}

			if (json && tag && strcmp(tag, "!str"))
				fputs(" ]", fp);
		}
		break;

	default:
		/* nothing */
		break;
	}
}

void __yaml_assign_temp_labels(struct tree *t, struct node *np, int *next)
{
	struct node *npref, *child;
	struct property *prop;
	struct ref *ref;
	const char *p;
	int len;
	char namebuf[128];	/* enough for temp__<n>__ */

	/* for each ref, verify that a label exists */
	/* if it doesn't create one temporary */
	for_each_property_of_node(np, prop) {

		for_each_ref_of_property(prop, ref) {
			if (ref->type != r_anchor)
				continue;

			len = ref->len;
			p = ref->data;

			if (len > 0 && *p == '/')
				npref = node_lookup_by_path(t, ref->data, ref->len);
			else
				npref = node_lookup_by_label(t, ref->data, ref->len);

			/* we don't care about unresolved here */
			if (!npref)
				continue;

			/* there is one, we're OK */
			if (!list_empty(&npref->labels))
				continue;

			/* add a temporary label name */
			memset(namebuf, 0, sizeof(namebuf));
			snprintf(namebuf, sizeof(namebuf) - 1, "temp__%d__", (*next)++);
			namebuf[sizeof(namebuf) - 1] = '\0';

			label_add(t, npref, namebuf);
		}
	}

	for_each_child_of_node(np, child)
		__yaml_assign_temp_labels(t, child, next);
}

void yaml_assign_temp_labels(struct tree *t)
{
	int next = 0;

	__yaml_assign_temp_labels(t, tree_root(t), &next);
}

static bool needs_quotes(const char *str)
{
	char c;

	/* quote empty */
	if (*str == '\0')
		return true;

	while ((c = *str++)) {
		if (c == '#' || isspace(c))
			return true;
	}
	return false;
}

void __yaml_flatten_node(struct tree *t, FILE *fp,
			 struct node *np, bool object,
			 int depth)
{
	struct node *child;
	struct property *prop;
	struct ref *ref;
	struct label *l = NULL;
	int outcount, count, i;

	if (depth > 0) {
		fprintf(fp, "%*s", (depth - 1) * 2, "");
		if (needs_quotes(np->name))
			fprintf(fp, "\"%s\":", np->name);
		else
			fprintf(fp, "%s:", np->name);

		/* output only first label */
		for_each_label_of_node(np, l) {
			fprintf(fp, " &%s", l->label);
			break;
		}
		fputc('\n', fp);
	}

	outcount = 0;
	for_each_property_of_node(np, prop) {

		outcount++;

		fprintf(fp, "%*s", depth * 2, "");
		if (prop->name[0] == '\0')
			fprintf(fp, "-");
		else if (needs_quotes(prop->name))
			fprintf(fp, "\"%s\":", prop->name);
		else
			fprintf(fp, "%s:", prop->name);

		count = 0;
		for_each_ref_of_property(prop, ref) {
			if (ref->type == r_seq_start ||
			    ref->type == r_seq_end)
				continue;
			count++;
		}

		if (count > 1)
			fputs(" [", fp);

		i = 0;
		for_each_ref_of_property(prop, ref) {

			if (ref->type == r_seq_start ||
			    ref->type == r_seq_end)
				continue;

			if (i > 0)
				fputc(',', fp);
			fputc(' ', fp);

			if (ref->type == r_null)
				fputc('~', fp);
			else
				ref_output_single(t, fp, ref, object,
						  false, depth);
			i++;
		}

		if (count > 1)
			fputs(" ]", fp);

		fputc('\n', fp);
	}

	for_each_child_of_node(np, child)
		outcount++;

	/* "~: ~" for an empty tree without props or children */
	if (outcount == 0)
		fprintf(fp, "%*s~: ~\n", depth * 2, "");

	for_each_child_of_node(np, child)
		__yaml_flatten_node(t, fp, child, object, depth + 1);

	/* multiple labels to same node; spit out only the labels */
	if (l && depth > 0) {
		for_each_label_of_node_continue(np, l) {
			fprintf(fp, "%*s# %s: &%s { }\n", (depth - 1) * 2, "",
					np->name, l->label);
		}
	}
}

void yaml_flatten_node(struct tree *t, FILE *fp, bool object)
{
	__yaml_flatten_node(t, fp, tree_root(t), object, 0);
}

void __json_flatten_node(struct tree *t, FILE *fp,
			 struct node *np, bool object,
			 bool last, int depth)
{
	struct node *child;
	struct property *prop;
	struct ref *ref;
	struct label *l;
	int label_count, prop_count, children_count, item_count, count, i, j;

	if (np != tree_root(t))
		fprintf(fp, "%*s\"%s\": {\n", depth * 2, "", np->name);
	else
		fprintf(fp, "%*s{\n", depth * 2, "");

	label_count = 0;
	for_each_label_of_node(np, l)
		label_count++;

	prop_count = 0;
	for_each_property_of_node(np, prop)
		prop_count++;

	children_count = 0;
	for_each_child_of_node(np, child)
		children_count++;

	item_count = (label_count > 0) + prop_count + children_count;

	j = 0;

	/* output labels */
	if (label_count > 0) {
		fprintf(fp, "%*s", (depth + 1) * 2, "");
		fprintf(fp, "\"%s\":", "/label/");
		if (label_count > 1)
			fputs(" [", fp);
		i = 0;
		for_each_label_of_node(np, l) {
			fprintf(fp, " \"%s\"", l->label);
			if (label_count > 1 && i < (label_count - 1))
				fputc(',', fp);
		}
		if (label_count > 1)
			fputs(" ]", fp);
		if (++j < item_count)
			fputc(',', fp);
		fputc('\n', fp);
	}

	for_each_property_of_node(np, prop) {

		if (!prop->name[0]) {
			tree_error_at_property(t, prop,
				"JSON can't handle bare sequences\n");
			continue;
		}

		fprintf(fp, "%*s", (depth + 1) * 2, "");
		/* JSON always needs quotes for key */
		fprintf(fp, "\"%s\":", prop->name);

		count = 0;
		for_each_ref_of_property(prop, ref) {
			if (ref->type == r_seq_start ||
			    ref->type == r_seq_end)
				continue;
			count++;
		}

		if (count > 1)
			fputs(" [", fp);

		i = 0;
		for_each_ref_of_property(prop, ref) {

			if (ref->type == r_seq_start ||
			    ref->type == r_seq_end)
				continue;

			if (i > 0)
				fputc(',', fp);
			fputc(' ', fp);

			if (ref->type == r_null)
				fputs("null", fp);
			else
				ref_output_single(t, fp, ref, object,
						  true, depth);
			i++;
		}

		if (count > 1)
			fputs(" ]", fp);
		if (++j < item_count)
			fputc(',', fp);
		fputc('\n', fp);
	}

	for_each_child_of_node(np, child)
		__json_flatten_node(t, fp, child, object,
				    ++j == item_count, depth + 1);

	fprintf(fp, "%*s}", depth * 2, "");
	if (!last)
		fputc(',', fp);
	fputc('\n', fp);
}

void json_flatten_node(struct tree *t, FILE *fp, bool object)
{
	__json_flatten_node(t, fp, tree_root(t), object, true, 0);
}

int yaml_setup(struct yaml_dt_state *dt)
{
	dt_debug(dt, "YAML configuration:\n");
	dt_debug(dt, " object        = %s\n", dt->cfg.object ? "true" : "false");
	dt_debug(dt, " output_format = %s\n", dt->cfg.output_format);
	return 0;
}

void yaml_cleanup(struct yaml_dt_state *dt)
{
	/* nothing */
}

int yaml_emit(struct yaml_dt_state *dt)
{
	tree_apply_ref_nodes(to_tree(dt), dt->cfg.object, false);
	if (!dt->cfg.object)
		tree_detect_duplicate_labels(to_tree(dt), tree_root(to_tree(dt)));
	yaml_assign_temp_labels(to_tree(dt));
	if (!strcmp(dt->cfg.output_format, "json"))
		json_flatten_node(to_tree(dt), dt->output, dt->cfg.object);
	else
		yaml_flatten_node(to_tree(dt), dt->output, dt->cfg.object);

	return 0;
}

static const struct yaml_dt_emitter_ops yaml_emitter_ops = {
	.setup		= yaml_setup,
	.cleanup	= yaml_cleanup,
	.emit		= yaml_emit,
};

static const char *yaml_suffixes[] = {
	".yaml",
	NULL
};

struct yaml_dt_emitter yaml_emitter = {
	.name		= "yaml",
	.tops		= &yaml_tree_ops,
	.suffixes	= yaml_suffixes,
	.eops		= &yaml_emitter_ops,
};
