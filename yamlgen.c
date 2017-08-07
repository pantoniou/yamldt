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

#include "yamldt.h"

#include "yamlgen.h"

struct yaml_emit_state {
	bool object;
	char *input_compiler_tag;
	char *output_compiler_tag;
};
#define to_yaml(_dt) ((struct yaml_emit_state *)(_dt)->emitter_state)

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
	.error_at_node		= yaml_dt_tree_error_at_node,
	.error_at_property	= yaml_dt_tree_error_at_property,
	.error_at_ref		= yaml_dt_tree_error_at_ref,
};

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

static void ref_output_single(struct tree *t, FILE *fp,
			      struct ref *ref, bool object,
			      const char *compiler, const char *cflags,
			      const char *input_compiler_tag,
			      const char *output_compiler_tag,
			      int depth)
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
	char *refname;
	int refnamelen;
	const char *s, *e;
	void *output;
	size_t output_size;
	void *b64_output;
	size_t b64_output_size;

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

	switch (ref->type) {
	case r_anchor:
		np = node_lookup_by_label(t, ref->data, ref->len);
		if (!np && !object) {
			tree_error_at_ref(t, ref,
				    "Can't resolve reference to label %s\n",
				    refname);
			return;
		}

		/* object mode, just leave references here */
		if (!np && object) {
			fputc('*', fp);
			fwrite(ref->data, ref->len, 1, fp);
			break;
		}

		/* if not the first label, switch it to the first */
		l = list_first_entry(&np->labels, struct label, node);
		if (strlen(l->label) != ref->len ||
		    memcmp(l->label, ref->data, ref->len)) {
			strncat(namebuf, ref->data, sizeof(namebuf) - 1);
			namebuf[sizeof(namebuf) - 1] = '\0';
			tree_debug(t, "Switching label %s to label %s\n",
				    namebuf, l->label);
		}

		fprintf(fp, "*%s", l->label);
		break;

	case r_path:
		np = node_lookup_by_label(t, ref->data, ref->len);
		if (!np && !object) {
			tree_error_at_ref(t, ref,
				    "Can't resolve reference to label %s\n",
				    refname);
			return;
		}

		/* object mode, just leave references here */
		if (!np && object) {
			fputs("!pathref ", fp);
			fwrite(ref->data, ref->len, 1, fp);
			break;
		}

		/* if not the first label, switch it to the first */
		l = list_first_entry(&np->labels, struct label, node);
		if (strlen(l->label) != ref->len ||
		    memcmp(l->label, ref->data, ref->len)) {
			strncat(namebuf, ref->data, sizeof(namebuf) - 1);
			namebuf[sizeof(namebuf) - 1] = '\0';
			tree_debug(t, "Switching label %s to label %s\n",
				    namebuf, l->label);
		}

		fprintf(fp, "!pathref %s", l->label);
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
		if (xtag && strcmp(xtag, "!str") &&
			(input_compiler_tag && strcmp(xtag, input_compiler_tag)))
			fprintf(fp, "%s ", xtag);

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
				tree_error_at_ref(t, ref,
					    "Invalid integer syntax; %s\n",
					    refname);
				return;
			}
			if (!int_val_in_range(tag, val, is_unsigned, is_hex)) {
				tree_error_at_ref(t, ref,
					    "Integer out of range: %s\n",
					    refname);
				return;
			}

			if (is_hex)
				fprintf(fp, "0x%llx", val);
			else if (is_unsigned)
				fprintf(fp, "%llu", val);
			else
				fprintf(fp, "%lld", (long long)val);

		} else if (!strcmp(tag, "!str")) {

			/* no newlines? easy */
			if (!memchr(ref->data, '\n', ref->len)) {
				fputc('"', fp);
				fwrite(ref->data, ref->len, 1, fp);
				fputc('"', fp);
			} else {
				fputs("|", fp);
				s = ref->data;
				while (s && s < (char *)ref->data + ref->len) {
					e = memchr(s, '\n', (char *)ref->data + ref->len - s);
					if (!e)
						e = ref->data + ref->len;
					fprintf(fp, "\n%*s", (depth + 1) * 2, "");
					fwrite(s, e - s, 1, fp);
					s = e < ((char *)ref->data + ref->len) ? e + 1 : NULL;
				}
			}

		} else if (!strcmp(tag, "!bool")) {
			fwrite(ref->data, ref->len, 1, fp);
		} else if (!strcmp(tag, "!null")) {
			fwrite(ref->data, ref->len, 1, fp);
		} else if (input_compiler_tag && !strcmp(tag, input_compiler_tag)) {
			tree_debug(t, "Compiling...\n");

			ret = compile(ref->data, ref->len,
					compiler,cflags,
					&output, &output_size);
			if (ret) {
				tree_error_at_ref(t, ref,
					"Failed to compile %s:\n%s %s\n%s\n",
					tag, compiler, cflags, refname);
				break;
			}

			b64_output = base64_encode(output, output_size, &b64_output_size);
			free(output);

			if (!b64_output) {
				tree_error_at_ref(t, ref,
					"Failed to encode to base64 %s: %s\n", tag, refname);
				break;
			}

			/* base64 output */
			fprintf(fp, "%s |", output_compiler_tag);
			s = b64_output;
			while (s && s < (char *)b64_output + b64_output_size) {
				e = memchr(s, '\n', (char *)b64_output + b64_output_size - s);
				if (!e)
					e = b64_output + b64_output_size;
				fprintf(fp, "\n%*s", (depth + 1) * 2, "");
				fwrite(s, e - s, 1, fp);
				s = e < ((char *)b64_output + b64_output_size) ? e + 1 : NULL;
			}

			free(b64_output);

		} else {
			fwrite(ref->data, ref->len, 1, fp);
			tree_debug(t, "Unknown tag %s: %s\n", tag, refname);
		}

		break;

	default:
		/* nothing */
		break;
	}
}

void __yaml_flatten_node(struct tree *t, FILE *fp,
			 struct node *np, bool object,
			 const char *compiler, const char *cflags,
			 const char *input_compiler_tag,
			 const char *output_compiler_tag,
			 int depth)
{
	struct node *child;
	struct property *prop;
	struct ref *ref;
	struct label *l = NULL;
	int outcount, count, i;

	if (depth > 0) {
		fprintf(fp, "%*s%s:", (depth - 1) * 2, "",
				np->name);

		/* output only first label */
		list_for_each_entry(l, &np->labels, node) {
			fprintf(fp, " &%s", l->label);
			break;
		}
		fputc('\n', fp);
	}

	outcount = 0;
	list_for_each_entry(prop, &np->properties, node) {
		outcount++;

		fprintf(fp, "%*s", depth * 2, "");
		if (prop->name[0] == '\0')
			fprintf(fp, "-");
		else if (prop->name[0] != '#')
			fprintf(fp, "%s:", prop->name);
		else
			fprintf(fp, "\"%s\":", prop->name);

		count = 0;
		list_for_each_entry(ref, &prop->refs, node) {
			if (ref->type == r_seq_start ||
			    ref->type == r_seq_end)
				continue;
			count++;
		}

		if (count > 1)
			fputs(" [", fp);

		i = 0;
		list_for_each_entry(ref, &prop->refs, node) {

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
						compiler, cflags,
						input_compiler_tag,
						output_compiler_tag,
						depth);
			i++;
		}

		if (count > 1)
			fputs(" ]", fp);

		fputc('\n', fp);
	}

	list_for_each_entry(child, &np->children, node)
		outcount++;

	/* "~: ~" for an empty tree without props or children */
	if (outcount == 0)
		fprintf(fp, "%*s~: ~\n", depth * 2, "");

	list_for_each_entry(child, &np->children, node)
		__yaml_flatten_node(t, fp, child, object,
				    compiler, cflags,
				    input_compiler_tag, output_compiler_tag,
				    depth + 1);

	/* multiple labels to same node; spit out only the labels */
	if (l && depth > 0) {
		list_for_each_entry_continue(l, &np->labels, node) {
			fprintf(fp, "%*s# %s: &%s { }\n", (depth - 1) * 2, "",
					np->name, l->label);
		}
	}
}

void yaml_flatten_node(struct tree *t, FILE *fp, bool object,
		       const char *compiler, const char *cflags,
		       const char *input_compiler_tag,
		       const char *output_compiler_tag)
{
	__yaml_flatten_node(t, fp, tree_root(t), object, compiler, cflags,
			input_compiler_tag, output_compiler_tag, 0);
}

int yaml_setup(struct yaml_dt_state *dt)
{
	struct yaml_emit_state *yaml;

	yaml = malloc(sizeof(*yaml));
	assert(yaml);
	memset(yaml, 0, sizeof(*yaml));

	dt->emitter_state = yaml;

	yaml->object = dt->cfg.object;

	dt_debug(dt, "YAML configuration:\n");
	dt_debug(dt, " object     = %s\n", yaml->object ? "true" : "false");

	return 0;
}

void yaml_cleanup(struct yaml_dt_state *dt)
{
	struct yaml_emit_state *yaml = to_yaml(dt);

	free(yaml->input_compiler_tag);
	free(yaml->output_compiler_tag);

	memset(yaml, 0, sizeof(*yaml));
	free(yaml);
}

int yaml_emit(struct yaml_dt_state *dt)
{
	struct yaml_emit_state *yaml = to_yaml(dt);

	tree_apply_ref_nodes(to_tree(dt), yaml->object);
	yaml_flatten_node(to_tree(dt), dt->output,
			  yaml->object,
			  dt->cfg.compiler, dt->cfg.cflags,
			  dt->input_compiler_tag,
			  dt->output_compiler_tag);

	return 0;
}

static bool yaml_select(int argc, char **argv)
{
	int i;

	/* explicit yaml mode select */
	for (i = 1; i < argc; i++) {
		if (argv[i][0] == '-' && argv[i][1] == 'y')
			return true;
	}
	return false;
}

static const struct yaml_dt_emitter_ops yaml_emitter_ops = {
	.select		= yaml_select,
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
