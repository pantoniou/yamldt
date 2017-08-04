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

#define DEFAULT_COMPILER "clang-5.0"
#define DEFAULT_CFLAGS "-x c -target bpf -O2 -c -o - -"
#define DEFAULT_TAGS "!filter,!ebpf"

struct yaml_emit_config {
	bool object;
	const char *compiler;
	const char *cflags;
	const char *compiler_tags;
};
#define to_yaml_cfg(_dt) ((struct yaml_emit_config *)((_dt)->emitter_cfg))

struct yaml_emit_state {
	bool object;
	const char *compiler;
	const char *cflags;
	const char *compiler_tags;
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
	.ref_alloc	= yaml_ref_alloc,
	.ref_free	= yaml_ref_free,
	.prop_alloc	= yaml_prop_alloc,
	.prop_free	= yaml_prop_free,
	.label_alloc	= yaml_label_alloc,
	.label_free	= yaml_label_free,
	.node_alloc	= yaml_node_alloc,
	.node_free	= yaml_node_free,
	.debugf		= yaml_dt_tree_debugf,
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

static void ref_output_single(struct yaml_dt_state *dt, struct ref *ref, int depth)
{
	struct yaml_emit_state *yaml = to_yaml(dt);
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
		np = node_lookup_by_label(to_tree(dt),
				ref->data, ref->len);
		if (!np && !yaml->object) {
			dt_error_at(dt, &to_dt_ref(ref)->m,
				    "Can't resolve reference to label %s\n",
				    refname);
			return;
		}

		/* object mode, just leave references here */
		if (!np && yaml->object) {
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
			dt_warning_at(dt, &to_dt_ref(ref)->m,
				    "Switching label %s to label %s\n",
				    namebuf, l->label);
		}

		fprintf(dt->output, "*%s", l->label);
		break;

	case r_path:
		np = node_lookup_by_label(to_tree(dt),
				ref->data, ref->len);
		if (!np && !yaml->object) {
			dt_error_at(dt, &to_dt_ref(ref)->m,
				    "Can't resolve reference to label %s\n",
				    refname);
			return;
		}

		/* object mode, just leave references here */
		if (!np && yaml->object) {
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
			dt_warning_at(dt, &to_dt_ref(ref)->m,
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
		if (xtag && strcmp(xtag, "!str") &&
			    strcmp(xtag, yaml->input_compiler_tag))
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
				dt_error_at(dt, &to_dt_ref(ref)->m,
					    "Invalid integer syntax; %s\n",
					    refname);
				return;
			}
			if (!int_val_in_range(tag, val, is_unsigned, is_hex)) {
				dt_error_at(dt, &to_dt_ref(ref)->m,
					    "Integer out of range: %s\n",
					    refname);
				return;
			}

			if (is_hex)
				fprintf(dt->output, "0x%llx", val);
			else if (is_unsigned)
				fprintf(dt->output, "%llu", val);
			else
				fprintf(dt->output, "%lld", (long long)val);

		} else if (!strcmp(tag, "!str")) {

			/* no newlines? easy */
			if (!memchr(ref->data, '\n', ref->len)) {
				fputc('"', dt->output);
				fwrite(ref->data, ref->len, 1, dt->output);
				fputc('"', dt->output);
			} else {
				fputs("|", dt->output);
				s = ref->data;
				while (s && s < (char *)ref->data + ref->len) {
					e = memchr(s, '\n', (char *)ref->data + ref->len - s);
					if (!e)
						e = ref->data + ref->len;
					fprintf(dt->output, "\n%*s", (depth + 1) * 2, "");
					fwrite(s, e - s, 1, dt->output);
					s = e < ((char *)ref->data + ref->len) ? e + 1 : NULL;
				}
			}

		} else if (!strcmp(tag, "!bool")) {
			fwrite(ref->data, ref->len, 1, dt->output);
		} else if (!strcmp(tag, "!null")) {
			fwrite(ref->data, ref->len, 1, dt->output);
		} else if (!strcmp(tag, yaml->input_compiler_tag)) {
			dt_debug(dt, "Compiling...\n");

			ret = compile(ref->data, ref->len,
					yaml->compiler, yaml->cflags,
					&output, &output_size);
			if (ret) {
				dt_error_at(dt, &to_dt_ref(ref)->m,
					"Failed to compile %s:\n%s %s\n%s\n",
					tag, yaml->compiler, yaml->cflags, refname);
				break;
			}

			b64_output = base64_encode(output, output_size, &b64_output_size);
			free(output);

			if (!b64_output) {
				dt_error_at(dt, &to_dt_ref(ref)->m,
					"Failed to encode to base64 %s: %s\n", tag, refname);
				break;
			}

			/* base64 output */
			fprintf(dt->output, "%s |", yaml->output_compiler_tag);
			s = b64_output;
			while (s && s < (char *)b64_output + b64_output_size) {
				e = memchr(s, '\n', (char *)b64_output + b64_output_size - s);
				if (!e)
					e = b64_output + b64_output_size;
				fprintf(dt->output, "\n%*s", (depth + 1) * 2, "");
				fwrite(s, e - s, 1, dt->output);
				s = e < ((char *)b64_output + b64_output_size) ? e + 1 : NULL;
			}

			free(b64_output);

		} else {
			fwrite(ref->data, ref->len, 1, dt->output);
			dt_warning_at(dt, &to_dt_ref(ref)->m,
				"Unknown tag %s: %s\n", tag, refname);
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
	struct yaml_emit_state *yaml = to_yaml(dt);
	struct node *np, *npn, *npref;
	struct list_head *ref_nodes = tree_ref_nodes(to_tree(dt));

	list_for_each_entry_safe(np, npn, ref_nodes, node) {

		npref = node_lookup_by_label(to_tree(dt), np->name + 1,
				strlen(np->name + 1));

		if (!npref && !yaml->object)
			dt_error_at(dt, &to_dt_node(np)->m,
				"reference to unknown label %s\n",
				np->name + 1);

		if (npref)
			tree_apply_ref_node(to_tree(dt), npref, np);

		/* free everything now */
		if (npref || !yaml->object) {
			list_del(&np->node);
			node_free(to_tree(dt), np);
		}
	}

	if (!yaml->object)
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

int yaml_setup(struct yaml_dt_state *dt)
{
	struct yaml_emit_config *yaml_cfg = to_yaml_cfg(dt);
	struct yaml_emit_state *yaml;
	int len;
	char *s;

	yaml = malloc(sizeof(*yaml));
	assert(yaml);
	memset(yaml, 0, sizeof(*yaml));

	dt->emitter_state = yaml;

	yaml->object = yaml_cfg->object;
	yaml->compiler = yaml_cfg->compiler;
	yaml->cflags = yaml_cfg->cflags;
	yaml->compiler_tags = yaml_cfg->compiler_tags;

	s = strchr(yaml->compiler_tags, ',');
	assert(s);	/* should be already handled by parseopts */

	len = s - yaml->compiler_tags;
	yaml->input_compiler_tag = malloc(len + 1);
	assert(yaml->input_compiler_tag);
	memcpy(yaml->input_compiler_tag, yaml->compiler_tags, len);
	yaml->input_compiler_tag[len] = '\0';

	len = strlen(++s);
	yaml->output_compiler_tag = malloc(len + 1);
	assert(yaml->output_compiler_tag);
	memcpy(yaml->output_compiler_tag, s, len);
	yaml->output_compiler_tag[len] = '\0';

	tree_init(to_tree(dt), &yaml_tree_ops);

	dt_debug(dt, "YAML configuration:\n");
	dt_debug(dt, " object     = %s\n", yaml->object ? "true" : "false");
	dt_debug(dt, " compiler   = %s\n", yaml->compiler);
	dt_debug(dt, " cflags     = %s\n", yaml->cflags);
	dt_debug(dt, " in-tag     = %s\n", yaml->input_compiler_tag);
	dt_debug(dt, " out-tag    = %s\n", yaml->output_compiler_tag);

	return 0;
}

void yaml_cleanup(struct yaml_dt_state *dt)
{
	struct yaml_emit_state *yaml = to_yaml(dt);
	struct yaml_emit_config *yaml_cfg = to_yaml_cfg(dt);

	tree_cleanup(to_tree(dt));

	if (yaml_cfg)
		free(yaml_cfg);


	free(yaml->input_compiler_tag);
	free(yaml->output_compiler_tag);

	memset(yaml, 0, sizeof(*yaml));
	free(yaml);
}

int yaml_emit(struct yaml_dt_state *dt)
{
	yaml_apply_ref_nodes(dt);
	yaml_flatten_node(dt);

	return 0;
}

static struct option opts[] = {
	{ "yaml",	 no_argument, 0, 'y' },
	{ "object",	 no_argument, 0, 'c' },
	{0, 0, 0, 0}
};

static bool yaml_select(int argc, char **argv)
{
	int cc, option_index = -1;

	optind = 0;
	opterr = 0;	/* do not print error for invalid option */
	while ((cc = getopt_long(argc, argv,
			"y", opts, &option_index)) != -1) {
		/* explicit yaml mode select */
		if (cc == 'y')
			return true;
	}

	return false;
}

static int yaml_parseopts(int *argcp, char **argv, int *optindp,
			  const struct yaml_dt_config *cfg, void **ecfg)
{
	int cc, option_index = -1;
	struct yaml_emit_config *yaml_cfg;

	yaml_cfg = malloc(sizeof(*yaml_cfg));
	assert(yaml_cfg);
	memset(yaml_cfg, 0, sizeof(*yaml_cfg));

	/* get and consume non common options */
	option_index = -1;
	*optindp = 0;
	opterr = 1;	/* do print error for invalid option */
	while ((cc = getopt_long(*argcp, argv,
			"ycO:f:t:", opts, &option_index)) != -1) {

		switch (cc) {
		case 'c':
			yaml_cfg->object = true;
			break;
		case 'y':
			/* nothing to do for this */
			break;
		case 'O':
			yaml_cfg->compiler = optarg;
			break;
		case 'f':
			yaml_cfg->cflags = optarg;
			break;
		case 't':
			/* must be seperated by comma */
			if (!strchr(optarg, ','))
				return -1;
			yaml_cfg->compiler_tags = optarg;
			break;
		case '?':
			/* invalid option */
			return -1;
		}

		long_opt_consume(argcp, argv, opts, optindp, optarg, cc,
				 option_index);
	}

	if (!yaml_cfg->compiler)
		yaml_cfg->compiler = DEFAULT_COMPILER;
	if (!yaml_cfg->cflags)
		yaml_cfg->cflags = DEFAULT_CFLAGS;
	if (!yaml_cfg->compiler_tags)
		yaml_cfg->compiler_tags = DEFAULT_TAGS;

	*ecfg = yaml_cfg;

	return 0;
}

static const struct yaml_dt_emitter_ops yaml_emitter_ops = {
	.select		= yaml_select,
	.parseopts	= yaml_parseopts,
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

	.usage_banner	= 
"   -y, --yaml          Generate YAML output\n"
"   -c, --object        Object mode\n"
"   -O, --compiler      Compiler to use for !filter tag\n"
"                       (default: " DEFAULT_COMPILER ")\n"
"   -f, --cflags        CFLAGS when compiling\n"
"                       (default: " DEFAULT_CFLAGS ")\n"
"   -t, --cflags        Tags to use for compiler input/output markers\n"
"                       (default: " DEFAULT_TAGS ")\n",

	.suffixes	= yaml_suffixes,
	.eops		= &yaml_emitter_ops,
};
