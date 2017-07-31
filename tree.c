/*
 * tree.c - DT methods
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

#include "utils.h"

#include "yamldt.h"

#define tree_debug(_t, _fmt, ...) \
	do { \
		if (_t->ops->debugf) \
			_t->ops->debugf(_t, _fmt, ##__VA_ARGS__); \
	} while(0)

struct ref *ref_alloc(struct tree *t, enum ref_type type,
		const void *data, int len,
		const char *xtag)
{
	struct ref *ref;

	assert(t && data);

	ref = t->ops->ref_alloc(t, type, data, len, xtag);
	if (!ref)
		return NULL;
	ref->type = type;

	return ref;
}

void ref_free(struct tree *t, struct ref *ref)
{
	assert(t && ref);

	/* either from the unresolved or node ref list */
	list_del(&ref->node);

	t->ops->ref_free(t, ref);
}

struct property *prop_alloc(struct tree *t, const char *name)
{
	struct property *prop;

	assert(t && name);

	prop = t->ops->prop_alloc(t, name);
	if (!prop)
		return NULL;

	INIT_LIST_HEAD(&prop->refs);

	return prop;
}

void prop_free(struct tree *t, struct property *prop)
{
	struct ref *ref, *refn;

	assert(t && prop);

	if (prop->np)
		list_del(&prop->node);

	list_for_each_entry_safe(ref, refn, &prop->refs, node)
		ref_free(t, ref);

	t->ops->prop_free(t, prop);
}

void prop_del(struct tree *t, struct property *prop)
{
	assert(t && prop);

	if (prop->np) {
		list_del(&prop->node);
		prop->np = NULL;
	}
	prop->deleted = true;
	list_add_tail(&prop->node, &t->del_props);
}

void prop_ref_clear(struct tree *t, struct property *prop)
{
	struct ref *ref, *refn;

	list_for_each_entry_safe(ref, refn, &prop->refs, node)
		ref_free(t, ref);
}

struct label *label_alloc(struct tree *t, const char *label)
{
	assert(t && label);

	return t->ops->label_alloc(t, label);
}

void label_add(struct tree *t, struct node *np,
		const char *label)
{
	struct label *l;

	assert(t && np && label);

	/* do not add duplicate */
	list_for_each_entry(l, &np->labels, node) {
		if (!strcmp(l->label, label))
			return;
	}

	l = label_alloc(t, label);
	l->np = np;
	list_add_tail(&l->node, &np->labels);
}

void label_free(struct tree *t, struct label *l)
{
	assert(t && l);

	if (l->np)
		list_del(&l->node);

	t->ops->label_free(t, l);
}

struct node *node_alloc(struct tree *t, const char *name,
			     const char *label)
{
	struct node *np;

	assert(t && name);

	np = t->ops->node_alloc(t, name, label);
	if (!np)
		return NULL;

	INIT_LIST_HEAD(&np->children);
	INIT_LIST_HEAD(&np->properties);
	INIT_LIST_HEAD(&np->labels);
	if (label)
		label_add(t, np, label);
	return np;
}

void node_free(struct tree *t, struct node *np)
{
	struct node *child, *childn;
	struct property *prop, *propn;
	struct label *l, *ln;

	assert(t && np);

	list_for_each_entry_safe(child, childn, &np->children, node)
		node_free(t, child);

	list_for_each_entry_safe(prop, propn, &np->properties, node)
		prop_del(t, prop);

	list_for_each_entry_safe(l, ln, &np->labels, node)
		label_free(t, l);

	if (np->parent)
		list_del(&np->node);

	t->ops->node_free(t, np);
}

static struct node *__node_lookup_by_label(struct tree *t, struct node *np,
		const char *label, int len)
{
	struct node *child, *found;
	struct label *l;

	list_for_each_entry(l, &np->labels, node) {
		if (strlen(l->label) == len &&
		    !memcmp(l->label, label, len))
			return np;
	}

	list_for_each_entry(child, &np->children, node) {
		found = __node_lookup_by_label(t, child, label, len);
		if (found)
			return found;
	}
	return NULL;
}

struct node *node_lookup_by_label(struct tree *t,
		const char *label, int len)
{
	assert(t && label);

	if (!t->root)
		return NULL;

	if (len < 0)
		len = strlen(label);

	return __node_lookup_by_label(t, t->root, label, len);
}

const char *dn_fullname_multi(struct node *np, char **buf, int *size)
{
	struct node *npt;
	char *p;
	int len, tlen;
	const char *ret;

	/* special case for root */
	if (np->parent == NULL) {
		/* either / or ref node (which shouldn't have / at start) */
		if (!np->name || !strcmp(np->name, "/") || strlen(np->name) == 0)
			return "/";
		return np->name;
	}

	npt = np;
	tlen = 0;
	while (npt != NULL) {
		if (npt != np)
			tlen++;
		len = strlen(npt->name);
		tlen += len;
		npt = npt->parent;
	}
	tlen++;

	/* truncated */
	if (tlen > *size)
		return "<>";

	ret = *buf;
	p = *buf + tlen;
	*--p = '\0';

	npt = np;
	while (npt != NULL) {
		if (npt != np)
			*--p = '/';
		len = strlen(npt->name);
		memcpy(p - len, npt->name, len);
		p -= len;
		npt = npt->parent;
	}
	/* verify that we are correct */
	assert(ret == *buf);

	*size -= tlen;
	*buf += tlen;

	return ret;
}

const char *dn_fullname(struct node *np, char *buf, int size)
{
	return dn_fullname_multi(np, &buf, &size);
}

void tree_init(struct tree *t, const struct tree_ops *ops)
{
	assert(t && ops &&
		ops->ref_alloc &&
		ops->ref_free &&
		ops->prop_alloc &&
		ops->prop_free &&
		ops->label_alloc &&
		ops->label_free &&
		ops->node_alloc &&
		ops->node_free);

	t->root = NULL;
	INIT_LIST_HEAD(&t->ref_nodes);
	INIT_LIST_HEAD(&t->del_props);
	t->ops = ops;
}

void tree_cleanup(struct tree *t)
{
	struct node *np, *npn;
	struct property *prop, *propn;

	/* free the root */
	if (t->root)
		node_free(t, t->root);
	t->root = NULL;

	/* free the ref nodes */
	list_for_each_entry_safe(np, npn, &t->ref_nodes, node) {
		list_del(&np->node);
		assert(!np->parent);
		node_free(t, np);
	}

	/* free the deleted properties */
	list_for_each_entry_safe(prop, propn, &t->del_props, node)
		prop_free(t, prop);
}

/* clear any crud that shouldn't be part of the base tree */
static void sanitize_base(struct tree *t, struct node *np)
{
	struct node *child;
	struct property *prop, *propn;
	char namebuf[NODE_FULLNAME_MAX];

	list_for_each_entry_safe(prop, propn, &np->properties, node) {
		if (prop->is_delete || !strcmp(prop->name, "~")) {
			tree_debug(t, "removing property %s @%s\n",
				prop->name, dn_fullname(np, namebuf, sizeof(namebuf)));
			prop_del(t, prop);
		}
	}

	list_for_each_entry(child, &np->children, node)
		sanitize_base(t, child);
}

void tree_apply_ref_node(struct tree *t, struct node *npref,
			 struct node *np)
{
	struct property *prop, *propn;
	struct property *propref, *proprefn;
	struct label *l, *ln;
	struct node *child, *childn, *childref, *childrefn;
	bool found;
	char namebuf[2][NODE_FULLNAME_MAX];

	/* add label to noderef */
	list_for_each_entry_safe(l, ln, &np->labels, node)
		label_add(t, npref, l->label);

	list_for_each_entry_safe(prop, propn, &np->properties, node) {

		tree_debug(t, "using property %s @%s\n",
			prop->name,
			dn_fullname(np, &namebuf[0][0], sizeof(namebuf[0])));

		if (prop->is_delete) {
			list_for_each_entry_safe(propref, proprefn, &npref->properties, node) {
				if (strcmp(propref->name, prop->name))
					continue;

				tree_debug(t, "deleting property %s at %s\n",
					propref->name,
					dn_fullname(npref, &namebuf[0][0], sizeof(namebuf[0])));

				prop_del(t, propref);
			}

			list_for_each_entry_safe(childref, childrefn, &npref->children, node) {
				if (strcmp(childref->name, prop->name))
					continue;

				tree_debug(t, "deleting child %s at %s\n",
					dn_fullname(childref, &namebuf[0][0], sizeof(namebuf[0])),
					dn_fullname(npref, &namebuf[1][0], sizeof(namebuf[1])));

				node_free(t, childref);
			}

			prop_del(t, prop);
			continue;
		}

		found = false;
		list_for_each_entry_safe(propref, proprefn, &npref->properties, node) {
			if (!strcmp(propref->name, prop->name)) {
				found = true;
				break;
			}
		}

		list_del(&prop->node);
		prop->np = npref;

		/* if found, free old copy */
		if (found) {
			/* carefully put it at the same point in the list */
			list_add(&prop->node, &propref->node);
			list_del(&propref->node);
			propref->np = NULL;
			prop_del(t, propref);
		} else /* move property over to new parent */
			list_add_tail(&prop->node, &npref->properties);
	}

	list_for_each_entry_safe(child, childn, &np->children, node) {

		/* find matching child */
		found = false;
		list_for_each_entry(childref, &npref->children, node) {
			if (!strcmp(childref->name, child->name)) {
				found = true;
				break;
			}
		}

		if (!found) {
			/* child at ref does not exist, just move self over */
			list_del(&child->node);
			child->parent = npref;
			list_add_tail(&child->node, &npref->children);
			sanitize_base(t, child);
		} else
			tree_apply_ref_node(t, childref, child);

	}
}
