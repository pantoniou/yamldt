/*
 * tree.h - Generic tree handling
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
#ifndef TREE_H
#define TREE_H

#include <stdint.h>
#include <sys/time.h>
#ifdef __linux__
#include <linux/limits.h>
#else
#include <limits.h>
#endif

#include "list.h"

struct node;

struct property {
	struct list_head node;
	struct node *np;
	char *name;
	struct list_head refs;
	bool is_delete : 1;	/* set to true it is signals deletion */
	bool deleted : 1;
};

struct node {
	struct list_head node;
	struct node *parent;
	struct list_head children;
	struct list_head properties;
	struct list_head labels;
	char *name;
	bool is_delete : 1;	/* set to true it is signals deletion */
	bool deleted : 1;
};

struct label {
	struct list_head node;
	struct node *np;
	char *label;
	size_t len;
	struct list_head hnode;	/* for hashing */
	uint32_t hash;
	bool duplicate : 1;
};

enum ref_type {
	r_anchor,
	r_path,
	r_scalar,
	r_null,
	r_seq_start,
	r_seq_end
};

struct ref {
	struct list_head node;
	enum ref_type type;
	struct property *prop;
	const void *data;
	int len;
	char *xtag;	/* explicit tag */
	const char *xtag_builtin;
};

struct tree;

typedef void (*tree_debugf_t)(struct tree *t, const char *fmt, ...)
		__attribute__ ((__format__ (__printf__, 2, 0)));

struct tree_ops {
	struct ref *(*ref_alloc)(struct tree *t, enum ref_type type,
			const void *data, int len, const char *xtag);
	void (*ref_free)(struct tree *t, struct ref *ref);

	struct property *(*prop_alloc)(struct tree *t, const char *name);
	void (*prop_free)(struct tree *t, struct property *prop);

	struct label *(*label_alloc)(struct tree *t, const char *name);
	void (*label_free)(struct tree *t, struct label *l);

	struct node *(*node_alloc)(struct tree *t, const char *name,
					 const char *label);
	void (*node_free)(struct tree *t, struct node *np);

	void (*debugf)(struct tree *t, const char *fmt, ...)
			__attribute__ ((__format__ (__printf__, 2, 0)));
	void (*error_at_node)(struct tree *t, struct node *np,
			const char *fmt, ...)
			__attribute__ ((__format__ (__printf__, 3, 0)));
	void (*error_at_property)(struct tree *t, struct property *prop,
			const char *fmt, ...)
			__attribute__ ((__format__ (__printf__, 3, 0)));
	void (*error_at_ref)(struct tree *t, struct ref *ref,
			const char *fmt, ...)
			__attribute__ ((__format__ (__printf__, 3, 0)));
	void (*error_at_label)(struct tree *t, struct label *l,
			const char *fmt, ...)
			__attribute__ ((__format__ (__printf__, 3, 0)));
};

#ifndef LABEL_HASH_SIZE
#define LABEL_HASH_SIZE	251	/* the largest prime less than 255 */
#endif

struct tree {
	struct node *root;
	struct list_head ref_nodes;
	const struct tree_ops *ops;
	struct list_head lhash[LABEL_HASH_SIZE];
};

/* FVN-1 hash */
static inline uint32_t label_hash(const char *label, size_t len)
{
	uint32_t hval;

	/* initial FV1 hash value */
	hval = 0x811c9dc5;
	while (len > 0) {
		/* multiply by the 32 bit FNV magic prime mod 2^32 */
		hval += (hval << 1) + (hval << 4) +
			(hval << 7) + (hval << 8) +
			(hval << 24);
		/* xor the bottom with the current octet */
		hval ^= (uint32_t)*label++;
		len--;
	}
	return hval;
}

static inline struct node *tree_root(struct tree *t)
{
	return t->root;
}

static inline void tree_set_root(struct tree *t, struct node *np)
{
	t->root = np;
}

static inline struct list_head *tree_ref_nodes(struct tree *t)
{
	return &t->ref_nodes;
}

/* children list accessors */
#define for_each_child_of_node(np, child) \
	list_for_each_entry(child, &(np)->children, node) \
		if (!(child)->deleted)

#define for_each_child_of_node_safe(np, child, childn) \
	list_for_each_entry_safe(child, childn, &(np)->children, node) \
		if (!(child)->deleted)

#define for_each_child_of_node_withdel(np, child) \
	list_for_each_entry(child, &(np)->children, node)

#define for_each_child_of_node_safe_withdel(np, child, childn) \
	list_for_each_entry_safe(child, childn, &(np)->children, node) 

#define first_child_of_node(np) \
	list_entry(&(np)->children, struct node, node)

/* property list accessors */
#define for_each_property_of_node(np, prop) \
	list_for_each_entry(prop, &(np)->properties, node) \
		if (!(prop)->deleted)

#define for_each_property_of_node_safe(np, prop, propn) \
	list_for_each_entry_safe(prop, propn, &(np)->properties, node) \
		if (!(prop)->deleted)

#define for_each_property_of_node_withdel(np, prop) \
	list_for_each_entry(prop, &(np)->properties, node)

#define for_each_property_of_node_safe_withdel(np, prop, propn) \
	list_for_each_entry_safe(prop, propn, &(np)->properties, node) 

#define first_property_of_node(np) \
	list_entry(&(np)->properties, struct property, node)

/* ref list accessors */
#define for_each_ref_of_property(prop, ref) \
	list_for_each_entry(ref, &(prop)->refs, node)

#define for_each_ref_of_property_safe(prop, ref, refn) \
	list_for_each_entry_safe(ref, refn, &(prop)->refs, node)

#define for_each_ref_of_property_continue(prop, ref) \
	list_for_each_entry_continue(ref, &(prop)->refs, node)

#define first_ref_of_property(prop) \
	list_entry(&(prop)->refs, struct ref, node)

/* label list accessors */
#define for_each_label_of_node(np, l) \
	list_for_each_entry(l, &(np)->labels, node)

#define for_each_label_of_node_safe(np, l, ln) \
	list_for_each_entry_safe(l, ln, &(np)->labels, node)

#define for_each_label_of_node_continue(np, l) \
	list_for_each_entry_continue(l, &(np)->labels, node)

#define first_label_of_node(np) \
	list_entry(&(np)->labels, struct label, node)

void tree_init(struct tree *t, const struct tree_ops *ops);
void tree_cleanup(struct tree *t);

struct ref *ref_alloc(struct tree *t, enum ref_type type,
		const void *data, int len,
		const char *xtag);
void ref_free(struct tree *t, struct ref *ref);

struct label *label_add_nolink(struct tree *t, struct node *np,
			       const char *label);
void label_add(struct tree *t, struct node *np, const char *label);
void label_free(struct tree *t, struct label *l);

struct property *prop_alloc(struct tree *t, const char *name);
void prop_free(struct tree *t, struct property *prop);
void prop_del(struct tree *t, struct property *prop);
void prop_ref_clear(struct tree *t, struct property *prop);

struct node *node_alloc(struct tree *t, const char *name, const char *label);
void node_free(struct tree *t, struct node *np);
void node_clear(struct tree *t, struct node *np);
void node_del(struct tree *t, struct node *np);

struct node *node_lookup_by_label(struct tree *t,
		const char *label, int len);
struct node *node_lookup_by_path(struct tree *t,
		const char *path, int len);
/* leading * ref, leading / path */
struct node *node_lookup(struct tree *t, const char *key, int len);

struct node *node_get_child_by_name(struct tree *t,
			    struct node *np, const char *name,
			    int index);
struct property *prop_get_by_name(struct tree *t,
		struct node *np, const char *name,
		int index);
struct ref *ref_get_by_index(struct tree *t,
		struct property *prop, int index);

bool tree_apply_single_ref_node(struct tree *t, struct node *np,
				bool object, bool compatible);
void tree_apply_ref_node(struct tree *t, struct node *npref,
			 struct node *np, bool compatible);
void tree_apply_ref_nodes(struct tree *t, bool object, bool compatible);

int tree_detect_duplicate_labels(struct tree *t, struct node *np);

/* this should be enough */
#define NODE_FULLNAME_MAX	4096
const char *dn_fullname_multi(struct node *np, char **buf, int *size);
const char *dn_fullname(struct node *np, char *buf, int bufsize);

#define tree_debug(_t, _fmt, ...) \
	do { \
		if (_t->ops->debugf) \
			_t->ops->debugf(_t, _fmt, ##__VA_ARGS__); \
	} while(0)

#define tree_error_at_node(_t, _np, _fmt, ...) \
	do { \
		if (_t->ops->error_at_node) \
			_t->ops->error_at_node(_t, _np, _fmt, ##__VA_ARGS__); \
	} while(0)
#define tree_error_at_property(_t, _prop, _fmt, ...) \
	do { \
		if (_t->ops->error_at_property) \
			_t->ops->error_at_property(_t, _prop, _fmt, ##__VA_ARGS__); \
	} while(0)
#define tree_error_at_ref(_t, _ref, _fmt, ...) \
	do { \
		if (_t->ops->error_at_ref) \
			_t->ops->error_at_ref(_t, _ref, _fmt, ##__VA_ARGS__); \
	} while(0)
#define tree_error_at_label(_t, _ref, _fmt, ...) \
	do { \
		if (_t->ops->error_at_label) \
			_t->ops->error_at_label(_t, _ref, _fmt, ##__VA_ARGS__); \
	} while(0)

#endif
