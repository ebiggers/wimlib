/*
 *  Red Black Trees
 *  Copyright (C) 1999  Andrea Arcangeli <andrea@suse.de>
 *
 *  This program is free software; you can redistribute it and/or modify
 *  it under the terms of the GNU General Public License as published by
 *  the Free Software Foundation; either version 2 of the License, or
 *  (at your option) any later version.
 *
 *  This program is distributed in the hope that it will be useful,
 *  but WITHOUT ANY WARRANTY; without even the implied warranty of
 *  MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
 *  GNU General Public License for more details.
 *
 *  You should have received a copy of the GNU General Public License
 *  along with this program; if not, write to the Free Software
 *  Foundation, Inc., 59 Temple Place, Suite 330, Boston, MA  02111-1307  USA
 */

#ifndef	_RBTREE_H
#define	_RBTREE_H

#include <stdint.h>
#include <stddef.h>
#include <stdbool.h>

struct rb_node {
	uintptr_t __rb_parent_color;
	struct rb_node *rb_right;
	struct rb_node *rb_left;
};

struct rb_root {
	struct rb_node *rb_node;
};

#define	rb_entry(ptr, type, member) container_of(ptr, type, member)

#define RB_ROOT	(struct rb_root) { NULL, }

static inline bool
rb_empty_root(const struct rb_root *root)
{
	return root->rb_node == NULL;
}

static inline struct rb_node *
rb_parent(const struct rb_node *node)
{
	return (struct rb_node *)(node->__rb_parent_color & ~1);
}

/* 'empty' nodes are nodes that are known not to be inserted in an rbtree */
static inline bool
rb_empty_node(const struct rb_node *node)
{
	return node->__rb_parent_color == (uintptr_t)node;
}

static inline void
rb_clear_node(struct rb_node *node)
{
	node->__rb_parent_color = (uintptr_t)node;
}

extern void
rb_insert_color(struct rb_node *node, struct rb_root *root);

extern void
rb_erase(struct rb_node *node, struct rb_root *root);

extern struct rb_node *
rb_first(const struct rb_root *root);

extern struct rb_node *
rb_first_postorder(const struct rb_root *root);

extern struct rb_node *
rb_next(const struct rb_node *node);

extern struct rb_node *
rb_next_postorder(const struct rb_node *node, const struct rb_node *parent);

static inline void
rb_link_node(struct rb_node *node, struct rb_node *parent,
	     struct rb_node **rb_link)
{
	node->__rb_parent_color = (uintptr_t)parent;
	node->rb_left = node->rb_right = NULL;
	*rb_link = node;
}

#endif	/* _RBTREE_H */
