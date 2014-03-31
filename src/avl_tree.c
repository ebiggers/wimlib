/*
 * avl_tree.c
 *
 * Intrusive, nonrecursive AVL tree data structure (self-balancing binary search
 * tree), implementation file.
 *
 * Author:  Eric Biggers
 * Year:    2014
 *
 * This file is placed into the public domain.  You can do whatever you want
 * with it.
 */

#include <wimlib/avl_tree.h>

/* Starts an in-order traversal of the tree: returns the least-valued node, or
 * NULL if the tree is empty.  */
struct avl_tree_node *
avl_tree_first_in_order(const struct avl_tree_node *root)
{
	const struct avl_tree_node *first = root;

	if (first)
		while (first->left)
			first = first->left;
	return (struct avl_tree_node *)first;
}

/* Continues an in-order traversal of the tree: returns the next-greatest-valued
 * node, or NULL if there is none.  */
struct avl_tree_node *
avl_tree_next_in_order(const struct avl_tree_node *prev)
{
	const struct avl_tree_node *next;

	if (prev->right)
		for (next = prev->right;
		     next->left;
		     next = next->left)
			;
	else
		for (next = avl_get_parent(prev);
		     next && prev == next->right;
		     prev = next, next = avl_get_parent(next))
			;
	return (struct avl_tree_node *)next;
}

/* Starts a postorder traversal of the tree.  */
struct avl_tree_node *
avl_tree_first_in_postorder(const struct avl_tree_node *root)
{
	const struct avl_tree_node *first = root;

	if (first)
		while (first->left || first->right)
			first = first->left ? first->left : first->right;

	return (struct avl_tree_node *)first;
}

/* Continues a postorder traversal of the tree.  @prev will not be deferenced as
 * it's allowed that its memory has been freed; @prev_parent must be its saved
 * parent node.  Returns NULL if there are no more nodes (i.e. @prev was the
 * root of the tree).  */
struct avl_tree_node *
avl_tree_next_in_postorder(const struct avl_tree_node *prev,
			   const struct avl_tree_node *prev_parent)
{
	const struct avl_tree_node *next = prev_parent;

	if (next && prev == next->left && next->right)
		for (next = next->right;
		     next->left || next->right;
		     next = next->left ? next->left : next->right)
			;
	return (struct avl_tree_node *)next;
}

/* Get the left child (sign < 0) or the right child (sign > 0)
 * Note: for all calls of this, 'sign' is constant at compilation time and the
 * compiler can remove the conditional.  */
static AVL_INLINE struct avl_tree_node *
avl_get_child(const struct avl_tree_node *parent, int sign)
{
	if (sign < 0)
		return parent->left;
	else
		return parent->right;
}

/* Set the left child (sign < 0) or the right child (sign > 0)
 * Note: for all calls of this, 'sign' is constant at compilation time and the
 * compiler can remove the conditional.  */
static AVL_INLINE void
avl_set_child(struct avl_tree_node *parent, int sign,
	      struct avl_tree_node *child)
{
	if (sign < 0)
		parent->left = child;
	else
		parent->right = child;
}

/* Sets the parent of the AVL tree @node to @parent.  */
static AVL_INLINE void
avl_set_parent(struct avl_tree_node *node, struct avl_tree_node *parent)
{
	node->parent_balance =
		(node->parent_balance & 3) | (uintptr_t)parent;
}

/* Sets the parent and balance factor of the AVL tree @node.  */
static AVL_INLINE void
avl_set_parent_balance(struct avl_tree_node *node, struct avl_tree_node *parent,
		       int balance_factor)
{
	node->parent_balance = (uintptr_t)parent | (balance_factor + 1);
}

/* Returns the balance factor of the specified AVL tree node --- that is, the
 * height of its right subtree minus the height of its left subtree.  */
static AVL_INLINE int
avl_get_balance_factor(const struct avl_tree_node *node)
{
	return (int)(node->parent_balance & 3) - 1;
}

/* Sets the balance factor of the specified AVL tree node.  The caller MUST
 * ensure that this number is valid and maintains the AVL tree invariants.  */
static AVL_INLINE void
avl_set_balance_factor(struct avl_tree_node *node, int balance_factor)
{
	node->parent_balance =
		(node->parent_balance & ~3) | (balance_factor + 1);
}

/* Increments the balance factor of the specified AVL tree @node by the
 * specified @amount.  The caller MUST ensure that this number is valid and
 * maintains the AVL tree invariants.  */
static AVL_INLINE void
avl_adjust_balance_factor(struct avl_tree_node *node, int amount)
{
	node->parent_balance += amount;
}

/*
 * Template for performing a rotation ---
 *
 * Clockwise/Right (sign > 0):
 *
 *           X             X
 *           |             |
 *           A             B
 *          / \           / \
 *         B   C   =>    D   A
 *        / \               / \
 *       D   E             E   C
 *
 * Counterclockwise/Left (sign < 0)- same, except left and right are reversed:
 *
 *           X             X
 *           |             |
 *           A             B
 *          / \           / \
 *         C   B   =>    A   D
 *            / \       / \
 *           E   D     C   E
 *
 * This updates pointers but not balance factors!
 */
static AVL_INLINE void
avl_rotate(struct avl_tree_node ** const root_ptr,
	   struct avl_tree_node * const A, const int sign)
{
	struct avl_tree_node * const B = avl_get_child(A, -sign);
	struct avl_tree_node * const C = avl_get_child(A, +sign);
	struct avl_tree_node * const E = avl_get_child(B, +sign);
	struct avl_tree_node * const X = avl_get_parent(A);

	avl_set_child(A, -sign, E);
	avl_set_child(A, +sign, C);
	avl_set_parent(A, B);

	avl_set_child(B, +sign, A);
	avl_set_parent(B, X);

	if (E)
		avl_set_parent(E, A);

	if (X) {
		if (avl_get_child(X, +sign) == A)
			avl_set_child(X, +sign, B);
		else
			avl_set_child(X, -sign, B);
	} else {
		*root_ptr = B;
	}
}

/*
 * Template for performing a double rotation ---
 *
 * Rotate counterclockwise (left) rooted at B, then clockwise (right) rooted at
 * A (sign > 0):
 *
 *           A             A           E
 *          / \           / \        /   \
 *         B   C   =>    E   C  =>  B     A
 *        / \           / \        / \   / \
 *       D   E         B   G      D   F G   C
 *          / \       / \
 *         F   G     D   F
 *
 * Rotate clockwise (right) rooted at B, then counterclockwise (left) rooted at
 * A (sign < 0):
 *
 *         A           A               E
 *        / \         / \            /   \
 *       C   B   =>  C   E    =>    A     B
 *          / \         / \        / \   / \
 *         E   D       G   B      C   G F   D
 *        / \             / \
 *       G   F           F   D
 *
 * Returns a pointer to E, the new root, and updates balance factors.  Except
 * for that, this is equivalent to:
 *	avl_rotate(root_ptr, B, -sign);
 *	avl_rotate(root_ptr, A, +sign);
 *
 */
static AVL_INLINE struct avl_tree_node *
avl_do_double_rotate(struct avl_tree_node ** const root_ptr,
		     struct avl_tree_node * const B,
		     struct avl_tree_node * const A, const int sign)
{
	struct avl_tree_node * const E = avl_get_child(B, +sign);
	struct avl_tree_node * const F = avl_get_child(E, -sign);
	struct avl_tree_node * const G = avl_get_child(E, +sign);
	struct avl_tree_node * const X = avl_get_parent(A);
	const int e = avl_get_balance_factor(E);

	avl_set_child(A, -sign, G);
	avl_set_parent_balance(A, E, ((sign * e >= 0) ? 0 : -e));

	avl_set_child(B, +sign, F);
	avl_set_parent_balance(B, E, ((sign * e <= 0) ? 0 : -e));

	avl_set_child(E, +sign, A);
	avl_set_child(E, -sign, B);
	avl_set_parent_balance(E, X, 0);

	if (G)
		avl_set_parent(G, A);

	if (F)
		avl_set_parent(F, B);

	if (X) {
		if (avl_get_child(X, +sign) == A)
			avl_set_child(X, +sign, E);
		else
			avl_set_child(X, -sign, E);
	} else {
		*root_ptr = E;
	}

	return E;
}

static AVL_INLINE bool
avl_handle_subtree_growth(struct avl_tree_node ** const root_ptr,
			  struct avl_tree_node * const node,
			  struct avl_tree_node * const parent,
			  const int sign)
{
	/* The subtree rooted at @node, which is a child of @parent, has
	 * increased by 1.
	 *
	 * Adjust @parent's balance factor and check whether rotations need to
	 * be done.  */

	int old_balance_factor, new_balance_factor;

	old_balance_factor = avl_get_balance_factor(parent);

	if (old_balance_factor == 0) {
		/* Parent has increased in height but is still sufficiently
		 * balanced.  Continue up the tree.  */
		avl_adjust_balance_factor(parent, sign);
		return false;
	}

	new_balance_factor = old_balance_factor + sign;

	if (new_balance_factor == 0) {
		/* Parent is balanced; nothing more to to.  */
		avl_adjust_balance_factor(parent, sign);
		return true;
	}

	/* FROM THIS POINT ONWARDS THE COMMENTS ASSUME sign < 0.
	 * The other case is symmetric --- that is, the rotations done are the
	 * the mirror images, all the balance factors are inverted, and left and
	 * right pointers are otherwise reversed.  */

	/* Parent is left-heavy (balance_factor == -2).  */

	if (sign * avl_get_balance_factor(node) > 0) {

		/* Child node (@node, also B below) is also left-heavy.
		 * It must have balance_factor == -1.
		 * Do a clockwise ("right") rotation rooted at
		 * @parent (A below):
		 *
		 *           A              B
		 *          / \           /   \
		 *         B   C   =>    D     A
		 *        / \           / \   / \
		 *       D   E         F   G E   C
		 *      / \
		 *     F   G
		 *
		 * Before the rotation:
		 *	balance(A) = -2
		 *	balance(B) = -1
		 * Let x = height(C).  Then:
		 *	height(B) = x + 2
		 *	height(D) = x + 1
		 *	height(E) = x
		 *	max(height(F), height(G)) = x.
		 *
		 * After the rotation:
		 *	height(D) = max(height(F), height(G)) + 1
		 *		  = x + 1
		 *	height(A) = max(height(E), height(C)) + 1
		 *		  = max(x, x) + 1 = x + 1
		 *	balance(B) = 0
		 *	balance(A) = 0
		 */

		avl_rotate(root_ptr, parent, -sign);
		avl_adjust_balance_factor(parent, -sign); /* A */
		avl_adjust_balance_factor(node, -sign);   /* B */
	} else {
		/* Child node (@node, also B below) is right-heavy.
		 * It must have balance_factor == +1.
		 * Do a counterclockwise ("left") rotation rooted at child node
		 * (B below), then a clockwise ("right") rotation rooted at
		 * parent node (A below).
		 *
		 *           A             A           E
		 *          / \           / \        /   \
		 *         B   C   =>    E   C  =>  B     A
		 *        / \           / \        / \   / \
		 *       D   E         B   G      D   F G   C
		 *          / \       / \
		 *         F   G     D   F
		 *
		 * Before the rotation:
		 *	balance(A) = -2
		 *	balance(B) = +1
		 * Let x = height(C).  Then:
		 *	height(B) = x + 2
		 *	height(E) = x + 1
		 *	height(D) = x
		 *	max(height(F), height(G)) = x
		 *
		 * After both rotations:
		 *	height(A) = max(height(G), height(C)) + 1
		 *		  = x + 1
		 *	balance(A) = balance(E{orig}) >= 0 ? 0 : -balance(E{orig})
		 *	height(B) = max(height(D), height(F)) + 1
		 *		  = x + 1
		 *	balance(B) = balance(E{orig} <= 0) ? 0 : -balance(E{orig})
		 *
		 *	height(E) = x + 2
		 *	balance(E) = 0
		 */
		avl_do_double_rotate(root_ptr, node, parent, -sign);
	}
	return true;
}

/* Rebalance the tree after insertion of the specified node.  */
void
avl_tree_rebalance_after_insert(struct avl_tree_node **root_ptr,
				struct avl_tree_node *inserted)
{
	struct avl_tree_node *node, *parent;
	bool done;

	inserted->left = NULL;
	inserted->right = NULL;

	node = inserted;

	/* Adjust balance factor of new node's parent.
	 * No rotation will need to be done at this level.  */

	parent = avl_get_parent(node);
	if (!parent)
		return;

	if (node == parent->left)
		avl_adjust_balance_factor(parent, -1);
	else
		avl_adjust_balance_factor(parent, +1);

	if (avl_get_balance_factor(parent) == 0)
		/* @parent did not change in height.  Nothing more to do.  */
		return;

	/* The subtree rooted at @parent increased in height by 1.  */

	do {
		/* Adjust balance factor of next ancestor.  */

		node = parent;
		parent = avl_get_parent(node);
		if (!parent)
			return;

		/* The subtree rooted at @node has increased in height by 1.  */
		if (node == parent->left)
			done = avl_handle_subtree_growth(root_ptr, node,
							 parent, -1);
		else
			done = avl_handle_subtree_growth(root_ptr, node,
							 parent, +1);
	} while (!done);
}

static AVL_INLINE struct avl_tree_node *
avl_handle_subtree_shrink(struct avl_tree_node ** const root_ptr,
			  struct avl_tree_node *parent,
			  const int sign,
			  bool * const left_deleted_ret)
{
	struct avl_tree_node *node;

	const int old_balance_factor = avl_get_balance_factor(parent);
	const int new_balance_factor = old_balance_factor + sign;

	if (old_balance_factor == 0) {
		/* Prior to the deletion, the subtree rooted at
		 * @parent was perfectly balanced.  It's now
		 * unbalanced by 1, but that's okay and its height
		 * hasn't changed.  Nothing more to do.  */
		avl_adjust_balance_factor(parent, sign);
		return NULL;
	} else if (new_balance_factor == 0) {
		/* The subtree rooted at @parent is now perfectly
		 * balanced, whereas before the deletion it was
		 * unbalanced by 1.  Its height must have decreased
		 * by 1.  No rotation is needed at this location,
		 * but continue up the tree.  */
		avl_adjust_balance_factor(parent, sign);
		node = parent;
	} else {
		/* The subtree rooted at @parent is now significantly
		 * unbalanced (by 2 in some direction).  */
		node = avl_get_child(parent, sign);

		/* The rotations below are similar to those done during
		 * insertion.  The only new case is the one where the
		 * child node has a balance factor of 0.  */

		if (sign * avl_get_balance_factor(node) >= 0) {
			avl_rotate(root_ptr, parent, -sign);

			if (avl_get_balance_factor(node) == 0) {
				/* Child node (@node, also B below) is balanced.
				 * Do a clockwise ("right") rotation rooted at
				 * @parent (A below):
				 *
				 *           A              B
				 *          / \           /   \
				 *         B   C   =>    D     A
				 *        / \           / \   / \
				 *       D   E         F   G E   C
				 *      / \
				 *     F   G
				 *
				 * Before the rotation:
				 *	balance(A) = -2
				 *	balance(B) =  0
				 * Let x = height(C).  Then:
				 *	height(B) = x + 2
				 *	height(D) = x + 1
				 *	height(E) = x + 1
				 *	max(height(F), height(G)) = x.
				 *
				 * After the rotation:
				 *	height(D) = max(height(F), height(G)) + 1
				 *		  = x + 1
				 *	height(A) = max(height(E), height(C)) + 1
				 *		  = max(x + 1, x) + 1 = x + 2
				 *	balance(A) = -1
				 *	balance(B) = +1
				 */

				/* A: -2 => -1 (sign < 0)
				 * or +2 => +1 (sign > 0)
				 * No change needed --- that's the same as
				 * old_balance_factor.  */

				/* B: 0 => +1 (sign < 0)
				 * or 0 => -1 (sign > 0)  */
				avl_adjust_balance_factor(node, -sign);

				/* Height is unchanged; nothing more to do.  */
				return NULL;
			} else {
				avl_adjust_balance_factor(parent, -sign);
				avl_adjust_balance_factor(node, -sign);
			}
		} else {
			node = avl_do_double_rotate(root_ptr, node,
						    parent, -sign);
		}
	}
	parent = avl_get_parent(node);
	if (parent)
		*left_deleted_ret = (node == parent->left);
	return parent;
}

/* Swaps node X, which must have 2 children, with its in-order successor, then
 * unlinks node X.  Returns the parent of X just before unlinking, without its
 * balance factor having been updated to account for the unlink.  */
static AVL_INLINE struct avl_tree_node *
avl_tree_swap_with_successor(struct avl_tree_node **root_ptr,
			     struct avl_tree_node *X,
			     bool *left_deleted_ret)
{
	struct avl_tree_node *Y, *P, *ret;

	Y = X->right;
	if (!Y->left) {
		/*
		 *     P?           P?           P?
		 *     |            |            |
		 *     X            Y            Y
		 *    / \          / \          / \
		 *   A   Y    =>  A   X    =>  A   B?
		 *      / \          / \
		 *    (0)  B?      (0)  B?
		 *
		 * [ X removed, Y returned ]
		 */
		ret = Y;
		*left_deleted_ret = false;
	} else {
		struct avl_tree_node *Q;

		do {
			Q = Y;
			Y = Y->left;
		} while (Y->left);

		/*
		 *     P?           P?           P?
		 *     |            |            |
		 *     X            Y            Y
		 *    / \          / \          / \
		 *   A   ...  =>  A  ...   =>  A  ...
		 *       |            |            |
		 *       Q            Q            Q
		 *      /            /            /
		 *     Y            X            B?
		 *    / \          / \
		 *  (0)  B?      (0)  B?
		 *
		 *
		 * [ X removed, Q returned ]
		 */

		Q->left = Y->right;
		if (Q->left)
			avl_set_parent(Q->left, Q);
		Y->right = X->right;
		avl_set_parent(X->right, Y);
		ret = Q;
		*left_deleted_ret = true;
	}

	Y->left = X->left;
	avl_set_parent(X->left, Y);

	Y->parent_balance = X->parent_balance;
	P = avl_get_parent(X);
	if (P) {
		if (P->left == X)
			P->left = Y;
		else
			P->right = Y;
	} else {
		*root_ptr = Y;
	}

	return ret;
}

/* Removes the specified @node from the AVL tree.  @root_ptr must point to the
 * pointer to the root node of the tree; *root_ptr may change if the tree is
 * rebalanced.
 *
 * This *only* removes the node and rebalances the tree; it does not free
 * memory, nor does it do the equivalent of avl_tree_node_set_unlinked().  */
void
avl_tree_remove(struct avl_tree_node **root_ptr, struct avl_tree_node *node)
{
	struct avl_tree_node *child, *parent;
	bool left_deleted;

	if (node->left && node->right) {
		parent = avl_tree_swap_with_successor(root_ptr, node,
						      &left_deleted);
	} else {
		/* Unlink @node  */
		child = node->left ? node->left : node->right;
		parent = avl_get_parent(node);
		if (parent) {
			if (node == parent->left) {
				parent->left = child;
				left_deleted = true;
			} else {
				parent->right = child;
				left_deleted = false;
			}
		} else {
			*root_ptr = child;
		}
		if (child)
			avl_set_parent(child, parent);
		if (!parent)
			return;
	}

	/* Rebalance the tree  */
	do {
		if (left_deleted)
			parent = avl_handle_subtree_shrink(root_ptr, parent,
							   +1, &left_deleted);
		else
			parent = avl_handle_subtree_shrink(root_ptr, parent,
							   -1, &left_deleted);
	} while (parent);
}
