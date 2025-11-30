/*
 * Stub sys/avl.h for Axiom
 * AVL tree implementation - FreeBSD may have this in different location
 */

#ifndef _SYS_AVL_H
#define _SYS_AVL_H

#include <sys/types.h>
#include <stdint.h>

#ifdef __cplusplus
extern "C" {
#endif

/* AVL tree node structure */
typedef struct avl_node {
    struct avl_node *avl_child[2];
    struct avl_node *avl_parent;
    uintptr_t avl_pcb;
} avl_node_t;

/* AVL tree structure */
typedef struct avl_tree {
    struct avl_node *avl_root;
    int (*avl_compar)(const void *, const void *);
    size_t avl_offset;
    uintptr_t avl_numnodes;
    size_t avl_size;
} avl_tree_t;

/* AVL tree index type */
typedef enum {
    AVL_BEFORE = 0,
    AVL_AFTER = 1
} avl_index_t;

/* AVL tree direction */
typedef enum {
    AVL_LEFT = 0,
    AVL_RIGHT = 1
} avl_direction_t;

/* Function declarations - these will be provided by libzfs */
extern void avl_create(avl_tree_t *, int (*)(const void *, const void *),
    size_t, size_t);
extern void *avl_find(avl_tree_t *, const void *, avl_index_t *);
extern void avl_insert(avl_tree_t *, void *, avl_index_t);
extern void *avl_first(avl_tree_t *);
extern void *avl_last(avl_tree_t *);
extern void *avl_nearest(avl_tree_t *, avl_index_t, avl_direction_t);
extern void avl_add(avl_tree_t *, void *);
extern void avl_remove(avl_tree_t *, void *);
extern void *avl_walk(avl_tree_t *, void *, avl_direction_t);
extern void avl_destroy(avl_tree_t *);
extern uintptr_t avl_numnodes(avl_tree_t *);
extern boolean_t avl_is_empty(avl_tree_t *);

#define AVL_NEXT(tree, node) avl_walk(tree, node, AVL_AFTER)
#define AVL_PREV(tree, node) avl_walk(tree, node, AVL_BEFORE)

#ifdef __cplusplus
}
#endif

#endif /* _SYS_AVL_H */
