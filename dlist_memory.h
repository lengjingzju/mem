#ifndef __DLIST_MEMORY_H__
#define __DLIST_MEMORY_H__
#include <stdlib.h>

struct mem_list_head {
    struct mem_list_head *next, *prev;
};

// mem_list_entry is different to list_entry of linux
#define mem_list_entry(ptr, type)  ((type *)(ptr))

#define mem_list_for_each_entry(pos, head, member)          \
for (pos = mem_list_entry((head)->next, typeof(*pos));      \
    &pos->member != (head);                                 \
    pos = mem_list_entry(pos->member.next, typeof(*pos)))

#define mem_list_for_each_entry_safe(pos, n, head, member)  \
for (pos = mem_list_entry((head)->next, typeof(*pos)),      \
        n = mem_list_entry(pos->member.next, typeof(*pos)); \
    &pos->member != (head);                                 \
    pos = n, n = mem_list_entry(n->member.next, typeof(*n)))

static inline void INIT_MEM_LIST_HEAD(struct mem_list_head *list)
{
    list->next = list;
    list->prev = list;
}

static inline void __mem_list_add(struct mem_list_head *_new,
   struct mem_list_head *prev, struct mem_list_head *next)
{
    next->prev = _new;
    _new->next = next;
    _new->prev = prev;
    prev->next = _new;
}

static inline void mem_list_add(struct mem_list_head *_new, struct mem_list_head *head)
{
    __mem_list_add(_new, head, head->next);
}

static inline void mem_list_add_tail(struct mem_list_head *_new, struct mem_list_head *head)
{
    __mem_list_add(_new, head->prev, head);
}

static inline void mem_list_del(struct mem_list_head *entry)
{
    struct mem_list_head *prev = entry->prev;
    struct mem_list_head *next = entry->next;
    next->prev = prev;
    prev->next = next;
    entry->next = NULL;
    entry->prev = NULL;
}

#endif
