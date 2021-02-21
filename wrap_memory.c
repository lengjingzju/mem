#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <pthread.h>
#include "dlist_memory.h"

// LDFLAGS += -Wl,--wrap=malloc -Wl,--wrap=calloc -Wl,--wrap=realloc -Wl,--wrap=strdup -Wl,--wrap=free

extern void* __real_malloc(size_t size);
extern void* __real_realloc(void *ptr, size_t size);
extern void  __real_free(void *ptr);
#define _dbg_malloc         __real_malloc
#define _dbg_realloc        __real_realloc
#define _dbg_free           __real_free

#define ADD_CHECK_BYTES     4
#if ADD_CHECK_BYTES
#define ADD_CHECK_VALUE     0x55
static char s_add_check_array[ADD_CHECK_BYTES];
#endif

#define PRINT_MEM_INFO(mgr) printf("size = %8u\talloc = %8d\tfree=%8d\tdiff=%8d\n", \
        (unsigned int)mgr->size, mgr->alloc_cnt, mgr->free_cnt, mgr->alloc_cnt - mgr->free_cnt)
#define _MERR(fmt, args...)     do { printf("[MERR][%s:%d]: ", __func__, __LINE__);printf(fmt, ##args); } while(0)

typedef struct {
    struct mem_list_head list;
    void *ptr;
} MemDebugNode;

typedef struct {
    struct mem_list_head list;
    struct mem_list_head head;

    size_t size;
    int alloc_cnt;
    int free_cnt;
    int change_flag;
} MemDebugMgr;

typedef struct {
    struct mem_list_head head;
    pthread_mutex_t mutex;
} MemDebugCtrl;

#if 1
static MemDebugCtrl s_mem_debug_ctrl = {
    .head = {
        .next = &s_mem_debug_ctrl.head,
        .prev = &s_mem_debug_ctrl.head
    },
    .mutex = PTHREAD_MUTEX_INITIALIZER
};
#define MEM_DEBUG_LOCK()    pthread_mutex_lock(&ctrl->mutex)
#define MEM_DEBUG_UNLOCK()  pthread_mutex_unlock(&ctrl->mutex)

#else
static MemDebugCtrl s_mem_debug_ctrl;
int wrap_mem_init(void)
{
    MemDebugCtrl *ctrl = &s_mem_debug_ctrl;
    if (ctrl->mutex == 0) {
        pthread_mutex_init(&ctrl->mutex, NULL);
        INIT_MEM_LIST_HEAD(&ctrl->head);
    }
    return 0;
}
#define MEM_DEBUG_LOCK()    do { wrap_mem_init(); pthread_mutex_lock  (&ctrl->mutex); } while(0)
#define MEM_DEBUG_UNLOCK()  do { wrap_mem_init(); pthread_mutex_unlock(&ctrl->mutex); } while(0)
#endif

typedef struct {
   size_t min_size;
   size_t max_size;
   void *test_ptr;
   void (*set_ptr)(void *ptr);
} MemDebugHook;

static MemDebugHook s_mem_debug_hook;

void wrap_mem_set_test_ptr(void *ptr)
{
    MemDebugHook *hook = &s_mem_debug_hook;
    hook->test_ptr = ptr;
}

void wrap_mem_set_test_size(size_t min_size, size_t max_size, void (*set_ptr)(void *ptr))
{
    MemDebugHook *hook = &s_mem_debug_hook;
    hook->min_size = min_size;
    hook->max_size = max_size;
    hook->set_ptr = set_ptr ? set_ptr : wrap_mem_set_test_ptr;
}

static void _mem_hook_for_alloc(void *ptr, size_t size)
{
    MemDebugHook *hook = &s_mem_debug_hook;
    if (size >= hook->min_size && size < hook->max_size) {
        if (hook->set_ptr) hook->set_ptr(ptr);
    }
}

static void _mem_hook_for_free(void *ptr)
{
    MemDebugHook *hook = &s_mem_debug_hook;
    if (ptr == hook->test_ptr) {
        if (hook->set_ptr) hook->set_ptr(NULL);
    }
}

static int _check_mem_info_node(void)
{
    int ret = 0;
#if ADD_CHECK_BYTES 
    MemDebugCtrl *ctrl = &s_mem_debug_ctrl;
    MemDebugMgr *mgr_pos = NULL, *mgr_n = NULL;
    MemDebugNode *node_pos = NULL, *node_n = NULL;

    memset(s_add_check_array, ADD_CHECK_VALUE, ADD_CHECK_BYTES);
    MEM_DEBUG_LOCK();
    mem_list_for_each_entry_safe(mgr_pos, mgr_n, &ctrl->head, list) {
        mem_list_for_each_entry_safe(node_pos, node_n, &mgr_pos->head, list) {
            if (memcmp(s_add_check_array, (unsigned char *)node_pos->ptr + mgr_pos->size, ADD_CHECK_BYTES) != 0) {
                printf("\033[31m[MERR]: ptr(%p) check faild!\033[0m\t", node_pos->ptr);
                PRINT_MEM_INFO(mgr_pos);
            }
        }
    }

    MEM_DEBUG_UNLOCK();
#endif
    return ret;
}

static int _add_mem_info_node(void *ptr, size_t size)
{
    int ret = -1;
    MemDebugCtrl *ctrl = &s_mem_debug_ctrl;
    MemDebugMgr *mgr = NULL, *mgr_pos = NULL, *mgr_n = NULL;
    MemDebugNode *node = NULL, *node_pos = NULL, *node_n = NULL;

    if (!ptr) return -1;
    _mem_hook_for_alloc(ptr, size);
    _check_mem_info_node();
#if ADD_CHECK_BYTES
    memset((unsigned char *)ptr + size, ADD_CHECK_VALUE, ADD_CHECK_BYTES);
#endif

    MEM_DEBUG_LOCK();
#if 1 // 避免add相同值的ptr, 例如用了其它函数free了内存
    mem_list_for_each_entry_safe(mgr_pos, mgr_n, &ctrl->head, list) {
        mem_list_for_each_entry_safe(node_pos, node_n, &mgr_pos->head, list) {
            if (node_pos->ptr == ptr) {
                printf("\033[33m[MWARN]: free mem without using debug_mem_free()! ptr = %p, size = %u\033[0m\n",
                        ptr, (unsigned int)mgr_pos->size);
                mgr_pos->change_flag = 1;
                ++mgr_pos->free_cnt;
                mem_list_del(&node_pos->list);
                _dbg_free(node_pos);
            }
        }
    }
#endif

    node = _dbg_malloc(sizeof(MemDebugNode));
    if (!node) {
        _MERR("\033[31mnode_pool overflow!\033[0m\n");
        goto end;
    }
    memset(node, 0, sizeof(MemDebugNode));
    node->ptr = ptr;
    mem_list_for_each_entry_safe(mgr_pos, mgr_n, &ctrl->head, list) {
        if (mgr_pos->size == size) {
            ++mgr_pos->alloc_cnt;
            mem_list_add_tail(&node->list, &mgr_pos->head);
            ret = 0;
            goto end;
        }
    }

    mgr = _dbg_malloc(sizeof(MemDebugMgr));
    if (!mgr) {
        _dbg_free(node);
        _MERR("\033[31mmgr_pool overflow!\033[0m\n");
        goto end;
    }
    memset(mgr, 0, sizeof(MemDebugMgr));
    INIT_MEM_LIST_HEAD(&mgr->head);
    mgr->size = size;
    mgr->alloc_cnt = 1;
    mgr->free_cnt = 0;
    mgr->change_flag = 1;
    mem_list_add_tail(&mgr->list, &ctrl->head);
    mem_list_add_tail(&node->list, &mgr->head);
    ret = 0;

end:
    MEM_DEBUG_UNLOCK();
    return ret;
}

static int _del_mem_info_node(void *ptr)
{
    int ret = -1;
    MemDebugCtrl *ctrl = &s_mem_debug_ctrl;
    MemDebugMgr *mgr_pos = NULL, *mgr_n = NULL;
    MemDebugNode *node_pos = NULL, *node_n = NULL;

    if (!ptr) return -1;
    _mem_hook_for_free(ptr);
    _check_mem_info_node();

    MEM_DEBUG_LOCK();
    mem_list_for_each_entry_safe(mgr_pos, mgr_n, &ctrl->head, list) {
        mem_list_for_each_entry_safe(node_pos, node_n, &mgr_pos->head, list) {
            if (node_pos->ptr == ptr) {
                mgr_pos->change_flag = 1;
                ++mgr_pos->free_cnt;
                mem_list_del(&node_pos->list);
                _dbg_free(node_pos);
                ret = 0;
                goto end;
            }
        }
    }

    printf("\033[33m[MERR]: free ptr not found! ptr = %p\033[0m\n", ptr);
end:
    MEM_DEBUG_UNLOCK();
    return ret;
}

static MemDebugMgr* _show_mem_info_node(int print_en, void *ptr)
{
    MemDebugCtrl *ctrl = &s_mem_debug_ctrl;
    MemDebugMgr *mgr = NULL, *mgr_pos = NULL, *mgr_n = NULL;
    MemDebugNode *node_pos = NULL, *node_n = NULL;

    if (!ptr) return NULL;

    MEM_DEBUG_LOCK();
    mem_list_for_each_entry_safe(mgr_pos, mgr_n, &ctrl->head, list) {
        mem_list_for_each_entry_safe(node_pos, node_n, &mgr_pos->head, list) {
            if (node_pos->ptr == ptr) {
                if (print_en) {
                    PRINT_MEM_INFO(mgr_pos);
                }
                mgr = mgr_pos;
                goto end;
           }
        }
    }

    printf("\033[33m[MERR]: ptr not found! ptr = %p\033[0m\n", ptr);
end:
    MEM_DEBUG_UNLOCK();
    return mgr;
}

static MemDebugMgr* _show_mem_info_mgr(int print_en, size_t size)
{
    MemDebugCtrl *ctrl = &s_mem_debug_ctrl;
    MemDebugMgr *mgr = NULL, *mgr_pos = NULL, *mgr_n = NULL;
    MemDebugNode *node_pos = NULL, *node_n = NULL;

    MEM_DEBUG_LOCK();
    mem_list_for_each_entry_safe(mgr_pos, mgr_n, &ctrl->head, list) {
        if (mgr_pos->size == size) {
            if (print_en) {
                PRINT_MEM_INFO(mgr_pos);
                if (mgr_pos->alloc_cnt != mgr_pos->free_cnt) {
                    int cnt = 0;
                    printf("--------------------------------\n");
                    mem_list_for_each_entry_safe(node_pos, node_n, &mgr_pos->head, list) {
                        printf("%p ", node_pos->ptr);
                        if (++cnt / 8 == 0)
                            printf("\n");
                    }
                    printf("--------------------------------\n");
                }
            }
            mgr = mgr_pos;
            goto end;
        }
    }

    printf("\033[33m[MERR]: mgr not found! size = %u\033[0m\n", (unsigned int)size);
end:
    MEM_DEBUG_UNLOCK();
    return mgr;
}

static int _print_mem_info_node(int print_flag)
{
    MemDebugCtrl *ctrl = &s_mem_debug_ctrl;
    MemDebugMgr *mgr = NULL;

    MEM_DEBUG_LOCK();

    switch (print_flag)
    {
        case 0:
            mem_list_for_each_entry(mgr, &ctrl->head, list) {
                PRINT_MEM_INFO(mgr);
                mgr->change_flag = 0;
            }
            break;
        case 1:
            mem_list_for_each_entry(mgr, &ctrl->head, list) {
                if (mgr->change_flag) {
                    PRINT_MEM_INFO(mgr);
                }
                mgr->change_flag = 0;
            }
            break;
        case 2:
            mem_list_for_each_entry(mgr, &ctrl->head, list) {
                if (mgr->alloc_cnt != mgr->free_cnt) {
                    PRINT_MEM_INFO(mgr);
                }
                mgr->change_flag = 0;
            }
            break;
        case 3:
            mem_list_for_each_entry(mgr, &ctrl->head, list) {
                if (mgr->change_flag && mgr->alloc_cnt != mgr->free_cnt) {
                    PRINT_MEM_INFO(mgr);
                }
                mgr->change_flag = 0;
            }
            break;
        case 4:
            _check_mem_info_node();
            break;
        default:
            printf("\033[31mUsage: %s(flag)\n\t flag: 0, all; 1, changed; 2, not free; 3, changed and not free. 4. out of boundary\033[0m\n\n", __func__);
            break;
    }

    MEM_DEBUG_UNLOCK();
    return 0;
}

void* __wrap_malloc(size_t size)
{
    void *ptr = _dbg_malloc(size + ADD_CHECK_BYTES);
    if (ptr) {
        _add_mem_info_node(ptr, size);
    }
    return ptr;
}

void* __wrap_calloc(size_t nmemb, size_t size)
{
    size_t nsize = nmemb * size;
    void *ptr = _dbg_malloc(nsize + ADD_CHECK_BYTES);
    if (ptr) {
        _add_mem_info_node(ptr, nsize);
        memset(ptr, 0, nsize);
    }
    return ptr;
}

void* __wrap_realloc(void *ptr, size_t size)
{
    void *nptr = NULL;
    MemDebugMgr *mgr = NULL;

    if (ptr != NULL && (mgr = _show_mem_info_node(0, ptr)) != NULL) {
        if (mgr->size == size) {
            return ptr;
        } else {
            _del_mem_info_node(ptr);
            if (mgr->size > size) {
                nptr = _dbg_realloc(ptr, size + ADD_CHECK_BYTES);
            } else {
                nptr = _dbg_malloc(size + ADD_CHECK_BYTES);
                if (ptr && nptr) {
                    memcpy(nptr, ptr, mgr->size);
                }
                _dbg_free(ptr);
            }
            _add_mem_info_node(nptr, size);
        }
    } else if (ptr == NULL) {
        nptr = _dbg_malloc(size + ADD_CHECK_BYTES);
        _add_mem_info_node(nptr, size);
    } else {
        printf("\033[33m[MERR]: realloc ptr(%p) not found!\033[0m\n", ptr);
    }

    return nptr;
}

char* __wrap_strdup(const char *s)
{
    size_t size = strlen(s);
    char *ptr = _dbg_malloc(size + ADD_CHECK_BYTES);
    if (ptr) {
        _add_mem_info_node(ptr, size);
        memcpy(ptr, s, size);
        ptr[size] = 0;
    }
    return ptr;
}

void __wrap_free(void *ptr)
{
    if (ptr) {
        _del_mem_info_node(ptr);
        _dbg_free(ptr);
    }
}

void wrap_mem_print_node(void *ptr)
{
    _show_mem_info_node(1, ptr);
}

void wrap_mem_print_mgr(size_t size)
{
    _show_mem_info_mgr(1, size);
}

void wrap_mem_print(int choice)
{
    _print_mem_info_node(choice);
}

