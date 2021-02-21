#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <pthread.h>
#include "dlist_memory.h"
#include "pool_memory.h"
#include "hook_memory.h"

#define ADD_CHECK_BYTES     0
#if ADD_CHECK_BYTES
#define ADD_CHECK_VALUE     0x55
static char s_add_check_array[ADD_CHECK_BYTES];
#endif

#define PRINT_MEM_INFO(mgr) printf("size = %8u\talloc = %8d\tfree=%8d\tdiff=%8d\n", \
        (unsigned int)mgr->size, mgr->alloc_cnt, mgr->free_cnt, mgr->alloc_cnt - mgr->free_cnt)
#define _MERR(fmt, args...)     do { printf("[MERR][%s:%d]: ", __func__, __LINE__);printf(fmt, ##args); } while(0)

// please use spin_lock, ecos is as follows:
#if ECOS_OS
#define MEM_DEBUG_LOCK()        do { cyg_interrupt_disable(); cyg_scheduler_lock(); } while(0)
#define MEM_DEBUG_UNLOCK()      do { cyg_interrupt_enable(); cyg_scheduler_unlock(); } while(0)
#else
#define MEM_DEBUG_LOCK()
#define MEM_DEBUG_UNLOCK()
#endif
extern void memory_hook_insert(int (*malloc_cb)(void* ptr, size_t size), int (*free_cb)(void* ptr));

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
    PoolMemMgr mgr_pool;
    PoolMemMgr node_pool;
    int test_en;
} MemDebugCtrl;

static MemDebugCtrl s_mem_debug_ctrl;

typedef struct {
   size_t min_size;
   size_t max_size;
   void *test_ptr;
   void (*set_ptr)(void *ptr);
} MemDebugHook;

static MemDebugHook s_mem_debug_hook;

void hook_mem_set_test_ptr(void *ptr)
{
    MemDebugHook *hook = &s_mem_debug_hook;
    hook->test_ptr = ptr;
}

void hook_mem_set_test_size(size_t min_size, size_t max_size, void (*set_ptr)(void *ptr))
{
    MemDebugHook *hook = &s_mem_debug_hook;
    hook->min_size = min_size;
    hook->max_size = max_size;
    hook->set_ptr = set_ptr ? set_ptr : hook_mem_set_test_ptr;
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

    if (!ctrl->test_en) return -1;

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
    if (!ctrl->test_en) return -1;

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
                pool_mem_mgr_free(&ctrl->node_pool, node_pos);
            }
        }
    }
#endif

    node = pool_mem_mgr_mallocz(&ctrl->node_pool);
    if (!node) {
        _MERR("\033[31mnode_pool overflow!\033[0m\n");
        goto end;
    }
    node->ptr = ptr;
    mem_list_for_each_entry_safe(mgr_pos, mgr_n, &ctrl->head, list) {
        if (mgr_pos->size == size) {
            ++mgr_pos->alloc_cnt;
            mem_list_add_tail(&node->list, &mgr_pos->head);
            ret = 0;
            goto end;
        }
    }

    mgr = pool_mem_mgr_mallocz(&ctrl->mgr_pool);
    if (!mgr) {
        pool_mem_mgr_free(&ctrl->node_pool, node);
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
    if (!ctrl->test_en) return -1;

    _check_mem_info_node();

    MEM_DEBUG_LOCK();
    mem_list_for_each_entry_safe(mgr_pos, mgr_n, &ctrl->head, list) {
        mem_list_for_each_entry_safe(node_pos, node_n, &mgr_pos->head, list) {
            if (node_pos->ptr == ptr) {
                mgr_pos->change_flag = 1;
                ++mgr_pos->free_cnt;
                mem_list_del(&node_pos->list);
                pool_mem_mgr_free(&ctrl->node_pool, node_pos);
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

int hook_mem_init(int mgr_num, int node_num)
{
    MemDebugCtrl *ctrl = &s_mem_debug_ctrl;

    INIT_MEM_LIST_HEAD(&ctrl->head);
    if (pool_mem_mgr_init(&ctrl->mgr_pool, sizeof(MemDebugMgr), mgr_num, 0) < 0) {
        _MERR("malloc failed! mgr_num = %d.\n", mgr_num);
        return -1;
    }
    if (pool_mem_mgr_init(&ctrl->node_pool, sizeof(MemDebugNode), node_num, 0) < 0) {
        _MERR("malloc failed! node_num = %d.\n", node_num);
        pool_mem_mgr_release(&ctrl->mgr_pool);
        return -1;
    }
    memory_hook_insert(_add_mem_info_node, _del_mem_info_node);
    return 0;
}

void hook_mem_release(void)
{
    MemDebugCtrl *ctrl = &s_mem_debug_ctrl;

    memory_hook_insert(NULL, NULL);
    pool_mem_mgr_release(&ctrl->mgr_pool);
    pool_mem_mgr_release(&ctrl->node_pool);
    memset(ctrl, 0, sizeof(MemDebugCtrl));
    INIT_MEM_LIST_HEAD(&ctrl->head);
}

void hook_mem_enset(int enable_flag)
{
    MemDebugCtrl *ctrl = &s_mem_debug_ctrl;
    ctrl->test_en = enable_flag;
}

void hook_mem_print(int choice)
{
    _print_mem_info_node(choice);
}
