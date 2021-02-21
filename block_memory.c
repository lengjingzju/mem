#include <stdio.h>
#include <string.h>
#include "block_memory.h"

#define _block_malloc         malloc
#define _block_calloc         calloc
#define _block_realloc        realloc
#define _block_strdup         strdup
#define _block_free           free

static BlockMemData s_invalid_block_mem;

BlockMemMgr *block_mem_mgr_get(BlockMemCtrl *ctrl, int mem_id)
{
    BlockMemMgr *pos = NULL;
    mem_list_for_each_entry(pos, &ctrl->head, list) {
        if (pos->attr.mem_id == mem_id)
            return pos;
    }
    return NULL;
}

void block_mem_datafree(BlockMemMgr *mgr, PoolMemMgr *pool)
{
    BlockMemData *pos = NULL, *n = NULL;

    mem_list_for_each_entry_safe(pos, n, &mgr->head, list) {
        mem_list_del(&pos->list);
        _block_free(pos->ptr);
        pool_mem_mgr_free(pool, pos);
    }
    mgr->cur_node = &s_invalid_block_mem;
}

static void *_block_mem_new(size_t size, BlockMemMgr *mgr, PoolMemMgr *pool)
{
    BlockMemData *node = NULL;

    if ((node = pool_mem_mgr_mallocz(pool)) == NULL) {
        printf("[%s:%d]malloc failed!\n", __func__, __LINE__);
        return NULL;
    }
    node->size = size;
    if ((node->ptr = _block_calloc(1, node->size)) == NULL) {
        pool_mem_mgr_free(pool, node);
        printf("[%s:%d]malloc failed!\n", __func__, __LINE__);
        return NULL;
    }
    node->cur = node->ptr;
    mem_list_add(&node->list, &mgr->head);

    return node;
}

void *block_mem_malloc(BlockMemMgr *mgr, PoolMemMgr *pool, size_t size)
{
    BlockMemData *pos = NULL;
    void *p = NULL;
    size_t data_size = 0, block_size = 0;

    data_size = size % mgr->attr.align_byte;
    data_size = (data_size != 0) ? (size + mgr->attr.align_byte - data_size) : (size);
    block_size = (data_size > mgr->attr.def_size) ? data_size : mgr->attr.def_size;

    if (mgr->cur_node->cur + data_size <= mgr->cur_node->ptr + mgr->cur_node->size)
        goto end;

    if (!mgr->attr.fast_alloc) {
        mem_list_for_each_entry(pos, &mgr->head, list) {
            if (pos->cur + data_size <= pos->ptr + pos->size) {
                mgr->cur_node = pos;
                goto end;
            }
        }
    }

    if (_block_mem_new(block_size, mgr, pool) != NULL) {
        mgr->cur_node =  (BlockMemData *) (mgr->head.next);
        goto end;
    }

    return NULL;
end:
    p = mgr->cur_node->cur;
    mgr->cur_node->cur += data_size;
    return p;
}

void *block_mem_datadup(BlockMemMgr *mgr, PoolMemMgr *pool, void *ptr, size_t size)
{
    void *p = NULL;

    if (!ptr) {
        printf("[%s:%d]null ptr!\n", __func__, __LINE__);
        return NULL;
    }
    if ((p = block_mem_malloc(mgr, pool, size)) != NULL) {
        memcpy(p, ptr, size);
    }

    return p;
}

void *block_mem_strdup(BlockMemMgr *mgr, PoolMemMgr *pool, const char *str)
{
    void *p = NULL;
    size_t size = 0;

    if (!str) {
        printf("[%s:%d]null ptr!\n", __func__, __LINE__);
        return NULL;
    }
    size = strlen(str) + 1;
    if ((p = block_mem_malloc(mgr, pool, size)) != NULL) {
        memcpy(p, str, size);
    }

    return p;
}

void block_mem_mgr_adjust(BlockMemMgr *mgr, PoolMemMgr *pool)
{
    BlockMemData *pos = NULL, *n = NULL;

    mem_list_for_each_entry_safe(pos, n, &mgr->head, list) {
        if (pos->cur == pos->ptr) {
            mem_list_del(&pos->list);
            _block_free(pos->ptr);
            pool_mem_mgr_free(pool, pos);
        } else {
            pos->size = pos->cur - pos->ptr;
            pos->ptr = _block_realloc(pos->ptr, pos->size);
        }
    }
    mgr->cur_node = &s_invalid_block_mem;
}

size_t block_mem_mgr_tell(BlockMemMgr *mgr)
{
    BlockMemData *pos = NULL;
    size_t size = 0;

    mem_list_for_each_entry(pos, &mgr->head, list) {
        size += pos->size;
    }
    return size;
}

void block_mem_mgr_free(BlockMemCtrl *ctrl, BlockMemMgr *mgr)
{
    if (!mgr)
        return;

    mem_list_del(&mgr->list);
    block_mem_datafree(mgr, &ctrl->data_pool);
    pool_mem_mgr_free(&ctrl->mgr_pool, mgr);
}

int block_mem_mgr_init(BlockMemMgr *mgr, BlockMemAttr *attr)
{
    if (attr->def_size <= 0 || attr->align_byte <= 0) {
        printf("[%s:%d]def_size or align_byte is 0!\n", __func__, __LINE__);
        return -1;
    }
    memcpy(&mgr->attr, attr, sizeof(BlockMemAttr));
    INIT_MEM_LIST_HEAD(&mgr->head);
    mgr->cur_node = &s_invalid_block_mem;
    return 0;
}

BlockMemMgr *block_mem_mgr_alloc(BlockMemCtrl *ctrl, BlockMemAttr *attr)
{
    BlockMemMgr *mgr = NULL;

    if ((mgr = pool_mem_mgr_mallocz(&ctrl->mgr_pool)) == NULL) {
        printf("[%s:%d]malloc failed!\n", __func__, __LINE__);
        return NULL;
    }
    if (block_mem_mgr_init(mgr, attr) < 0) {
        pool_mem_mgr_free(&ctrl->mgr_pool, mgr);
        return NULL;
    }
    mem_list_add(&mgr->list, &ctrl->head);

    return mgr;
}

void block_mem_ctrl_datafree(BlockMemCtrl *ctrl)
{
    BlockMemMgr *pos = NULL;
    mem_list_for_each_entry(pos, &ctrl->head, list) {
        block_mem_datafree(pos, &ctrl->data_pool);
    }
}

void block_mem_ctrl_adjust(BlockMemCtrl *ctrl)
{
    BlockMemMgr *pos = NULL;
    mem_list_for_each_entry(pos, &ctrl->head, list) {
        block_mem_mgr_adjust(pos, &ctrl->data_pool);
    }
}

size_t block_mem_ctrl_tell(BlockMemCtrl *ctrl)
{
    BlockMemMgr *pos = NULL;
    size_t size = 0;
    mem_list_for_each_entry(pos, &ctrl->head, list) {
        size += block_mem_mgr_tell(pos);
    }
    return size;
}

int block_mem_ctrl_init(BlockMemCtrl *ctrl, int mgr_pool_num, int data_pool_num)
{
    if (!ctrl)
        return -1;

    memset(ctrl, 0, sizeof(BlockMemCtrl));
    INIT_MEM_LIST_HEAD(&ctrl->head);

    if (pool_mem_mgr_init(&ctrl->mgr_pool, sizeof(BlockMemMgr), mgr_pool_num, 1) < 0) {
        return -1;
    }
    if (pool_mem_mgr_init(&ctrl->data_pool, sizeof(BlockMemData), data_pool_num, 1) < 0) {
        pool_mem_mgr_release(&ctrl->mgr_pool);
        return -1;
    }

    return 0;
}

void block_mem_ctrl_release(BlockMemCtrl *ctrl)
{
    BlockMemMgr *pos = NULL, *n = NULL;
    mem_list_for_each_entry_safe(pos, n, &ctrl->head, list) {
        block_mem_mgr_free(ctrl, pos);
    }
    pool_mem_mgr_release(&ctrl->mgr_pool);
    pool_mem_mgr_release(&ctrl->data_pool);
}

