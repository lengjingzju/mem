#include <stdio.h>
#include <string.h>
#include "pool_memory.h"
#include "dlist_memory.h"

#define _pool_malloc         malloc
#define _pool_calloc         calloc
#define _pool_realloc        realloc
#define _pool_strdup         strdup
#define _pool_free           free

int pool_mem_mgr_init(PoolMemMgr *mgr, int size, int num, int redo)
{
    int i = 0;
    size_t tmp_size = 0;
    if (mgr == NULL || size == 0)
        return -1;

    tmp_size = num * sizeof(int);
    if (tmp_size && (mgr->puse = _pool_malloc(tmp_size)) == NULL) {
        printf("%s:%d malloc failed! size = %lu.\n", __func__, __LINE__, (unsigned long)tmp_size);
        return -1;
    }
    tmp_size = num * size;
    if (tmp_size && (mgr->begin = _pool_malloc(tmp_size)) == NULL) {
        printf("%s:%d malloc failed! size = %lu.\n", __func__, __LINE__, (unsigned long)tmp_size);
        _pool_free(mgr->puse);
        mgr->puse = NULL;
        return -1;
    }
    mgr->end = (unsigned char*)mgr->begin + tmp_size;

    mgr->num = num;
    mgr->size = size;
    mgr->sel = 0;
    for (i = 0; i < num; i++)
        mgr->puse[i] = i;
    mgr->redo = redo;
    return 0;
}

int pool_mem_mgr_release(PoolMemMgr *mgr)
{
    if (mgr == NULL)
        return -1;

    if (mgr->puse) {
        _pool_free(mgr->puse);
        mgr->puse = NULL;
    }
    if (mgr->begin) {
        _pool_free(mgr->begin);
        mgr->puse = NULL;
    }
    memset(mgr, 0, sizeof(PoolMemMgr));
    return 0;
}

void* pool_mem_mgr_malloc(PoolMemMgr *mgr)
{
    void *ptr = NULL;

    if (mgr->sel < mgr->num) {
        ptr = (unsigned char *)mgr->begin + mgr->size * mgr->puse[mgr->sel];
        ++mgr->sel;
    } else {
        if (mgr->redo) {
            ptr = _pool_malloc(mgr->size);
        }
    }
    return ptr;
}

void* pool_mem_mgr_mallocz(PoolMemMgr *mgr)
{
    void *ptr = NULL;
    ptr = pool_mem_mgr_malloc(mgr);
    if (ptr)
        memset(ptr, 0, mgr->size);
    return ptr;
}

void pool_mem_mgr_free(PoolMemMgr *mgr, void *ptr)
{
    if (ptr == NULL)
        return;

    if (ptr < mgr->begin || ptr >= mgr->end) {
        _pool_free(ptr);
    } else {
        int val = ((unsigned char *)ptr - (unsigned char *)mgr->begin) / mgr->size;
        --mgr->sel;
        mgr->puse[mgr->sel] = val;
    }
}

int _get_mgr_sel(PoolMemCtrl *ctrl, void *ptr)
{
    int i = 0;
    for (i = 0; i < ctrl->mgr_num; i++) {
        if (ptr < ctrl->mgr_array[i].begin || ptr >= ctrl->mgr_array[i].end) {
            return i;
        }
    }
    return -1;
}

int pool_mem_ctrl_init(PoolMemCtrl *ctrl, int total, int *size, int *num,  int redo)
{
    int i = 0;
    if (!ctrl || !total || !size || !num)
        return -1;

    memset(ctrl, 0, sizeof(PoolMemCtrl));
    ctrl->mgr_array = _pool_calloc(total, sizeof(PoolMemMgr));
    if (!ctrl->mgr_array) {
        printf("%s:%d malloc failed! size = %lu.\n", __func__, __LINE__, (unsigned long)(total * sizeof(PoolMemMgr)));
        return -1;
    }

    for (i = 0; i < total; i++) {
        if (pool_mem_mgr_init(&ctrl->mgr_array[i], size[i], num[i], 0) < 0) {
            printf("%s:%d pool_mem_mgr_init failed.\n", __func__, __LINE__);
            goto err;
        }
        ++ctrl->mgr_num;
    }
    ctrl->redo = redo;

    return 0;
err:
    pool_mem_ctrl_release(ctrl);
    return -1;
}

int pool_mem_ctrl_release(PoolMemCtrl *ctrl)
{
    int i = 0;

    if (ctrl == NULL)
        return -1;

    if (ctrl->mgr_array) {
        for (i = 0; i < ctrl->mgr_num; i++) {
            pool_mem_mgr_release(&ctrl->mgr_array[i]);
        }
        _pool_free(ctrl->mgr_array);
    }
    memset(ctrl, 0, sizeof(PoolMemCtrl));

    return 0;
}

void* pool_mem_ctrl_malloc(PoolMemCtrl *ctrl, size_t size)
{
    int i = 0;

    for (i = 0; i < ctrl->mgr_num; i++) {
        if (ctrl->mgr_array[i].size >= (int)size && ctrl->mgr_array[i].sel < ctrl->mgr_array[i].num) {
            return pool_mem_mgr_malloc(&ctrl->mgr_array[i]);
        }
    }
    if (ctrl->redo)
        return _pool_malloc(size);

    return NULL;
}

void* pool_mem_ctrl_mallocz(PoolMemCtrl *ctrl, size_t size)
{
    void *ptr = NULL;
    ptr = pool_mem_ctrl_malloc(ctrl, size);
    if (ptr)
        memset(ptr, 0, size);
    return ptr;
}

void* pool_mem_ctrl_calloc(PoolMemCtrl *ctrl, size_t nmemb, size_t size)
{
    void *ptr = NULL;
    size_t total_size = nmemb * size;
    ptr = pool_mem_ctrl_malloc(ctrl, total_size);
    if (ptr)
        memset(ptr, 0, total_size);
    return ptr;
}

void* pool_mem_ctrl_realloc(PoolMemCtrl *ctrl, void *ptr, size_t size)
{
    if (ptr) {
        int mgr_sel = _get_mgr_sel(ctrl, ptr);
        if (mgr_sel < 0) {
            return _pool_realloc(ptr, size);
        } else {
            if (ctrl->mgr_array[mgr_sel].size >= (int)size) {
                return ptr;
            } else {
                void *tmp = pool_mem_ctrl_malloc(ctrl, size);
                if (tmp) {
                    memcpy(tmp, ptr, ctrl->mgr_array[mgr_sel].size);
                    return tmp;
                } else {
                    pool_mem_ctrl_free(ctrl, ptr);
                    return NULL;
                }
            }
        }
    } else {
        return pool_mem_ctrl_malloc(ctrl, size);
    }

    return NULL;
}

char* pool_mem_ctrl_strdup(PoolMemCtrl *ctrl, const char *s)
{
    char *ptr = NULL;
    size_t size = strlen(s);
    ptr = pool_mem_ctrl_malloc(ctrl, size + 1);
    if (ptr) {
        memcpy(ptr, s, size);
        ptr[size] = 0;
    }
    return ptr;
}

char* pool_mem_ctrl_strndup(PoolMemCtrl *ctrl, const char *s, size_t n)
{
    char *ptr = NULL;
    size_t size = strlen(s);
    if (size > n)
        size = n;
    ptr = pool_mem_ctrl_malloc(ctrl, size + 1);
    if (ptr) {
        memcpy(ptr, s, size);
        ptr[size] = 0;
    }
    return ptr;
}

void pool_mem_ctrl_free(PoolMemCtrl *ctrl, void *ptr)
{
    if (ptr == NULL)
        return;

    int mgr_sel = _get_mgr_sel(ctrl, ptr);
    if (mgr_sel < 0) {
        return _pool_free(ptr);
    } else {
        pool_mem_mgr_free(&ctrl->mgr_array[mgr_sel], ptr);
    }
}

