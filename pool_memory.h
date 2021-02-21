#ifndef __POOL_MEMORY_H__
#define __POOL_MEMORY_H__
#include <stdlib.h>

typedef struct {
    int size;               // 每个内存单元的大小
    int num;                // 内存单元总数
    int sel;                // 当前空闲的序号
    int *puse;              // 内存池状态数组
    void *begin;            // 内存池开始地址
    void *end;              // 内存池结束地址
    int redo;               // 内存池分配不到时: 0, 返回失败; 1, 继续malloc分配
} PoolMemMgr;

typedef struct {
    int mgr_num;
    PoolMemMgr *mgr_array;
    int redo;
} PoolMemCtrl;

int pool_mem_mgr_init(PoolMemMgr *mgr, int size, int num, int redo);
int pool_mem_mgr_release(PoolMemMgr *mgr);
void* pool_mem_mgr_malloc(PoolMemMgr *mgr);
void* pool_mem_mgr_mallocz(PoolMemMgr *mgr);
void pool_mem_mgr_free(PoolMemMgr *mgr, void *ptr);

int pool_mem_ctrl_init(PoolMemCtrl *ctrl, int total, int *size, int *num, int redo);
int pool_mem_ctrl_release(PoolMemCtrl *ctrl);
void* pool_mem_ctrl_malloc(PoolMemCtrl *ctrl, size_t size);
void* pool_mem_ctrl_mallocz(PoolMemCtrl *ctrl, size_t size);
void* pool_mem_ctrl_calloc(PoolMemCtrl *ctrl, size_t nmemb, size_t size);
void* pool_mem_ctrl_realloc(PoolMemCtrl *ctrl, void *ptr, size_t size);
char* pool_mem_ctrl_strdup(PoolMemCtrl *ctrl, const char *s);
char* pool_mem_ctrl_strndup(PoolMemCtrl *ctrl, const char *s, size_t n);
void pool_mem_ctrl_free(PoolMemCtrl *ctrl, void *ptr);

#endif

