#ifndef __BLOCK_MEMORY_H__
#define __BLOCK_MEMORY_H__
#include "pool_memory.h"
#include "dlist_memory.h"

typedef struct {
    struct mem_list_head list;  // 链表节点
    size_t size;                // 内存大小
    unsigned char *ptr;         // 首部地址
    unsigned char *cur;         // 当前地址
} BlockMemData;

typedef struct {
    int mem_id;                 // 所属类别ID
    size_t def_size;            // 默认分配块大小
    size_t align_byte;          // 几字节对齐要求
    int fast_alloc;             // (0只查找当前节点 / 1查找所有节点)分配不到就重新分配
} BlockMemAttr;

typedef struct {
    struct mem_list_head list;  // 链表节点
    struct mem_list_head head;  // BlockMemData挂载节点
    BlockMemData *cur_node;     // 当前使用的内存块
    BlockMemAttr attr;
} BlockMemMgr;

typedef struct {
    struct mem_list_head head;  // BlockMemMgr挂载节点
    PoolMemMgr mgr_pool;
    PoolMemMgr data_pool;
} BlockMemCtrl;

/* 通过mem_id找到挂载在ctrl上的内存块管理节点 */
BlockMemMgr *block_mem_mgr_get(BlockMemCtrl *ctrl, int mem_id);

/* 释放mgr管理的全部内存块节点 */
void block_mem_datafree(BlockMemMgr *mgr, PoolMemMgr *pool);
static inline void block_mem_datafree2(BlockMemCtrl *ctrl, int mem_id)
{
    BlockMemMgr *mgr = block_mem_mgr_get(ctrl, mem_id);
    if (mgr) block_mem_datafree(mgr, &ctrl->data_pool);
}

/* 从mgr管理的内存块中分配一块size大小的内存 */
void *block_mem_malloc(BlockMemMgr *mgr, PoolMemMgr *pool, size_t size);
static inline void *block_mem_malloc2(BlockMemCtrl *ctrl, int mem_id, size_t size)
{
    BlockMemMgr *mgr = block_mem_mgr_get(ctrl, mem_id);
    return mgr ? block_mem_malloc(mgr, &ctrl->data_pool, size) : NULL;
}

/* 从mgr管理的内存块中分配一块内存并将ptr的数据copy进去 */
void *block_mem_datadup(BlockMemMgr *mgr, PoolMemMgr *pool, void *ptr, size_t size);
static inline void *block_mem_datadup2(BlockMemCtrl *ctrl, int mem_id, void *ptr, size_t size)
{
    BlockMemMgr *mgr = block_mem_mgr_get(ctrl, mem_id);
    return mgr ? block_mem_datadup(mgr, &ctrl->data_pool, ptr, size) : NULL;
}

/* 从mgr管理的内存块中分配一块内存并将str字符串dup进去 */
void *block_mem_strdup(BlockMemMgr *mgr, PoolMemMgr *pool, const char *str);
static inline void *block_mem_strdup2(BlockMemCtrl *ctrl, int mem_id, const char *str)
{
    BlockMemMgr *mgr = block_mem_mgr_get(ctrl, mem_id);
    return mgr ? block_mem_strdup(mgr, &ctrl->data_pool, str) : NULL;
}

/* 将mgr管理的全部内存块节点realloc到已使用的大小 */
void block_mem_mgr_adjust(BlockMemMgr *mgr, PoolMemMgr *pool);
static inline void block_mem_mgr_adjust2(BlockMemCtrl *ctrl, int mem_id)
{
    BlockMemMgr *mgr = block_mem_mgr_get(ctrl, mem_id);
    if (mgr) block_mem_mgr_adjust(mgr, &ctrl->data_pool);
}

/* 计算mgr管理的全部内存块节点的内存使用的大小 */
size_t block_mem_mgr_tell(BlockMemMgr *mgr);
static inline size_t block_mem_mgr_tell2(BlockMemCtrl *ctrl, int mem_id)
{
    BlockMemMgr *mgr = block_mem_mgr_get(ctrl, mem_id);
    return mgr ? block_mem_mgr_tell(mgr) : 0;
}

/* 释放mgr管理的全部内存块节点并释放mgr */
void block_mem_mgr_free(BlockMemCtrl *ctrl, BlockMemMgr *mgr);
static inline void block_mem_mgr_free2(BlockMemCtrl *ctrl, int mem_id)
{
    BlockMemMgr *mgr = block_mem_mgr_get(ctrl, mem_id);
    if (mgr) block_mem_mgr_free(ctrl, mgr);
}

/* 初始化一个内存块管理节点，需要调用者先设置好mgr的attr属性 */
int block_mem_mgr_init(BlockMemMgr *mgr, BlockMemAttr *attr);

/* 分配并初始化内存块管理节点, 并挂载到ctrl上，使用完成后需要调用block_mem_mgr_free释放*/
BlockMemMgr *block_mem_mgr_alloc(BlockMemCtrl *ctrl, BlockMemAttr *attr);

/* 释放挂载在ctrl的mgr管理的所有内存块节点(不含内存块管理节点) */
void block_mem_ctrl_datafree(BlockMemCtrl *ctrl);

/* 将挂载在ctrl上的mgr管理的所有内存块节点realloc到已使用的大小 */
void block_mem_ctrl_adjust(BlockMemCtrl *ctrl);

/* 计算挂载在ctrl上的mgr管理的所有内存块节点的内存使用的大小 */
size_t block_mem_ctrl_tell(BlockMemCtrl *ctrl);

/* 初始化内存块管理入口 */
int block_mem_ctrl_init(BlockMemCtrl *ctrl, int mgr_pool_num, int data_pool_num);

/* 释放挂载在ctrl上的mgr管理的所有内存块节点和所有内存块管理节点 */
void block_mem_ctrl_release(BlockMemCtrl *ctrl);

#endif

