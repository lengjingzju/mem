#ifndef __HOOK_MEMORY_H__
#define __HOOK_MEMORY_H__

/**
 * @brief:	初始化memory_debug的管理结构，主要是内存池
 * @param:	mgr_num, 最大信息节点的数目; node_num, 最大数据节点的数目
 * @return:	0, 成功; -1，失败
 * @description: 信息节点存储了内存的大小和分配释放的次数，数据节点记录了指针值
 *               信息节点挂载在管理结构上，数据节点挂载在信息节点上，双向链表管理
 *               本函数只能初始化或release后调用一次
 */
int hook_mem_init(int mgr_num, int node_num);

/**
 * @brief:	释放memory_debug的管理结构，主要是内存池
 * @description: 使用本函数释放管理结构后，可以再次使用 hook_mem_init 初始化
 */
void hook_mem_release(void);

/**
 * @brief:	开始或停止记录内存分配释放信息到内存池
 * @param:	enable_flag，0 停止记录, 1 开始记录
 */
void hook_mem_enset(int enable_flag);

/**
 * @brief:	打印堆内存申请释放信息
 * @param:	print_flag, 0 全部打印, 1 只打印变化过的内存, 2 只打印未释放的内存, 3 只打印变化过的且未释放的内存, 4 打印越界的内存
 * @description: 请在idle线程(HAL_IDLE_THREAD_ACTION(idle_thread_loops[CYG_KERNEL_CPU_THIS()]);) 运行本函数
 */
void hook_mem_print(int print_flag);

/**
 * @brief:	需要观察的指针值赋值给一个全局变量
 * @param:	test_ptr, 需要观察的指针值
 * @description: 外面不要运行此函数，本函数主要用于gdb设置断点查看堆栈
 */
void hook_mem_set_test_ptr(void *ptr);

/**
 * @brief:	设置需要观察的特定大小内存分配
 * @param:	min_size, 下限大小(含);  max_size, 上限大小(不含)
 * @description: 当分配的内存大小 min_size <= size <= max_size 时，分配的指针值将会赋值给一个全局变量
 *               用户可以自定义set_ptr, 如果set_ptr为NULL, 则会取默认值hook_mem_set_test_ptr
 */
void hook_mem_set_test_size(size_t min_size, size_t max_size, void (*set_ptr)(void *ptr));

/** 内存泄漏调试方法
 * 第1阶段:
 *   1. 设置一个观察点，一般是个静态显示界面，例如main menu
 *   2. 使用(假设设置的节点数目为1000和20000) hook_mem_init(1000, 20000) 初始化
 *   3. 使用 hook_mem_enset(1) 开始记录内存分配释放信息
 *   4. 进行疑似内存泄漏的操作，回到观察点
 *   5. 使用 hook_mem_print(3) 查看变化过的且未释放的内存，打印如下:
 *      size =    30564 alloc =    94632        free=   94631   diff=       1
 *      size, 申请内存的大小; alloc, 申请次数; free, 释放次数; diff, 未释放的次数
 *   6. 重复第4步和第5步，如果某个size的内存的diff一直增大，此处可能存在内存泄漏
 *   7. 使用 hook_mem_enset(0) 停止记录内存分配释放信息
 * 第2阶段:
 *   1. gdb设置断点在 hook_mem_set_test_ptr 函数
 *   2. 使用(假设第1阶段疑似内存泄漏的size为300) hook_mem_set_test_size(300, 301, NULL) 设置需要观察的特定大小内存分配
 *   3. 断点停止时查看堆栈，并使用 hook_mem_set_test_size(0, 0, NULL) 防止记录的内存指针被覆盖，继续运行
 *   4. 如果后面一直不会断点在 hook_mem_set_test_ptr ，说明该处存在内存泄漏，否则重复第2步和第3步
 * 疑似内存泄漏的这个大小的内存分配太多怎么办?
 *   1. 屏蔽不相干的功能，减少干扰
 *   2. 假设我们需要观察size=8的内存泄漏，我们可以把经常断点的地方的内存值改为9,10，... , 排除干扰
 */

#endif
