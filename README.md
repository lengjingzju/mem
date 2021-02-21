# LMEM
LMEM, memory debug for embedded C language (Linux and ECOS).

## pool_memory
一个通用内存池的代码实现，用于管理各种类型的节点，也可以作为小内存的内存池使用，可以减少内存碎片化。

## block_memory
一个通用内存块的代码实现，用于提高小内存的分配效率和减少内存碎片化，适用于可以统一申请和释放的小内存使用场景，例如我开发的LJSON。

## debug_memory
内存调试方法1：通用方法，需要使用该模块定义的函数替换调试代码中使用的malloc/free等内存函数，适合一些模块代码的内存调试。

## wrap_memory
内存调试方法2：库函数替换法，一般用于Linux用户态的内存调试。链接成可执行文件时需要加上链接选项 "-Wl,--wrap=malloc -Wl,--wrap=calloc -Wl,--wrap=realloc -Wl,--wrap=strdup -Wl,--wrap=free"。

## hook_memory
内存调试方法3：钩子方法，需要可以在库函数malloc/free上加上钩子，例如ECOS的malloc.cxx文件，嵌入式实时操作系统的驱动模块的内存也可以调试。不初始化时几乎没有资源开销。
