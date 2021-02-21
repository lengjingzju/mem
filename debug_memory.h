#ifndef __DEBUG_MEMORY_H__
#define __DEBUG_MEMORY_H__
#include <stdlib.h>

void* debug_mem_malloc(size_t size, const char *func, int line);
void* debug_mem_mallocz(size_t size, const char *func, int line);
void* debug_mem_calloc(size_t nmemb, size_t size, const char *func, int line);
void* debug_mem_realloc(void *ptr, size_t size, const char *func, int line);
char* debug_mem_strdup(const char *s, const char *func, int line);
void debug_mem_free(void *ptr, const char *func, int line);
void debug_mem_print_node(void *ptr);
void debug_mem_print_mgr(size_t size, const char *func, int line);
void debug_mem_print(int choice);

#endif
