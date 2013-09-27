
#ifndef HMALLOC_H
#define HMALLOC_H

#include <stdio.h>
#include <stdlib.h>

/*
 *	Replacements for malloc, realloc and free, which never fail,
 *	and might keep statistics on memory allocation...
 */

extern void *hmalloc(size_t size);
extern void *hrealloc(void *ptr, size_t size);
extern void hfree(void *ptr);

extern char *hstrdup(const char *s);

extern void hmalloc_stats(FILE *f);

extern long long hmallocs;
extern long long hmallocs_b;
extern long long hfrees;
extern long long hfree_nulls;
extern long long hreallocs;
extern long long hstrdups;

#endif

