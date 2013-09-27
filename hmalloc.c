
/*
 *	Replacements for malloc, realloc and free, which never fail,
 *	and might keep statistics on memory allocation...
 *
 *	GPL'ed, by Heikki Hannikainen <hessu@hes.iki.fi>
 */

#include <unistd.h>
#include <string.h>
#include <stdio.h>

#include "hmalloc.h"

int mem_panic = 0;

long long hmallocs;
long long hmallocs_b;
long long hfrees;
long long hfree_nulls;
long long hreallocs;
long long hstrdups;

void *hmalloc(size_t size)
{
	void *p;
	
	if (!(p = malloc(size))) {
		if (mem_panic)
			exit(1);	/* To prevent a deadlock */
		mem_panic = 1;
		fprintf(stderr, "hmalloc: Out of memory! Could not allocate %d bytes.", size);
		exit(1);
	}
	
	hmallocs++;
	hmallocs_b += size;
	return p;
}

void *hrealloc(void *ptr, size_t size)
{
	void *p;
	
	if (!(p = realloc(ptr, size))) {
		if (mem_panic)
			exit(1);
		mem_panic = 1;
		fprintf(stderr, "hrealloc: Out of memory! Could not reallocate %d bytes.", size);
		exit(1);
	}
	
	hreallocs++;
	return p;
}

void hfree(void *ptr)
{
	if (ptr)
		free(ptr);
	else
		hfree_nulls++;
	hfrees++;
}

char *hstrdup(const char *s)
{
	char *p;
	
	p = hmalloc(strlen(s)+1);
	strcpy(p, s);
	
	hstrdups++;
	return p;
}

void hmalloc_stats(FILE *f)
{
	fprintf(f, "hmalloc:\n\tmallocs\t%lld (%lld bytes)\n\tfrees\t%lld\n\treallocs\t%lld\n\tstrdups\t%lld\n",
		hmallocs, hmallocs_b, hfrees, hreallocs, hstrdups);
}

