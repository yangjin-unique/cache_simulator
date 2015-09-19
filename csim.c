/**
 * @brief This is a cache simulator to compute the hit/miss/eviction counts 
 *		  with trace files. LRU algorithm is used to simulate cache operations.
 * 
 * LRU algorithm:
 *		 We use a double linked list to hold all cache lines in a set. Head of 
 *		 the list is potential candidate for evictions when caches missing, while
 *		 tail of list is a cache that is used recently.
 *		 When a cache line is hitted, we move this cache line into tailer of the list,
 *		 and updating counters. When a cache line is missed, we select an eviction if 
 *		 there are no free caches.
 * 
 * @author jinyang.hust@gmail.com
 */
#include <stdlib.h>
#include <stdio.h>
#include <unistd.h>
#include <getopt.h>
#include <string.h>
#include <math.h>
#include <assert.h>
#include <stdarg.h>
#include "cachelab.h"
#include "list.h"


typedef int		bool_t;
typedef unsigned char	uint8;
typedef unsigned short	uint16;
typedef unsigned int	uint32;
typedef unsigned long	uint64;

#define BUF_LINE_SIZE	64

typedef struct _option {
	int set;
	int line;
	int block;
	char *file;
	int verbo;
}option_t;


/* description for a cache operation */
typedef struct _cache_ops {
	char op; /* cache operation: M: modfiy, I: instruction, L: load, S: store */
	uint64 addr; /* cache address */
	uint32 size; /* bytes of accesee memory */
} cache_ops_t;


/* below are cache memory description structure */
typedef struct _cache_line {
	uint8 valid;
	uint64 tag;
	struct list_head list;
} cache_line_t;


typedef struct _cache_set {
	uint32 nused;
	struct list_head lhead; /* cache line double linked list */	
} cache_set_t;


/* Cache organisatin: (S, E, B) */
typedef struct _cache_desc {
	int sbits; /* number of bits in a cache address, S=2^s (s=sbits) */
	int nlines; /* E way association, E=2^e (E=nlines, not e)*/
	int bbits; /* block size, B=2^b (b=bbits)*/
	cache_set_t *sets;
} cache_desc_t;

/* global statistics info */
int hit_cnt;
int miss_cnt;
int evict_cnt; 

void
usage(void)
{
	printf("Usage: ./csim -s 2 -E 2 -b 3 -t traces/dave.trace -v \n");
	exit(0);
}


void
dbg(int verbo, char *fmt, ...)
{
	va_list ap;

	if (verbo) {
		va_start(ap, fmt);	
		vprintf(fmt, ap);
		va_end(ap);
	}
	return;
}


void
print_args(option_t *opt)
{
	printf("\n----------------\n");
	printf("Number of sets: %f\n", pow(2, opt->set));
	printf("Number of lines: %d\n", opt->line);
	printf("Block size: %f\n", pow(2, opt->block));
	printf("File name: %s\n", opt->file);
	printf("Verbose: %d\n", opt->verbo);
}



/**
 * @brief Cache sets api
 *
 */
void
cache_destroy(cache_desc_t *cache)
{
	int i;
	cache_line_t *lcache, *n;

	for (i = 0; i < pow(2, cache->sbits); i++) {
		list_for_each_entry_safe(lcache, n, &cache->sets[i].lhead, list) {
			list_del(&lcache->list);
			free(lcache);			
		}
	}
	free(cache->sets);
	free(cache);
}



cache_desc_t *
cache_init(int set, int line, int block)
{
	cache_desc_t *cache;
	cache_line_t *new_line;
	int i, j;
	int total_sets;

	assert(set && line && block);
	cache = calloc(1, sizeof(*cache));
	if (cache == NULL)
		goto m_cache_err;

	cache->sbits = set;
	cache->nlines = line;
	cache->bbits = block;
	total_sets = pow(2, set);
	cache->sets = calloc(total_sets, sizeof(cache_set_t));
	if (cache->sets == NULL) 
		goto m_set_err;

	for (i = 0; i < total_sets; i++) {
		INIT_LIST_HEAD(&cache->sets[i].lhead);
		for (j = 0; j < cache->nlines; j++) {
			new_line = calloc(1, sizeof(cache_line_t));
			if (new_line == NULL) 
				goto m_line_err;

			list_add_tail(&new_line->list, &cache->sets[i].lhead);
		}
	}
	return cache;

m_line_err:
	cache_destroy(cache);
m_set_err:
	free(cache->sets);
m_cache_err:
	free(cache);
	return NULL;
}

void
cache_simulate(cache_desc_t *cache, cache_ops_t *ops)
{
	cache_line_t *cache_line;
	cache_line_t *evic = NULL;
	uint64 tag;
	uint64 sidx;
	bool_t found = 0;

	tag = 1;
	sidx = 1;
	assert(cache && ops);
	tag = ops->addr >> (cache->sbits + cache->bbits); 
	sidx = (ops->addr >> cache->bbits) & ~((~0UL) << cache->sbits);
	dbg(0, "tag=%lx, sidx=%lx\n", tag, sidx);
	switch (ops->op) {
		case 'I': 
			break;
		case 'M':
			/* 
			 * Modify: equals to a load and a store followed.
			 */
		case 'L':
		case 'S':
			list_for_each_entry(cache_line, &cache->sets[sidx].lhead, list) {
				if (!cache_line->valid)
					evic = cache_line;
				if (cache_line->valid && cache_line->tag == tag) {
					/* hit a cache */
					hit_cnt++;
					dbg(1, "hit\t");
					if (ops->op == 'M') {
						hit_cnt++;
						dbg(1, "M hit\t");
					}
					found = 1;
					break;
				}
			}
			if (found) {
				/* LRU: move the hitted cache into tail of list */
				list_del(&cache_line->list);
				list_add_tail(&cache_line->list, &cache->sets[sidx].lhead);
			}
			else {
				dbg(1, "miss\t");
				miss_cnt++;
				if (ops->op == 'M') { /* one M equals to two hits when cache hitted */
					hit_cnt++;
					dbg(1, "Mhit\t");
				}
				if (!evic) { 
					/* no free cache, select a cache in head per LRU algorithm */
					evic = list_entry(cache->sets[sidx].lhead.next, cache_line_t, list);
					evict_cnt++;
					dbg(1, "eviction\t");
				}
				list_del(&evic->list);
				evic->valid = 1;
				evic->tag = tag;
				list_add_tail(&evic->list, &cache->sets[sidx].lhead);
			}
			break;
		default:
			dbg(1, "unknown cache operation\n");
			break;
	}
	return;
}


int 
main(int argc, char *argv[])
{
	int c;
	option_t opt;
	FILE *fp;
	char buf[BUF_LINE_SIZE];
	cache_ops_t ops;	
	cache_desc_t *cache = NULL; /* cache */
	
	memset(&opt, 0, sizeof(opt));

	while ((c = getopt(argc, argv, "vs:E:b:t:")) != -1) {
		switch (c) {
			case 'v':
				opt.verbo = 1;
				break;
			case 's':
				opt.set = atoi(optarg);	
				break;
			case 'E':
				opt.line = atoi(optarg);
				break;
			case 'b':
				opt.block = atoi(optarg);
				break;
			case 't':
				opt.file = optarg;
				break;
			default:
				usage();
				break;
		}
	}

	print_args(&opt);

	/* open trace file */
	fp = fopen(opt.file, "r");
	if (fp == NULL) {
		perror("file open failed");
		return 0;
	}

	/* build cache per args */
	cache = cache_init(opt.set, opt.line, opt.block);

	while (fgets(buf, sizeof(buf), fp)) {
		dbg(1, "line: %s", buf);	
		sscanf(buf, " %c %lx,%d", &ops.op, &ops.addr, &ops.size);	
		dbg(1, "decode: %c %lx %d\n", ops.op, ops.addr, ops.size);
		cache_simulate(cache, &ops);
	}

	cache_destroy(cache);
    printSummary(hit_cnt, miss_cnt, evict_cnt);
    return 0;
}
