#Cache Simulator
This is a simple cache simulator to measure the performance of a program by by counting
miss/hit/eviction times towards trace files produced by **valgrind**. The cache algorithm is LRU-based.

##Basic Knowledge about Cache
In general, cache organisation can be denoted simply as: (S, E, B), when E equals to 1, that is
**direct mapped cache**, otherwise, we call **E-way set associative cache**. Fig below shows the
organisation of cache.

![cache_org](https://github.com/yangjin-unique/cache_simulator/blob/master/fig/cache.jpg)





##Usage
*Compile:
    linux> make

*Run:
    linux> ./driver.py    

******
Files:
******

csim.c       cache simulator main logic
trans.c      transpose function
driver.py*   The driver program, runs test-csim and test-trans
cachelab.c   Required helper functions
cachelab.h   Required header file
traces/      Trace files used by test-csim.c
