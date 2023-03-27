#include "fuzzer.h"

static int64_t num_allocs_remaining;

static void *
faultinject_malloc(size_t size)
{
	if (__atomic_sub_fetch(&num_allocs_remaining, 1, __ATOMIC_RELAXED) <= 0)
		return NULL;
	return malloc(size);
}

static void
faultinject_free(void *p)
{
	free(p);
}

static void *
faultinject_realloc(void *p, size_t size)
{
	if (__atomic_sub_fetch(&num_allocs_remaining, 1, __ATOMIC_RELAXED) <= 0)
		return NULL;
	return realloc(p, size);
}

bool
setup_fault_nth(const uint8_t **in, size_t *insize, uint16_t *fault_nth)
{
	uint16_t n;

	if (*insize < 2)
		return false;
	memcpy(&n, *in, 2);
	wimlib_set_memory_allocator(faultinject_malloc, faultinject_free,
				    faultinject_realloc);
	num_allocs_remaining = n ?: INT64_MAX;
	*in += 2;
	*insize -= 2;
	*fault_nth = n;
	return true;
}
