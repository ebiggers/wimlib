/*
 * matchfinder_avx2.h
 *
 * Matchfinding routines optimized for Intel AVX2 (Advanced Vector Extensions).
 *
 * Author:	Eric Biggers
 * Year:	2014, 2015
 *
 * The author dedicates this file to the public domain.
 * You can do whatever you want with this file.
 */

#include <immintrin.h>

static inline bool
matchfinder_init_avx2(pos_t *data, size_t size)
{
	__m256i v, *p;
	size_t n;

	if (size % sizeof(__m256i) * 4)
		return false;

	if (sizeof(pos_t) == 2)
		v = _mm256_set1_epi16((u16)MATCHFINDER_NULL);
	else if (sizeof(pos_t) == 4)
		v = _mm256_set1_epi32((u32)MATCHFINDER_NULL);
	else
		return false;

	p = (__m256i *)data;
	n = size / (sizeof(__m256i) * 4);
	do {
		p[0] = v;
		p[1] = v;
		p[2] = v;
		p[3] = v;
		p += 4;
	} while (--n);
	return true;
}
