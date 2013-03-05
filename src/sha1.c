/*
 * sha1.c
 *
 * Parts of this file are based on public domain code written by Steve Reid.
 */

/*
 * Copyright (C) 2012, 2013 Biggers
 *
 * This file is part of wimlib, a library for working with WIM files.
 *
 * wimlib is free software; you can redistribute it and/or modify it under the
 * terms of the GNU General Public License as published by the Free
 * Software Foundation; either version 3 of the License, or (at your option)
 * any later version.
 *
 * wimlib is distributed in the hope that it will be useful, but WITHOUT ANY
 * WARRANTY; without even the implied warranty of MERCHANTABILITY or FITNESS FOR
 * A PARTICULAR PURPOSE. See the GNU General Public License for more
 * details.
 *
 * You should have received a copy of the GNU General Public License
 * along with wimlib; if not, see http://www.gnu.org/licenses/.
 */

#include "util.h"
#include "wimlib.h"
#include "sha1.h"
#include "endianness.h"
#include <string.h>

/* The SHA1 support in wimlib can use an external libcrypto (part of openssl) or
 * use a built-in SHA1 function.  The built-in functions are either based on
 * Steve Reid's public domain code, or based on Intel's SSSE3 SHA1 code.
 */

const u8 zero_hash[SHA1_HASH_SIZE] = {
	0, 0, 0, 0, 0,
	0, 0, 0, 0, 0,
	0, 0, 0, 0, 0,
	0, 0, 0, 0, 0,
};


#ifndef WITH_LIBCRYPTO

/*  Initialize new context */
void sha1_init(SHA_CTX* context)
{
	/* SHA1 initialization constants */
	context->state[0] = 0x67452301;
	context->state[1] = 0xEFCDAB89;
	context->state[2] = 0x98BADCFE;
	context->state[3] = 0x10325476;
	context->state[4] = 0xC3D2E1F0;
	context->count[0] = context->count[1] = 0;
}

#ifdef ENABLE_SSSE3_SHA1
extern void sha1_update_intel(int *hash, const char* input, size_t num_blocks);

void sha1_update(SHA_CTX *context, const u8 data[], size_t len)
{
	sha1_update_intel((int*)&context->state, data, len / 64);
	size_t j = (context->count[0] >> 3) & 63;
	if ((context->count[0] += len << 3) < (len << 3)) context->count[1]++;
	context->count[1] += (len >> 29);
}
#include <stdlib.h>
void ssse3_not_found()
{
	fprintf(stderr,
"Cannot calculate SHA1 message digest: CPU does not support SSSE3\n"
"instructions!  Recompile wimlib without the --enable-ssse3-sha1 flag\n"
"to use wimlib on this CPU.\n");
	abort();
}
#else /* ENABLE_SSSE3_SHA1 */

#define rol(value, bits) (((value) << (bits)) | ((value) >> (32 - (bits))))

/* blk0() and blk() perform the initial expand. */
/* I got the idea of expanding during the round function from SSLeay */
/* FIXME: can we do this in an endian-proof way? */
#ifdef WORDS_BIGENDIAN
#define blk0(i) block->l[i]
#else
#define blk0(i) (block->l[i] = (rol(block->l[i],24)&0xFF00FF00) \
    |(rol(block->l[i],8)&0x00FF00FF))
#endif
#define blk(i) (block->l[i&15] = rol(block->l[(i+13)&15]^block->l[(i+8)&15] \
    ^block->l[(i+2)&15]^block->l[i&15],1))

/* (R0+R1), R2, R3, R4 are the different operations used in SHA1 */
#define R0(v,w,x,y,z,i) z+=((w&(x^y))^y)+blk0(i)+0x5A827999+rol(v,5);w=rol(w,30);
#define R1(v,w,x,y,z,i) z+=((w&(x^y))^y)+blk(i)+0x5A827999+rol(v,5);w=rol(w,30);
#define R2(v,w,x,y,z,i) z+=(w^x^y)+blk(i)+0x6ED9EBA1+rol(v,5);w=rol(w,30);
#define R3(v,w,x,y,z,i) z+=(((w|x)&y)|(w&x))+blk(i)+0x8F1BBCDC+rol(v,5);w=rol(w,30);
#define R4(v,w,x,y,z,i) z+=(w^x^y)+blk(i)+0xCA62C1D6+rol(v,5);w=rol(w,30);

/* Hash a single 512-bit block. This is the core of the algorithm. */
static void sha1_transform(u32 state[5], const u8 buffer[64])
{
	u32 a, b, c, d, e;
	typedef union {
		u8 c[64];
		u32 l[16];
	} CHAR64LONG16;
	CHAR64LONG16* block;

	u8 workspace[64];
	block = (CHAR64LONG16*)workspace;
	memcpy(block, buffer, 64);

	/* Copy context->state[] to working vars */
	a = state[0];
	b = state[1];
	c = state[2];
	d = state[3];
	e = state[4];

	/* 4 rounds of 20 operations each. Loop unrolled. */
	R0(a,b,c,d,e, 0); R0(e,a,b,c,d, 1); R0(d,e,a,b,c, 2); R0(c,d,e,a,b, 3);
	R0(b,c,d,e,a, 4); R0(a,b,c,d,e, 5); R0(e,a,b,c,d, 6); R0(d,e,a,b,c, 7);
	R0(c,d,e,a,b, 8); R0(b,c,d,e,a, 9); R0(a,b,c,d,e,10); R0(e,a,b,c,d,11);
	R0(d,e,a,b,c,12); R0(c,d,e,a,b,13); R0(b,c,d,e,a,14); R0(a,b,c,d,e,15);
	R1(e,a,b,c,d,16); R1(d,e,a,b,c,17); R1(c,d,e,a,b,18); R1(b,c,d,e,a,19);
	R2(a,b,c,d,e,20); R2(e,a,b,c,d,21); R2(d,e,a,b,c,22); R2(c,d,e,a,b,23);
	R2(b,c,d,e,a,24); R2(a,b,c,d,e,25); R2(e,a,b,c,d,26); R2(d,e,a,b,c,27);
	R2(c,d,e,a,b,28); R2(b,c,d,e,a,29); R2(a,b,c,d,e,30); R2(e,a,b,c,d,31);
	R2(d,e,a,b,c,32); R2(c,d,e,a,b,33); R2(b,c,d,e,a,34); R2(a,b,c,d,e,35);
	R2(e,a,b,c,d,36); R2(d,e,a,b,c,37); R2(c,d,e,a,b,38); R2(b,c,d,e,a,39);
	R3(a,b,c,d,e,40); R3(e,a,b,c,d,41); R3(d,e,a,b,c,42); R3(c,d,e,a,b,43);
	R3(b,c,d,e,a,44); R3(a,b,c,d,e,45); R3(e,a,b,c,d,46); R3(d,e,a,b,c,47);
	R3(c,d,e,a,b,48); R3(b,c,d,e,a,49); R3(a,b,c,d,e,50); R3(e,a,b,c,d,51);
	R3(d,e,a,b,c,52); R3(c,d,e,a,b,53); R3(b,c,d,e,a,54); R3(a,b,c,d,e,55);
	R3(e,a,b,c,d,56); R3(d,e,a,b,c,57); R3(c,d,e,a,b,58); R3(b,c,d,e,a,59);
	R4(a,b,c,d,e,60); R4(e,a,b,c,d,61); R4(d,e,a,b,c,62); R4(c,d,e,a,b,63);
	R4(b,c,d,e,a,64); R4(a,b,c,d,e,65); R4(e,a,b,c,d,66); R4(d,e,a,b,c,67);
	R4(c,d,e,a,b,68); R4(b,c,d,e,a,69); R4(a,b,c,d,e,70); R4(e,a,b,c,d,71);
	R4(d,e,a,b,c,72); R4(c,d,e,a,b,73); R4(b,c,d,e,a,74); R4(a,b,c,d,e,75);
	R4(e,a,b,c,d,76); R4(d,e,a,b,c,77); R4(c,d,e,a,b,78); R4(b,c,d,e,a,79);

	/* Add the working vars back into context.state[] */
	state[0] += a;
	state[1] += b;
	state[2] += c;
	state[3] += d;
	state[4] += e;
}

void sha1_update(SHA_CTX* context, const u8 data[], const size_t len)
{
	size_t i, j;

	j = (context->count[0] >> 3) & 63;
	if ((context->count[0] += len << 3) < (len << 3))
		context->count[1]++;
	context->count[1] += (len >> 29);
	if ((j + len) > 63) {
		i = 64 - j;
		memcpy(&context->buffer[j], data, i);
		sha1_transform(context->state, context->buffer);
		for ( ; i + 63 < len; i += 64)
			sha1_transform(context->state, data + i);
		j = 0;
	} else  {
		i = 0;
	}
	memcpy(&context->buffer[j], &data[i], len - i);
}

#endif /* !ENABLE_SSSE3_SHA1 */

/* Add padding and return the message digest. */
void sha1_final(u8 md[SHA1_HASH_SIZE], SHA_CTX* context)
{
	u32 i;
	u8  finalcount[8];

	for (i = 0; i < 8; i++) {
		finalcount[i] = (unsigned char)((context->count[(i >= 4 ? 0 : 1)]
					>> ((3-(i & 3)) * 8) ) & 255);  /* Endian independent */
	}
	sha1_update(context, (u8 *)"\200", 1);
	while ((context->count[0] & 504) != 448) {
		sha1_update(context, (u8 *)"\0", 1);
	}
	sha1_update(context, finalcount, 8);  /* Should cause a sha1_transform() */
	for (i = 0; i < SHA1_HASH_SIZE; i++) {
		md[i] = (u8)((context->state[i>>2] >> ((3-(i & 3)) * 8) ) & 255);
	}
}

void sha1_buffer(const u8 buffer[], size_t len, u8 md[SHA1_HASH_SIZE])
{
	SHA_CTX ctx;
	sha1_init(&ctx);
	sha1_update(&ctx, buffer, len);
	sha1_final(md, &ctx);
}

#endif /* !WITH_LIBCRYPTO */

static int sha1_stream(FILE *fp, u8 md[SHA1_HASH_SIZE])
{
	char buf[BUFFER_SIZE];
	size_t bytes_read;
	SHA_CTX ctx;
	sha1_init(&ctx);
	while (1) {
		bytes_read = fread(buf, 1, sizeof(buf), fp);
		sha1_update(&ctx, buf, bytes_read);
		if (bytes_read < sizeof(buf)) {
			if (ferror(fp))
				return WIMLIB_ERR_READ;
			break;
		}
	}
	sha1_final(md, &ctx);
	return 0;

}

/* Calculates the SHA1 message digest of a file.  @md must point to a buffer of
 * length 20 bytes into which the message digest is written. */
int sha1sum(const char *filename, u8 md[SHA1_HASH_SIZE])
{
	FILE *fp;
	int ret;

	fp = fopen(filename, "rb");
	if (!fp) {
		ERROR_WITH_ERRNO("Cannot open the file `%s' for reading",
				 filename);
		return WIMLIB_ERR_OPEN;
	}
	ret = sha1_stream(fp, md);
	if (ret != 0) {
		ERROR_WITH_ERRNO("Error calculating SHA1 message digest of "
				 "`%s'", filename);
	}
	fclose(fp);
	return ret;
}
