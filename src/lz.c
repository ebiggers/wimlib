/*
 * lz.c
 *
 * This file provides the code to analyze a buffer of uncompressed data for
 * matches, as per the LZ77 algorithm.  It uses a hash table to accelerate the
 * process.  This is based on code from zlib (v. 1.2.5).
 */

/*
 * Copyright (C) 2012 Eric Biggers
 * Copyright (C) 1995-2010 Jean-loup Gailly and Mark Adler
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

#include "comp.h"
#include <string.h>

#define LZ_MIN_MATCH 3

#define HASH_BITS	15
#define HASH_SIZE	(1 << HASH_BITS)
#define HASH_MASK	(HASH_SIZE - 1)

#if LZ_MIN_MATCH == 2
#	define HASH_SHIFT	8
#elif LZ_MIN_MATCH == 3
#	define HASH_SHIFT	5
#else
#error "Invalid LZ_MIN_MATCH"
#endif

/* Hash function, based on code from zlib.  This function will update and return
 * the hash value @hash for the string ending on the additional input character
 * @c.  This function must be called for each consecutive character, because it
 * uses a running hash value rather than computing it separately for each
 * 3-character string.
 *
 * The AND operation guarantees that only 3 characters will affect the hash
 * value, so every identical 3-character string will have the same hash value.
 */
static inline uint update_hash(uint hash, u8 c)
{
	return ((hash << HASH_SHIFT) ^ c) & HASH_MASK;
}


/* Insert a 3-character string at position @str_pos in @window and with hash
 * code @hash into the hash table described by @hash_tab and @prev_tab.  Based
 * on code from zlib.
 *
 * The hash table uses chains (linked lists) for the hash buckets, but there are
 * no real pointers involved.  Indexing `hash_tab' by hash value gives the index
 * within the window of the last string in the hash bucket.  To find the index
 * of the previous string in the hash chain, the `prev_tab' array is indexed by
 * the string index.  `prev_tab' can be indexed repeatedly by the string index
 * to walk through the hash chain, until the special index `0' is reached,
 * indicating the end of the hash chain.
 */
static inline uint insert_string(u16 hash_tab[], u16 prev_tab[],
				 const u8 window[], uint str_pos, uint hash)
{
	hash = update_hash(hash, window[str_pos + LZ_MIN_MATCH - 1]);
	prev_tab[str_pos] = hash_tab[hash];
	hash_tab[hash] = str_pos;
	return hash;
}


/*
 * Returns the longest match for a given input position.
 *
 * @window:		The window of uncompressed data.
 * @bytes_remaining:	The number of bytes remaining in the window.
 * @strstart:		The index of the start of the string in the window that
 * 				we are trying to find a match for.
 * @prev_tab:		The array of prev pointers for the hash table.
 * @cur_match:		The index of the head of the hash chain for matches
 * 				having the hash value of the string beginning
 * 				at index @strstart.
 * @prev_len:		The length of the match that was found for the string
 * 				beginning at (@strstart - 1).
 * @match_start_ret:	A location into which the index of the start of the
 * 				match will be returned.
 * @params:		Parameters that affect how long the search will proceed
 * 				before going with the best that has been found
 * 				so far.
 *
 * Returns the length of the match that was found.
 */
static uint longest_match(const u8 window[], uint bytes_remaining,
			  uint strstart, const u16 prev_tab[],
			  uint cur_match, uint prev_len,
			  uint *match_start_ret,
			  const struct lz_params *params)
{
	uint chain_len = params->max_chain_len;

	const u8 *scan = window + strstart;
	const u8 *match;
	uint len;
	uint best_len = prev_len;
	uint match_start = cur_match;

	uint nice_match = min(params->nice_match, bytes_remaining);

	const u8 *strend = scan + min(params->max_match, bytes_remaining);

	u8 scan_end1 = scan[best_len - 1];
	u8 scan_end = scan[best_len];


	/* Do not waste too much time if we already have a good match: */
	if (best_len >= params->good_match)
		chain_len >>= 2;

	do {
		match = &window[cur_match];

		/* Skip to next match if the match length cannot increase or if
		 * the match length is less than 2.  Note that the checks below
		 * for insufficient lookahead only occur occasionally for
		 * performance reasons.  Therefore uninitialized memory will be
		 * accessed, and conditional jumps will be made that depend on
		 * those values.  However the length of the match is limited to
		 * the lookahead, so the output of deflate is not affected by
		 * the uninitialized values.
		 */

		if (match[best_len] != scan_end
		    || match[best_len - 1] != scan_end1
		    || *match != *scan
		    || *++match != scan[1])
			continue;
		scan++;

	#if 0
		do {
		} while (scan < strend && *++match == *++scan);
	#else

		do {
		} while (
			 *++match == *++scan && *++match == *++scan &&
			 *++match == *++scan && *++match == *++scan &&
			 *++match == *++scan && *++match == *++scan &&
			 *++match == *++scan && *++match == *++scan &&
			 scan < strend);
	#endif
		len = match - &window[cur_match];

		scan = &window[strstart];

		if (len > best_len) {
			match_start = cur_match;
			best_len = len;
			if (len >= nice_match)
				break;
			scan_end1  = scan[best_len - 1];
			scan_end   = scan[best_len];
		}
	} while (--chain_len != 0 && (cur_match = prev_tab[cur_match]) != 0);
	*match_start_ret = match_start;
	return min(min(best_len, bytes_remaining), params->max_match);
}



/*
 * Determines the sequence of matches and literals that a block of data will be
 * compressed to.
 *
 * @uncompressed_data:	The data that is to be compressed.
 * @uncompressed_len:	The length of @uncompressed_data, in bytes.
 * @match_tab:		An array for the intermediate representation of matches.
 * @record_match:	A function that will be called to produce the
 * 				intermediate representation of a match, given
 * 				the offset and length.  This function should also
 * 				update the appropriate symbol frequency counts
 * 				so that any needed Huffman codes can be made
 * 				later.
 * @record_literal:	A function that will be called to produce the
 * 				intermediate representation of a literal, given
 * 				the character of the literal.  This function
 * 				should also update the appropriate symbol
 * 				frequency counts so that any needed Huffman
 * 				codes can be made later.
 * @record_match_arg_1:
 * @record_match_arg_2:	Extra arguments to be passed to @record_match.
 * @record_literal_arg:	Extra arguments to be passed to @record_literal.
 * @params:		Structure that contains parameters that affect how the
 * 				analysis proceeds (mainly how good the matches
 * 				have to be).
 *
 * Returns the total number of matches and literal bytes that were found; this
 * is the number of slots in @match_tab that have been filled with the
 * intermediate representation of a match or literal byte.
 */
uint lz_analyze_block(const u8 uncompressed_data[], uint uncompressed_len,
		      u32 match_tab[], lz_record_match_t record_match,
		      lz_record_literal_t record_literal, void *record_match_arg1,
		      void *record_match_arg2, void *record_literal_arg,
		      const struct lz_params *params)
{
	uint cur_match_pos = 0;
	uint cur_input_pos = 0;
	uint hash          = 0;
	uint hash_head     = 0;
	uint prev_len      = params->min_match - 1;
	uint prev_start;
	uint match_len     = params->min_match - 1;
	uint match_start   = 0;
	bool match_available = false;
	u16 hash_tab[HASH_SIZE];
	u32 match;
	u16 prev_tab[uncompressed_len];

	ZERO_ARRAY(hash_tab);
	ZERO_ARRAY(prev_tab);

	do {
		/* If there are at least 3 characters remaining in the input,
		 * insert the 3-character string beginning at
		 * uncompressed_data[cur_input_pos] into the hash table.
		 *
		 * hash_head is set to the index of the previous string in the
		 * hash bucket, or 0 if there is no such string */
		if (uncompressed_len - cur_input_pos >= params->min_match) {
			hash = insert_string(hash_tab, prev_tab,
					     uncompressed_data,
					     cur_input_pos, hash);
			hash_head = prev_tab[cur_input_pos];
		} else {
			hash_head = 0;
		}


		/* Find the longest match, discarding those <= prev_len. */
		prev_len = match_len;
		prev_start = match_start;
		match_len = params->min_match - 1;

		if (hash_head != 0 && prev_len < params->max_lazy_match) {
			/* To simplify the code, we prevent matches with the
			 * string of window index 0 (in particular we have to
			 * avoid a match of the string with itself at the start
			 * of the input file).  */
			match_len = longest_match(uncompressed_data,
						  uncompressed_len - cur_input_pos,
						  cur_input_pos, prev_tab,
						  hash_head, prev_len,
						  &match_start, params);

			if (match_len == params->min_match &&
			     cur_input_pos - match_start > params->too_far)
				match_len = params->min_match - 1;
		}

		/* If there was a match at the previous step and the current
		 * match is not better, output the previous match:
		 */
		if (prev_len >= params->min_match && match_len <= prev_len) {

			/* Do not insert strings in hash table beyond this. */
			uint max_insert = uncompressed_len - params->min_match;

			/*DEBUG("Recording match (pos = %u, offset = %u, len = %u)\n",*/
					/*cur_input_pos - 1, */
					/*cur_input_pos - 1 - prev_start,*/
					/*prev_len);*/

			match = (*record_match)(cur_input_pos - 1 - prev_start,
						prev_len,
						record_match_arg1,
						record_match_arg2);

			match_tab[cur_match_pos++] = match;

			/* Insert in hash table all strings up to the end of the match.
			 * strstart-1 and strstart are already inserted. If there is not
			 * enough lookahead, the last two strings are not inserted in
			 * the hash table.
			 */
#if LZ_MIN_MATCH == 2
			if (prev_len >= 3)
#endif
			{
				prev_len -= 2;

				do {
					if (++cur_input_pos <= max_insert) {
						hash = insert_string(hash_tab, prev_tab,
								     uncompressed_data,
								     cur_input_pos,
								     hash);
					}
				} while (--prev_len != 0);
			}
			match_available = false;
			match_len = params->min_match - 1;
		} else if (match_available) {
			/* If there was no match at the previous position, output a
			 * single literal. If there was a match but the current match
			 * is longer, truncate the previous match to a single literal.
			 */

			/*DEBUG("Recording litrl (pos = %u, value = %u)\n",*/
					/*cur_input_pos - 1, */
					/*uncompressed_data[cur_input_pos - 1]);*/

			match = (*record_literal)(
					uncompressed_data[cur_input_pos - 1],
							record_literal_arg);
			match_tab[cur_match_pos++] = match;
		} else {
			/* There is no previous match to compare with, wait for
			 * the next step to decide.  */
			match_available = true;
		}
	} while (++cur_input_pos < uncompressed_len);

	if (match_available) {
		match = (*record_literal)(uncompressed_data[cur_input_pos - 1],
						record_literal_arg);
		match_tab[cur_match_pos++] = match;
	}
	return cur_match_pos;
}
