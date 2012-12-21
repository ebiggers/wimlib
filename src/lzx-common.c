#include "lzx.h"

#ifdef USE_LZX_EXTRA_BITS_ARRAY
/* LZX uses what it calls 'position slots' to represent match offsets.
 * What this means is that a small 'position slot' number and a small
 * offset from that slot are encoded instead of one large offset for
 * every match.
 * - lzx_position_base is an index to the position slot bases
 * - lzx_extra_bits states how many bits of offset-from-base data is needed.
 */
const u8 lzx_extra_bits[LZX_NUM_POSITION_SLOTS] = {
	0 , 0 , 0 , 0 , 1 ,
	1 , 2 , 2 , 3 , 3 ,
	4 , 4 , 5 , 5 , 6 ,
	6 , 7 , 7 , 8 , 8 ,
	9 , 9 , 10, 10, 11,
	11, 12, 12, 13, 13,
	/*14, 14, 15, 15, 16,*/
	/*16, 17, 17, 17, 17,*/
	/*17, 17, 17, 17, 17,*/
	/*17, 17, 17, 17, 17,*/
	/*17*/
};
#endif

const u32 lzx_position_base[LZX_NUM_POSITION_SLOTS] = {
	0      , 1      , 2      , 3      , 4      ,
	6      , 8      , 12     , 16     , 24     ,
	32     , 48     , 64     , 96     , 128    ,
	192    , 256    , 384    , 512    , 768    ,
	1024   , 1536   , 2048   , 3072   , 4096   ,
	6144   , 8192   , 12288  , 16384  , 24576  ,
	/*32768  , 49152  , 65536  , 98304  , 131072 ,*/
	/*196608 , 262144 , 393216 , 524288 , 655360 ,*/
	/*786432 , 917504 , 1048576, 1179648, 1310720,*/
	/*1441792, 1572864, 1703936, 1835008, 1966080,*/
	/*2097152*/
};

