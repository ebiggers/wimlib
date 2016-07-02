#define _In_
#define __in
#define __out
#define __in_opt
#define __out_opt
#define __inout
#define __out_bcount(x)
#define __in_bcount(x)
#define __out_bcount_opt(x)
#define _Out_opt_
#define _Out_
#define _Out_writes_bytes_to_(x, y)
#define _Inout_
#define _In_opt_
#define _Out_writes_bytes_opt_(x)
#define _Out_writes_bytes_(x)
#define __typefix(x)
#define __deref_out_ecount_z(x)
#define _In_reads_bytes_(x)

#include <stdio.h>
#include <windows.h>
#include "wimgapi.h"

#define WIM_FLAG_SOLID 0x20000000 /* undocumented */
