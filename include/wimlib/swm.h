#ifndef _WIMLIB_SWM_H
#define _WIMLIB_SWM_H

#include "wimlib/types.h"

extern int
verify_swm_set(WIMStruct *wim,
	       WIMStruct **additional_swms, unsigned num_additional_swms);

extern void
merge_lookup_tables(WIMStruct *wim,
		    WIMStruct **additional_swms, unsigned num_additional_swms);

extern void
unmerge_lookup_table(WIMStruct *wim);

#endif
