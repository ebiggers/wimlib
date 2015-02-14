#ifndef _WIMLIB_SOLID_H
#define _WIMLIB_SOLID_H

struct list_head;

extern int
sort_stream_list_for_solid_compression(struct list_head *stream_list);

#endif /* _WIMLIB_SOLID_H */
