/*
 * ntfs_fragreport.c
 *
 * Use NTFS-3G to report on the fragmentation of an NTFS volume.
 *
 * Compile and run with something like:
 *
 *	gcc ntfs_fragreport.c -o ntfs_fragreport -O2 -Wall -lntfs-3g
 *	./ntfs_fragreport /dev/sda2
 */

#include <errno.h>
#include <inttypes.h>
#include <stdarg.h>
#include <stdbool.h>
#include <stdio.h>
#include <stdlib.h>
#include <time.h>

#include <ntfs-3g/attrib.h>
#include <ntfs-3g/dir.h>
#include <ntfs-3g/volume.h>

#define VERBOSE 0
#define ARRAY_LEN(A)	(sizeof(A) / sizeof((A)[0]))

static void __attribute__((noreturn))
fatal_error(const char *format, ...)
{
	va_list va;

	va_start(va, format);
	fprintf(stderr, "ERROR: ");
	vfprintf(stderr, format, va);
	fprintf(stderr, ": %m\n");
	va_end(va);

	exit(1);
}

struct inode_details {
	u64 ino;
	u64 num_extents;
};

struct frag_stats {
	u64 num_files;
	u64 num_resident_files;
	u64 num_nonresident_sparse_files;
	u64 num_nonresident_nonsparse_files;
	u64 num_fragmented_files;
	u64 num_extents;
	struct inode_details most_fragmented_files[100];
};

static struct frag_stats dir_frag_stats;
static struct frag_stats nondir_frag_stats;

static void
print_file_details(ntfs_inode *ni, u64 num_extents, size_t i)
{
	bool first = true;
	ntfs_attr_search_ctx *actx;

	printf("\t\t%zu. Inode %"PRIu64" (", i + 1, ni->mft_no);

	actx = ntfs_attr_get_search_ctx(ni, NULL);
	if (!actx) {
		fatal_error("getting attribute search context for "
			    "inode %"PRIu64, ni->mft_no);
	}

	while (!ntfs_attr_lookup(AT_FILE_NAME, NULL, 0, 0, 0, NULL, 0, actx)) {
                const FILE_NAME_ATTR *fn = (const FILE_NAME_ATTR *)
			((u8 *)actx->attr +
			 le16_to_cpu(actx->attr->value_offset));
		char *filename = NULL;

		if (fn->file_name_type == FILE_NAME_DOS)
			continue;

		if (ntfs_ucstombs(fn->file_name, fn->file_name_length,
				  &filename, 0) < 0) {
			fatal_error("translating filename for inode "
				    "%"PRIu64, ni->mft_no);
		}

		if (!first)
			printf(", ");
		printf("\"%s\"", filename);
		first = false;
		free(filename);
	}
	ntfs_attr_put_search_ctx(actx);

	printf("): %"PRIu64" extents, size %"PRIi64"\n",
	      num_extents, ni->data_size);
}

static void
print_frag_stats(const struct frag_stats *stats, ntfs_volume *vol)
{
	double extents_per_file;

	printf("\tFiles: %"PRIu64"\n", stats->num_files);

	printf("\tResident files: %"PRIu64"\n", stats->num_resident_files);

	printf("\tNonresident, sparse files: %"PRIu64"\n",
	       stats->num_nonresident_sparse_files);

	printf("\tNonresident, nonsparse files: %"PRIu64"\n",
	       stats->num_nonresident_nonsparse_files);
	printf("\t\tFragmented files: %"PRIu64" "
	       "(%.3f%%)\n", stats->num_fragmented_files,
	       100 * stats->num_fragmented_files /
			(double)stats->num_nonresident_nonsparse_files);
	extents_per_file = stats->num_extents /
			   (double)stats->num_nonresident_nonsparse_files;
	printf("\t\tExtents per file: %.5f (%.3f%% fragmented)\n",
	       extents_per_file, 100 * (extents_per_file - 1));

	if (stats->num_fragmented_files != 0) {
		printf("\tMost fragmented files:\n");
		for (size_t i = 0; i < ARRAY_LEN(stats->most_fragmented_files);
		     i++)
		{
			const struct inode_details *file =
					&stats->most_fragmented_files[i];
			if (file->ino != 0) {
				ntfs_inode *ni = ntfs_inode_open(vol, file->ino);
				if (!ni) {
					fatal_error("opening inode %"PRIu64,
						    file->ino);
				}
				print_file_details(ni, file->num_extents, i);
				ntfs_inode_close(ni);
			}
		}
	}
}

static void
insert_fragmented_file(struct frag_stats *stats, const ntfs_inode *ni,
		       u64 num_extents)
{
	const size_t n = ARRAY_LEN(stats->most_fragmented_files);
	struct inode_details *files = stats->most_fragmented_files;
	size_t i;
	struct inode_details next = {
		.ino = ni->mft_no,
		.num_extents = num_extents,
	};

	if (num_extents <= files[n - 1].num_extents)
		return;

	for (i = 0; i < n && num_extents <= files[i].num_extents; i++)
		;

	for (; i < n; i++) {
		struct inode_details tmp = files[i];
		files[i] = next;
		next = tmp;
	}
}

static void
process_file(ntfs_inode *ni, ATTR_TYPES type, ntfschar *name, u32 name_len)
{
	ntfs_attr *na;
	runlist *rl;
	u64 num_extents = 0;
	struct frag_stats *stats;

	na = ntfs_attr_open(ni, type, name, name_len);
	if (!na) {
		if (errno == ENOENT)
			return;
		fatal_error("opening attribute of inode %"PRIu64, ni->mft_no);
	}

	if (ni->mrec->flags & MFT_RECORD_IS_DIRECTORY)
		stats = &dir_frag_stats;
	else
		stats = &nondir_frag_stats;

	stats->num_files++;

	if (NAttrNonResident(na)) {
		s64 allocated_size = 0;
		bool sparse = false;

		if (ntfs_attr_map_whole_runlist(na) != 0)
			fatal_error("mapping runlist of attribute for "
				    "inode %"PRIu64, ni->mft_no);

		for (rl = na->rl; rl->length; rl++) {
			if (rl->lcn == LCN_HOLE) {
				sparse = true;
			} else if (rl->lcn < 0) {
				fatal_error("unexpected LCN: %"PRIi64,
					    (s64)rl->lcn);
			} else {
				num_extents++;
				allocated_size += rl->length <<
						  ni->vol->cluster_size_bits;
			}
		}
		if (sparse || num_extents == 0) {
			stats->num_nonresident_sparse_files++;
		} else {
			stats->num_nonresident_nonsparse_files++;

			if (allocated_size != na->allocated_size) {
				fatal_error("allocated size inconsistency for "
					    "inode %"PRIu64, ni->mft_no);
			}
			if (num_extents > 1) {
				stats->num_fragmented_files++;
				insert_fragmented_file(stats, ni, num_extents);
			}
			stats->num_extents += num_extents;
		}
	} else {
		stats->num_resident_files++;
	}

#if VERBOSE
	printf("%"PRIu64"\t", ni->mft_no);
	printf("%sdirectory\t", (stats == &nondir_frag_stats ? "non" : ""));
	printf("%"PRIi64"\t", na->data_size);
	printf("%"PRIi64"\t", na->allocated_size);
	printf("%s\t", NAttrNonResident(na) ? "nonresident" : "resident");
	printf("%"PRIu64"\t", num_extents);
	printf("\n");
#endif

	ntfs_attr_close(na);
}

int main(int argc, char **argv)
{
	ntfs_volume *vol;
	u64 num_mft_records;

	if (argc != 2) {
		fprintf(stderr, "Usage: %s VOLUME\n", argv[0]);
		return 1;
	}

	vol = ntfs_mount(argv[1], NTFS_MNT_RDONLY);
	if (!vol)
		fatal_error("mounting NTFS volume");

#if VERBOSE
	printf("INO\tTYPE\tDATA_SIZE\tALLOCATED_SIZE\tRESIDENT\tNUM_EXTENTS\n");
#endif

	num_mft_records = vol->mft_na->data_size >> vol->mft_record_size_bits;
	for (u64 ino = FILE_first_user; ino < num_mft_records; ino++) {
		ntfs_inode *ni;

		ni = ntfs_inode_open(vol, ino);
		if (!ni) {
			if (errno == ENOENT)
				continue;
			fatal_error("opening inode %"PRIu64, ino);
		}

		if (ni->nr_extents >= 0) {
			if (ni->mrec->flags & MFT_RECORD_IS_DIRECTORY) {
				process_file(ni, AT_INDEX_ALLOCATION,
					     NTFS_INDEX_I30, 4);
			} else {
				process_file(ni, AT_DATA, AT_UNNAMED, 0);
			}
		}

		ntfs_inode_close(ni);
	}

	printf("\n");
	printf("Directory stats:\n");
	print_frag_stats(&dir_frag_stats, vol);

	printf("\n");
	printf("Nondirectory stats:\n");
	print_frag_stats(&nondir_frag_stats, vol);

	ntfs_umount(vol, 0);

	return 0;
}
