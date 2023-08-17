/*
 * win32_common.h - common header for Windows-specific files.  This always
 * should be included first.
 */

#ifndef _WIMLIB_WIN32_COMMON_H
#define _WIMLIB_WIN32_COMMON_H

#define _WINIOCTL_ // excludes winioctl.h
#include <ntstatus.h>
#include <windows.h>
#include <winternl.h>

#ifdef ERROR
#  undef ERROR
#endif
#include "wimlib/win32.h"

/* ntdll definitions */

#define FILE_OPENED 0x00000001

typedef struct _RTLP_CURDIR_REF {
	LONG RefCount;
	HANDLE Handle;
} RTLP_CURDIR_REF, *PRTLP_CURDIR_REF;

typedef struct _RTL_RELATIVE_NAME_U {
	UNICODE_STRING RelativeName;
	HANDLE ContainingDirectory;
	PRTLP_CURDIR_REF CurDirRef;
} RTL_RELATIVE_NAME_U, *PRTL_RELATIVE_NAME_U;

#ifndef FSCTL_SET_PERSISTENT_VOLUME_STATE
#define FSCTL_SET_PERSISTENT_VOLUME_STATE \
	CTL_CODE(FILE_DEVICE_FILE_SYSTEM, 142, METHOD_BUFFERED, FILE_ANY_ACCESS)

#define PERSISTENT_VOLUME_STATE_SHORT_NAME_CREATION_DISABLED 0x00000001

typedef struct _FILE_FS_PERSISTENT_VOLUME_INFORMATION {
	ULONG VolumeFlags;
	ULONG FlagMask;
	ULONG Version;
	ULONG Reserved;
} FILE_FS_PERSISTENT_VOLUME_INFORMATION, *PFILE_FS_PERSISTENT_VOLUME_INFORMATION;
#endif /* FSCTL_SET_PERSISTENT_VOLUME_STATE */

/* ntdll functions  */

NTSTATUS
NTAPI
NtReadFile(IN HANDLE FileHandle,
           IN HANDLE Event OPTIONAL,
           IN PIO_APC_ROUTINE ApcRoutine OPTIONAL,
           IN PVOID ApcContext OPTIONAL,
           OUT PIO_STATUS_BLOCK IoStatusBlock,
           OUT PVOID Buffer,
           IN ULONG Length,
           IN PLARGE_INTEGER ByteOffset OPTIONAL,
           IN PULONG Key OPTIONAL);

NTSTATUS
NTAPI
NtWriteFile(IN HANDLE FileHandle,
            IN HANDLE Event OPTIONAL,
            IN PIO_APC_ROUTINE ApcRoutine OPTIONAL,
            IN PVOID ApcContext OPTIONAL,
            OUT PIO_STATUS_BLOCK IoStatusBlock,
            IN PVOID Buffer,
            IN ULONG Length,
            IN PLARGE_INTEGER ByteOffset OPTIONAL,
            IN PULONG Key OPTIONAL);

NTSTATUS
NTAPI
NtQueryDirectoryFile(IN HANDLE FileHandle,
                     IN HANDLE EventHandle OPTIONAL,
                     IN PIO_APC_ROUTINE ApcRoutine OPTIONAL,
                     IN PVOID ApcContext OPTIONAL,
                     OUT PIO_STATUS_BLOCK IoStatusBlock,
                     OUT PVOID FileInformation,
                     IN ULONG Length,
                     IN FILE_INFORMATION_CLASS FileInformationClass,
                     IN BOOLEAN ReturnSingleEntry,
                     IN PUNICODE_STRING FileName OPTIONAL,
                     IN BOOLEAN RestartScan);

NTSTATUS
NTAPI
NtQuerySecurityObject(IN HANDLE Handle,
                      IN SECURITY_INFORMATION SecurityInformation,
                      OUT PSECURITY_DESCRIPTOR SecurityDescriptor,
                      IN ULONG Length,
                      OUT PULONG ResultLength);

NTSTATUS
NTAPI
NtSetSecurityObject(IN HANDLE Handle,
                    IN SECURITY_INFORMATION SecurityInformation,
                    IN PSECURITY_DESCRIPTOR SecurityDescriptor);

NTSTATUS
NTAPI
NtOpenSymbolicLinkObject(PHANDLE LinkHandle,
			 ACCESS_MASK DesiredAccess,
			 POBJECT_ATTRIBUTES ObjectAttributes);

NTSTATUS
NTAPI
NtQueryEaFile(IN HANDLE FileHandle,
	      OUT PIO_STATUS_BLOCK IoStatusBlock,
	      OUT PVOID Buffer,
	      IN ULONG Length,
	      IN BOOLEAN ReturnSingleEntry,
	      IN PVOID EaList OPTIONAL,
	      IN ULONG EaListLength,
	      IN PULONG EaIndex OPTIONAL,
	      IN BOOLEAN RestartScan);

NTSTATUS
NTAPI
NtSetEaFile(IN HANDLE FileHandle,
	    OUT PIO_STATUS_BLOCK IoStatusBlock,
	    OUT PVOID Buffer,
	    IN ULONG Length);

/* Dynamically loaded ntdll functions */

extern NTSTATUS (WINAPI *func_RtlDosPathNameToNtPathName_U_WithStatus)
		(IN PCWSTR DosName,
		 OUT PUNICODE_STRING NtName,
		 OUT PCWSTR *PartName,
		 OUT PRTL_RELATIVE_NAME_U RelativeName);

extern NTSTATUS (WINAPI *func_RtlCreateSystemVolumeInformationFolder)
			(PCUNICODE_STRING VolumeRootPath);

/* Other utility functions */

int
win32_path_to_nt_path(const wchar_t *win32_path, UNICODE_STRING *nt_path);

int
win32_get_drive_path(const wchar_t *file_path, wchar_t drive_path[7]);

bool
win32_try_to_attach_wof(const wchar_t *drive);

void __attribute__((cold))
win32_warning(DWORD err, const wchar_t *format, ...);

void __attribute__((cold))
win32_error(DWORD err, const wchar_t *format, ...);

void __attribute__((cold))
winnt_warning(NTSTATUS status, const wchar_t *format, ...);

void __attribute__((cold))
winnt_error(NTSTATUS status, const wchar_t *format, ...);

NTSTATUS
winnt_fsctl(HANDLE h, u32 code, const void *in, u32 in_size,
	    void *out, u32 out_size_avail, u32 *actual_out_size_ret);
#ifdef _MSC_VER
#pragma region win32_typedefs
#define DEVICE_TYPE DWORD

#define FILE_ANY_ACCESS			0
#define FILE_SPECIAL_ACCESS		(FILE_ANY_ACCESS)
#define FILE_READ_ACCESS		(0x0001) // file & pipe
#define FILE_WRITE_ACCESS		(0x0002) // file & pipe
#define METHOD_BUFFERED			0
#define METHOD_IN_DIRECT		1
#define METHOD_OUT_DIRECT		2
#define METHOD_NEITHER			3
#define FILE_DEVICE_BEEP		0x00000001
#define FILE_DEVICE_CD_ROM		0x00000002
#define FILE_DEVICE_CD_ROM_FILE_SYSTEM	0x00000003
#define FILE_DEVICE_CONTROLLER		0x00000004
#define FILE_DEVICE_DATALINK		0x00000005
#define FILE_DEVICE_DFS			0x00000006
#define FILE_DEVICE_DISK		0x00000007
#define FILE_DEVICE_DISK_FILE_SYSTEM	0x00000008
#define FILE_DEVICE_FILE_SYSTEM		0x00000009
#define FILE_DEVICE_INPORT_PORT		0x0000000a
#define FILE_DEVICE_KEYBOARD		0x0000000b
#define FILE_DEVICE_MAILSLOT		0x0000000c
#define FILE_DEVICE_MIDI_IN		0x0000000d
#define FILE_DEVICE_MIDI_OUT		0x0000000e
#define FILE_DEVICE_MOUSE		0x0000000f
#define FILE_DEVICE_MULTI_UNC_PROVIDER	0x00000010
#define FILE_DEVICE_NAMED_PIPE		0x00000011
#define FILE_DEVICE_NETWORK		0x00000012
#define FILE_DEVICE_NETWORK_BROWSER	0x00000013
#define FILE_DEVICE_NETWORK_FILE_SYSTEM 0x00000014
#define FILE_DEVICE_NULL		0x00000015
#define FILE_DEVICE_PARALLEL_PORT	0x00000016
#define FILE_DEVICE_PHYSICAL_NETCARD	0x00000017
#define FILE_DEVICE_PRINTER		0x00000018
#define FILE_DEVICE_SCANNER		0x00000019
#define FILE_DEVICE_SERIAL_MOUSE_PORT	0x0000001a
#define FILE_DEVICE_SERIAL_PORT		0x0000001b
#define FILE_DEVICE_SCREEN		0x0000001c
#define FILE_DEVICE_SOUND		0x0000001d
#define FILE_DEVICE_STREAMS		0x0000001e
#define FILE_DEVICE_TAPE		0x0000001f
#define FILE_DEVICE_TAPE_FILE_SYSTEM	0x00000020
#define FILE_DEVICE_TRANSPORT		0x00000021
#define FILE_DEVICE_UNKNOWN		0x00000022
#define FILE_DEVICE_VIDEO		0x00000023
#define FILE_DEVICE_VIRTUAL_DISK	0x00000024
#define FILE_DEVICE_WAVE_IN		0x00000025
#define FILE_DEVICE_WAVE_OUT		0x00000026
#define FILE_DEVICE_8042_PORT		0x00000027
#define FILE_DEVICE_NETWORK_REDIRECTOR	0x00000028
#define FILE_DEVICE_BATTERY		0x00000029
#define FILE_DEVICE_BUS_EXTENDER	0x0000002a
#define FILE_DEVICE_MODEM		0x0000002b
#define FILE_DEVICE_VDM			0x0000002c
#define FILE_DEVICE_MASS_STORAGE	0x0000002d
#define FILE_DEVICE_SMB			0x0000002e
#define FILE_DEVICE_KS			0x0000002f
#define FILE_DEVICE_CHANGER		0x00000030
#define FILE_DEVICE_SMARTCARD		0x00000031
#define FILE_DEVICE_ACPI		0x00000032
#define FILE_DEVICE_DVD			0x00000033
#define FILE_DEVICE_FULLSCREEN_VIDEO	0x00000034
#define FILE_DEVICE_DFS_FILE_SYSTEM	0x00000035
#define FILE_DEVICE_DFS_VOLUME		0x00000036
#define FILE_DEVICE_SERENUM		0x00000037
#define FILE_DEVICE_TERMSRV		0x00000038
#define FILE_DEVICE_KSEC		0x00000039
#define FILE_DEVICE_FIPS		0x0000003A
#define FILE_DEVICE_INFINIBAND		0x0000003B
#define FILE_DEVICE_VMBUS		0x0000003E
#define FILE_DEVICE_CRYPT_PROVIDER	0x0000003F
#define FILE_DEVICE_WPD			0x00000040
#define FILE_DEVICE_BLUETOOTH		0x00000041
#define FILE_DEVICE_MT_COMPOSITE	0x00000042
#define FILE_DEVICE_MT_TRANSPORT	0x00000043
#define FILE_DEVICE_BIOMETRIC		0x00000044
#define FILE_DEVICE_PMI			0x00000045
#define FILE_DEVICE_EHSTOR		0x00000046
#define FILE_DEVICE_DEVAPI		0x00000047
#define FILE_DEVICE_GPIO		0x00000048
#define FILE_DEVICE_USBEX		0x00000049
#define FILE_DEVICE_CONSOLE		0x00000050
#define FILE_DEVICE_NFP			0x00000051
#define FILE_DEVICE_SYSENV		0x00000052
#define FILE_DEVICE_VIRTUAL_BLOCK	0x00000053
#define FILE_DEVICE_POINT_OF_SERVICE	0x00000054
#define FILE_DEVICE_STORAGE_REPLICATION 0x00000055
#define FILE_DEVICE_TRUST_ENV		0x00000056
#define FILE_DEVICE_UCM			0x00000057
#define FILE_DEVICE_UCMTCPCI		0x00000058
#define FILE_DEVICE_PERSISTENT_MEMORY	0x00000059
#define FILE_DEVICE_NVDIMM		0x0000005a
#define FILE_DEVICE_HOLOGRAPHIC		0x0000005b
#define FILE_DEVICE_SDFXHCI		0x0000005c
#define FILE_DEVICE_UCMUCSI		0x0000005d
#define FILE_DEVICE_PRM			0x0000005e
#define FILE_DEVICE_EVENT_COLLECTOR	0x0000005f
#define FILE_DEVICE_USB4		0x00000060
#define FILE_DEVICE_SOUNDWIRE		0x00000061
#define CTL_CODE(DeviceType, Function, Method, Access)                         \
	(((DeviceType) << 16) | ((Access) << 14) | ((Function) << 2) | (Method))
#define FSCTL_REQUEST_OPLOCK_LEVEL_1                                           \
	CTL_CODE(FILE_DEVICE_FILE_SYSTEM, 0, METHOD_BUFFERED, FILE_ANY_ACCESS)
#define FSCTL_REQUEST_OPLOCK_LEVEL_2                                           \
	CTL_CODE(FILE_DEVICE_FILE_SYSTEM, 1, METHOD_BUFFERED, FILE_ANY_ACCESS)
#define FSCTL_REQUEST_BATCH_OPLOCK                                             \
	CTL_CODE(FILE_DEVICE_FILE_SYSTEM, 2, METHOD_BUFFERED, FILE_ANY_ACCESS)
#define FSCTL_OPLOCK_BREAK_ACKNOWLEDGE                                         \
	CTL_CODE(FILE_DEVICE_FILE_SYSTEM, 3, METHOD_BUFFERED, FILE_ANY_ACCESS)
#define FSCTL_OPBATCH_ACK_CLOSE_PENDING                                        \
	CTL_CODE(FILE_DEVICE_FILE_SYSTEM, 4, METHOD_BUFFERED, FILE_ANY_ACCESS)
#define FSCTL_OPLOCK_BREAK_NOTIFY                                              \
	CTL_CODE(FILE_DEVICE_FILE_SYSTEM, 5, METHOD_BUFFERED, FILE_ANY_ACCESS)
#define FSCTL_LOCK_VOLUME                                                      \
	CTL_CODE(FILE_DEVICE_FILE_SYSTEM, 6, METHOD_BUFFERED, FILE_ANY_ACCESS)
#define FSCTL_UNLOCK_VOLUME                                                    \
	CTL_CODE(FILE_DEVICE_FILE_SYSTEM, 7, METHOD_BUFFERED, FILE_ANY_ACCESS)
#define FSCTL_DISMOUNT_VOLUME                                                  \
	CTL_CODE(FILE_DEVICE_FILE_SYSTEM, 8, METHOD_BUFFERED, FILE_ANY_ACCESS)
// decommissioned fsctl value                                              9
#define FSCTL_IS_VOLUME_MOUNTED                                                \
	CTL_CODE(FILE_DEVICE_FILE_SYSTEM, 10, METHOD_BUFFERED, FILE_ANY_ACCESS)
#define FSCTL_IS_PATHNAME_VALID                                                \
	CTL_CODE(FILE_DEVICE_FILE_SYSTEM, 11, METHOD_BUFFERED,                 \
		 FILE_ANY_ACCESS) // PATHNAME_BUFFER,
#define FSCTL_MARK_VOLUME_DIRTY                                                \
	CTL_CODE(FILE_DEVICE_FILE_SYSTEM, 12, METHOD_BUFFERED, FILE_ANY_ACCESS)
// decommissioned fsctl value                                             13
#define FSCTL_QUERY_RETRIEVAL_POINTERS                                         \
	CTL_CODE(FILE_DEVICE_FILE_SYSTEM, 14, METHOD_NEITHER, FILE_ANY_ACCESS)
#define FSCTL_GET_COMPRESSION                                                  \
	CTL_CODE(FILE_DEVICE_FILE_SYSTEM, 15, METHOD_BUFFERED, FILE_ANY_ACCESS)
#define FSCTL_SET_COMPRESSION                                                  \
	CTL_CODE(FILE_DEVICE_FILE_SYSTEM, 16, METHOD_BUFFERED,                 \
		 FILE_READ_DATA | FILE_WRITE_DATA)
// decommissioned fsctl value                                             17
// decommissioned fsctl value                                             18
#define FSCTL_SET_BOOTLOADER_ACCESSED                                          \
	CTL_CODE(FILE_DEVICE_FILE_SYSTEM, 19, METHOD_NEITHER, FILE_ANY_ACCESS)
#define FSCTL_MARK_AS_SYSTEM_HIVE FSCTL_SET_BOOTLOADER_ACCESSED
#define FSCTL_OPLOCK_BREAK_ACK_NO_2                                            \
	CTL_CODE(FILE_DEVICE_FILE_SYSTEM, 20, METHOD_BUFFERED, FILE_ANY_ACCESS)
#define FSCTL_INVALIDATE_VOLUMES                                               \
	CTL_CODE(FILE_DEVICE_FILE_SYSTEM, 21, METHOD_BUFFERED, FILE_ANY_ACCESS)
#define FSCTL_QUERY_FAT_BPB                                                    \
	CTL_CODE(FILE_DEVICE_FILE_SYSTEM, 22, METHOD_BUFFERED,                 \
		 FILE_ANY_ACCESS) // FSCTL_QUERY_FAT_BPB_BUFFER
#define FSCTL_REQUEST_FILTER_OPLOCK                                            \
	CTL_CODE(FILE_DEVICE_FILE_SYSTEM, 23, METHOD_BUFFERED, FILE_ANY_ACCESS)
#define FSCTL_FILESYSTEM_GET_STATISTICS                                        \
	CTL_CODE(FILE_DEVICE_FILE_SYSTEM, 24, METHOD_BUFFERED,                 \
		 FILE_ANY_ACCESS) // FILESYSTEM_STATISTICS

#if (_WIN32_WINNT >= _WIN32_WINNT_NT4)
#define FSCTL_GET_NTFS_VOLUME_DATA                                             \
	CTL_CODE(FILE_DEVICE_FILE_SYSTEM, 25, METHOD_BUFFERED,                 \
		 FILE_ANY_ACCESS) // NTFS_VOLUME_DATA_BUFFER
#define FSCTL_GET_NTFS_FILE_RECORD                                             \
	CTL_CODE(FILE_DEVICE_FILE_SYSTEM, 26, METHOD_BUFFERED,                 \
		 FILE_ANY_ACCESS) // NTFS_FILE_RECORD_INPUT_BUFFER,
				  // NTFS_FILE_RECORD_OUTPUT_BUFFER
#define FSCTL_GET_VOLUME_BITMAP                                                \
	CTL_CODE(FILE_DEVICE_FILE_SYSTEM, 27, METHOD_NEITHER,                  \
		 FILE_ANY_ACCESS) // STARTING_LCN_INPUT_BUFFER,
				  // VOLUME_BITMAP_BUFFER
#define FSCTL_GET_RETRIEVAL_POINTERS                                           \
	CTL_CODE(FILE_DEVICE_FILE_SYSTEM, 28, METHOD_NEITHER,                  \
		 FILE_ANY_ACCESS) // STARTING_VCN_INPUT_BUFFER,
				  // RETRIEVAL_POINTERS_BUFFER
#define FSCTL_MOVE_FILE                                                        \
	CTL_CODE(FILE_DEVICE_FILE_SYSTEM, 29, METHOD_BUFFERED,                 \
		 FILE_SPECIAL_ACCESS) // MOVE_FILE_DATA,
#define FSCTL_IS_VOLUME_DIRTY                                                  \
	CTL_CODE(FILE_DEVICE_FILE_SYSTEM, 30, METHOD_BUFFERED, FILE_ANY_ACCESS)
// decommissioned fsctl value                                             31
#define FSCTL_ALLOW_EXTENDED_DASD_IO                                           \
	CTL_CODE(FILE_DEVICE_FILE_SYSTEM, 32, METHOD_NEITHER, FILE_ANY_ACCESS)
#endif /* _WIN32_WINNT >= _WIN32_WINNT_NT4 */

#if (_WIN32_WINNT >= _WIN32_WINNT_WIN2K)
// decommissioned fsctl value                                             33
// decommissioned fsctl value                                             34
#define FSCTL_FIND_FILES_BY_SID                                                \
	CTL_CODE(FILE_DEVICE_FILE_SYSTEM, 35, METHOD_NEITHER, FILE_ANY_ACCESS)
// decommissioned fsctl value                                             36
// decommissioned fsctl value                                             37
#define FSCTL_SET_OBJECT_ID                                                    \
	CTL_CODE(FILE_DEVICE_FILE_SYSTEM, 38, METHOD_BUFFERED,                 \
		 FILE_SPECIAL_ACCESS) // FILE_OBJECTID_BUFFER
#define FSCTL_GET_OBJECT_ID                                                    \
	CTL_CODE(FILE_DEVICE_FILE_SYSTEM, 39, METHOD_BUFFERED,                 \
		 FILE_ANY_ACCESS) // FILE_OBJECTID_BUFFER
#define FSCTL_DELETE_OBJECT_ID                                                 \
	CTL_CODE(FILE_DEVICE_FILE_SYSTEM, 40, METHOD_BUFFERED,                 \
		 FILE_SPECIAL_ACCESS)
#define FSCTL_SET_REPARSE_POINT                                                \
	CTL_CODE(FILE_DEVICE_FILE_SYSTEM, 41, METHOD_BUFFERED,                 \
		 FILE_SPECIAL_ACCESS) // REPARSE_DATA_BUFFER,
#define FSCTL_GET_REPARSE_POINT                                                \
	CTL_CODE(FILE_DEVICE_FILE_SYSTEM, 42, METHOD_BUFFERED,                 \
		 FILE_ANY_ACCESS) // REPARSE_DATA_BUFFER
#define FSCTL_DELETE_REPARSE_POINT                                             \
	CTL_CODE(FILE_DEVICE_FILE_SYSTEM, 43, METHOD_BUFFERED,                 \
		 FILE_SPECIAL_ACCESS) // REPARSE_DATA_BUFFER,
#define FSCTL_ENUM_USN_DATA                                                    \
	CTL_CODE(FILE_DEVICE_FILE_SYSTEM, 44, METHOD_NEITHER,                  \
		 FILE_ANY_ACCESS) // MFT_ENUM_DATA,
#define FSCTL_SECURITY_ID_CHECK                                                \
	CTL_CODE(FILE_DEVICE_FILE_SYSTEM, 45, METHOD_NEITHER,                  \
		 FILE_READ_DATA) // BULK_SECURITY_TEST_DATA,
#define FSCTL_READ_USN_JOURNAL                                                 \
	CTL_CODE(FILE_DEVICE_FILE_SYSTEM, 46, METHOD_NEITHER,                  \
		 FILE_ANY_ACCESS) // READ_USN_JOURNAL_DATA, USN
#define FSCTL_SET_OBJECT_ID_EXTENDED                                           \
	CTL_CODE(FILE_DEVICE_FILE_SYSTEM, 47, METHOD_BUFFERED,                 \
		 FILE_SPECIAL_ACCESS)
#define FSCTL_CREATE_OR_GET_OBJECT_ID                                          \
	CTL_CODE(FILE_DEVICE_FILE_SYSTEM, 48, METHOD_BUFFERED,                 \
		 FILE_ANY_ACCESS) // FILE_OBJECTID_BUFFER
#define FSCTL_SET_SPARSE                                                       \
	CTL_CODE(FILE_DEVICE_FILE_SYSTEM, 49, METHOD_BUFFERED,                 \
		 FILE_SPECIAL_ACCESS)
#define FSCTL_SET_ZERO_DATA                                                    \
	CTL_CODE(FILE_DEVICE_FILE_SYSTEM, 50, METHOD_BUFFERED,                 \
		 FILE_WRITE_DATA) // FILE_ZERO_DATA_INFORMATION,
#define FSCTL_QUERY_ALLOCATED_RANGES                                           \
	CTL_CODE(FILE_DEVICE_FILE_SYSTEM, 51, METHOD_NEITHER,                  \
		 FILE_READ_DATA) // FILE_ALLOCATED_RANGE_BUFFER,
				 // FILE_ALLOCATED_RANGE_BUFFER
#define FSCTL_ENABLE_UPGRADE                                                   \
	CTL_CODE(FILE_DEVICE_FILE_SYSTEM, 52, METHOD_BUFFERED, FILE_WRITE_DATA)
#define FSCTL_SET_ENCRYPTION                                                   \
	CTL_CODE(                                                              \
	    FILE_DEVICE_FILE_SYSTEM, 53, METHOD_NEITHER,                       \
	    FILE_ANY_ACCESS) // ENCRYPTION_BUFFER, DECRYPTION_STATUS_BUFFER
#define FSCTL_ENCRYPTION_FSCTL_IO                                              \
	CTL_CODE(FILE_DEVICE_FILE_SYSTEM, 54, METHOD_NEITHER, FILE_ANY_ACCESS)
#define FSCTL_WRITE_RAW_ENCRYPTED                                              \
	CTL_CODE(FILE_DEVICE_FILE_SYSTEM, 55, METHOD_NEITHER,                  \
		 FILE_SPECIAL_ACCESS) // ENCRYPTED_DATA_INFO,
				      // EXTENDED_ENCRYPTED_DATA_INFO
#define FSCTL_READ_RAW_ENCRYPTED                                               \
	CTL_CODE(FILE_DEVICE_FILE_SYSTEM, 56, METHOD_NEITHER,                  \
		 FILE_SPECIAL_ACCESS) // REQUEST_RAW_ENCRYPTED_DATA,
				      // ENCRYPTED_DATA_INFO,
				      // EXTENDED_ENCRYPTED_DATA_INFO
#define FSCTL_CREATE_USN_JOURNAL                                               \
	CTL_CODE(FILE_DEVICE_FILE_SYSTEM, 57, METHOD_NEITHER,                  \
		 FILE_ANY_ACCESS) // CREATE_USN_JOURNAL_DATA,
#define FSCTL_READ_FILE_USN_DATA                                               \
	CTL_CODE(FILE_DEVICE_FILE_SYSTEM, 58, METHOD_NEITHER,                  \
		 FILE_ANY_ACCESS) // Read the Usn Record for a file
#define FSCTL_WRITE_USN_CLOSE_RECORD                                           \
	CTL_CODE(FILE_DEVICE_FILE_SYSTEM, 59, METHOD_NEITHER,                  \
		 FILE_ANY_ACCESS) // Generate Close Usn Record
#define FSCTL_EXTEND_VOLUME                                                    \
	CTL_CODE(FILE_DEVICE_FILE_SYSTEM, 60, METHOD_BUFFERED, FILE_ANY_ACCESS)
#define FSCTL_QUERY_USN_JOURNAL                                                \
	CTL_CODE(FILE_DEVICE_FILE_SYSTEM, 61, METHOD_BUFFERED, FILE_ANY_ACCESS)
#define FSCTL_DELETE_USN_JOURNAL                                               \
	CTL_CODE(FILE_DEVICE_FILE_SYSTEM, 62, METHOD_BUFFERED, FILE_ANY_ACCESS)
#define FSCTL_MARK_HANDLE                                                      \
	CTL_CODE(FILE_DEVICE_FILE_SYSTEM, 63, METHOD_BUFFERED, FILE_ANY_ACCESS)
#define FSCTL_SIS_COPYFILE                                                     \
	CTL_CODE(FILE_DEVICE_FILE_SYSTEM, 64, METHOD_BUFFERED, FILE_ANY_ACCESS)
#define FSCTL_SIS_LINK_FILES                                                   \
	CTL_CODE(FILE_DEVICE_FILE_SYSTEM, 65, METHOD_BUFFERED,                 \
		 FILE_READ_DATA | FILE_WRITE_DATA)
// decommissioned fsctl value                                             66
// decommissioned fsctl value                                             67
// decommissioned fsctl value                                             68
#define FSCTL_RECALL_FILE                                                      \
	CTL_CODE(FILE_DEVICE_FILE_SYSTEM, 69, METHOD_NEITHER, FILE_ANY_ACCESS)
// decommissioned fsctl value                                             70
#define FSCTL_READ_FROM_PLEX                                                   \
	CTL_CODE(FILE_DEVICE_FILE_SYSTEM, 71, METHOD_OUT_DIRECT, FILE_READ_DATA)
#define FSCTL_FILE_PREFETCH                                                    \
	CTL_CODE(FILE_DEVICE_FILE_SYSTEM, 72, METHOD_BUFFERED,                 \
		 FILE_SPECIAL_ACCESS) // FILE_PREFETCH
#endif				      /* _WIN32_WINNT >= _WIN32_WINNT_WIN2K */

#if (_WIN32_WINNT >= _WIN32_WINNT_VISTA)
#define FSCTL_MAKE_MEDIA_COMPATIBLE                                            \
	CTL_CODE(FILE_DEVICE_FILE_SYSTEM, 76, METHOD_BUFFERED,                 \
		 FILE_WRITE_DATA) // UDFS R/W
#define FSCTL_SET_DEFECT_MANAGEMENT                                            \
	CTL_CODE(FILE_DEVICE_FILE_SYSTEM, 77, METHOD_BUFFERED,                 \
		 FILE_WRITE_DATA) // UDFS R/W
#define FSCTL_QUERY_SPARING_INFO                                               \
	CTL_CODE(FILE_DEVICE_FILE_SYSTEM, 78, METHOD_BUFFERED,                 \
		 FILE_ANY_ACCESS) // UDFS R/W
#define FSCTL_QUERY_ON_DISK_VOLUME_INFO                                        \
	CTL_CODE(FILE_DEVICE_FILE_SYSTEM, 79, METHOD_BUFFERED,                 \
		 FILE_ANY_ACCESS) // C/UDFS
#define FSCTL_SET_VOLUME_COMPRESSION_STATE                                     \
	CTL_CODE(FILE_DEVICE_FILE_SYSTEM, 80, METHOD_BUFFERED,                 \
		 FILE_SPECIAL_ACCESS) // VOLUME_COMPRESSION_STATE
// decommissioned fsctl value                                                 80
#define FSCTL_TXFS_MODIFY_RM                                                   \
	CTL_CODE(FILE_DEVICE_FILE_SYSTEM, 81, METHOD_BUFFERED,                 \
		 FILE_WRITE_DATA) // TxF
#define FSCTL_TXFS_QUERY_RM_INFORMATION                                        \
	CTL_CODE(FILE_DEVICE_FILE_SYSTEM, 82, METHOD_BUFFERED,                 \
		 FILE_READ_DATA) // TxF
// decommissioned fsctl value                                                 83
#define FSCTL_TXFS_ROLLFORWARD_REDO                                            \
	CTL_CODE(FILE_DEVICE_FILE_SYSTEM, 84, METHOD_BUFFERED,                 \
		 FILE_WRITE_DATA) // TxF
#define FSCTL_TXFS_ROLLFORWARD_UNDO                                            \
	CTL_CODE(FILE_DEVICE_FILE_SYSTEM, 85, METHOD_BUFFERED,                 \
		 FILE_WRITE_DATA) // TxF
#define FSCTL_TXFS_START_RM                                                    \
	CTL_CODE(FILE_DEVICE_FILE_SYSTEM, 86, METHOD_BUFFERED,                 \
		 FILE_WRITE_DATA) // TxF
#define FSCTL_TXFS_SHUTDOWN_RM                                                 \
	CTL_CODE(FILE_DEVICE_FILE_SYSTEM, 87, METHOD_BUFFERED,                 \
		 FILE_WRITE_DATA) // TxF
#define FSCTL_TXFS_READ_BACKUP_INFORMATION                                     \
	CTL_CODE(FILE_DEVICE_FILE_SYSTEM, 88, METHOD_BUFFERED,                 \
		 FILE_READ_DATA) // TxF
#define FSCTL_TXFS_WRITE_BACKUP_INFORMATION                                    \
	CTL_CODE(FILE_DEVICE_FILE_SYSTEM, 89, METHOD_BUFFERED,                 \
		 FILE_WRITE_DATA) // TxF
#define FSCTL_TXFS_CREATE_SECONDARY_RM                                         \
	CTL_CODE(FILE_DEVICE_FILE_SYSTEM, 90, METHOD_BUFFERED,                 \
		 FILE_WRITE_DATA) // TxF
#define FSCTL_TXFS_GET_METADATA_INFO                                           \
	CTL_CODE(FILE_DEVICE_FILE_SYSTEM, 91, METHOD_BUFFERED,                 \
		 FILE_READ_DATA) // TxF
#define FSCTL_TXFS_GET_TRANSACTED_VERSION                                      \
	CTL_CODE(FILE_DEVICE_FILE_SYSTEM, 92, METHOD_BUFFERED,                 \
		 FILE_READ_DATA) // TxF
// decommissioned fsctl value                                                 93
#define FSCTL_TXFS_SAVEPOINT_INFORMATION                                       \
	CTL_CODE(FILE_DEVICE_FILE_SYSTEM, 94, METHOD_BUFFERED,                 \
		 FILE_WRITE_DATA) // TxF
#define FSCTL_TXFS_CREATE_MINIVERSION                                          \
	CTL_CODE(FILE_DEVICE_FILE_SYSTEM, 95, METHOD_BUFFERED,                 \
		 FILE_WRITE_DATA) // TxF
// decommissioned fsctl value                                                 96
// decommissioned fsctl value                                                 97
// decommissioned fsctl value                                                 98
#define FSCTL_TXFS_TRANSACTION_ACTIVE                                          \
	CTL_CODE(FILE_DEVICE_FILE_SYSTEM, 99, METHOD_BUFFERED,                 \
		 FILE_READ_DATA) // TxF
#define FSCTL_SET_ZERO_ON_DEALLOCATION                                         \
	CTL_CODE(FILE_DEVICE_FILE_SYSTEM, 101, METHOD_BUFFERED,                \
		 FILE_SPECIAL_ACCESS)
#define FSCTL_SET_REPAIR                                                       \
	CTL_CODE(FILE_DEVICE_FILE_SYSTEM, 102, METHOD_BUFFERED, FILE_ANY_ACCESS)
#define FSCTL_GET_REPAIR                                                       \
	CTL_CODE(FILE_DEVICE_FILE_SYSTEM, 103, METHOD_BUFFERED, FILE_ANY_ACCESS)
#define FSCTL_WAIT_FOR_REPAIR                                                  \
	CTL_CODE(FILE_DEVICE_FILE_SYSTEM, 104, METHOD_BUFFERED, FILE_ANY_ACCESS)
// decommissioned fsctl value 105
#define FSCTL_INITIATE_REPAIR                                                  \
	CTL_CODE(FILE_DEVICE_FILE_SYSTEM, 106, METHOD_BUFFERED, FILE_ANY_ACCESS)
#define FSCTL_CSC_INTERNAL                                                     \
	CTL_CODE(FILE_DEVICE_FILE_SYSTEM, 107, METHOD_NEITHER,                 \
		 FILE_ANY_ACCESS) // CSC internal implementation
#define FSCTL_SHRINK_VOLUME                                                    \
	CTL_CODE(FILE_DEVICE_FILE_SYSTEM, 108, METHOD_BUFFERED,                \
		 FILE_SPECIAL_ACCESS) // SHRINK_VOLUME_INFORMATION
#define FSCTL_SET_SHORT_NAME_BEHAVIOR                                          \
	CTL_CODE(FILE_DEVICE_FILE_SYSTEM, 109, METHOD_BUFFERED, FILE_ANY_ACCESS)
#define FSCTL_DFSR_SET_GHOST_HANDLE_STATE                                      \
	CTL_CODE(FILE_DEVICE_FILE_SYSTEM, 110, METHOD_BUFFERED, FILE_ANY_ACCESS)

//
//  Values 111 - 119 are reserved for FSRM.
//

#define FSCTL_TXFS_LIST_TRANSACTION_LOCKED_FILES                               \
	CTL_CODE(FILE_DEVICE_FILE_SYSTEM, 120, METHOD_BUFFERED,                \
		 FILE_READ_DATA) // TxF
#define FSCTL_TXFS_LIST_TRANSACTIONS                                           \
	CTL_CODE(FILE_DEVICE_FILE_SYSTEM, 121, METHOD_BUFFERED,                \
		 FILE_READ_DATA) // TxF
#define FSCTL_QUERY_PAGEFILE_ENCRYPTION                                        \
	CTL_CODE(FILE_DEVICE_FILE_SYSTEM, 122, METHOD_BUFFERED, FILE_ANY_ACCESS)
#endif /* _WIN32_WINNT >= _WIN32_WINNT_VISTA */

#if (_WIN32_WINNT >= _WIN32_WINNT_VISTA)
#define FSCTL_RESET_VOLUME_ALLOCATION_HINTS                                    \
	CTL_CODE(FILE_DEVICE_FILE_SYSTEM, 123, METHOD_BUFFERED, FILE_ANY_ACCESS)
#endif /* _WIN32_WINNT >= _WIN32_WINNT_VISTA */

#if (_WIN32_WINNT >= _WIN32_WINNT_WIN7)
#define FSCTL_QUERY_DEPENDENT_VOLUME                                           \
	CTL_CODE(FILE_DEVICE_FILE_SYSTEM, 124, METHOD_BUFFERED,                \
		 FILE_ANY_ACCESS) // Dependency File System Filter
#define FSCTL_SD_GLOBAL_CHANGE                                                 \
	CTL_CODE(FILE_DEVICE_FILE_SYSTEM, 125, METHOD_BUFFERED,                \
		 FILE_ANY_ACCESS) // Query/Change NTFS Security Descriptors
#endif				  /* _WIN32_WINNT >= _WIN32_WINNT_WIN7 */

#if (_WIN32_WINNT >= _WIN32_WINNT_VISTA)
#define FSCTL_TXFS_READ_BACKUP_INFORMATION2                                    \
	CTL_CODE(FILE_DEVICE_FILE_SYSTEM, 126, METHOD_BUFFERED,                \
		 FILE_ANY_ACCESS) // TxF
#endif				  /* _WIN32_WINNT >= _WIN32_WINNT_VISTA */

#if (_WIN32_WINNT >= _WIN32_WINNT_WIN7)
#define FSCTL_LOOKUP_STREAM_FROM_CLUSTER                                       \
	CTL_CODE(FILE_DEVICE_FILE_SYSTEM, 127, METHOD_BUFFERED, FILE_ANY_ACCESS)
#define FSCTL_TXFS_WRITE_BACKUP_INFORMATION2                                   \
	CTL_CODE(FILE_DEVICE_FILE_SYSTEM, 128, METHOD_BUFFERED,                \
		 FILE_ANY_ACCESS) // TxF
#define FSCTL_FILE_TYPE_NOTIFICATION                                           \
	CTL_CODE(FILE_DEVICE_FILE_SYSTEM, 129, METHOD_BUFFERED, FILE_ANY_ACCESS)
#endif

#if (_WIN32_WINNT >= _WIN32_WINNT_WIN8)
#define FSCTL_FILE_LEVEL_TRIM                                                  \
	CTL_CODE(FILE_DEVICE_FILE_SYSTEM, 130, METHOD_BUFFERED, FILE_WRITE_DATA)
#endif /*_WIN32_WINNT >= _WIN32_WINNT_WIN8 */

//
//  Values 131 - 139 are reserved for FSRM.
//

#if (_WIN32_WINNT >= _WIN32_WINNT_WIN7)
#define FSCTL_GET_BOOT_AREA_INFO                                               \
	CTL_CODE(FILE_DEVICE_FILE_SYSTEM, 140, METHOD_BUFFERED,                \
		 FILE_ANY_ACCESS) // BOOT_AREA_INFO
#define FSCTL_GET_RETRIEVAL_POINTER_BASE                                       \
	CTL_CODE(FILE_DEVICE_FILE_SYSTEM, 141, METHOD_BUFFERED,                \
		 FILE_ANY_ACCESS) // RETRIEVAL_POINTER_BASE
#define FSCTL_SET_PERSISTENT_VOLUME_STATE                                      \
	CTL_CODE(FILE_DEVICE_FILE_SYSTEM, 142, METHOD_BUFFERED,                \
		 FILE_ANY_ACCESS) // FILE_FS_PERSISTENT_VOLUME_INFORMATION
#define FSCTL_QUERY_PERSISTENT_VOLUME_STATE                                    \
	CTL_CODE(FILE_DEVICE_FILE_SYSTEM, 143, METHOD_BUFFERED,                \
		 FILE_ANY_ACCESS) // FILE_FS_PERSISTENT_VOLUME_INFORMATION

#define FSCTL_REQUEST_OPLOCK                                                   \
	CTL_CODE(FILE_DEVICE_FILE_SYSTEM, 144, METHOD_BUFFERED, FILE_ANY_ACCESS)

#define FSCTL_CSV_TUNNEL_REQUEST                                               \
	CTL_CODE(FILE_DEVICE_FILE_SYSTEM, 145, METHOD_BUFFERED,                \
		 FILE_ANY_ACCESS) // CSV_TUNNEL_REQUEST
#define FSCTL_IS_CSV_FILE                                                      \
	CTL_CODE(FILE_DEVICE_FILE_SYSTEM, 146, METHOD_BUFFERED,                \
		 FILE_ANY_ACCESS) // IS_CSV_FILE

#define FSCTL_QUERY_FILE_SYSTEM_RECOGNITION                                    \
	CTL_CODE(FILE_DEVICE_FILE_SYSTEM, 147, METHOD_BUFFERED,                \
		 FILE_ANY_ACCESS) //
#define FSCTL_CSV_GET_VOLUME_PATH_NAME                                         \
	CTL_CODE(FILE_DEVICE_FILE_SYSTEM, 148, METHOD_BUFFERED, FILE_ANY_ACCESS)
#define FSCTL_CSV_GET_VOLUME_NAME_FOR_VOLUME_MOUNT_POINT                       \
	CTL_CODE(FILE_DEVICE_FILE_SYSTEM, 149, METHOD_BUFFERED, FILE_ANY_ACCESS)
#define FSCTL_CSV_GET_VOLUME_PATH_NAMES_FOR_VOLUME_NAME                        \
	CTL_CODE(FILE_DEVICE_FILE_SYSTEM, 150, METHOD_BUFFERED, FILE_ANY_ACCESS)
#define FSCTL_IS_FILE_ON_CSV_VOLUME                                            \
	CTL_CODE(FILE_DEVICE_FILE_SYSTEM, 151, METHOD_BUFFERED, FILE_ANY_ACCESS)
#endif /* _WIN32_WINNT >= _WIN32_WINNT_WIN7 */

#if (_WIN32_WINNT >= _WIN32_WINNT_WIN8)
#define FSCTL_CORRUPTION_HANDLING                                              \
	CTL_CODE(FILE_DEVICE_FILE_SYSTEM, 152, METHOD_BUFFERED, FILE_ANY_ACCESS)
#define FSCTL_OFFLOAD_READ                                                     \
	CTL_CODE(FILE_DEVICE_FILE_SYSTEM, 153, METHOD_BUFFERED,                \
		 FILE_READ_ACCESS)
#define FSCTL_OFFLOAD_WRITE                                                    \
	CTL_CODE(FILE_DEVICE_FILE_SYSTEM, 154, METHOD_BUFFERED,                \
		 FILE_WRITE_ACCESS)
#endif /*_WIN32_WINNT >= _WIN32_WINNT_WIN8 */

#if (_WIN32_WINNT >= _WIN32_WINNT_WIN7)
#define FSCTL_CSV_INTERNAL                                                     \
	CTL_CODE(FILE_DEVICE_FILE_SYSTEM, 155, METHOD_BUFFERED, FILE_ANY_ACCESS)
#endif /* _WIN32_WINNT >= _WIN32_WINNT_WIN7 */

#if (_WIN32_WINNT >= _WIN32_WINNT_WIN8)
#define FSCTL_SET_PURGE_FAILURE_MODE                                           \
	CTL_CODE(FILE_DEVICE_FILE_SYSTEM, 156, METHOD_BUFFERED, FILE_ANY_ACCESS)
#define FSCTL_QUERY_FILE_LAYOUT                                                \
	CTL_CODE(FILE_DEVICE_FILE_SYSTEM, 157, METHOD_NEITHER, FILE_ANY_ACCESS)
#define FSCTL_IS_VOLUME_OWNED_BYCSVFS                                          \
	CTL_CODE(FILE_DEVICE_FILE_SYSTEM, 158, METHOD_BUFFERED, FILE_ANY_ACCESS)

#define FSCTL_GET_INTEGRITY_INFORMATION                                        \
	CTL_CODE(FILE_DEVICE_FILE_SYSTEM, 159, METHOD_BUFFERED,                \
		 FILE_ANY_ACCESS) // FSCTL_GET_INTEGRITY_INFORMATION_BUFFER
#define FSCTL_SET_INTEGRITY_INFORMATION                                        \
	CTL_CODE(                                                              \
	    FILE_DEVICE_FILE_SYSTEM, 160, METHOD_BUFFERED,                     \
	    FILE_READ_DATA |                                                   \
		FILE_WRITE_DATA) // FSCTL_SET_INTEGRITY_INFORMATION_BUFFER

#define FSCTL_QUERY_FILE_REGIONS                                               \
	CTL_CODE(FILE_DEVICE_FILE_SYSTEM, 161, METHOD_BUFFERED, FILE_ANY_ACCESS)

#endif /*_WIN32_WINNT >= _WIN32_WINNT_WIN8 */

#if (_WIN32_WINNT >= _WIN32_WINNT_WIN8)
#define FSCTL_RKF_INTERNAL                                                     \
	CTL_CODE(FILE_DEVICE_FILE_SYSTEM, 171, METHOD_NEITHER,                 \
		 FILE_ANY_ACCESS) // Resume Key Filter

#define FSCTL_SCRUB_DATA                                                       \
	CTL_CODE(FILE_DEVICE_FILE_SYSTEM, 172, METHOD_BUFFERED, FILE_ANY_ACCESS)
#define FSCTL_REPAIR_COPIES                                                    \
	CTL_CODE(FILE_DEVICE_FILE_SYSTEM, 173, METHOD_BUFFERED,                \
		 FILE_READ_DATA | FILE_WRITE_DATA)
#define FSCTL_DISABLE_LOCAL_BUFFERING                                          \
	CTL_CODE(FILE_DEVICE_FILE_SYSTEM, 174, METHOD_BUFFERED, FILE_ANY_ACCESS)
#define FSCTL_CSV_MGMT_LOCK                                                    \
	CTL_CODE(FILE_DEVICE_FILE_SYSTEM, 175, METHOD_BUFFERED, FILE_ANY_ACCESS)
#define FSCTL_CSV_QUERY_DOWN_LEVEL_FILE_SYSTEM_CHARACTERISTICS                 \
	CTL_CODE(FILE_DEVICE_FILE_SYSTEM, 176, METHOD_BUFFERED, FILE_ANY_ACCESS)
#define FSCTL_ADVANCE_FILE_ID                                                  \
	CTL_CODE(FILE_DEVICE_FILE_SYSTEM, 177, METHOD_BUFFERED, FILE_ANY_ACCESS)
#define FSCTL_CSV_SYNC_TUNNEL_REQUEST                                          \
	CTL_CODE(FILE_DEVICE_FILE_SYSTEM, 178, METHOD_BUFFERED, FILE_ANY_ACCESS)
#define FSCTL_CSV_QUERY_VETO_FILE_DIRECT_IO                                    \
	CTL_CODE(FILE_DEVICE_FILE_SYSTEM, 179, METHOD_BUFFERED, FILE_ANY_ACCESS)
#define FSCTL_WRITE_USN_REASON                                                 \
	CTL_CODE(FILE_DEVICE_FILE_SYSTEM, 180, METHOD_BUFFERED, FILE_ANY_ACCESS)
#define FSCTL_CSV_CONTROL                                                      \
	CTL_CODE(FILE_DEVICE_FILE_SYSTEM, 181, METHOD_BUFFERED, FILE_ANY_ACCESS)
#define FSCTL_GET_REFS_VOLUME_DATA                                             \
	CTL_CODE(FILE_DEVICE_FILE_SYSTEM, 182, METHOD_BUFFERED, FILE_ANY_ACCESS)
#define FSCTL_CSV_H_BREAKING_SYNC_TUNNEL_REQUEST                               \
	CTL_CODE(FILE_DEVICE_FILE_SYSTEM, 185, METHOD_BUFFERED, FILE_ANY_ACCESS)
#endif /*_WIN32_WINNT >= _WIN32_WINNT_WIN8 */

#if (_WIN32_WINNT >= _WIN32_WINNT_WINBLUE)
#define FSCTL_QUERY_STORAGE_CLASSES                                            \
	CTL_CODE(FILE_DEVICE_FILE_SYSTEM, 187, METHOD_BUFFERED, FILE_ANY_ACCESS)
#define FSCTL_QUERY_REGION_INFO                                                \
	CTL_CODE(FILE_DEVICE_FILE_SYSTEM, 188, METHOD_BUFFERED, FILE_ANY_ACCESS)
#define FSCTL_USN_TRACK_MODIFIED_RANGES                                        \
	CTL_CODE(FILE_DEVICE_FILE_SYSTEM, 189, METHOD_BUFFERED,                \
		 FILE_ANY_ACCESS) // USN_TRACK_MODIFIED_RANGES
#endif				  /* (_WIN32_WINNT >= _WIN32_WINNT_WINBLUE) */
#if (_WIN32_WINNT >= _WIN32_WINNT_WINBLUE)
#define FSCTL_QUERY_SHARED_VIRTUAL_DISK_SUPPORT                                \
	CTL_CODE(FILE_DEVICE_FILE_SYSTEM, 192, METHOD_BUFFERED, FILE_ANY_ACCESS)
#define FSCTL_SVHDX_SYNC_TUNNEL_REQUEST                                        \
	CTL_CODE(FILE_DEVICE_FILE_SYSTEM, 193, METHOD_BUFFERED, FILE_ANY_ACCESS)
#define FSCTL_SVHDX_SET_INITIATOR_INFORMATION                                  \
	CTL_CODE(FILE_DEVICE_FILE_SYSTEM, 194, METHOD_BUFFERED, FILE_ANY_ACCESS)
#endif /* (_WIN32_WINNT >= _WIN32_WINNT_WINBLUE) */
#if (_WIN32_WINNT >= _WIN32_WINNT_WIN7)
#define FSCTL_SET_EXTERNAL_BACKING                                             \
	CTL_CODE(FILE_DEVICE_FILE_SYSTEM, 195, METHOD_BUFFERED,                \
		 FILE_SPECIAL_ACCESS)
#define FSCTL_GET_EXTERNAL_BACKING                                             \
	CTL_CODE(FILE_DEVICE_FILE_SYSTEM, 196, METHOD_BUFFERED, FILE_ANY_ACCESS)
#define FSCTL_DELETE_EXTERNAL_BACKING                                          \
	CTL_CODE(FILE_DEVICE_FILE_SYSTEM, 197, METHOD_BUFFERED,                \
		 FILE_SPECIAL_ACCESS)
#define FSCTL_ENUM_EXTERNAL_BACKING                                            \
	CTL_CODE(FILE_DEVICE_FILE_SYSTEM, 198, METHOD_BUFFERED, FILE_ANY_ACCESS)
#define FSCTL_ENUM_OVERLAY                                                     \
	CTL_CODE(FILE_DEVICE_FILE_SYSTEM, 199, METHOD_NEITHER, FILE_ANY_ACCESS)
#define FSCTL_ADD_OVERLAY                                                      \
	CTL_CODE(FILE_DEVICE_FILE_SYSTEM, 204, METHOD_BUFFERED, FILE_WRITE_DATA)
#define FSCTL_REMOVE_OVERLAY                                                   \
	CTL_CODE(FILE_DEVICE_FILE_SYSTEM, 205, METHOD_BUFFERED, FILE_WRITE_DATA)
#define FSCTL_UPDATE_OVERLAY                                                   \
	CTL_CODE(FILE_DEVICE_FILE_SYSTEM, 206, METHOD_BUFFERED, FILE_WRITE_DATA)
#endif /* (_WIN32_WINNT >= _WIN32_WINNT_WIN7) */
#if (_WIN32_WINNT >= _WIN32_WINNT_WIN8)
#define FSCTL_SHUFFLE_FILE                                                     \
	CTL_CODE(FILE_DEVICE_FILE_SYSTEM, 208, METHOD_BUFFERED,                \
		 FILE_READ_ACCESS | FILE_WRITE_ACCESS) // SHUFFLE_FILE_DATA
#endif /*_WIN32_WINNT >= _WIN32_WINNT_WIN8 */
#if (_WIN32_WINNT >= _WIN32_WINNT_WINBLUE)
#define FSCTL_DUPLICATE_EXTENTS_TO_FILE                                        \
	CTL_CODE(FILE_DEVICE_FILE_SYSTEM, 209, METHOD_BUFFERED, FILE_WRITE_DATA)
#endif /* (_WIN32_WINNT >= _WIN32_WINNT_WINBLUE) */
#if (_WIN32_WINNT >= _WIN32_WINNT_WINBLUE)
#define FSCTL_SPARSE_OVERALLOCATE                                              \
	CTL_CODE(FILE_DEVICE_FILE_SYSTEM, 211, METHOD_BUFFERED,                \
		 FILE_SPECIAL_ACCESS)
#define FSCTL_STORAGE_QOS_CONTROL                                              \
	CTL_CODE(FILE_DEVICE_FILE_SYSTEM, 212, METHOD_BUFFERED, FILE_ANY_ACCESS)
#endif /* (_WIN32_WINNT >= _WIN32_WINNT_WINBLUE) */
#if (_WIN32_WINNT >= _WIN32_WINNT_WINTHRESHOLD)
#define FSCTL_INITIATE_FILE_METADATA_OPTIMIZATION                              \
	CTL_CODE(FILE_DEVICE_FILE_SYSTEM, 215, METHOD_BUFFERED,                \
		 FILE_SPECIAL_ACCESS)
#define FSCTL_QUERY_FILE_METADATA_OPTIMIZATION                                 \
	CTL_CODE(FILE_DEVICE_FILE_SYSTEM, 216, METHOD_BUFFERED,                \
		 FILE_SPECIAL_ACCESS)
#endif /* (_WIN32_WINNT >= _WIN32_WINNT_WINTHRESHOLD) */

#if (_WIN32_WINNT >= _WIN32_WINNT_WINBLUE)
#define FSCTL_SVHDX_ASYNC_TUNNEL_REQUEST                                       \
	CTL_CODE(FILE_DEVICE_FILE_SYSTEM, 217, METHOD_BUFFERED, FILE_ANY_ACCESS)
#endif /* (_WIN32_WINNT >= _WIN32_WINNT_WINBLUE) */

#if (_WIN32_WINNT >= _WIN32_WINNT_WIN7)
#define FSCTL_GET_WOF_VERSION                                                  \
	CTL_CODE(FILE_DEVICE_FILE_SYSTEM, 218, METHOD_BUFFERED, FILE_ANY_ACCESS)
#endif

#if (_WIN32_WINNT >= _WIN32_WINNT_WINTHRESHOLD)
#define FSCTL_HCS_SYNC_TUNNEL_REQUEST                                          \
	CTL_CODE(FILE_DEVICE_FILE_SYSTEM, 219, METHOD_BUFFERED, FILE_ANY_ACCESS)
#define FSCTL_HCS_ASYNC_TUNNEL_REQUEST                                         \
	CTL_CODE(FILE_DEVICE_FILE_SYSTEM, 220, METHOD_BUFFERED, FILE_ANY_ACCESS)
#define FSCTL_QUERY_EXTENT_READ_CACHE_INFO                                     \
	CTL_CODE(FILE_DEVICE_FILE_SYSTEM, 221, METHOD_NEITHER,                 \
		 FILE_ANY_ACCESS) // VCN_RANGE_INPUT_BUFFER,
				  // EXTENT_READ_CACHE_INFO_BUFFER
#define FSCTL_QUERY_REFS_VOLUME_COUNTER_INFO                                   \
	CTL_CODE(FILE_DEVICE_FILE_SYSTEM, 222, METHOD_NEITHER,                 \
		 FILE_ANY_ACCESS) // REFS_VOLUME_COUNTER_INFO_INPUT_BUFFER,
				  // VOLUME_REFS_INFO_BUFFER
#define FSCTL_CLEAN_VOLUME_METADATA                                            \
	CTL_CODE(FILE_DEVICE_FILE_SYSTEM, 223, METHOD_BUFFERED, FILE_ANY_ACCESS)
#define FSCTL_SET_INTEGRITY_INFORMATION_EX                                     \
	CTL_CODE(FILE_DEVICE_FILE_SYSTEM, 224, METHOD_BUFFERED,                \
		 FILE_ANY_ACCESS) // FSCTL_SET_INTEGRITY_INFORMATION_BUFFER_EX
#endif /* (_WIN32_WINNT >= _WIN32_WINNT_WINTHRESHOLD) */
#if (_WIN32_WINNT >= _WIN32_WINNT_WIN7)
#define FSCTL_SUSPEND_OVERLAY                                                  \
	CTL_CODE(FILE_DEVICE_FILE_SYSTEM, 225, METHOD_BUFFERED, FILE_ANY_ACCESS)
#endif
#if (_WIN32_WINNT >= _WIN32_WINNT_WINTHRESHOLD)
#define FSCTL_VIRTUAL_STORAGE_QUERY_PROPERTY                                   \
	CTL_CODE(FILE_DEVICE_FILE_SYSTEM, 226, METHOD_BUFFERED, FILE_ANY_ACCESS)
#define FSCTL_FILESYSTEM_GET_STATISTICS_EX                                     \
	CTL_CODE(FILE_DEVICE_FILE_SYSTEM, 227, METHOD_BUFFERED,                \
		 FILE_ANY_ACCESS) // FILESYSTEM_STATISTICS_EX
#define FSCTL_QUERY_VOLUME_CONTAINER_STATE                                     \
	CTL_CODE(FILE_DEVICE_FILE_SYSTEM, 228, METHOD_BUFFERED, FILE_ANY_ACCESS)
#define FSCTL_SET_LAYER_ROOT                                                   \
	CTL_CODE(FILE_DEVICE_FILE_SYSTEM, 229, METHOD_BUFFERED,                \
		 FILE_ANY_ACCESS) // CONTAINER_ROOT_INFO_INPUT
				  // CONTAINER_ROOT_INFO_OUTPUT
#endif

#if (_WIN32_WINNT >= _WIN32_WINNT_WIN10_TH2)
#define FSCTL_QUERY_DIRECT_ACCESS_EXTENTS                                      \
	CTL_CODE(FILE_DEVICE_FILE_SYSTEM, 230, METHOD_NEITHER,                 \
		 FILE_ANY_ACCESS) // QUERY_DIRECT_ACCESS_EXTENTS
#define FSCTL_NOTIFY_STORAGE_SPACE_ALLOCATION                                  \
	CTL_CODE(FILE_DEVICE_FILE_SYSTEM, 231, METHOD_BUFFERED, FILE_ANY_ACCESS)
#define FSCTL_SSDI_STORAGE_REQUEST                                             \
	CTL_CODE(FILE_DEVICE_FILE_SYSTEM, 232, METHOD_BUFFERED, FILE_ANY_ACCESS)
#endif

#if (_WIN32_WINNT >= _WIN32_WINNT_WIN10_RS1)
#define FSCTL_QUERY_DIRECT_IMAGE_ORIGINAL_BASE                                 \
	CTL_CODE(FILE_DEVICE_FILE_SYSTEM, 233, METHOD_BUFFERED, FILE_ANY_ACCESS)
#define FSCTL_READ_UNPRIVILEGED_USN_JOURNAL                                    \
	CTL_CODE(FILE_DEVICE_FILE_SYSTEM, 234, METHOD_NEITHER,                 \
		 FILE_ANY_ACCESS) // READ_USN_JOURNAL_DATA, USN
#endif

#if (_WIN32_WINNT >= _WIN32_WINNT_WIN10_TH2)
#define FSCTL_GHOST_FILE_EXTENTS                                               \
	CTL_CODE(FILE_DEVICE_FILE_SYSTEM, 235, METHOD_BUFFERED,                \
		 FILE_WRITE_ACCESS) // FSCTL_GHOST_FILE_EXTENTS_INPUT_BUFFER
#define FSCTL_QUERY_GHOSTED_FILE_EXTENTS                                       \
	CTL_CODE(FILE_DEVICE_FILE_SYSTEM, 236, METHOD_BUFFERED, FILE_ANY_ACCESS)
#endif

#if (_WIN32_WINNT >= _WIN32_WINNT_WIN10_TH2)
#define FSCTL_UNMAP_SPACE                                                      \
	CTL_CODE(FILE_DEVICE_FILE_SYSTEM, 237, METHOD_BUFFERED, FILE_ANY_ACCESS)
#endif

#if (_WIN32_WINNT >= _WIN32_WINNT_WINTHRESHOLD)
#define FSCTL_HCS_SYNC_NO_WRITE_TUNNEL_REQUEST                                 \
	CTL_CODE(FILE_DEVICE_FILE_SYSTEM, 238, METHOD_BUFFERED, FILE_ANY_ACCESS)
#endif
#if (_WIN32_WINNT >= _WIN32_WINNT_WIN10_RS1)
#define FSCTL_START_VIRTUALIZATION_INSTANCE                                    \
	CTL_CODE(FILE_DEVICE_FILE_SYSTEM, 240, METHOD_BUFFERED,                \
		 FILE_ANY_ACCESS) // VIRTUALIZATION_INSTANCE_INFO_INPUT,
				  // VIRTUALIZATION_INSTANCE_INFO_OUTPUT
#define FSCTL_GET_FILTER_FILE_IDENTIFIER                                       \
	CTL_CODE(FILE_DEVICE_FILE_SYSTEM, 241, METHOD_BUFFERED,                \
		 FILE_ANY_ACCESS) // GET_FILTER_FILE_IDENTIFIER_INPUT,
				  // GET_FILTER_FILE_IDENTIFIER_OUTPUT
#endif				  /* (_WIN32_WINNT >= _WIN32_WINNT_WIN10_RS1) */

#if (_WIN32_WINNT >= _WIN32_WINNT_WIN10_RS2)
#define FSCTL_STREAMS_QUERY_PARAMETERS                                         \
	CTL_CODE(FILE_DEVICE_FILE_SYSTEM, 241, METHOD_BUFFERED, FILE_ANY_ACCESS)
#define FSCTL_STREAMS_ASSOCIATE_ID                                             \
	CTL_CODE(FILE_DEVICE_FILE_SYSTEM, 242, METHOD_BUFFERED, FILE_ANY_ACCESS)
#define FSCTL_STREAMS_QUERY_ID                                                 \
	CTL_CODE(FILE_DEVICE_FILE_SYSTEM, 243, METHOD_BUFFERED, FILE_ANY_ACCESS)

#define FSCTL_GET_RETRIEVAL_POINTERS_AND_REFCOUNT                              \
	CTL_CODE(FILE_DEVICE_FILE_SYSTEM, 244, METHOD_NEITHER,                 \
		 FILE_ANY_ACCESS) // STARTING_VCN_INPUT_BUFFER,
				  // RETRIEVAL_POINTERS_AND_REFCOUNT_BUFFER

#define FSCTL_QUERY_VOLUME_NUMA_INFO                                           \
	CTL_CODE(FILE_DEVICE_FILE_SYSTEM, 245, METHOD_BUFFERED, FILE_ANY_ACCESS)

#endif

#if (_WIN32_WINNT >= _WIN32_WINNT_WIN10_RS2)

#define FSCTL_REFS_DEALLOCATE_RANGES                                           \
	CTL_CODE(FILE_DEVICE_FILE_SYSTEM, 246, METHOD_BUFFERED, FILE_ANY_ACCESS)
#endif

#if (_WIN32_WINNT >= _WIN32_WINNT_WIN10_TH2)
#define FSCTL_QUERY_REFS_SMR_VOLUME_INFO                                       \
	CTL_CODE(FILE_DEVICE_FILE_SYSTEM, 247, METHOD_BUFFERED, FILE_ANY_ACCESS)
#define FSCTL_SET_REFS_SMR_VOLUME_GC_PARAMETERS                                \
	CTL_CODE(FILE_DEVICE_FILE_SYSTEM, 248, METHOD_BUFFERED, FILE_ANY_ACCESS)
#define FSCTL_SET_REFS_FILE_STRICTLY_SEQUENTIAL                                \
	CTL_CODE(FILE_DEVICE_FILE_SYSTEM, 249, METHOD_BUFFERED, FILE_ANY_ACCESS)
#endif

#if (_WIN32_WINNT >= _WIN32_WINNT_WIN10_RS3)
#define FSCTL_DUPLICATE_EXTENTS_TO_FILE_EX                                     \
	CTL_CODE(FILE_DEVICE_FILE_SYSTEM, 250, METHOD_BUFFERED, FILE_WRITE_DATA)
#define FSCTL_QUERY_BAD_RANGES                                                 \
	CTL_CODE(FILE_DEVICE_FILE_SYSTEM, 251, METHOD_BUFFERED, FILE_ANY_ACCESS)
#define FSCTL_SET_DAX_ALLOC_ALIGNMENT_HINT                                     \
	CTL_CODE(FILE_DEVICE_FILE_SYSTEM, 252, METHOD_BUFFERED, FILE_ANY_ACCESS)
#define FSCTL_DELETE_CORRUPTED_REFS_CONTAINER                                  \
	CTL_CODE(FILE_DEVICE_FILE_SYSTEM, 253, METHOD_BUFFERED, FILE_ANY_ACCESS)
#define FSCTL_SCRUB_UNDISCOVERABLE_ID                                          \
	CTL_CODE(FILE_DEVICE_FILE_SYSTEM, 254, METHOD_BUFFERED, FILE_ANY_ACCESS)
#endif /* (_WIN32_WINNT >= _WIN32_WINNT_WIN10_RS3) */

#if (_WIN32_WINNT >= _WIN32_WINNT_WIN10_RS4)
#define FSCTL_NOTIFY_DATA_CHANGE                                               \
	CTL_CODE(FILE_DEVICE_FILE_SYSTEM, 255, METHOD_BUFFERED, FILE_ANY_ACCESS)
#endif /* (_WIN32_WINNT >= _WIN32_WINNT_WIN10_RS4) */

#if (_WIN32_WINNT >= _WIN32_WINNT_WIN10_RS1)
#define FSCTL_START_VIRTUALIZATION_INSTANCE_EX                                 \
	CTL_CODE(FILE_DEVICE_FILE_SYSTEM, 256, METHOD_BUFFERED, FILE_ANY_ACCESS)
#endif /* (_WIN32_WINNT >= _WIN32_WINNT_WIN10_RS1) */

#if (_WIN32_WINNT >= _WIN32_WINNT_WIN10_RS4)
#define FSCTL_ENCRYPTION_KEY_CONTROL                                           \
	CTL_CODE(FILE_DEVICE_FILE_SYSTEM, 257, METHOD_BUFFERED,                \
		 FILE_ANY_ACCESS) // protect/unprotect under DPL
#define FSCTL_VIRTUAL_STORAGE_SET_BEHAVIOR                                     \
	CTL_CODE(FILE_DEVICE_FILE_SYSTEM, 258, METHOD_BUFFERED, FILE_ANY_ACCESS)
#endif /* (_WIN32_WINNT >= _WIN32_WINNT_WIN10_RS4) */

#if (_WIN32_WINNT >= _WIN32_WINNT_WIN10_RS1)
#define FSCTL_SET_REPARSE_POINT_EX                                             \
	CTL_CODE(FILE_DEVICE_FILE_SYSTEM, 259, METHOD_BUFFERED,                \
		 FILE_SPECIAL_ACCESS) // REPARSE_DATA_BUFFER_EX
#endif /* (_WIN32_WINNT >= _WIN32_WINNT_WIN10_RS1) */
#if (_WIN32_WINNT >= _WIN32_WINNT_WIN10_RS5)
#define FSCTL_REARRANGE_FILE                                                   \
	CTL_CODE(FILE_DEVICE_FILE_SYSTEM, 264, METHOD_BUFFERED,                \
		 FILE_READ_ACCESS | FILE_WRITE_ACCESS) // REARRANGE_FILE_DATA
#define FSCTL_VIRTUAL_STORAGE_PASSTHROUGH                                      \
	CTL_CODE(FILE_DEVICE_FILE_SYSTEM, 265, METHOD_BUFFERED, FILE_ANY_ACCESS)
#define FSCTL_GET_RETRIEVAL_POINTER_COUNT                                      \
	CTL_CODE(FILE_DEVICE_FILE_SYSTEM, 266, METHOD_NEITHER,                 \
		 FILE_ANY_ACCESS) // STARTING_VCN_INPUT_BUFFER,
				  // RETRIEVAL_POINTER_COUNT
#if defined(_WIN64)
#define FSCTL_ENABLE_PER_IO_FLAGS                                              \
	CTL_CODE(FILE_DEVICE_FILE_SYSTEM, 267, METHOD_BUFFERED, FILE_ANY_ACCESS)
#endif /* _WIN64 */
#endif /* (_WIN32_WINNT >= _WIN32_WINNT_WIN10_RS5) */
#if (NTDDI_VERSION >= NTDDI_WIN10_RS5)
#define FSCTL_QUERY_ASYNC_DUPLICATE_EXTENTS_STATUS                             \
	CTL_CODE(FILE_DEVICE_FILE_SYSTEM, 268, METHOD_BUFFERED, FILE_ANY_ACCESS)
#endif
#if (NTDDI_VERSION >= NTDDI_WIN10_MN)
#define FSCTL_SMB_SHARE_FLUSH_AND_PURGE                                        \
	CTL_CODE(FILE_DEVICE_FILE_SYSTEM, 271, METHOD_BUFFERED, FILE_ANY_ACCESS)
#endif

#if (NTDDI_VERSION >= NTDDI_WIN10_FE)
#define FSCTL_REFS_STREAM_SNAPSHOT_MANAGEMENT                                  \
	CTL_CODE(FILE_DEVICE_FILE_SYSTEM, 272, METHOD_BUFFERED, FILE_ANY_ACCESS)
#endif
#if (NTDDI_VERSION >= NTDDI_WIN10_CO)
#define FSCTL_MANAGE_BYPASS_IO                                                 \
	CTL_CODE(FILE_DEVICE_FILE_SYSTEM, 274, METHOD_BUFFERED, FILE_ANY_ACCESS)
#endif

#if (NTDDI_VERSION >= NTDDI_WIN10_FE)
#define FSCTL_REFS_DEALLOCATE_RANGES_EX                                        \
	CTL_CODE(FILE_DEVICE_FILE_SYSTEM, 275, METHOD_BUFFERED, FILE_ANY_ACCESS)
#endif

#if (NTDDI_VERSION >= NTDDI_WIN10_FE)
#define FSCTL_SET_CACHED_RUNS_STATE                                            \
	CTL_CODE(FILE_DEVICE_FILE_SYSTEM, 276, METHOD_BUFFERED, FILE_ANY_ACCESS)
#endif
#if (NTDDI_VERSION >= NTDDI_WIN10_NI)
#define FSCTL_REFS_SET_VOLUME_COMPRESSION_INFO                                 \
	CTL_CODE(FILE_DEVICE_FILE_SYSTEM, 277, METHOD_BUFFERED, FILE_ANY_ACCESS)
#define FSCTL_REFS_QUERY_VOLUME_COMPRESSION_INFO                               \
	CTL_CODE(FILE_DEVICE_FILE_SYSTEM, 278, METHOD_BUFFERED, FILE_ANY_ACCESS)
#endif
#if (NTDDI_VERSION >= NTDDI_WIN10_NI)
#define FSCTL_DUPLICATE_CLUSTER                                                \
	CTL_CODE(FILE_DEVICE_FILE_SYSTEM, 279, METHOD_BUFFERED, FILE_ANY_ACCESS)
#define FSCTL_CREATE_LCN_WEAK_REFERENCE                                        \
	CTL_CODE(FILE_DEVICE_FILE_SYSTEM, 280, METHOD_BUFFERED, FILE_ANY_ACCESS)
#define FSCTL_DELETE_LCN_WEAK_REFERENCE                                        \
	CTL_CODE(FILE_DEVICE_FILE_SYSTEM, 281, METHOD_BUFFERED, FILE_ANY_ACCESS)
#define FSCTL_QUERY_LCN_WEAK_REFERENCE                                         \
	CTL_CODE(FILE_DEVICE_FILE_SYSTEM, 282, METHOD_BUFFERED, FILE_ANY_ACCESS)
#define FSCTL_DELETE_LCN_WEAK_REFERENCES                                       \
	CTL_CODE(FILE_DEVICE_FILE_SYSTEM, 283, METHOD_BUFFERED, FILE_ANY_ACCESS)
#endif
#if (NTDDI_VERSION >= NTDDI_WIN10_NI)
#define FSCTL_REFS_SET_VOLUME_DEDUP_INFO                                       \
	CTL_CODE(FILE_DEVICE_FILE_SYSTEM, 284, METHOD_BUFFERED, FILE_ANY_ACCESS)
#define FSCTL_REFS_QUERY_VOLUME_DEDUP_INFO                                     \
	CTL_CODE(FILE_DEVICE_FILE_SYSTEM, 285, METHOD_BUFFERED, FILE_ANY_ACCESS)
#endif
#if (NTDDI_VERSION >= NTDDI_WIN10_RS5)
#define FSCTL_LMR_QUERY_INFO                                                   \
	CTL_CODE(FILE_DEVICE_FILE_SYSTEM, 286, METHOD_BUFFERED, FILE_ANY_ACCESS)
#endif
#define IOCTL_VOLUME_BASE 0x00000056 // 'V'
#define IOCTL_VOLUME_GET_VOLUME_DISK_EXTENTS    CTL_CODE(IOCTL_VOLUME_BASE, 0, METHOD_BUFFERED, FILE_ANY_ACCESS)
#define IOCTL_DISK_BASE FILE_DEVICE_DISK
#define IOCTL_DISK_GET_PARTITION_INFO_EX                                       \
	CTL_CODE(IOCTL_DISK_BASE, 0x0012, METHOD_BUFFERED, FILE_ANY_ACCESS)
#define IOCTL_DISK_SET_PARTITION_INFO_EX                                       \
	CTL_CODE(IOCTL_DISK_BASE, 0x0013, METHOD_BUFFERED,                     \
		 FILE_READ_ACCESS | FILE_WRITE_ACCESS)
#define IOCTL_DISK_GET_DRIVE_LAYOUT_EX                                         \
	CTL_CODE(IOCTL_DISK_BASE, 0x0014, METHOD_BUFFERED, FILE_ANY_ACCESS)
#define IOCTL_DISK_SET_DRIVE_LAYOUT_EX                                         \
	CTL_CODE(IOCTL_DISK_BASE, 0x0015, METHOD_BUFFERED,                     \
		 FILE_READ_ACCESS | FILE_WRITE_ACCESS)
#define IOCTL_DISK_CREATE_DISK                                                 \
	CTL_CODE(IOCTL_DISK_BASE, 0x0016, METHOD_BUFFERED,                     \
		 FILE_READ_ACCESS | FILE_WRITE_ACCESS)
#define IOCTL_DISK_GET_LENGTH_INFO                                             \
	CTL_CODE(IOCTL_DISK_BASE, 0x0017, METHOD_BUFFERED, FILE_READ_ACCESS)
#define IOCTL_DISK_GET_DRIVE_GEOMETRY_EX                                       \
	CTL_CODE(IOCTL_DISK_BASE, 0x0028, METHOD_BUFFERED, FILE_ANY_ACCESS)
typedef struct _FILE_BASIC_INFORMATION {
	LARGE_INTEGER CreationTime;
	LARGE_INTEGER LastAccessTime;
	LARGE_INTEGER LastWriteTime;
	LARGE_INTEGER ChangeTime;
	u32 FileAttributes;
} FILE_BASIC_INFORMATION, *PFILE_BASIC_INFORMATION;
typedef struct _FILE_NAME_INFORMATION {
	u32 FileNameLength;
	WCHAR FileName[1];
} FILE_NAME_INFORMATION, *PFILE_NAME_INFORMATION;
typedef struct _FILE_DISPOSITION_INFORMATION {
	u8 DoDeleteFile;
} FILE_DISPOSITION_INFORMATION, *PFILE_DISPOSITION_INFORMATION;
typedef enum _FILE_INFORMATION_CLASS2 {
	FileDirectoryInformation2 = 1,
	FileFullDirectoryInformation,		 // 2
	FileBothDirectoryInformation,		 // 3
	FileBasicInformation,			 // 4
	FileStandardInformation,		 // 5
	FileInternalInformation,		 // 6
	FileEaInformation,			 // 7
	FileAccessInformation,			 // 8
	FileNameInformation,			 // 9
	FileRenameInformation,			 // 10
	FileLinkInformation,			 // 11
	FileNamesInformation,			 // 12
	FileDispositionInformation,		 // 13
	FilePositionInformation,		 // 14
	FileFullEaInformation,			 // 15
	FileModeInformation,			 // 16
	FileAlignmentInformation,		 // 17
	FileAllInformation,			 // 18
	FileAllocationInformation,		 // 19
	FileEndOfFileInformation,		 // 20
	FileAlternateNameInformation,		 // 21
	FileStreamInformation,			 // 22
	FilePipeInformation,			 // 23
	FilePipeLocalInformation,		 // 24
	FilePipeRemoteInformation,		 // 25
	FileMailslotQueryInformation,		 // 26
	FileMailslotSetInformation,		 // 27
	FileCompressionInformation,		 // 28
	FileObjectIdInformation,		 // 29
	FileCompletionInformation,		 // 30
	FileMoveClusterInformation,		 // 31
	FileQuotaInformation,			 // 32
	FileReparsePointInformation,		 // 33
	FileNetworkOpenInformation,		 // 34
	FileAttributeTagInformation,		 // 35
	FileTrackingInformation,		 // 36
	FileIdBothDirectoryInformation,		 // 37
	FileIdFullDirectoryInformation,		 // 38
	FileValidDataLengthInformation,		 // 39
	FileShortNameInformation,		 // 40
	FileIoCompletionNotificationInformation, // 41
	FileIoStatusBlockRangeInformation,	 // 42
	FileIoPriorityHintInformation,		 // 43
	FileSfioReserveInformation,		 // 44
	FileSfioVolumeInformation,		 // 45
	FileHardLinkInformation,		 // 46
	FileProcessIdsUsingFileInformation,	 // 47
	FileNormalizedNameInformation,		 // 48
	FileNetworkPhysicalNameInformation,	 // 49
	FileIdGlobalTxDirectoryInformation,	 // 50
	FileIsRemoteDeviceInformation,		 // 51
	FileUnusedInformation,			 // 52
	FileNumaNodeInformation,		 // 53
	FileStandardLinkInformation,		 // 54
	FileRemoteProtocolInformation,		 // 55

	//
	//  These are special versions of these operations (defined earlier)
	//  which can be used by kernel mode drivers only to bypass security
	//  access checks for Rename and HardLink operations.  These operations
	//  are only recognized by the IOManager, a file system should never
	//  receive these.
	//

	FileRenameInformationBypassAccessCheck, // 56
	FileLinkInformationBypassAccessCheck,	// 57

	//
	// End of special information classes reserved for IOManager.
	//

	FileVolumeNameInformation,		      // 58
	FileIdInformation,			      // 59
	FileIdExtdDirectoryInformation,		      // 60
	FileReplaceCompletionInformation,	      // 61
	FileHardLinkFullIdInformation,		      // 62
	FileIdExtdBothDirectoryInformation,	      // 63
	FileDispositionInformationEx,		      // 64
	FileRenameInformationEx,		      // 65
	FileRenameInformationExBypassAccessCheck,     // 66
	FileDesiredStorageClassInformation,	      // 67
	FileStatInformation,			      // 68
	FileMemoryPartitionInformation,		      // 69
	FileStatLxInformation,			      // 70
	FileCaseSensitiveInformation,		      // 71
	FileLinkInformationEx,			      // 72
	FileLinkInformationExBypassAccessCheck,	      // 73
	FileStorageReserveIdInformation,	      // 74
	FileCaseSensitiveInformationForceAccessCheck, // 75
	FileKnownFolderInformation,		      // 76

	FileMaximumInformation
} FILE_INFORMATION_CLASS,
    *PFILE_INFORMATION_CLASS;
typedef enum _FSINFOCLASS {
	FileFsVolumeInformation = 1,
	FileFsLabelInformation = 2,
	FileFsSizeInformation = 3,
	FileFsDeviceInformation = 4,
	FileFsAttributeInformation = 5,
	FileFsControlInformation = 6,
	FileFsFullSizeInformation = 7,
	FileFsObjectIdInformation = 8,
	FileFsDriverPathInformation = 9,
	FileFsVolumeFlagsInformation = 10,
	FileFsSectorSizeInformation = 11,
	FileFsDataCopyInformation = 12,
	FileFsMetadataSizeInformation = 13,
	FileFsFullSizeInformationEx = 14,
	FileFsGuidInformation,
	FileFsMaximumInformation
} FS_INFORMATION_CLASS,
    *PFS_INFORMATION_CLASS;
typedef struct _FILE_LINK_INFORMATION {
#if (_WIN32_WINNT >= _WIN32_WINNT_WIN10_RS5)
	union {
		u8 ReplaceIfExists; // FileLinkInformation
		u32 Flags;	    // FileLinkInformationEx
	} DUMMYUNIONNAME;
#else
	u8 ReplaceIfExists;
#endif
	HANDLE RootDirectory;
	u32 FileNameLength;
	WCHAR FileName[1];
} FILE_LINK_INFORMATION, *PFILE_LINK_INFORMATION;
typedef struct _FILE_ALLOCATION_INFORMATION {
	LARGE_INTEGER AllocationSize;
} FILE_ALLOCATION_INFORMATION, *PFILE_ALLOCATION_INFORMATION;
typedef struct _FILE_END_OF_FILE_INFORMATION {
	LARGE_INTEGER EndOfFile;
} FILE_END_OF_FILE_INFORMATION, *PFILE_END_OF_FILE_INFORMATION;
typedef struct _FILE_FULL_EA_INFORMATION {
	u32 NextEntryOffset;
	UCHAR Flags;
	UCHAR EaNameLength;
	USHORT EaValueLength;
	CHAR EaName[1];
} FILE_FULL_EA_INFORMATION, *PFILE_FULL_EA_INFORMATION;
typedef struct _FILE_NAMES_INFORMATION {
	u32 NextEntryOffset;
	u32 FileIndex;
	u32 FileNameLength;
	WCHAR FileName[1];
} FILE_NAMES_INFORMATION, *PFILE_NAMES_INFORMATION;
typedef struct _FILE_INTERNAL_INFORMATION {
	LARGE_INTEGER IndexNumber;
} FILE_INTERNAL_INFORMATION, *PFILE_INTERNAL_INFORMATION;
typedef struct _FILE_FS_VOLUME_INFORMATION {
	LARGE_INTEGER VolumeCreationTime;
	u32 VolumeSerialNumber;
	u32 VolumeLabelLength;
	u8 SupportsObjects;
	WCHAR VolumeLabel[1];
} FILE_FS_VOLUME_INFORMATION, *PFILE_FS_VOLUME_INFORMATION;
typedef struct _FILE_STREAM_INFORMATION {
	u32 NextEntryOffset;
	u32 StreamNameLength;
	LARGE_INTEGER StreamSize;
	LARGE_INTEGER StreamAllocationSize;
	WCHAR StreamName[1];
} FILE_STREAM_INFORMATION, *PFILE_STREAM_INFORMATION;
typedef struct _FILE_STANDARD_INFORMATION {
	LARGE_INTEGER AllocationSize;
	LARGE_INTEGER EndOfFile;
	u32 NumberOfLinks;
	u8 DeletePending;
	u8 Directory;
} FILE_STANDARD_INFORMATION, *PFILE_STANDARD_INFORMATION;
typedef struct _FILE_EA_INFORMATION {
	u32 EaSize;
} FILE_EA_INFORMATION, *PFILE_EA_INFORMATION;
typedef struct _FILE_ACCESS_INFORMATION {
	ACCESS_MASK AccessFlags;
} FILE_ACCESS_INFORMATION, *PFILE_ACCESS_INFORMATION;
typedef struct _FILE_POSITION_INFORMATION {
	LARGE_INTEGER CurrentByteOffset;
} FILE_POSITION_INFORMATION, *PFILE_POSITION_INFORMATION;
typedef struct _FILE_MODE_INFORMATION {
	u32 Mode;
} FILE_MODE_INFORMATION, *PFILE_MODE_INFORMATION;
typedef struct _FILE_ALIGNMENT_INFORMATION {
	u32 AlignmentRequirement;
} FILE_ALIGNMENT_INFORMATION, *PFILE_ALIGNMENT_INFORMATION;
typedef struct _FILE_ALL_INFORMATION {
	FILE_BASIC_INFORMATION BasicInformation;
	FILE_STANDARD_INFORMATION StandardInformation;
	FILE_INTERNAL_INFORMATION InternalInformation;
	FILE_EA_INFORMATION EaInformation;
	FILE_ACCESS_INFORMATION AccessInformation;
	FILE_POSITION_INFORMATION PositionInformation;
	FILE_MODE_INFORMATION ModeInformation;
	FILE_ALIGNMENT_INFORMATION AlignmentInformation;
	FILE_NAME_INFORMATION NameInformation;
} FILE_ALL_INFORMATION, *PFILE_ALL_INFORMATION;
typedef struct _FILE_FS_ATTRIBUTE_INFORMATION {
	u32 FileSystemAttributes;
	s32 MaximumComponentNameLength;
	u32 FileSystemNameLength;
	WCHAR FileSystemName[1];
} FILE_FS_ATTRIBUTE_INFORMATION, *PFILE_FS_ATTRIBUTE_INFORMATION;

typedef struct _FILE_OBJECTID_BUFFER {

	u8 ObjectId[16];

	union {
		struct {
			u8 BirthVolumeId[16];
			u8 BirthObjectId[16];
			u8 DomainId[16];
		};
		u8 ExtendedInfo[48];
	};

} FILE_OBJECTID_BUFFER, *PFILE_OBJECTID_BUFFER;
typedef struct RETRIEVAL_POINTERS_BUFFER {

	DWORD ExtentCount;
	LARGE_INTEGER StartingVcn;
	struct {
		LARGE_INTEGER NextVcn;
		LARGE_INTEGER Lcn;
	} Extents[1];

} RETRIEVAL_POINTERS_BUFFER, *PRETRIEVAL_POINTERS_BUFFER;

typedef struct {

	LARGE_INTEGER StartingVcn;

} STARTING_VCN_INPUT_BUFFER, *PSTARTING_VCN_INPUT_BUFFER;

typedef enum _PARTITION_STYLE {
	PARTITION_STYLE_MBR,
	PARTITION_STYLE_GPT,
	PARTITION_STYLE_RAW
} PARTITION_STYLE;
typedef struct _PARTITION_INFORMATION_MBR {

	BYTE PartitionType;

	BOOLEAN BootIndicator;

	BOOLEAN RecognizedPartition;

	DWORD HiddenSectors;

#if (NTDDI_VERSION >= NTDDI_WINBLUE) /* ABRACADABRA_THRESHOLD */
	GUID PartitionId;
#endif

} PARTITION_INFORMATION_MBR, *PPARTITION_INFORMATION_MBR;
typedef struct _PARTITION_INFORMATION_GPT {

	GUID PartitionType; // Partition type. See table 16-3.

	GUID PartitionId; // Unique GUID for this partition.

	DWORD64 Attributes; // See table 16-4.

	WCHAR Name[36]; // Partition Name in Unicode.

} PARTITION_INFORMATION_GPT, *PPARTITION_INFORMATION_GPT;
typedef struct _PARTITION_INFORMATION_EX {

	PARTITION_STYLE PartitionStyle;

	LARGE_INTEGER StartingOffset;

	LARGE_INTEGER PartitionLength;

	DWORD PartitionNumber;

	BOOLEAN RewritePartition;

#if (NTDDI_VERSION >= NTDDI_WIN10_RS3) /* ABRACADABRA_WIN10_RS3 */
	BOOLEAN IsServicePartition;
#endif

	union {

		PARTITION_INFORMATION_MBR Mbr;

		PARTITION_INFORMATION_GPT Gpt;

	} ;

} PARTITION_INFORMATION_EX, *PPARTITION_INFORMATION_EX;
typedef struct _DRIVE_LAYOUT_INFORMATION_GPT {

	GUID DiskId;

	LARGE_INTEGER StartingUsableOffset;

	LARGE_INTEGER UsableLength;

	DWORD MaxPartitionCount;

} DRIVE_LAYOUT_INFORMATION_GPT, *PDRIVE_LAYOUT_INFORMATION_GPT;

typedef struct _DRIVE_LAYOUT_INFORMATION_MBR {

	DWORD Signature;

#if (NTDDI_VERSION >= NTDDI_WIN10_RS1) /* ABRACADABRA_WIN10_RS1 */
	DWORD CheckSum;
#endif

} DRIVE_LAYOUT_INFORMATION_MBR, *PDRIVE_LAYOUT_INFORMATION_MBR;
typedef struct _DRIVE_LAYOUT_INFORMATION_EX {

	DWORD PartitionStyle;

	DWORD PartitionCount;

	union {

		DRIVE_LAYOUT_INFORMATION_MBR Mbr;

		DRIVE_LAYOUT_INFORMATION_GPT Gpt;

	};

	PARTITION_INFORMATION_EX PartitionEntry[1];

} DRIVE_LAYOUT_INFORMATION_EX, *PDRIVE_LAYOUT_INFORMATION_EX;
typedef struct _DISK_EXTENT {

	//
	// Specifies the storage device number of
	// the disk on which this extent resides.
	//
	DWORD DiskNumber;

	//
	// Specifies the offset and length of this
	// extent relative to the beginning of the
	// disk.
	//
	LARGE_INTEGER StartingOffset;
	LARGE_INTEGER ExtentLength;

} DISK_EXTENT, *PDISK_EXTENT;
typedef struct _VOLUME_DISK_EXTENTS {

	//
	// Specifies one or more contiguous range
	// of sectors that make up this volume.
	//
	DWORD NumberOfDiskExtents;
	DISK_EXTENT Extents[ANYSIZE_ARRAY];

} VOLUME_DISK_EXTENTS, *PVOLUME_DISK_EXTENTS;
#pragma endregion
NTSTATUS __stdcall NtFsControlFile(HANDLE FileHandle, HANDLE Event,
				   PIO_APC_ROUTINE ApcRoutine, PVOID ApcContext,
				   PIO_STATUS_BLOCK IoStatusBlock,
				   ULONG FsControlCode, PVOID InputBuffer,
				   ULONG InputBufferLength, PVOID OutputBuffer,
				   ULONG OutputBufferLength);
NTSTATUS __stdcall NtSetInformationFile(
    HANDLE FileHandle, PIO_STATUS_BLOCK IoStatusBlock, PVOID FileInformation,
    ULONG Length, FILE_INFORMATION_CLASS FileInformationClass);
NTSTATUS __stdcall NtQueryInformationFile(
    HANDLE FileHandle, PIO_STATUS_BLOCK IoStatusBlock, PVOID FileInformation,
    ULONG Length, FILE_INFORMATION_CLASS FileInformationClass);
NTSTATUS __stdcall NtQueryVolumeInformationFile(
    HANDLE FileHandle, PIO_STATUS_BLOCK IoStatusBlock, PVOID FsInformation,
    ULONG Length, FS_INFORMATION_CLASS FsInformationClass);
BOOLEAN __stdcall RtlDosPathNameToNtPathName_U(PCWSTR DosName, PUNICODE_STRING NtName,
			     PCWSTR *PartName,
			     PRTL_RELATIVE_NAME_U RelativeName);
#endif
#endif /* _WIMLIB_WIN32_COMMON_H */
