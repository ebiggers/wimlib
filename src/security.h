/*
 *
 * Macros and structures for security descriptors
 *
 * From Microsoft's public documentation and the WINE project
 */

#include "util.h"

#ifndef _WIMLIB_SECURITY_H
#define _WIMLIB_SECURITY_H

#define	SECURITY_DESCRIPTOR_REVISION	1
#define	SECURITY_DESCRIPTOR_REVISION1	1

/* inherit AceFlags */
#define	OBJECT_INHERIT_ACE		0x01
#define	CONTAINER_INHERIT_ACE		0x02
#define	NO_PROPAGATE_INHERIT_ACE	0x04
#define	INHERIT_ONLY_ACE		0x08
#define	INHERITED_ACE		        0x10
#define	VALID_INHERIT_FLAGS		0x1F

#define SE_OWNER_DEFAULTED		0x00000001
#define SE_GROUP_DEFAULTED		0x00000002
#define SE_DACL_PRESENT			0x00000004
#define SE_DACL_DEFAULTED		0x00000008
#define SE_SACL_PRESENT			0x00000010
#define SE_SACL_DEFAULTED		0x00000020
#define SE_DACL_AUTO_INHERIT_REQ	0x00000100
#define SE_SACL_AUTO_INHERIT_REQ	0x00000200
#define SE_DACL_AUTO_INHERITED		0x00000400
#define SE_SACL_AUTO_INHERITED		0x00000800
#define SE_DACL_PROTECTED 		0x00001000
#define SE_SACL_PROTECTED 		0x00002000
#define SE_RM_CONTROL_VALID		0x00004000
#define SE_SELF_RELATIVE		0x00008000

/* Flags in access control entries */
#define DELETE                     0x00010000
#define READ_CONTROL               0x00020000
#define WRITE_DAC                  0x00040000
#define WRITE_OWNER                0x00080000
#define SYNCHRONIZE                0x00100000
#define STANDARD_RIGHTS_REQUIRED   0x000f0000

#define STANDARD_RIGHTS_READ       READ_CONTROL
#define STANDARD_RIGHTS_WRITE      READ_CONTROL
#define STANDARD_RIGHTS_EXECUTE    READ_CONTROL

#define STANDARD_RIGHTS_ALL        0x001f0000

#define SPECIFIC_RIGHTS_ALL        0x0000ffff

#define GENERIC_READ               0x80000000
#define GENERIC_WRITE              0x40000000
#define GENERIC_EXECUTE            0x20000000
#define GENERIC_ALL                0x10000000

#define MAXIMUM_ALLOWED            0x02000000
#define ACCESS_SYSTEM_SECURITY     0x01000000

#define EVENT_QUERY_STATE          0x0001
#define EVENT_MODIFY_STATE         0x0002
#define EVENT_ALL_ACCESS           (STANDARD_RIGHTS_REQUIRED|SYNCHRONIZE|0x3)

#define SEMAPHORE_MODIFY_STATE     0x0002
#define SEMAPHORE_ALL_ACCESS       (STANDARD_RIGHTS_REQUIRED|SYNCHRONIZE|0x3)

#define MUTEX_MODIFY_STATE         0x0001
#define MUTEX_ALL_ACCESS           (STANDARD_RIGHTS_REQUIRED|SYNCHRONIZE|0x1)

#define JOB_OBJECT_ASSIGN_PROCESS           0x0001
#define JOB_OBJECT_SET_ATTRIBUTES           0x0002
#define JOB_OBJECT_QUERY                    0x0004
#define JOB_OBJECT_TERMINATE                0x0008
#define JOB_OBJECT_SET_SECURITY_ATTRIBUTES  0x0010
#define JOB_OBJECT_ALL_ACCESS               (STANDARD_RIGHTS_REQUIRED|SYNCHRONIZE|0x1f)

#define TIMER_QUERY_STATE          0x0001
#define TIMER_MODIFY_STATE         0x0002
#define TIMER_ALL_ACCESS           (STANDARD_RIGHTS_REQUIRED|SYNCHRONIZE|0x3)

#define PROCESS_TERMINATE          0x0001
#define PROCESS_CREATE_THREAD      0x0002
#define PROCESS_VM_OPERATION       0x0008
#define PROCESS_VM_READ            0x0010
#define PROCESS_VM_WRITE           0x0020
#define PROCESS_DUP_HANDLE         0x0040
#define PROCESS_CREATE_PROCESS     0x0080
#define PROCESS_SET_QUOTA          0x0100
#define PROCESS_SET_INFORMATION    0x0200
#define PROCESS_QUERY_INFORMATION  0x0400
#define PROCESS_SUSPEND_RESUME     0x0800
#define PROCESS_QUERY_LIMITED_INFORMATION 0x1000
#define PROCESS_ALL_ACCESS         (STANDARD_RIGHTS_REQUIRED|SYNCHRONIZE|0xfff)

#define THREAD_TERMINATE           0x0001
#define THREAD_SUSPEND_RESUME      0x0002
#define THREAD_GET_CONTEXT         0x0008
#define THREAD_SET_CONTEXT         0x0010
#define THREAD_SET_INFORMATION     0x0020
#define THREAD_QUERY_INFORMATION   0x0040
#define THREAD_SET_THREAD_TOKEN    0x0080
#define THREAD_IMPERSONATE         0x0100
#define THREAD_DIRECT_IMPERSONATION 0x0200
#define THREAD_ALL_ACCESS          (STANDARD_RIGHTS_REQUIRED|SYNCHRONIZE|0x3ff)

#define THREAD_BASE_PRIORITY_LOWRT  15
#define THREAD_BASE_PRIORITY_MAX    2
#define THREAD_BASE_PRIORITY_MIN   -2
#define THREAD_BASE_PRIORITY_IDLE  -15

/* predefined authority values for SID's (security identifiers) */
enum sid_authority_value {
	SECURITY_NULL_SID_AUTHORITY    = 0,
	SECURITY_WORLD_SID_AUTHORITY   = 1,
	SECURITY_LOCAL_SID_AUTHORITY   = 2,
	SECURITY_CREATOR_SID_AUTHORITY = 3,
	SECURITY_NON_UNIQUE_AUTHORITY  = 4,
	SECURITY_NT_AUTHORITY          = 5,
};

/* local administrators group */
#define SECURITY_BUILTIN_DOMAIN_RID 32
#define DOMAIN_ALIAS_RID_ADMINS     544

/* See ACEHeader. */
enum ace_type {
	ACCESS_ALLOWED_ACE_TYPE = 0,
	ACCESS_DENIED_ACE_TYPE  = 1,
	SYSTEM_AUDIT_ACE_TYPE   = 2,
};

/* At the start of each type of access control entry.  */
typedef struct {
	/* enum ace_type, specifies what type of ACE this is.  */
	u8 type;

	/* bitwise OR of the inherit ACE flags #defined above */
	u8 flags;

	/* Size of the access control entry. */
	u8 size;
} ACEHeader;

/* Grants rights to a user or group */
typedef struct {
	ACEHeader hdr;
	u32 mask;
	u32 sid_start;
} AccessAllowedACE;

/* Denies rights to a user or group */
typedef struct {
	ACEHeader hdr;
	u32 mask;
	u32 sid_start;
} AccessDeniedACE;

typedef struct {
	ACEHeader hdr;
	u32 mask;
	u32 sid_start;
} SystemAuditACE;


/* Header of an access control list. */
typedef struct {
	/* ACL_REVISION or ACL_REVISION_DS */
	u8 revision;

	/* padding */
	u8 sbz1;

	/* Total size of the ACL, including all access control entries */
	u16 acl_size;

	/* Number of access control entry structures that follow the ACL
	 * structure. */
	u16 ace_count;

	/* padding */
	u16 sbz2;
} ACL;

/* A structure used to identify users or groups. */
typedef struct {

	/* example: 0x1 */
	u8  revision;
	u8  sub_authority_count;

	/* Identifies the authority that issued the SID.  Can be, but does not
	 * have to be, one of enum sid_authority_value */
	u8  identifier_authority[6];

	u32 sub_authority[0];
} SID;


typedef struct {
	/* Example: 0x1 */
	u8 revision;
	/* Example: 0x0 */
	u8 sbz1;
	/* Example: 0x4149 */
	u16 security_descriptor_control;

	/* Offset of a SID structure in the security descriptor. */
	/* Example: 0x14 */
	u32 owner_offset;

	/* Offset of a SID structure in the security descriptor. */
	/* Example: 0x24 */
	u32 group_offset;

	/* Offset of an ACL structure in the security descriptor. */
	/* System ACL. */
	/* Example: 0x00 */
	u32 sacl_offset;

	/* Offset of an ACL structure in the security descriptor. */
	/* Discretionary ACL. */
	/* Example: 0x34 */
	u32 dacl_offset;
} SecurityDescriptor;


#endif /* _WIMLIB_SECURITY_H */
