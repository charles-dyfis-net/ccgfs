/*
 *	CC Network Filesystem (ccgfs)
 *	Mount Daemon
 *
 *	Copyright © CC Computer Consultants GmbH, 2007
 *	Contact: Jan Engelhardt <jengelh [at] computergmbh de>
 *
 *	This file is part of CCGFS. CCGFS is free software; you can
 *	redistribute it and/or modify it under the terms of the GNU
 *	General Public License as published by the Free Software
 *	Foundation; either version 2 or 3 of the License.
 */
#ifndef _CCGFS_PKT_H
#define _CCGFS_PKT_H 1

#include <limits.h>
#include <stdint.h>
#include <string.h>
#include "ccgfs.h"

enum {
	/* Wire protocol */
	PT_16       = 2,
	PT_32       = 4,
	PT_64       = 8,
	PT_DATA     = 255,
	PT_DATA_BIT = (1 << 31),

	/* Shortcuts for malloc */
	PV_16       = sizeof(uint32_t) + PT_16,
	PV_32       = sizeof(uint32_t) + PT_32,
	PV_64       = sizeof(uint32_t) + PT_64,
	PV_STRING   = sizeof(uint32_t) + PATH_MAX,
};

enum {
	CCGFS_CHMOD_REQUEST,
	CCGFS_CHOWN_REQUEST,
	CCGFS_CREATE_REQUEST,
	CCGFS_FGETATTR_REQUEST,
	CCGFS_FSYNC_REQUEST,
	CCGFS_FTRUNCATE_REQUEST,
	CCGFS_GETATTR_REQUEST,
	CCGFS_GETXATTR_REQUEST,
	CCGFS_LINK_REQUEST,
	CCGFS_LISTXATTR_REQUEST,
	CCGFS_MKDIR_REQUEST,
	CCGFS_MKNOD_REQUEST,
	CCGFS_OPEN_REQUEST,
	CCGFS_OPENDIR_REQUEST,
	CCGFS_READ_REQUEST,
	CCGFS_READDIR_REQUEST,
	CCGFS_READLINK_REQUEST,
	CCGFS_RELEASE_REQUEST,
	CCGFS_REMOVEXATTR_REQUEST,
	CCGFS_RENAME_REQUEST,
	CCGFS_RMDIR_REQUEST,
	CCGFS_SETXATTR_REQUEST,
	CCGFS_STATFS_REQUEST,
	CCGFS_SYMLINK_REQUEST,
	CCGFS_TRUNCATE_REQUEST,
	CCGFS_UNLINK_REQUEST,
	CCGFS_UTIMENS_REQUEST,
	CCGFS_WRITE_REQUEST,

	CCGFS_CREATE_RESPONSE,
	CCGFS_ERRNO_RESPONSE,
	CCGFS_GETATTR_RESPONSE,
	CCGFS_GETXATTR_RESPONSE,
	CCGFS_LISTXATTR_RESPONSE,
	CCGFS_OPEN_RESPONSE,
	CCGFS_READ_RESPONSE,
	CCGFS_READDIR_RESPONSE,
	CCGFS_READLINK_RESPONSE,
	CCGFS_STATFS_RESPONSE,

	CCGFS_FSINFO,
};

/**
 * local packet
 * @alloc:		allocated size of the data block
 * @space:		used size of the data block
 * @push_offset:	offset for new data
 * @data:		data
 */
struct lo_packet {
	unsigned int alloc, length, shift;
	void *data;
};

/**
 * ccgfs_pkt_header, ccgfs_fsid_header - header common to all packets
 * @opcode:	request/response type
 * @length:	length of total packet, including ccgfs_pkt_header
 * @fsuid:	UID to be used for this request
 * @fsgid:	GID to be used for this request
 */
struct ccgfs_pkt_header {
	uint32_t opcode, length;
};

struct ccgfs_fsid_header {
	uint32_t opcode, length;
	uint32_t fsuid, fsgid;
};

/* functions */
extern struct lo_packet *pkt_init(unsigned int, unsigned int);
extern void *pkt_resize(struct lo_packet *, unsigned int);
extern void pkt_push(struct lo_packet *, const void *, unsigned int,
	unsigned int);
extern uint32_t pkt_shift_32(struct lo_packet *);
extern uint64_t pkt_shift_64(struct lo_packet *);
extern const void *pkt_shift_s(struct lo_packet *);
extern struct lo_packet *pkt_recv(int);
extern void pkt_send(int, struct lo_packet *);
extern void pkt_destroy(struct lo_packet *);

/* inline functions */
static inline void pkt_push_32(struct lo_packet *pkt, uint32_t val)
{
	val = cpu_to_le32(val);
	pkt_push(pkt, &val, sizeof(val), PT_32);
}

static inline void pkt_push_64(struct lo_packet *pkt, uint64_t val)
{
	val = cpu_to_le64(val);
	pkt_push(pkt, &val, sizeof(val), PT_64);
}

static inline void pkt_push_s(struct lo_packet *pkt, const char *s)
{
	pkt_push(pkt, s, strlen(s) + 1, PT_DATA);
}

#endif /* _CCGFS_PKT_H */
