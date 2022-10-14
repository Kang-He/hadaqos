/*
  Copyright (c) 2006-2009 HADA, Inc. <http://www.hada.com>
  This file is part of HADAFS.

  HADAFS is free software; you can redistribute it and/or modify
  it under the terms of the GNU General Public License as published
  by the Free Software Foundation; either version 3 of the License,
  or (at your option) any later version.

  HADAFS is distributed in the hope that it will be useful, but
  WITHOUT ANY WARRANTY; without even the implied warranty of
  MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the GNU
  General Public License for more details.

  You should have received a copy of the GNU General Public License
  along with this program.  If not, see
  <http://www.gnu.org/licenses/>.
*/

#ifndef _PROTOCOL_H
#define _PROTOCOL_H

#ifndef _CONFIG_H
#define _CONFIG_H
#include "config.h"
#endif

#include <inttypes.h>
#include <sys/time.h>
#include <sys/types.h>
#include <sys/stat.h>
#include <sys/statvfs.h>
#include <unistd.h>
#include <fcntl.h>

#include "byte-order.h"

/* Any changes in the protocol structure or adding new '[f,m]ops' needs to 
 * bump the protocol version by "0.1" 
 */
/* Protocol version 1.0 was ASCII based dictionary protocol */
#define HF_PROTOCOL_VERSION "0.0"

struct hf_stat {
	uint64_t ino;
	uint64_t size;
	uint64_t blocks;
	uint32_t dev;
	uint32_t rdev;
	uint32_t mode;
	uint32_t nlink;
	uint32_t uid;
	uint32_t gid;
	uint32_t blksize;
	uint32_t atime;
	uint32_t atime_nsec;
	uint32_t mtime;
	uint32_t mtime_nsec;
	uint32_t ctime;
	uint32_t ctime_nsec;
} __attribute__((packed));

static inline void
hf_stat_to_stat (struct hf_stat *hf_stat, struct stat *stat)
{
	stat->st_dev          = ntoh32 (hf_stat->dev);
	stat->st_ino          = ntoh64 (hf_stat->ino);
	stat->st_mode         = ntoh32 (hf_stat->mode);
	stat->st_nlink        = ntoh32 (hf_stat->nlink);
	stat->st_uid          = ntoh32 (hf_stat->uid);
	stat->st_gid          = ntoh32 (hf_stat->gid);
	stat->st_rdev         = ntoh32 (hf_stat->rdev);
	stat->st_size         = ntoh64 (hf_stat->size);
	stat->st_blksize      = ntoh32 (hf_stat->blksize);
	stat->st_blocks       = ntoh64 (hf_stat->blocks);
	stat->st_atime        = ntoh32 (hf_stat->atime);
	stat->st_mtime        = ntoh32 (hf_stat->mtime);
	stat->st_ctime        = ntoh32 (hf_stat->ctime);
	/* TODO: handle nsec */
}


static inline void
hf_stat_from_stat (struct hf_stat *hf_stat, struct stat *stat)
{
	hf_stat->dev         = hton32 (stat->st_dev);
	hf_stat->ino         = hton64 (stat->st_ino);
	hf_stat->mode        = hton32 (stat->st_mode);
	hf_stat->nlink       = hton32 (stat->st_nlink);
	hf_stat->uid         = hton32 (stat->st_uid);
	hf_stat->gid         = hton32 (stat->st_gid);
	hf_stat->rdev        = hton32 (stat->st_rdev);
	hf_stat->size        = hton64 (stat->st_size);
	hf_stat->blksize     = hton32 (stat->st_blksize);
	hf_stat->blocks      = hton64 (stat->st_blocks);
	hf_stat->atime       = hton32 (stat->st_atime);
	hf_stat->mtime       = hton32 (stat->st_mtime);
	hf_stat->ctime       = hton32 (stat->st_ctime);
	/* TODO: handle nsec */
}


struct hf_statfs {
	uint64_t bsize;
	uint64_t frsize;
	uint64_t blocks;
	uint64_t bfree;
	uint64_t bavail;
	uint64_t files;
	uint64_t ffree;
	uint64_t favail;
	uint64_t fsid;
	uint64_t flag;
	uint64_t namemax;
} __attribute__((packed));


static inline void
hf_statfs_to_statfs (struct hf_statfs *hf_stat, struct statvfs *stat)
{
	stat->f_bsize   = ntoh64 (hf_stat->bsize);
	stat->f_frsize  = ntoh64 (hf_stat->frsize);
	stat->f_blocks  = ntoh64 (hf_stat->blocks);
	stat->f_bfree   = ntoh64 (hf_stat->bfree);
	stat->f_bavail  = ntoh64 (hf_stat->bavail);
	stat->f_files   = ntoh64 (hf_stat->files);
	stat->f_ffree   = ntoh64 (hf_stat->ffree);
	stat->f_favail  = ntoh64 (hf_stat->favail);
	stat->f_fsid    = ntoh64 (hf_stat->fsid);
	stat->f_flag    = ntoh64 (hf_stat->flag);
	stat->f_namemax = ntoh64 (hf_stat->namemax);
}


static inline void
hf_statfs_from_statfs (struct hf_statfs *hf_stat, struct statvfs *stat)
{
	hf_stat->bsize   = hton64 (stat->f_bsize);
	hf_stat->frsize  = hton64 (stat->f_frsize);
	hf_stat->blocks  = hton64 (stat->f_blocks);
	hf_stat->bfree   = hton64 (stat->f_bfree);
	hf_stat->bavail  = hton64 (stat->f_bavail);
	hf_stat->files   = hton64 (stat->f_files);
	hf_stat->ffree   = hton64 (stat->f_ffree);
	hf_stat->favail  = hton64 (stat->f_favail);
	hf_stat->fsid    = hton64 (stat->f_fsid);
	hf_stat->flag    = hton64 (stat->f_flag);
	hf_stat->namemax = hton64 (stat->f_namemax);
}


struct hf_flock {
	uint16_t type;
	uint16_t whence;
	uint64_t start;
	uint64_t len;
	uint32_t pid;
} __attribute__((packed));


static inline void
hf_flock_to_flock (struct hf_flock *hf_flock, struct flock *flock)
{
	flock->l_type   = ntoh16 (hf_flock->type);
	flock->l_whence = ntoh16 (hf_flock->whence);
	flock->l_start  = ntoh64 (hf_flock->start);
	flock->l_len    = ntoh64 (hf_flock->len);
	flock->l_pid    = ntoh32 (hf_flock->pid);
}


static inline void
hf_flock_from_flock (struct hf_flock *hf_flock, struct flock *flock)
{
	hf_flock->type   = hton16 (flock->l_type);
	hf_flock->whence = hton16 (flock->l_whence);
	hf_flock->start  = hton64 (flock->l_start);
	hf_flock->len    = hton64 (flock->l_len);
	hf_flock->pid    = hton32 (flock->l_pid);
}


struct hf_timespec {
	uint32_t tv_sec;
	uint32_t tv_nsec;
} __attribute__((packed));


static inline void
hf_timespec_to_timespec (struct hf_timespec *hf_ts, struct timespec *ts)
{

	ts[0].tv_sec  = ntoh32 (hf_ts[0].tv_sec);
	ts[0].tv_nsec = ntoh32 (hf_ts[0].tv_nsec);
	ts[1].tv_sec  = ntoh32 (hf_ts[1].tv_sec);
	ts[1].tv_nsec = ntoh32 (hf_ts[1].tv_nsec);
}


static inline void
hf_timespec_from_timespec (struct hf_timespec *hf_ts, struct timespec *ts)
{
	hf_ts[0].tv_sec  = hton32 (ts[0].tv_sec);
	hf_ts[0].tv_nsec = hton32 (ts[0].tv_nsec);
	hf_ts[1].tv_sec  = hton32 (ts[1].tv_sec);
	hf_ts[1].tv_nsec = hton32 (ts[1].tv_nsec);
}


#define HF_O_ACCMODE           003
#define HF_O_RDONLY             00
#define HF_O_WRONLY             01
#define HF_O_RDWR               02
#define HF_O_CREAT            0100
#define HF_O_EXCL             0200
#define HF_O_NOCTTY           0400
#define HF_O_TRUNC           01000
#define HF_O_APPEND          02000
#define HF_O_NONBLOCK        04000
#define HF_O_SYNC           010000

#define HF_O_DIRECT         040000
#define HF_O_DIRECTORY     0200000
#define HF_O_NOFOLLOW      0400000

#define HF_O_LARGEFILE     0100000

#define XLATE_BIT(from, to, bit)    do {                \
                if (from & bit)                         \
                        to = to | HF_##bit;             \
        } while (0)

#define UNXLATE_BIT(from, to, bit)  do {                \
                if (from & HF_##bit)                    \
                        to = to | bit;                  \
        } while (0)

#define XLATE_ACCESSMODE(from, to) do {                 \
                switch (from & O_ACCMODE) {             \
                case O_RDONLY: to |= HF_O_RDONLY;       \
                        break;                          \
                case O_WRONLY: to |= HF_O_WRONLY;       \
                        break;                          \
                case O_RDWR: to |= HF_O_RDWR;           \
                        break;                          \
                }                                       \
        } while (0)

#define UNXLATE_ACCESSMODE(from, to) do {               \
                switch (from & HF_O_ACCMODE) {          \
                case HF_O_RDONLY: to |= O_RDONLY;       \
                        break;                          \
                case HF_O_WRONLY: to |= O_WRONLY;       \
                        break;                          \
                case HF_O_RDWR: to |= O_RDWR;           \
                        break;                          \
                }                                       \
        } while (0)

static inline uint32_t
hf_flags_from_flags (uint32_t flags)
{
        uint32_t hf_flags = 0;

        XLATE_ACCESSMODE (flags, hf_flags);

        XLATE_BIT (flags, hf_flags, O_CREAT);
        XLATE_BIT (flags, hf_flags, O_EXCL);
        XLATE_BIT (flags, hf_flags, O_NOCTTY);
        XLATE_BIT (flags, hf_flags, O_TRUNC);
        XLATE_BIT (flags, hf_flags, O_APPEND);
        XLATE_BIT (flags, hf_flags, O_NONBLOCK);
        XLATE_BIT (flags, hf_flags, O_SYNC);

        XLATE_BIT (flags, hf_flags, O_DIRECT);
        XLATE_BIT (flags, hf_flags, O_DIRECTORY);
        XLATE_BIT (flags, hf_flags, O_NOFOLLOW);

        XLATE_BIT (flags, hf_flags, O_LARGEFILE);

        return hf_flags;
}

static inline uint32_t
hf_flags_to_flags (uint32_t hf_flags)
{
        uint32_t flags = 0;

        UNXLATE_ACCESSMODE (hf_flags, flags);

        UNXLATE_BIT (hf_flags, flags, O_CREAT);
        UNXLATE_BIT (hf_flags, flags, O_EXCL);
        UNXLATE_BIT (hf_flags, flags, O_NOCTTY);
        UNXLATE_BIT (hf_flags, flags, O_TRUNC);
        UNXLATE_BIT (hf_flags, flags, O_APPEND);
        UNXLATE_BIT (hf_flags, flags, O_NONBLOCK);
        UNXLATE_BIT (hf_flags, flags, O_SYNC);

        UNXLATE_BIT (hf_flags, flags, O_DIRECT);
        UNXLATE_BIT (hf_flags, flags, O_DIRECTORY);
        UNXLATE_BIT (hf_flags, flags, O_NOFOLLOW);

        UNXLATE_BIT (hf_flags, flags, O_LARGEFILE);

        return flags;
}

typedef struct {	
	uint64_t soffset;
	char     path[0];     /* NULL terminated */
	char     sid[0];	
} __attribute__((packed)) hf_fop_unlink_req_t;
typedef struct {
} __attribute__((packed)) hf_fop_unlink_rsp_t;

typedef struct {
	int64_t  fd;
	uint64_t offset;
} __attribute__((packed)) hf_fop_ftruncate_req_t;
typedef struct {
        struct hf_stat poststat;
} __attribute__((packed)) hf_fop_ftruncate_rsp_t;

typedef struct {
	uint64_t offset;
	uint64_t soffset;
	char     path[0];
	char     sid[0];	
} __attribute__((packed)) hf_fop_truncate_req_t;

typedef struct {
        struct hf_stat poststat;
} __attribute__((packed)) hf_fop_truncate_rsp_t;
typedef struct {
	uint64_t soffset;
	char     path[0];     /* NULL terminated */
	char     sid[0];	
} __attribute__((packed)) hf_fop_stat_req_t;;
typedef struct {
	struct hf_stat stat;
} __attribute__((packed)) hf_fop_stat_rsp_t;

typedef struct {
	int64_t  fd;
} __attribute__((packed)) hf_fop_fstat_req_t;
typedef struct {
	struct hf_stat stat;
} __attribute__((packed)) hf_fop_fstat_rsp_t;

typedef struct {
	uint64_t ino;
	int64_t  fd;
	uint64_t offset;
	uint32_t size;
} __attribute__((packed)) hf_fop_read_req_t;
typedef struct {
	struct hf_stat stat;
	char buf[0];
} __attribute__((packed)) hf_fop_read_rsp_t;

typedef struct {
	uint64_t ino;
	int64_t  fd;
	uint64_t offset;
	uint32_t size;
} __attribute__((packed)) hf_fop_write_req_t;
typedef struct {
	struct hf_stat stat;
} __attribute__((packed)) hf_fop_write_rsp_t;

typedef struct {
	int64_t  fd;
	uint32_t cmd; /* More data can be included here */
} __attribute__((packed)) hf_fop_ioctl_req_t;
typedef struct {
} __attribute__((packed)) hf_fop_ioctl_rsp_t;
typedef struct {
	uint64_t ino;
	int64_t  fd;
} __attribute__((packed)) hf_fop_flush_req_t;
typedef struct {
        struct hf_stat stat;
} __attribute__((packed)) hf_fop_flush_rsp_t;
typedef struct {
	metadata_t object_info;
	char path[0];
} __attribute__ ((packed)) hf_fop_setobject_req_t;
typedef struct {
	uint32_t  object_status;
} __attribute__ ((packed)) hf_fop_setobject_rsp_t;
typedef struct {
	int32_t updatebits;
	metadata_t  object_info;
	char path[0];
} __attribute__ ((packed)) hf_fop_updateobject_req_t;
typedef struct {
	uint32_t object_status;
} __attribute__ ((packed)) hf_fop_updateobject_rsp_t;
typedef struct {
	char path[0];
} __attribute__ ((packed)) hf_fop_getobject_req_t;
typedef struct {
	uint32_t object_status;
	metadata_t object_info;
} __attribute__ ((packed)) hf_fop_getobject_rsp_t;
typedef struct {
	char path[0];
} __attribute__ ((packed)) hf_fop_lookupobject_req_t;
typedef struct {
	uint32_t object_status;
	metadata_t object_info;
} __attribute__ ((packed)) hf_fop_lookupobject_rsp_t;
typedef struct {
	char path[0];
} __attribute__ ((packed)) hf_fop_deleteobject_req_t;
typedef struct {
	uint32_t object_status;
} __attribute__ ((packed)) hf_fop_deleteobject_rsp_t;
typedef struct {
	uint32_t flags;
	uint32_t mode;
	uint32_t soffset;
	char	 vmp[0];
	char     sid[0];
	char     path[0];
} __attribute__((packed)) hf_fop_open_req_t;
typedef struct {
	uint64_t       fd;
	struct hf_stat stat;
} __attribute__((packed)) hf_fop_open_rsp_t;
typedef struct {
	uint64_t  ino;
	uint32_t  flag;
	char      path[0];
} __attribute__((packed)) hf_fop_checksum_req_t;
typedef struct {
	unsigned char fchecksum[0];
} __attribute__((packed)) hf_fop_checksum_rsp_t;
typedef struct {
	uint32_t  flags;
} __attribute__((packed)) hf_mop_stats_req_t;
typedef struct {
	char buf[0];
} __attribute__((packed)) hf_mop_stats_rsp_t;
typedef struct {
	uint32_t flags;
	uint32_t keylen;
	char     key[0];
} __attribute__((packed)) hf_mop_getspec_req_t;
typedef struct {
	char spec[0];
} __attribute__((packed)) hf_mop_getspec_rsp_t;


typedef struct {
	uint32_t dict_len;
	char buf[0];
} __attribute__((packed)) hf_mop_setvolume_req_t;
typedef struct {
	uint32_t dict_len;
	char buf[0];
} __attribute__((packed)) hf_mop_setvolume_rsp_t;


typedef struct {
} __attribute__((packed)) hf_mop_ping_req_t;
typedef struct {
} __attribute__((packed)) hf_mop_ping_rsp_t;


typedef struct {
	uint64_t ino;
	int64_t fd;
} __attribute__((packed)) hf_cbk_release_req_t;
typedef struct {
} __attribute__((packed)) hf_cbk_release_rsp_t;


typedef struct {
	uint32_t count;
	uint32_t pathlen_array[0];
	char path_array[0];
} __attribute__((packed)) hf_cbk_forget_req_t;
typedef struct { } __attribute__((packed)) hf_cbk_forget_rsp_t;


typedef struct {
	uint32_t pid;
	uint32_t uid;
	uint32_t gid;
} __attribute__ ((packed)) hf_hdr_req_t;


typedef struct {
	uint32_t op_ret;
	uint32_t op_errno;
} __attribute__ ((packed)) hf_hdr_rsp_t;


typedef struct {
	uint64_t callid;
	uint32_t type;
	uint32_t op;
	uint32_t size;
	union {
		hf_hdr_req_t req;
		hf_hdr_rsp_t rsp;
	} __attribute__ ((packed));
} __attribute__ ((packed)) hf_hdr_common_t;


static inline hf_hdr_common_t *
__hf_hdr_new (int size)
{
	hf_hdr_common_t *hdr = NULL;

	/* TODO: use mem-pool */
	hdr = CALLOC (sizeof (hf_hdr_common_t) + size, 1);

	if (!hdr) {
		return NULL;
	}

	hdr->size = hton32 (size);

	return hdr;
}


#define hf_hdr_len(type, x) (sizeof (hf_hdr_common_t) + sizeof (*type) + x)
#define hf_hdr_new(type, x) __hf_hdr_new (sizeof (*type) + x)


static inline void *
hf_param (hf_hdr_common_t *hdr)
{
	return ((void *)hdr) + sizeof (*hdr);
}

#endif
