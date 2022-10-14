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

#ifndef _HADAFS_H
#define _HADAFS_H

#ifndef _CONFIG_H
#define _CONFIG_H
#include "config.h"
#endif

#include <stdio.h>
#include <string.h>
#include <stdlib.h>
#include <netinet/in.h>
#include <sys/socket.h>
#include <sys/types.h>
#include <sys/stat.h>
#include <sys/statvfs.h>
#include <netdb.h>
#include <errno.h>
#include <dirent.h>
#include <unistd.h>
#include <fcntl.h>
#include <arpa/inet.h>
#include <sys/poll.h>
#include <pthread.h>

#include "list.h"
#include "logging.h"

#define HF_YES 1
#define HF_NO  0

#ifndef O_LARGEFILE
/* savannah bug #20053, patch for compiling on darwin */
#define O_LARGEFILE 0
#endif

#ifndef O_DIRECT
/* savannah bug #20050, #20052 */
#define O_DIRECT 0 /* From asm/fcntl.h */
#endif

#ifndef O_DIRECTORY
/* FreeBSD does not need O_DIRECTORY */
#define O_DIRECTORY 0
#endif

#define ZR_FILE_CONTENT_STR     "hadafs.file."
#define ZR_FILE_CONTENT_STRLEN 15

#define HADAFS_OPEN_FD_COUNT "hadafs.open-fd-count"

#define ZR_FILE_CONTENT_REQUEST(key) (!strncmp(key, ZR_FILE_CONTENT_STR, \
					       ZR_FILE_CONTENT_STRLEN))

/* TODO: Should we use PATH-MAX? On some systems it may save space */
#define ZR_PATH_MAX 512
#define LONG_NAME ZR_PATH_MAX

/* This is used as the maximum permitted filename length over FS. 
 * If the backend FS supports higher than this, it should be changed. 
 */
#define ZR_FILENAME_MAX 256
#define SHORT_NAME 128


/* NOTE: add members ONLY at the end (just before _MAXVALUE) */
typedef enum {
		HF_FOP_UNLINK,  /* 0 */
		HF_FOP_STAT,
		HF_FOP_FSTAT,
		HF_FOP_OPEN,
		HF_FOP_READ,
		HF_FOP_WRITE, /* 5 */
		HF_FOP_FLUSH,
		HF_FOP_SETOBJECT,
		HF_FOP_UPDATEOBJECT,
		HF_FOP_GETOBJECT,
		HF_FOP_LOOKUPOBJECT,
		HF_FOP_DELETEOBJECT,
		HF_FOP_IOCTL,
		HF_FOP_CHECKSUM, /* 8 */
		HF_FOP_TRUNCATE,
		HF_FOP_FTRUNCATE,
		HF_FOP_MAXVALUE
} hadafs_fop_t;

/* NOTE: add members ONLY at the end (just before _MAXVALUE) */
typedef enum {
        HF_MOP_SETVOLUME, /* 0 */
        HF_MOP_GETVOLUME, /* 1 */
        HF_MOP_STATS,
        HF_MOP_SETSPEC,
        HF_MOP_GETSPEC,
	HF_MOP_PING,
        HF_MOP_MAXVALUE   /* 5 */
} hadafs_mop_t;

typedef enum {
	HF_CBK_FORGET,      /* 0 */
	HF_CBK_RELEASE,     /* 1 */
	HF_CBK_MAXVALUE     /* 2 */
} hadafs_cbk_t;

typedef enum {
        HF_OP_TYPE_FOP_REQUEST = 1,
        HF_OP_TYPE_MOP_REQUEST,
	HF_OP_TYPE_CBK_REQUEST,
        HF_OP_TYPE_FOP_REPLY,
        HF_OP_TYPE_MOP_REPLY,
	HF_OP_TYPE_CBK_REPLY
} hadafs_op_type_t;

#define HF_SET_IF_NOT_PRESENT 0x1 /* default behaviour */
#define HF_SET_OVERWRITE      0x2 /* Overwrite with the buf given */
#define HF_SET_DIR_ONLY       0x4
#define HF_SET_EPOCH_TIME     0x8 /* used by afr dir lookup selfheal */

#define HF_REPLICATE_TRASH_DIR          ".landfill"

struct _xlator_cmdline_option {
	struct list_head cmd_args;
	char *volume;
	char *key;
	char *value;
};
typedef struct _xlator_cmdline_option xlator_cmdline_option_t;

struct _cmd_args {
	/* basic options */
	char		*volfile_server;
	char            *server_type;
	char            *volume_file;
	hf_loglevel_t    log_level;
	char            *log_file;
        int32_t          max_connect_attempts;
	/* advanced options */
	uint32_t         volfile_server_port;
	char            *volfile_server_transport;
	char            *pid_file;
	char		*volume_name;
	int              no_daemon_mode;
	char            *run_id;
	int              debug_mode;
	struct list_head xlator_options;  /* list of xlator_option_t */
	
	/* key args */
	char            *mount_point;
	char            *volfile_id;
};
typedef struct _cmd_args cmd_args_t;

struct _hadafs_ctx {
	cmd_args_t         cmd_args;
	char              *process_uuid;
	FILE              *specfp;
	FILE              *pidfp;
	char               fin;
	void              *timer;
	void              *ib;
	void	          *swnet;
	void              *pool;
	void              *graph;
	void              *top; /* either fuse or server protocol */
	void              *event_pool;
        void              *iobuf_pool;
	pthread_mutex_t    lock;
	int                xl_count;
        uint32_t           volfile_checksum;
        size_t             page_size;
};

typedef struct _hadafs_ctx hadafs_ctx_t;

typedef enum {
  HF_EVENT_PARENT_UP = 1,
  HF_EVENT_POLLIN,
  HF_EVENT_POLLOUT,
  HF_EVENT_POLLERR,
  HF_EVENT_CHILD_UP,
  HF_EVENT_CHILD_DOWN,
  HF_EVENT_CHILD_CONNECTING,
  HF_EVENT_TRANSPORT_CLEANUP,
  HF_EVENT_TRANSPORT_CONNECTED,
  HF_EVENT_VOLFILE_MODIFIED,
} hadafs_event_t;

#define HF_MUST_CHECK __attribute__((warn_unused_result))

#endif /* _HADAFS_H */
