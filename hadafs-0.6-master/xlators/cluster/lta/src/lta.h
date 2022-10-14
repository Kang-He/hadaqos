/*
  Copyright (c) 2006-2009 LW, Inc. <http://www.lw.com>
  This file is part of LWFS.

  LWFS is free software; you can redistribute it and/or modify
  it under the terms of the GNU General Public License as published
  by the Free Software Foundation; either version 3 of the License,
  or (at your option) any later version.

  LWFS is distributed in the hope that it will be useful, but
  WITHOUT ANY WARRANTY; without even the implied warranty of
  MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the GNU
  General Public License for more details.

  You should have received a copy of the GNU General Public License
  along with this program.  If not, see
  <http://www.gnu.org/licenses/>.
*/

#ifndef _CONFIG_H
#define _CONFIG_H
#include "config.h"
#endif

#ifndef _LTA_H
#define _LTA_H

#include "list.h"
#include "xlator.h"
#include "object.h"

/* This is used to allocate memory for local structure */
#define INIT_LOCAL(fr, local)                   \
do {                                          \
  local = CALLOC (1, sizeof (lta_local_t));   \
  if (!local) {                                 \
    STACK_UNWIND (fr, -1, ENOMEM);            \
    return 0;                                 \
  }                                           \
  fr->local = local;                            \
  local->op_ret1 = -1;                           \
  local->op_errno1 = ENOENT;                     \
  local->op_ret2 = -1;                           \
  local->op_errno2 = ENOENT;                     \
} while (0)

#define LOCAL_WIPE(local) 			\
do {						\
	if(local->fd)				\
		fd_unref(local->fd);		\
	if(local->iobref)			\
		iobref_unref(local->iobref);	\
	if(local->vector)			\
		FREE(local->vector);		\
	local->fd = NULL;			\
	FREE(local);				\
} while(0)

#define LTA_OBJECT_SET_STATUS(object, s) 	\
do {						\
	LOCK(&object->lock);			\
	object->status = s;			\
	UNLOCK(&object->lock);			\
} while(0)

typedef struct lta_obj{
	struct list_head meta_list;
	struct list_head update_list;
	object_t *object; 
} lta_obj_t;
  
struct lta_metaup_worker_arg{
	xlator_t *xlator;
	pthread_t thread;
	pthread_cond_t cond;
	hf_lock_t lock;
	uint32_t obj_count;
	struct list_head openobjs;
};

struct lta_private {
	xlator_t *local_xl;
	xlator_t *global_xl;
	xlator_t *ns_xl;
	hf_lock_t lock;
	object_metadata_sync_mode_t default_mmode;
	struct lta_metaup_worker_arg *update_worker;
};

typedef struct lta_private lta_private_t;

typedef int (*lta_resume_fn_t) (call_frame_t *frame, xlator_t *bound_xl);

struct _lta_local_t {
	int32_t isopen;
	int32_t updatebits;
	int32_t op_ret1;
	int32_t op_errno1;
	int32_t op_ret2;
	int32_t op_errno2;
	mode_t mode;
	off_t offset;
	int32_t flags;
	int32_t object_status;
	struct iovec *vector;
     	int32_t count;
     	struct stat stbuf;
     	struct iobref *iobref;
	loc_t *loc;
	loc_t metaup_loc;

	lta_resume_fn_t resume_fn;

	object_t *object;
	fd_t *fd;
};
typedef struct _lta_local_t lta_local_t;
#endif /* _LTA_H */
