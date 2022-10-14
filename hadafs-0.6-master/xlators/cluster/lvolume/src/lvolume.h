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

#ifndef _LVOLUME_H
#define _LVOLUME_H

#include "list.h"
#include "xlator.h"

/* This is used to allocate memory for local structure */
#define INIT_LOCAL(fr, local)                   \
do {                                          \
  local = CALLOC (1, sizeof (lvolume_local_t));   \
  if (!local) {                                 \
    STACK_UNWIND (fr, -1, ENOMEM);            \
    return 0;                                 \
  }                                           \
  fr->local = local;                            \
  local->op_ret = -1;                           \
  local->op_errno = ENOENT;                     \
} while (0)

struct lvolume_private {
	xlator_t *local_xl;
	xlator_t *ns_xl;
	hf_lock_t lock;
};
typedef struct lvolume_private lvolume_private_t;

typedef int (*lvolume_resume_fn_t) (call_frame_t *frame, xlator_t *bound_xl);

struct _lvolume_local_t {
	int32_t op_ret;
	int32_t op_errno;
	int32_t updatebits;
	int32_t object_status;
	struct stat *stbuf;
	loc_t *loc;
	object_t *object;
	fd_t *fd;
	lvolume_resume_fn_t resume_fn;
};
typedef struct _lvolume_local_t lvolume_local_t;

#endif /* _LVOLUME_H */
