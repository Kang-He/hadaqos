/*
  Copyright (c) 2008-2009 HADA, Inc. <http://www.hada.com>
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

#ifndef _SAVED_FRAMES_H
#define _SAVED_FRAMES_H

#ifndef _CONFIG_H
#define _CONFIG_H
#include "config.h"
#endif

#include <stdint.h>
#include <sys/time.h>
#include "stack.h"
#include "list.h"
#include "protocol.h"

/* UGLY: have common typedef b/w saved-frames.c and protocol-client.c */
typedef int32_t (*hf_op_t) (call_frame_t *frame,
                            hf_hdr_common_t *hdr, size_t hdrlen,
                            struct iobuf *iobuf);


struct saved_frame {
	union {
		struct list_head list;
		struct {
			struct saved_frame *frame_next;
			struct saved_frame *frame_prev;
		};
	};

	struct timeval  saved_at;
	call_frame_t   *frame;
	int32_t         op;
	int8_t          type;
	uint64_t        callid;
};


struct saved_frames {
	int64_t            count;
	struct saved_frame fops;
	struct saved_frame mops;
	struct saved_frame cbks;
};


struct saved_frames *saved_frames_new ();
int saved_frames_put (struct saved_frames *frames, call_frame_t *frame,
		      int32_t op, int8_t type, int64_t callid);
call_frame_t *saved_frames_get (struct saved_frames *frames, int32_t op,
				int8_t type, int64_t callid);

struct saved_frame *
saved_frames_get_timedout (struct saved_frames *frames, int8_t type, 
			   uint32_t timeout, struct timeval *current);

void saved_frames_destroy (xlator_t *this, struct saved_frames *frames,
			   hf_op_t hf_fops[], hf_op_t hf_mops[],
			   hf_op_t hf_cbks[]);

#endif /* _SAVED_FRAMES_H */
