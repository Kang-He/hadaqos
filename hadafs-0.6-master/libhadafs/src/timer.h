/*
   Copyright (c) 2007-2009 HADA, Inc. <http://www.hada.com>
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

#ifndef _TIMER_H
#define _TIMER_H

#ifndef _CONFIG_H
#define _CONFIG_H
#include "config.h"
#endif

#include "hadafs.h"
#include <sys/time.h>
#include <pthread.h>

typedef void (*hf_timer_cbk_t) (void *);

struct _hf_timer {
  struct _hf_timer *next, *prev;
  struct timeval at;
  hf_timer_cbk_t cbk;
  void *data;
};

struct _hf_timer_registry {
  pthread_t th;
  char fin;
  struct _hf_timer stale;
  struct _hf_timer active;
  pthread_mutex_t lock;
};

typedef struct _hf_timer hf_timer_t;
typedef struct _hf_timer_registry hf_timer_registry_t;

hf_timer_t *
hf_timer_call_after (hadafs_ctx_t *ctx,
		     struct timeval delta,
		     hf_timer_cbk_t cbk,
		     void *data);

int32_t
hf_timer_call_cancel (hadafs_ctx_t *ctx,
		      hf_timer_t *event);

void *
hf_timer_proc (void *data);

hf_timer_registry_t *
hf_timer_registry_init (hadafs_ctx_t *ctx);

#endif /* _TIMER_H */
