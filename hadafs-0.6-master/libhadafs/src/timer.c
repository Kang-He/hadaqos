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

#ifndef _CONFIG_H
#define _CONFIG_H
#include "config.h"
#endif

#include "timer.h"
#include "logging.h"
#include "common-utils.h"

#define TS(tv) ((((unsigned long long) tv.tv_sec) * 1000000) + (tv.tv_usec))

hf_timer_t *
hf_timer_call_after (hadafs_ctx_t *ctx,
                     struct timeval delta,
                     hf_timer_cbk_t cbk,
                     void *data)
{
        hf_timer_registry_t *reg = NULL;
        hf_timer_t *event = NULL;
        hf_timer_t *trav = NULL;
        unsigned long long at = 0L;
  
        if (ctx == NULL)
        {
                hf_log ("timer", HF_LOG_ERROR, "invalid argument");
                return NULL;
        }

        reg = hf_timer_registry_init (ctx);

        if (!reg) {
                hf_log ("timer", HF_LOG_ERROR, "!reg");
                return NULL;
        }

        event = CALLOC (1, sizeof (*event));
        if (!event) {
                hf_log ("timer", HF_LOG_CRITICAL, "Not enough memory");
                return NULL;
        }
        gettimeofday (&event->at, NULL);
        event->at.tv_usec = ((event->at.tv_usec + delta.tv_usec) % 1000000);
        event->at.tv_sec += ((event->at.tv_usec + delta.tv_usec) / 1000000);
        event->at.tv_sec += delta.tv_sec;
        at = TS (event->at);
        event->cbk = cbk;
        event->data = data;
        pthread_mutex_lock (&reg->lock);
        {
                trav = reg->active.prev;
                while (trav != &reg->active) {
                        if (TS (trav->at) < at)
                                break;
                        trav = trav->prev;
                }
                event->prev = trav;
                event->next = event->prev->next;
                event->prev->next = event;
                event->next->prev = event;
        }
        pthread_mutex_unlock (&reg->lock);
        return event;
}

int32_t
hf_timer_call_stale (hf_timer_registry_t *reg,
                     hf_timer_t *event)
{
        if (reg == NULL || event == NULL)
        {
                hf_log ("timer", HF_LOG_ERROR, "invalid argument");
                return 0;
        }
  
        event->next->prev = event->prev;
        event->prev->next = event->next;
        event->next = &reg->stale;
        event->prev = event->next->prev;
        event->next->prev = event;
        event->prev->next = event;

        return 0;
}

int32_t
hf_timer_call_cancel (hadafs_ctx_t *ctx,
                      hf_timer_t *event)
{
        hf_timer_registry_t *reg = NULL;
  
        if (ctx == NULL || event == NULL)
        {
                hf_log ("timer", HF_LOG_ERROR, "invalid argument");
                return 0;
        }
  
        reg = hf_timer_registry_init (ctx);
        if (!reg) {
                hf_log ("timer", HF_LOG_ERROR, "!reg");
                return 0;
        }

        pthread_mutex_lock (&reg->lock);
        {
                event->next->prev = event->prev;
                event->prev->next = event->next;
        }
        pthread_mutex_unlock (&reg->lock);

        FREE (event);
        return 0;
}

void *
hf_timer_proc (void *ctx)
{
        hf_timer_registry_t *reg = NULL;
  
        if (ctx == NULL)
        {
                hf_log ("timer", HF_LOG_ERROR, "invalid argument");
                return NULL;
        }
  
        reg = hf_timer_registry_init (ctx);
        if (!reg) {
                hf_log ("timer", HF_LOG_ERROR, "!reg");
                return NULL;
        }

        while (!reg->fin) {
                unsigned long long now;
                struct timeval now_tv;
                hf_timer_t *event = NULL;

                gettimeofday (&now_tv, NULL);
                now = TS (now_tv);
                while (1) {
                        unsigned long long at;
                        char need_cbk = 0;

                        pthread_mutex_lock (&reg->lock);
                        {
                                event = reg->active.next;
                                at = TS (event->at);
                                if (event != &reg->active && now >= at) {
                                        need_cbk = 1;
                                        hf_timer_call_stale (reg, event);
                                }
                        }
                        pthread_mutex_unlock (&reg->lock);
                        if (need_cbk)
                                event->cbk (event->data);

                        else
                                break;
                }
                usleep (1000000);
        }

        pthread_mutex_lock (&reg->lock);
        {
                while (reg->active.next != &reg->active) {
                        hf_timer_call_cancel (ctx, reg->active.next);
                }

                while (reg->stale.next != &reg->stale) {
                        hf_timer_call_cancel (ctx, reg->stale.next);
                }
        }
        pthread_mutex_unlock (&reg->lock);
        pthread_mutex_destroy (&reg->lock);
        FREE (((hadafs_ctx_t *)ctx)->timer);

        return NULL;
}

hf_timer_registry_t *
hf_timer_registry_init (hadafs_ctx_t *ctx)
{
        if (ctx == NULL)
        {
                hf_log ("timer", HF_LOG_ERROR, "invalid argument");
                return NULL;
        }
  
        if (!ctx->timer) {
                hf_timer_registry_t *reg = NULL;

                ctx->timer = reg = CALLOC (1, sizeof (*reg));
                ERR_ABORT (reg);
                pthread_mutex_init (&reg->lock, NULL);
                reg->active.next = &reg->active;
                reg->active.prev = &reg->active;
                reg->stale.next = &reg->stale;
                reg->stale.prev = &reg->stale;

                pthread_create (&reg->th, NULL, hf_timer_proc, ctx);
        }
        return ctx->timer;
}
