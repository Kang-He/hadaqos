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

#ifndef __LIBHADAFSCLIENT_INTERNALS_H
#define __LIBHADAFSCLIENT_INTERNALS_H

#include "hadafs.h"
#include "logging.h"
#include "object.h"
#include <pthread.h>
#include "stack.h"
#include "list.h"
#include <signal.h>
#include "call-stub.h"
#include <sys/time.h>
#include <sys/resource.h>
#include "fd.h"
#include "dirent.h"

#define LIBHF_IOBUF_SIZE        (1024 *HF_UNIT_KB)
//#define LIBHF_IOBUF_SIZE        (256 *HF_UNIT_KB)
#ifdef XIAOW_20180621
typedef void (*sighandler_t) (int);
#endif
typedef struct list_head list_head_t;

typedef struct libhadafs_client_ctx {
		hadafs_ctx_t hf_ctx;
		object_table_t *otable;
		pthread_t reply_thread;
		call_pool_t pool;
		uint32_t counter;
		pid_t pid;
		uid_t uid;          /* the user id from geteuid */
		gid_t gid;
		uid_t muid;
		gid_t mgid;
		mode_t mmode;
}libhadafs_client_ctx_t;

typedef struct signal_handler {
        int signo;
        sighandler_t handler;
        list_head_t next;
}libhf_client_signal_handler_t ;

typedef struct {
        pthread_mutex_t lock;
        pthread_cond_t reply_cond;
        call_stub_t *reply_stub;
        char complete;
}libhf_client_local_t;

typedef struct {
        pthread_cond_t init_con_established;
        pthread_mutex_t lock;
        char complete;
}libhadafs_client_private_t;

typedef struct {
        pthread_mutex_t lock;
        off_t offset;
        libhadafs_client_ctx_t *ctx;
} libhadafs_client_fd_ctx_t;

typedef struct libhadafs_client_async_local {
        void *cbk_data;
        union {
                struct {
                        fd_t *fd;
                        hadafs_readv_cbk_t cbk;
                        char update_offset;
                }readv_cbk;
    
                struct {
                        fd_t *fd;
                        hadafs_write_cbk_t cbk;
                }write_cbk;

                struct {
                        fd_t *fd;
                }close_cbk;
        }fop;
}libhadafs_client_async_local_t;

#ifndef XIAOW_20200428
#define CHECK_CTX_VALID(ctx, label)   \
        do{                           \
            if(ctx->hf_ctx.pool == NULL || ctx->hf_ctx.graph == NULL){  \
                errno = ENODEV;                                         \
                hf_log("libhadafsclient", HF_LOG_ERROR,                 \
                    "invalid argument:" #ctx);                          \
                goto label;                                             \
            }                                                           \
        }while (0);                                                     
#endif

#define LIBHF_STACK_WIND_AND_WAIT(frame, rfn, obj, fn, params ...)      \
        do {                                                            \
		STACK_WIND (frame, rfn, obj, fn, params);               \
                pthread_mutex_lock (&local->lock);                      \
                {                                                       \
                        while (!local->complete) {                      \
                                pthread_cond_wait (&local->reply_cond,  \
                                                   &local->lock);       \
                        }                                               \
                }                                                       \
                pthread_mutex_unlock (&local->lock);                    \
        } while (0)


#define LIBHF_CLIENT_SIGNAL(signal_handler_list, signo, handler)        \
        do {                                                            \
                libhf_client_signal_handler_t *libhf_handler = CALLOC (1, \
                                                    sizeof (*libhf_handler)); \
                ERR_ABORT (libhf_handler);                              \
                libhf_handler->signo = signo;                           \
                libhf_handler->handler = signal (signo, handler);       \
                list_add (&libhf_handler->next, signal_handler_list);   \
        } while (0)                                                           

#define LIBHF_INSTALL_SIGNAL_HANDLERS(signal_handlers)                  \
        do {                                                            \
                INIT_LIST_HEAD (&signal_handlers);                      \
                /* Handle SIGABORT and SIGSEGV */                       \
                LIBHF_CLIENT_SIGNAL (&signal_handlers, SIGSEGV, hf_print_trace); \
                LIBHF_CLIENT_SIGNAL (&signal_handlers, SIGABRT, hf_print_trace); \
                LIBHF_CLIENT_SIGNAL (&signal_handlers, SIGHUP, hf_log_logrotate); \
                /* LIBHF_CLIENT_SIGNAL (SIGTERM, hadafs_cleanup_and_exit); */ \
        } while (0)

#define LIBHF_RESTORE_SIGNAL_HANDLERS(local)                            \
        do {                                                            \
                libhf_client_signal_handler_t *ptr = NULL, *tmp = NULL; \
                list_for_each_entry_safe (ptr, tmp, &local->signal_handlers,\
                                          next) {                       \
                        signal (ptr->signo, ptr->handler);              \
                        FREE (ptr);                                     \
                }                                                       \
        } while (0)                                       

#define LIBHF_CLIENT_FOP(ctx, stub, op, local, args ...)                \
        do {                                                            \
                call_frame_t *frame = get_call_frame_for_req (ctx, 1);  \
                xlator_t *xl = frame->this->children ?                  \
                        frame->this->children->xlator : NULL;           \
                if (!local) {                                           \
                        local = CALLOC (1, sizeof (*local));            \
                }                                                       \
                ERR_ABORT (local);                                      \
                frame->local = local;                                   \
                frame->root->state = ctx;                               \
                pthread_cond_init (&local->reply_cond, NULL);           \
                pthread_mutex_init (&local->lock, NULL);                \
                LIBHF_STACK_WIND_AND_WAIT (frame, libhf_client_##op##_cbk, xl, \
                                           xl->fops->op, args);         \
                stub = local->reply_stub;                               \
                FREE (frame->local);                                    \
                frame->local = NULL;                                    \
                STACK_DESTROY (frame->root);                            \
        } while (0)

#define LIBHF_REPLY_NOTIFY(local)                                       \
        do {                                                            \
                pthread_mutex_lock (&local->lock);                      \
                {                                                       \
                        local->complete = 1;                            \
                        pthread_cond_broadcast (&local->reply_cond);    \
                }                                                       \
                pthread_mutex_unlock (&local->lock);                    \
        } while (0)


void
libhf_client_loc_wipe (loc_t *loc);

int32_t
libhf_client_loc_fill (loc_t *loc,
                       libhadafs_client_ctx_t *ctx,
                       char *path);

/* We're not expecting more than 10-15
 * VMPs per process so a list is acceptable.
 */
struct vmp_entry {
        struct list_head list;
        char * vmp;
        int vmplen;
        hadafs_handle_t handle;
};

#endif
