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

#ifndef _CONFIG_H
#define _CONFIG_H
#include "config.h"
#endif
#include <inttypes.h>


#include "hadafs.h"
#include "client-protocol.h"
#include "compat.h"
#include "dict.h"
#include "protocol.h"
#include "transport.h"
#include "xlator.h"
#include "logging.h"
#include "timer.h"
#include "defaults.h"
#include "compat.h"
#include "compat-errno.h"

#include <sys/resource.h>
#include <inttypes.h>

/* for default_*_cbk functions */
//#include "defaults.c"
#include "saved-frames.h"
#include "common-utils.h"

int protocol_client_cleanup (transport_t *trans);
int protocol_client_interpret (xlator_t *this, transport_t *trans,
                               char *hdr_p, size_t hdrlen,
                               struct iobuf *iobuf);
int
protocol_client_xfer (call_frame_t *frame, xlator_t *this, transport_t *trans,
                      int type, int op,
                      hf_hdr_common_t *hdr, size_t hdrlen,
                      struct iovec *vector, int count,
                      struct iobref *iobref);

static hf_op_t hf_fops[];
static hf_op_t hf_mops[];
static hf_op_t hf_cbks[];


transport_t *
client_channel (xlator_t *this, int id)
{
        transport_t              *trans = NULL;
        client_conf_t            *conf = NULL;
        int                       i = 0;
        struct client_connection *conn = NULL;

        conf = this->private;

        trans = conf->transport[id];
        conn = trans->xl_private;

        if (conn->connected == 1)
                goto ret;

        for (i = 0; i < CHANNEL_MAX; i++) {
                trans = conf->transport[i];
                conn = trans->xl_private;
                if (conn->connected == 1)
                        break;
        }

ret:
        return trans;
}


client_fd_ctx_t *
this_fd_del_ctx (fd_t *file, xlator_t *this)
{
	int         dict_ret = -1;
	uint64_t    ctxaddr  = 0;

	HF_VALIDATE_OR_GOTO ("client", this, out);
	HF_VALIDATE_OR_GOTO (this->name, file, out);

	dict_ret = fd_ctx_del (file, this, &ctxaddr);

	if (dict_ret < 0) {
		ctxaddr = 0;
	}

out:
	return (client_fd_ctx_t *)(unsigned long)ctxaddr;
}


client_fd_ctx_t *
this_fd_get_ctx (fd_t *file, xlator_t *this)
{
	int         dict_ret = -1;
	uint64_t    ctxaddr = 0;

	HF_VALIDATE_OR_GOTO ("client", this, out);
	HF_VALIDATE_OR_GOTO (this->name, file, out);

	dict_ret = fd_ctx_get (file, this, &ctxaddr);

	if (dict_ret < 0) {
		ctxaddr = 0;
	}

out:
	return (client_fd_ctx_t *)(unsigned long)ctxaddr;
}


static void
this_fd_set_ctx (fd_t *file, xlator_t *this, loc_t *loc, client_fd_ctx_t *ctx)
{
	uint64_t oldaddr = 0;
	int32_t  ret = -1;

	HF_VALIDATE_OR_GOTO ("client", this, out);
	HF_VALIDATE_OR_GOTO (this->name, file, out);

	ret = fd_ctx_get (file, this, &oldaddr);
	if (ret >= 0) {
		hf_log (this->name, HF_LOG_DEBUG,
			"%s (%"PRId64"): trying duplicate remote fd set. ",
			loc->path, loc->object->metadata.lno);
	}

	ret = fd_ctx_set (file, this, (uint64_t)(unsigned long)ctx);
	if (ret < 0) {
		hf_log (this->name, HF_LOG_DEBUG,
			"%s (%"PRId64"): failed to set remote fd",
			loc->path, loc->object->metadata.lno);
	}
out:
	return;
}


static int 
client_local_wipe (client_local_t *local)
{
	if (local) {
		loc_wipe (&local->loc);

		if (local->fd)
			fd_unref (local->fd);
		
		if (local->object)
			object_unref(local->object);

		free (local);
	} 
	
	return 0;
}

/*
 * lookup_frame - lookup call frame corresponding to a given callid
 * @trans: transport object
 * @callid: call id of the frame
 *
 * not for external reference
 */

static call_frame_t *
lookup_frame (transport_t *trans, int32_t op, int8_t type, int64_t callid)
{
	client_connection_t *conn = NULL;
	call_frame_t        *frame = NULL;

	conn = trans->xl_private;

	pthread_mutex_lock (&conn->lock);
	{
		frame = saved_frames_get (conn->saved_frames,
					  op, type, callid);
	}
	pthread_mutex_unlock (&conn->lock);

	return frame;
}

static void
call_bail (void *data)
{
	client_connection_t  *conn = NULL;
	struct timeval        current;
	transport_t          *trans = NULL;
	struct list_head      list;
	struct saved_frame   *saved_frame = NULL;
	struct saved_frame   *trav = NULL;
	struct saved_frame   *tmp = NULL;
	call_frame_t         *frame = NULL;
	hf_hdr_common_t       hdr = {0, };
	char                **hf_op_list = NULL;
	hf_op_t              *hf_ops = NULL;
	struct tm             frame_sent_tm;
	char                  frame_sent[32] = {0,};
        struct timeval        timeout = {0,};
        hf_timer_cbk_t        timer_cbk = NULL;

	HF_VALIDATE_OR_GOTO("client", data, out);
	trans = data;

	conn = trans->xl_private;

	gettimeofday (&current, NULL);
	INIT_LIST_HEAD (&list);

	pthread_mutex_lock (&conn->lock);
	{
		/* Chaining to get call-always functionality from 
		   call-once timer */
		if (conn->timer) {
			timer_cbk = conn->timer->cbk;

			timeout.tv_sec = 10;
			timeout.tv_usec = 0;

			hf_timer_call_cancel (trans->xl->ctx, conn->timer);
			conn->timer = hf_timer_call_after (trans->xl->ctx,
							   timeout,
							   timer_cbk,
							   trans);
			if (conn->timer == NULL) {
				hf_log (trans->xl->name, HF_LOG_DEBUG,
					"Cannot create bailout timer");
			}
		}

		do {
			saved_frame = 
			saved_frames_get_timedout (conn->saved_frames,
						   HF_OP_TYPE_MOP_REQUEST,
						   conn->frame_timeout,
						   &current);
			if (saved_frame)
				list_add (&saved_frame->list, &list);
			
		} while (saved_frame);

		do {
			saved_frame = 
			saved_frames_get_timedout (conn->saved_frames,
						   HF_OP_TYPE_FOP_REQUEST,
						   conn->frame_timeout,
						   &current);
			if (saved_frame)
				list_add (&saved_frame->list, &list);
		} while (saved_frame);

		do {
			saved_frame = 
			saved_frames_get_timedout (conn->saved_frames,
						   HF_OP_TYPE_CBK_REQUEST,
						   conn->frame_timeout,
						   &current);
			if (saved_frame)
				list_add (&saved_frame->list, &list);
		} while (saved_frame);
	}
	pthread_mutex_unlock (&conn->lock);

	hdr.rsp.op_ret   = hton32 (-1);
	hdr.rsp.op_errno = hton32 (ENOTCONN);

	list_for_each_entry_safe (trav, tmp, &list, list) {
		switch (trav->type)
		{
		case HF_OP_TYPE_FOP_REQUEST:
			hf_ops = hf_fops;
			hf_op_list = hf_fop_list;
			break;
		case HF_OP_TYPE_MOP_REQUEST:
			hf_ops = hf_mops;
			hf_op_list = hf_mop_list;
			break;
		case HF_OP_TYPE_CBK_REQUEST:
			hf_ops = hf_cbks;
			hf_op_list = hf_cbk_list;
			break;
		}

		localtime_r (&trav->saved_at.tv_sec, &frame_sent_tm);
		strftime (frame_sent, 32, "%Y-%m-%d %H:%M:%S", &frame_sent_tm);

		hf_log (trans->xl->name, HF_LOG_ERROR,
			"bailing out frame %s(%d) "
			"frame sent = %s. frame-timeout = %d",
                        hf_op_list[trav->op], trav->op,
			frame_sent, conn->frame_timeout);

		hdr.type = hton32 (trav->type);
		hdr.op   = hton32 (trav->op);

		frame = trav->frame;

		hf_ops[trav->op] (frame, &hdr, sizeof (hdr), NULL);

		list_del_init (&trav->list);
		FREE (trav);
	}
out:
	return;
}


void
save_frame (transport_t *trans, call_frame_t *frame,
	    int32_t op, int8_t type, uint64_t callid)
{
	client_connection_t *conn = NULL;
	struct timeval       timeout = {0, };


	conn = trans->xl_private;

	saved_frames_put (conn->saved_frames, frame, op, type, callid);

	if (conn->timer == NULL) {
		timeout.tv_sec  = 10;
		timeout.tv_usec = 0;
		conn->timer = hf_timer_call_after (trans->xl->ctx, timeout,
						   call_bail, (void *) trans);
       }
}

void 
client_ping_timer_expired (void *data)
{
	xlator_t            *this = NULL;
	transport_t         *trans = NULL;
	client_conf_t       *conf = NULL;
	client_connection_t *conn = NULL;
	int                  disconnect = 0;
	int                  transport_activity = 0;
	struct timeval       timeout = {0, };
	struct timeval       current = {0, };
	
	trans = data;
	this  = trans->xl;
	conf  = this->private;
	conn  = trans->xl_private;

	pthread_mutex_lock (&conn->lock);
	{
		if (conn->ping_timer)
			hf_timer_call_cancel (trans->xl->ctx, 
					      conn->ping_timer);
		gettimeofday (&current, NULL);

                pthread_mutex_lock (&conf->mutex);
                {
                        if (((current.tv_sec - conf->last_received.tv_sec) <
                             conn->ping_timeout)
                            || ((current.tv_sec - conf->last_sent.tv_sec) <
                                conn->ping_timeout)) {
                                transport_activity = 1;
                        }
                }
                pthread_mutex_unlock (&conf->mutex);

		if (transport_activity) {
			hf_log (this->name, HF_LOG_TRACE,
				"ping timer expired but transport activity "
				"detected - not bailing transport");
			conn->transport_activity = 0;
			timeout.tv_sec = conn->ping_timeout;
			timeout.tv_usec = 0;

			conn->ping_timer = 
				hf_timer_call_after (trans->xl->ctx, timeout,
						     client_ping_timer_expired,
						     (void *) trans);
			if (conn->ping_timer == NULL) 
				hf_log (this->name, HF_LOG_DEBUG,
					"unable to setup timer");

		} else {
			conn->ping_started = 0;
			conn->ping_timer = NULL;
			disconnect = 1;
		}
	}
	pthread_mutex_unlock (&conn->lock);
	if (disconnect) {
		hf_log (this->name, HF_LOG_ERROR,
			"Server %s has not responded in the last %d "
                        "seconds, disconnecting.",
                        conf->transport[0]->peerinfo.identifier,
                        conn->ping_timeout);
                
		transport_disconnect (conf->transport[0]);
		transport_disconnect (conf->transport[1]);
	}
}


void
client_start_ping (void *data)
{
	xlator_t            *this = NULL;
	transport_t         *trans = NULL;
	client_conf_t       *conf = NULL;
	client_connection_t *conn = NULL;
	int32_t              ret = -1;
	hf_hdr_common_t     *hdr = NULL;
	struct timeval       timeout = {0, };
	call_frame_t        *dummy_frame = NULL;
	size_t               hdrlen = -1;
	hf_mop_ping_req_t   *req = NULL;


	trans = data;
	this  = trans->xl;
	conf  = this->private;
	conn  = trans->xl_private;

	pthread_mutex_lock (&conn->lock);
	{
		if ((conn->saved_frames->count == 0) || 
		    !conn->connected) {
			/* using goto looked ugly here, 
			 * hence getting out this way */
			if (conn->ping_timer)
				hf_timer_call_cancel (trans->xl->ctx, 
						      conn->ping_timer);
			conn->ping_timer = NULL;
			conn->ping_started = 0;
			/* unlock */
			pthread_mutex_unlock (&conn->lock);
			return;
		}

		if (conn->saved_frames->count < 0) {
			hf_log (this->name, HF_LOG_DEBUG,
				"saved_frames->count is %"PRId64, 
				conn->saved_frames->count);
			conn->saved_frames->count = 0;
		}
		timeout.tv_sec = conn->ping_timeout;
		timeout.tv_usec = 0;

                if (conn->ping_timer)
                        hf_timer_call_cancel (trans->xl->ctx,
                                              conn->ping_timer);

		conn->ping_timer = 
			hf_timer_call_after (trans->xl->ctx, timeout,
					     client_ping_timer_expired,
					     (void *) trans);

		if (conn->ping_timer == NULL) {
			hf_log (this->name, HF_LOG_DEBUG,
				"unable to setup timer");
		} else {
			conn->ping_started = 1;
		}
	}
	pthread_mutex_unlock (&conn->lock);

	hdrlen = hf_hdr_len (req, 0);
	hdr    = hf_hdr_new (req, 0);

	dummy_frame = create_frame (this, this->ctx->pool);
	dummy_frame->local = trans;

	ret = protocol_client_xfer (dummy_frame, this, trans,
				    HF_OP_TYPE_MOP_REQUEST, HF_MOP_PING,
				    hdr, hdrlen, NULL, 0, NULL);
}


int
client_ping_cbk (call_frame_t *frame, hf_hdr_common_t *hdr, size_t hdrlen,
		 struct iobuf *iobuf)
{
	xlator_t            *this = NULL;
	transport_t         *trans = NULL;
	client_connection_t *conn = NULL;
	struct timeval       timeout = {0, };
	int                  op_ret = 0;

	trans  = frame->local; frame->local = NULL;
	this   = trans->xl;
	conn   = trans->xl_private;

	op_ret = ntoh32 (hdr->rsp.op_ret);

	if (op_ret == -1) {
		/* timer expired and transport bailed out */
		hf_log (this->name, HF_LOG_DEBUG, "timer must have expired");
		goto out;
	}

	pthread_mutex_lock (&conn->lock);
	{
		timeout.tv_sec  = conn->ping_timeout;
		timeout.tv_usec = 0;

		hf_timer_call_cancel (trans->xl->ctx, 
				      conn->ping_timer);
	
		conn->ping_timer = 
			hf_timer_call_after (trans->xl->ctx, timeout,
					     client_start_ping, (void *)trans);
		if (conn->ping_timer == NULL)
			hf_log (this->name, HF_LOG_DEBUG,
				"hf_timer_call_after() returned NULL");
	}
	pthread_mutex_unlock (&conn->lock);
out:
	STACK_DESTROY (frame->root);
	return 0;
}


int
protocol_client_xfer (call_frame_t *frame, xlator_t *this, transport_t *trans,
                      int type, int op,
                      hf_hdr_common_t *hdr, size_t hdrlen,
                      struct iovec *vector, int count,
                      struct iobref *iobref)
{
	client_conf_t        *conf = NULL;
	client_connection_t  *conn = NULL;
	uint64_t              callid = 0;
	int32_t               ret = -1;
	int                   start_ping = 0;
	hf_hdr_common_t       rsphdr = {0, };


	conf  = this->private;

	if (!trans) {
		/* default to bulk op since it is 'safer' */
		trans = conf->transport[CHANNEL_BULK];
	}
	conn  = trans->xl_private;

	pthread_mutex_lock (&conn->lock);
	{
		callid = ++conn->callid;

		hdr->callid = hton64 (callid);
		hdr->op     = hton32 (op);
		hdr->type   = hton32 (type);

		if (frame) {
			hdr->req.uid = hton32 (frame->root->uid);
			hdr->req.gid = hton32 (frame->root->gid);
			hdr->req.pid = hton32 (frame->root->pid);
		}

		if (conn->connected == 0)
			transport_connect (trans);

		ret = -1;

		if (conn->connected ||
		    ((type == HF_OP_TYPE_MOP_REQUEST) &&
		     (op == HF_MOP_SETVOLUME))) {
			ret = transport_submit (trans, (char *)hdr, hdrlen,
						vector, count, iobref);
		}
		
		if ((ret >= 0) && frame) {
                        pthread_mutex_lock (&conf->mutex);
                        {
                                gettimeofday (&conf->last_sent, NULL);
                        }
                        pthread_mutex_unlock (&conf->mutex);
			save_frame (trans, frame, op, type, callid);
		}

		if (!conn->ping_started && (ret >= 0)) {
			start_ping = 1;
		}
	}
	pthread_mutex_unlock (&conn->lock);

	if (start_ping)
		client_start_ping ((void *) trans);

	if (frame && (ret < 0)) {
		rsphdr.op = op;
		rsphdr.rsp.op_ret   = hton32 (-1);
		rsphdr.rsp.op_errno = hton32 (ENOTCONN);

		if (type == HF_OP_TYPE_FOP_REQUEST) {
			rsphdr.type = HF_OP_TYPE_FOP_REPLY;
			hf_fops[op] (frame, &rsphdr, sizeof (rsphdr), NULL);
		} else if (type == HF_OP_TYPE_MOP_REQUEST) {
			rsphdr.type = HF_OP_TYPE_MOP_REPLY;
			hf_mops[op] (frame, &rsphdr, sizeof (rsphdr), NULL);
		} else {
			rsphdr.type = HF_OP_TYPE_CBK_REPLY;
			hf_cbks[op] (frame, &rsphdr, sizeof (rsphdr), NULL);
		}

                FREE (hdr);
	}

	return ret;
}

/**
 * client_open - open function for client protocol
 * @frame: call frame
 * @this: this translator structure
 * @path: complete path to file
 * @flags: create flags
 * @mode: create mode
 *
 * external reference through client_protocol_xlator->fops->open
 */

int
client_open (call_frame_t *frame, xlator_t *this, loc_t *loc, int32_t flags,
               mode_t mode, fd_t *fd)
{
	hf_hdr_common_t     *hdr = NULL;
	hf_fop_open_req_t *req = NULL;
	size_t               hdrlen = 0;
	size_t               pathlen = 0;
	size_t               sidlen = 0;
	size_t		     vmplen = 0;
	int32_t              ret = -1;
	client_local_t      *local = NULL;


	local = calloc (1, sizeof (*local));
	HF_VALIDATE_OR_GOTO(this->name, local, unwind);

	local->fd = fd_ref (fd);
	loc_copy (&local->loc, loc);
	
	frame->local = local;

	pathlen = STRLEN_0(loc->path);
	sidlen = STRLEN_0(loc->sid);
	vmplen = STRLEN_0(loc->object->metadata.vmp);

	hdrlen = hf_hdr_len (req, pathlen + sidlen + vmplen);
	hdr    = hf_hdr_new (req, pathlen + sidlen + vmplen);
	HF_VALIDATE_OR_GOTO(this->name, hdr, unwind);

	req    = hf_param (hdr);

	req->flags   = hton32 (hf_flags_from_flags (flags));
	req->mode    = hton32 (mode);
	req->soffset     = hton32 (loc->soffset);
	strcpy (req->path, loc->path);
	strcpy (req->sid + pathlen, loc->sid);
	strcpy (req->vmp + pathlen + sidlen, loc->object->metadata.vmp);

	ret = protocol_client_xfer (frame, this,
				    CLIENT_CHANNEL (this, CHANNEL_BULK),
				    HF_OP_TYPE_FOP_REQUEST, HF_FOP_OPEN,
				    hdr, hdrlen, NULL, 0, NULL);
	return ret;
unwind:
	if (hdr)
		free (hdr);
	STACK_UNWIND(frame, -1, EINVAL, fd, NULL, NULL);
	return 0;

}

/**
 * client_readv - readv function for client protocol
 * @frame: call frame
 * @this: this translator structure
 * @fd: file descriptor structure
 * @size:
 * @offset:
 *
 * external reference through client_protocol_xlator->fops->readv
 */

int
client_readv (call_frame_t *frame, xlator_t *this, fd_t *fd, size_t size,
              off_t offset)
{
	hf_hdr_common_t    *hdr = NULL;
	hf_fop_read_req_t  *req = NULL;
	size_t              hdrlen = 0;
	int64_t             remote_fd = -1;
	int                 ret = -1;
        client_fd_ctx_t    *fdctx = NULL;
        client_conf_t      *conf = NULL; 

        conf = this->private;
 
        pthread_mutex_lock (&conf->mutex);
        {
                fdctx = this_fd_get_ctx (fd, this);
        }
        pthread_mutex_unlock (&conf->mutex);

	if (fdctx == NULL) {
		hf_log (this->name, HF_LOG_TRACE,
			"(%s): failed to get fd ctx, EBADFD",
			fd->object->path);
		STACK_UNWIND (frame, -1, EBADFD, NULL, 0, NULL);
		return 0;
	}
        remote_fd = fdctx->remote_fd;
	hdrlen = hf_hdr_len (req, 0);
	hdr    = hf_hdr_new (req, 0);
	HF_VALIDATE_OR_GOTO(this->name, hdr, unwind);

	req    = hf_param (hdr);

	req->fd     = hton64 (remote_fd);
	req->size   = hton32 (size);
	req->offset = hton64 (offset);

	ret = protocol_client_xfer (frame, this,
				    CLIENT_CHANNEL (this, CHANNEL_BULK),
				    HF_OP_TYPE_FOP_REQUEST, HF_FOP_READ,
				    hdr, hdrlen, NULL, 0, NULL);

	return 0;
unwind:
	if (hdr)
		free (hdr);
	STACK_UNWIND(frame, -1, EINVAL, NULL, 0, NULL);
	return 0;

}

/**
 * client_writev - writev function for client protocol
 * @frame: call frame
 * @this: this translator structure
 * @fd: file descriptor structure
 * @vector:
 * @count:
 * @offset:
 *
 * external reference through client_protocol_xlator->fops->writev
 */

int
client_writev (call_frame_t *frame, xlator_t *this, fd_t *fd,
               struct iovec *vector, int32_t count, off_t offset,
               struct iobref *iobref)
{
	hf_hdr_common_t    *hdr = NULL;
	hf_fop_write_req_t *req = NULL;
	size_t              hdrlen = 0;
	int64_t             remote_fd = -1;
	int                 ret = -1;
        client_fd_ctx_t    *fdctx = NULL;
        client_conf_t      *conf = NULL;

        conf = this->private;

        pthread_mutex_lock (&conf->mutex);
        {
                fdctx = this_fd_get_ctx (fd, this);
        }
        pthread_mutex_unlock (&conf->mutex);

	if (fdctx == NULL) {
		hf_log (this->name, HF_LOG_TRACE,
			"(%s): failed to get fd ctx. EBADFD",
			fd->object->path);
		STACK_UNWIND (frame, -1, EBADFD, NULL);
		return 0;
	}
        remote_fd = fdctx->remote_fd;
	hdrlen = hf_hdr_len (req, 0);
	hdr    = hf_hdr_new (req, 0);
	HF_VALIDATE_OR_GOTO(this->name, hdr, unwind);

	req    = hf_param (hdr);

	req->fd     = hton64 (remote_fd);
	req->size   = hton32 (iov_length (vector, count));
	req->offset = hton64 (offset);

	ret = protocol_client_xfer (frame, this,
				    CLIENT_CHANNEL (this, CHANNEL_BULK),
				    HF_OP_TYPE_FOP_REQUEST, HF_FOP_WRITE,
				    hdr, hdrlen, vector, count, iobref);
	return ret;
unwind:
	if (hdr)
		free (hdr);
	STACK_UNWIND(frame, -1, EINVAL, NULL);
	return 0;

}



/**
 * client_flush - flush function for client protocol
 * @frame: call frame
 * @this: this translator structure
 * @fd: file descriptor structure
 *
 * external reference through client_protocol_xlator->fops->flush
 */

int
client_flush (call_frame_t *frame, xlator_t *this, fd_t *fd)
{
	hf_hdr_common_t     *hdr = NULL;
	hf_fop_flush_req_t  *req = NULL;
	size_t               hdrlen = 0;
	int64_t              remote_fd = -1;
	int                  ret = -1;
        client_fd_ctx_t     *fdctx = NULL;
        client_conf_t       *conf = NULL;

        conf = this->private;

        pthread_mutex_lock (&conf->mutex);
        {
                fdctx = this_fd_get_ctx (fd, this);
        }
        pthread_mutex_unlock (&conf->mutex);

	if (fdctx == NULL) {
		hf_log (this->name, HF_LOG_TRACE,
			"(%s): failed to get fd ctx. EBADFD",
			fd->object->path);
		STACK_UNWIND (frame, -1, EBADFD);
		return 0;
	}
        remote_fd = fdctx->remote_fd;
	hdrlen = hf_hdr_len (req, 0);
	hdr    = hf_hdr_new (req, 0);
	HF_VALIDATE_OR_GOTO(this->name, hdr, unwind);

	req    = hf_param (hdr);

	req->fd = hton64 (remote_fd);

	ret = protocol_client_xfer (frame, this,
				    CLIENT_CHANNEL (this, CHANNEL_BULK),
				    HF_OP_TYPE_FOP_REQUEST, HF_FOP_FLUSH,
				    hdr, hdrlen, NULL, 0, NULL);

	return 0;
unwind:
	if (hdr)
		free (hdr);
	STACK_UNWIND(frame, -1, EINVAL);
	return 0;
}

/**
 * client_ioctl - ioctl function for client protocol
 * @frame: call frame
 * @this: this translator structure
 * @fd: file descriptor structure
 * @cmd: command number
 * @cmd: command argument
 *
 * external reference through client_protocol_xlator->fops->ioctl
 */

int
client_ioctl (call_frame_t *frame, xlator_t *this, fd_t *fd,
			uint32_t cmd, uint64_t arg)
{
	hf_hdr_common_t     *hdr = NULL;
	hf_fop_ioctl_req_t  *req = NULL;
	size_t               hdrlen = 0;
	int64_t              remote_fd = -1;
	int                  ret = -1;
        client_fd_ctx_t     *fdctx = NULL;
        client_conf_t       *conf = NULL;

        conf = this->private;

        pthread_mutex_lock (&conf->mutex);
        {
                fdctx = this_fd_get_ctx (fd, this);
        }
        pthread_mutex_unlock (&conf->mutex);

	if (fdctx == NULL) {
		hf_log (this->name, HF_LOG_TRACE,
			"(%s): failed to get fd ctx. EBADFD",
			fd->object->path);
		STACK_UNWIND (frame, -1, EBADFD);
		return 0;
	}
        remote_fd = fdctx->remote_fd;
	hdrlen = hf_hdr_len (req, 0);
	hdr    = hf_hdr_new (req, 0);
	HF_VALIDATE_OR_GOTO(this->name, hdr, unwind);

	req    = hf_param (hdr);

	req->fd = hton64 (remote_fd);
	req->cmd = hton32 (cmd);

	ret = protocol_client_xfer (frame, this,
				    CLIENT_CHANNEL (this, CHANNEL_BULK),
				    HF_OP_TYPE_FOP_REQUEST, HF_FOP_IOCTL,
				    hdr, hdrlen, NULL, 0, NULL);

	return 0;
unwind:
	if (hdr)
		free (hdr);

	STACK_UNWIND(frame, -1, EINVAL);
	return 0;
}

/**
 * client_unlink - unlink function for client protocol
 * @frame: call frame
 * @this: this translator structure
 * @loc: location of file
 *
 * external reference through client_protocol_xlator->fops->unlink
 */

int
client_unlink (call_frame_t *frame, xlator_t *this, loc_t *loc)
{
	hf_hdr_common_t     *hdr = NULL;
	hf_fop_unlink_req_t *req = NULL;
	size_t               hdrlen = -1;
	int                  ret = -1;
	size_t               pathlen = 0;
	size_t               sidlen = 0;

	pathlen = STRLEN_0(loc->path);
	sidlen = STRLEN_0(loc->sid);

	hdrlen = hf_hdr_len (req, pathlen + sidlen);
	hdr = hf_hdr_new(req, pathlen + sidlen);
	HF_VALIDATE_OR_GOTO(this->name, hdr, unwind);

	req    = hf_param (hdr);
	req->soffset = hton32 (loc->soffset);
	strcpy (req->path, loc->path);
	strcpy (req->sid + pathlen, loc->sid);

	ret = protocol_client_xfer (frame, this,
				    CLIENT_CHANNEL (this, CHANNEL_BULK),
				    HF_OP_TYPE_FOP_REQUEST, HF_FOP_UNLINK,
				    hdr, hdrlen, NULL, 0, NULL);

	return ret;
unwind:
	if (hdr)
		free (hdr);
	STACK_UNWIND(frame, -1, EINVAL);
	return 0;

}
int
client_ftruncate_cbk (call_frame_t *frame, hf_hdr_common_t *hdr, size_t hdrlen,
                      struct iobuf *iobuf)
{
        hf_fop_ftruncate_rsp_t *rsp = NULL;
        int32_t                 op_ret = 0;
        int32_t                 op_errno = 0;
        struct stat             prestat = {0, };
        struct stat             poststat = {0, };

        rsp = hf_param (hdr);

        op_ret   = ntoh32 (hdr->rsp.op_ret);
        op_errno = hf_error_to_errno (ntoh32 (hdr->rsp.op_errno));

        if (op_ret == 0) {
                hf_stat_to_stat (&rsp->poststat, &poststat);
        }

        STACK_UNWIND (frame, op_ret, op_errno,  &poststat);

        return 0;
}


/**
 * client_ftrucate - ftruncate function for client protocol
 * @frame: call frame
 * @this: this translator structure
 * @fd: file descriptor structure
 * @offset: offset to truncate to
 */
int
client_ftruncate (call_frame_t *frame, xlator_t *this, fd_t *fd,
                  off_t offset)
{
        hf_hdr_common_t        *hdr = NULL;
        hf_fop_ftruncate_req_t *req = NULL;
        int64_t                 remote_fd = -1;
        size_t                  hdrlen = -1;
        int                     ret = -1;
        client_fd_ctx_t        *fdctx = NULL;
        client_conf_t          *conf  = NULL;

        conf = this->private;

        pthread_mutex_lock (&conf->mutex);
        {
                fdctx = this_fd_get_ctx (fd, this);
        }
        pthread_mutex_unlock (&conf->mutex);

        if (fdctx == NULL) {
                hf_log (this->name, HF_LOG_TRACE,
                        "(%s): failed to get fd ctx. EBADFD",
                        fd->object->path);
                STACK_UNWIND (frame, -1, EBADFD, NULL);
                return 0;
        }

        if (fdctx->remote_fd == -1) {
                hf_log (this->name, HF_LOG_TRACE, "(%s): failed to get"
                        " fd ctx. EBADFD", fd->object->path);
                goto unwind;
        }

        remote_fd = fdctx->remote_fd;
        hdrlen = hf_hdr_len (req, 0);
        hdr    = hf_hdr_new (req, 0);
        HF_VALIDATE_OR_GOTO (this->name, hdr, unwind);

        req    = hf_param (hdr);

        req->fd     = hton64 (remote_fd);
        req->offset = hton64 (offset);

        ret = protocol_client_xfer (frame, this,
                                    CLIENT_CHANNEL (this, CHANNEL_BULK),
                                    HF_OP_TYPE_FOP_REQUEST, HF_FOP_FTRUNCATE,
                                    hdr, hdrlen, NULL, 0, NULL);

        return ret;
unwind:
        if (hdr)
                free (hdr);

        STACK_UNWIND (frame, -1, EINVAL, NULL);
        return 0;

}

int
client_truncate_cbk (call_frame_t *frame, hf_hdr_common_t *hdr, size_t hdrlen,
                     struct iobuf *iobuf)
{
        hf_fop_truncate_rsp_t *rsp = NULL;
        int32_t                op_ret = 0;
        int32_t                op_errno = 0;
        struct stat         prestat = {0, };
        struct stat         poststat = {0, };

        rsp = hf_param (hdr);

        op_ret   = ntoh32 (hdr->rsp.op_ret);
        op_errno = hf_error_to_errno (ntoh32 (hdr->rsp.op_errno));

        if (op_ret == 0) {
                hf_stat_to_stat (&rsp->poststat, &poststat);
        }

        STACK_UNWIND (frame, op_ret, op_errno,  &poststat);

        return 0;
}

int
client_truncate (call_frame_t *frame, xlator_t *this, loc_t *loc, off_t offset)
{
        hf_hdr_common_t       *hdr = NULL;
        hf_fop_truncate_req_t *req = NULL;
        size_t                 hdrlen = -1;
        int                    ret = -1;
        size_t                 pathlen = 0;
        size_t                 sidlen = 0;
        ino_t                  ino = 0;
        uint64_t               gen = 0;

        pathlen = STRLEN_0 (loc->path);
        sidlen = STRLEN_0 (loc->sid);
        hdrlen = hf_hdr_len (req, pathlen + sidlen);
        hdr    = hf_hdr_new (req, pathlen + sidlen);
        HF_VALIDATE_OR_GOTO (this->name, hdr, unwind);

        req    = hf_param (hdr);

        req->offset = hton64 (offset);
		req->soffset = hton32 (loc->soffset);
        strcpy (req->path, loc->path);
		strcpy (req->sid + pathlen, loc->sid);

        ret = protocol_client_xfer (frame, this,
                    CLIENT_CHANNEL (this, CHANNEL_BULK),
                    HF_OP_TYPE_FOP_REQUEST, HF_FOP_TRUNCATE,
                    hdr, hdrlen, NULL, 0, NULL);

        return ret;
unwind:
        if (hdr)
                free (hdr);
        STACK_UNWIND (frame, -1, EINVAL, NULL);
        return 0;

}
/* client_fstat_cbk - fstat callback for client protocol
 * @frame: call frame
 * @args: argument dictionary
 *
 * not for external reference
 */

int
client_fstat_cbk (call_frame_t *frame, hf_hdr_common_t *hdr, size_t hdrlen, 
		struct iobuf *iobuf)
{
        struct stat         stbuf = {0, };
        hf_fop_fstat_rsp_t *rsp = NULL;
        int32_t             op_ret = 0;
        int32_t             op_errno = 0;

        rsp = hf_param (hdr);

        op_ret   = ntoh32 (hdr->rsp.op_ret);
        op_errno = hf_error_to_errno (ntoh32 (hdr->rsp.op_errno));

        if (op_ret == 0) {
                hf_stat_to_stat (&rsp->stat, &stbuf);

        }

        STACK_UNWIND (frame, op_ret, op_errno, &stbuf);

        return 0;
}


/**
 * client_fstat - fstat function for client protocol
 * @frame: call frame
 * @this: this translator structure
 * @fd: file descriptor structure
 *
 * external reference through client_protocol_xlator->fops->fstat
 */

int
client_fstat (call_frame_t *frame, xlator_t *this, fd_t *fd)
{
        hf_hdr_common_t    *hdr = NULL;
        hf_fop_fstat_req_t *req = NULL;
        int64_t             remote_fd = -1;
        size_t              hdrlen = -1;
        int                 ret = -1;
        client_fd_ctx_t    *fdctx = NULL;
        client_conf_t      *conf  = NULL;

        conf = this->private;

        pthread_mutex_lock (&conf->mutex);
        {
                fdctx = this_fd_get_ctx (fd, this);
        }
        pthread_mutex_unlock (&conf->mutex);

        if (fdctx == NULL) {
                hf_log (this->name, HF_LOG_TRACE,
                        "(%s): failed to get fd ctx. EBADFD",
                        fd->object->path);
                STACK_UNWIND (frame, -1, EBADFD, NULL);
                return 0;
        }

        if (fdctx->remote_fd == -1) {
                hf_log (this->name, HF_LOG_TRACE, "(%s): failed to get"
                        " fd ctx. EBADFD", fd->object->path);
                goto unwind;
        }

        remote_fd = fdctx->remote_fd;
        hdrlen = hf_hdr_len (req, 0);
        hdr    = hf_hdr_new (req, 0);
        HF_VALIDATE_OR_GOTO (this->name, hdr, unwind);

        req    = hf_param (hdr);

        req->fd = hton64 (remote_fd);

        ret = protocol_client_xfer (frame, this,
                                    CLIENT_CHANNEL (this, CHANNEL_BULK),
                                    HF_OP_TYPE_FOP_REQUEST, HF_FOP_FSTAT,
                                    hdr, hdrlen, NULL, 0, NULL);

        return ret;
unwind:
        if (hdr)
                free (hdr);

        STACK_UNWIND (frame, -1, EINVAL, NULL);
        return 0;

}


/*
 * client_stat_cbk - stat callback for client protocol
 * @frame: call frame
 * @args: arguments dictionary
 *
 * not for external reference
 */

int
client_stat_cbk (call_frame_t *frame, hf_hdr_common_t *hdr, size_t hdrlen,
		struct iobuf *iobuf)
{
        struct stat        stbuf = {0, };
        hf_fop_stat_rsp_t *rsp = NULL;
        int32_t            op_ret = 0;
        int32_t            op_errno = 0;

        rsp = hf_param (hdr);

        op_ret   = ntoh32 (hdr->rsp.op_ret);
        op_errno = hf_error_to_errno (ntoh32 (hdr->rsp.op_errno));

        if (op_ret == 0) {
                hf_stat_to_stat (&rsp->stat, &stbuf);
        }

        STACK_UNWIND (frame, op_ret, op_errno, &stbuf);

        return 0;
}


/**
 * client_stat - stat function for client protocol
 * @frame: call frame
 * @this: this translator structure
 * @loc: location
 *
 * external reference through client_protocol_xlator->fops->stat
 */

int
client_stat (call_frame_t *frame, xlator_t *this, loc_t *loc)
{
        hf_hdr_common_t   *hdr = NULL;
        hf_fop_stat_req_t *req = NULL;
        size_t             hdrlen = -1;
        int32_t            ret = -1;
        size_t             pathlen = 0;
        size_t             sidlen = 0;
      
		pathlen = STRLEN_0 (loc->path);
		sidlen = STRLEN_0 (loc->sid);

		hf_log (this->name, HF_LOG_TRACE, "STAT %s ", loc->path);

        hdrlen = hf_hdr_len (req, pathlen + sidlen);
        hdr    = hf_hdr_new (req, pathlen + sidlen);
        HF_VALIDATE_OR_GOTO (this->name, hdr, unwind);

        req = hf_param (hdr);
		req->soffset = hton32(loc->soffset);
		strcpy (req->path, loc->path);
		strcpy (req->sid + pathlen, loc->sid);

        ret = protocol_client_xfer (frame, this,
                                    CLIENT_CHANNEL (this, CHANNEL_BULK),
                                    HF_OP_TYPE_FOP_REQUEST, HF_FOP_STAT,
                                    hdr, hdrlen, NULL, 0, NULL);

        return ret;
unwind:
        if (hdr)
                free (hdr);
        STACK_UNWIND (frame, -1, EINVAL, NULL);
        return 0;

}


/**
 * client_stats - stats function for client protocol
 * @frame: call frame
 * @this: this translator structure
 * @flags:
 *
 * external reference through client_protocol_xlator->mops->stats
 */

int
client_stats (call_frame_t *frame, xlator_t *this, int32_t flags)
{
	hf_hdr_common_t     *hdr = NULL;
	hf_mop_stats_req_t  *req = NULL;
	size_t               hdrlen = -1;
	int                  ret = -1;

	HF_VALIDATE_OR_GOTO ("client", this, unwind);

	hdrlen = hf_hdr_len (req, 0);
	hdr    = hf_hdr_new (req, 0);
	HF_VALIDATE_OR_GOTO (this->name, hdr, unwind);

	req    = hf_param (hdr);

	req->flags = hton32 (flags);

	ret = protocol_client_xfer (frame, this,
				    CLIENT_CHANNEL (this, CHANNEL_BULK),
				    HF_OP_TYPE_MOP_REQUEST, HF_MOP_STATS,
				    hdr, hdrlen, NULL, 0, NULL);

	return ret;
unwind:
	STACK_UNWIND (frame, -1, EINVAL, NULL);
	return 0;
}


/**
 * client_release - release function for client protocol
 * @this: this translator structure
 * @fd: file descriptor structure
 *
 * external reference through client_protocol_xlator->cbks->release
 *
 */
int
client_release (xlator_t *this, fd_t *fd)
{
	call_frame_t          *fr = NULL;
	int32_t                ret = -1;
	int64_t                remote_fd = 0;
	hf_hdr_common_t       *hdr = NULL;
	size_t                 hdrlen = 0;
	hf_cbk_release_req_t  *req = NULL;
	client_conf_t         *conf = NULL;
        client_fd_ctx_t       *fdctx = NULL;

	HF_VALIDATE_OR_GOTO ("client", this, out);
	HF_VALIDATE_OR_GOTO (this->name, fd, out);

    conf = this->private;
        pthread_mutex_lock (&conf->mutex);
        {
                fdctx = this_fd_del_ctx (fd, this);
                if (fdctx != NULL) {
                        list_del_init (&fdctx->sfd_pos);
                }
        }
        pthread_mutex_unlock (&conf->mutex);

        if (fdctx == NULL) {
                hf_log (this->name, HF_LOG_DEBUG,
                        "(%s): failed to get fd ctx.",
                        fd->object->path);
                goto out;
        }

	remote_fd = fdctx->remote_fd;
	hf_log (this->name, HF_LOG_DEBUG,
		"(%s): release %d on client.",fd->object->path, remote_fd);
	hdrlen = hf_hdr_len (req, 0);
	hdr    = hf_hdr_new (req, 0);
	HF_VALIDATE_OR_GOTO (this->name, hdr, out);
	req    = hf_param (hdr);

	req->fd = hton64 (remote_fd);

        FREE (fdctx);

	fr = create_frame (this, this->ctx->pool);
	HF_VALIDATE_OR_GOTO (this->name, fr, out);

	ret = protocol_client_xfer (fr, this,
				    CLIENT_CHANNEL (this, CHANNEL_BULK),
				    HF_OP_TYPE_CBK_REQUEST, HF_CBK_RELEASE,
				    hdr, hdrlen, NULL, 0, NULL);
out:
	return ret;
}

/*
 * client_open_cbk - open callback function for client protocol
 * @frame: call frame
 * @args: arguments in dictionary
 *
 * not for external reference
 */

int
client_open_cbk (call_frame_t *frame, hf_hdr_common_t *hdr, size_t hdrlen,
                   struct iobuf *iobuf)
{
	hf_fop_open_rsp_t  *rsp = NULL;
	int32_t               op_ret = 0;
	int32_t               op_errno = 0;
	fd_t                 *fd = NULL;
	struct stat           stbuf = {0, };
	int64_t               remote_fd = 0;
	client_local_t       *local = NULL;
	client_conf_t        *conf = NULL;
        client_fd_ctx_t      *fdctx = NULL;

	local = frame->local; frame->local = NULL;
	conf  = frame->this->private;
	fd    = local->fd;

	rsp = hf_param (hdr);

	op_ret    = ntoh32 (hdr->rsp.op_ret);
	op_errno  = ntoh32 (hdr->rsp.op_errno);

	if (op_ret >= 0) {
		remote_fd = ntoh64 (rsp->fd);
	}
	
	hf_stat_to_stat (&rsp->stat, &stbuf);

	if (op_ret >= 0) {
                fdctx = CALLOC (1, sizeof (*fdctx));
                if (!fdctx) {
                        op_ret = -1;
                        op_errno = ENOMEM;
                        goto unwind_out;
                }

                fdctx->remote_fd = remote_fd;
                INIT_LIST_HEAD (&fdctx->sfd_pos);
                fdctx->fd = fd;
		this_fd_set_ctx (fd, frame->this, &local->loc, fdctx);

    hf_log (frame->this->name, HF_LOG_DEBUG,
                    "(%s): open xhh %d  %lx %ld on client.",fd->object->path, remote_fd, rsp->fd, ntoh64 (rsp->fd));

		pthread_mutex_lock (&conf->mutex);
		{
                        list_add_tail (&fdctx->sfd_pos, &conf->saved_fds);
		}
		pthread_mutex_unlock (&conf->mutex);
	}
unwind_out:
	STACK_UNWIND (frame, op_ret, op_errno, fd, local->loc.object, &stbuf);
	
	client_local_wipe (local);

	return 0;
}


/* client_readv_cbk - readv callback for client protocol
 * @frame: call frame
 * @args: argument dictionary
 *
 * not for external referece
 */

int
client_readv_cbk (call_frame_t *frame, hf_hdr_common_t *hdr, size_t hdrlen,
                  struct iobuf *iobuf)
{
	hf_fop_read_rsp_t  *rsp = NULL;
	int32_t             op_ret = 0;
	int32_t             op_errno = 0;
	struct iovec        vector = {0, };
	struct stat        stbuf = {0, };
        struct iobref      *iobref = NULL;

	rsp = hf_param (hdr);

	op_ret   = ntoh32 (hdr->rsp.op_ret);
	op_errno = hf_error_to_errno (ntoh32 (hdr->rsp.op_errno));

	if (op_ret != -1) {
		iobref = iobref_new ();
        hf_stat_to_stat (&rsp->stat, &stbuf);
		vector.iov_len  = op_ret;
                if (op_ret > 0) {
                        vector.iov_base = iobuf->ptr;
                        iobref_add (iobref, iobuf);
                }
	}

 //   hf_log (frame->this->name, HF_LOG_DEBUG,
   //                 "readv %d on client.", op_ret);
	STACK_UNWIND (frame, op_ret, op_errno, &vector, 1, &stbuf, iobref);

	if (iobref)
		iobref_unref (iobref);

        if (iobuf)
                iobuf_unref (iobuf);

	return 0;
}

/*
 * client_write_cbk - write callback for client protocol
 * @frame: cal frame
 * @args: argument dictionary
 *
 * not for external reference
 */

int
client_writev_cbk (call_frame_t *frame, hf_hdr_common_t *hdr, size_t hdrlen,
                  struct iobuf *iobuf)
{
	hf_fop_write_rsp_t *rsp = NULL;
	int32_t             op_ret = 0;
	int32_t             op_errno = 0;
	struct stat         stbuf = {0, };

	rsp = hf_param (hdr);

	op_ret   = ntoh32 (hdr->rsp.op_ret);
	op_errno = hf_error_to_errno (ntoh32 (hdr->rsp.op_errno));

	if (op_ret >= 0)
		hf_stat_to_stat (&rsp->stat, &stbuf);

	STACK_UNWIND (frame, op_ret, op_errno, &stbuf);

	return 0;
}

/*
 * client_flush_cbk - flush callback for client protocol
 *
 * @frame: call frame
 * @args: argument dictionary
 *
 * not for external reference
 */

int
client_flush_cbk (call_frame_t *frame, hf_hdr_common_t *hdr, size_t hdrlen,
                  struct iobuf *iobuf)
{
	hf_fop_flush_rsp_t *rsp = NULL;
	int32_t op_ret = 0;
	int32_t op_errno = 0;
	struct stat         stbuf = {0, };

	rsp = hf_param (hdr);

	op_ret   = ntoh32 (hdr->rsp.op_ret);
	op_errno = hf_error_to_errno (ntoh32 (hdr->rsp.op_errno));

	if (op_ret >= 0)
		hf_stat_to_stat (&rsp->stat, &stbuf);

	STACK_UNWIND (frame, op_ret, op_errno, &stbuf);

	return 0;
}

/*
 * client_ioctl_cbk - ioctl callback for client protocol
 *
 * @frame: call frame
 * @args: argument dictionary
 *
 * not for external reference
 */
int
client_ioctl_cbk (call_frame_t *frame, hf_hdr_common_t *hdr, size_t hdrlen,
                  struct iobuf *iobuf)
{
	hf_fop_ioctl_rsp_t *rsp = NULL;
	int32_t op_ret = 0;
	int32_t op_errno = 0;
	struct stat         stbuf = {0, };

	rsp = hf_param (hdr);

	op_ret   = ntoh32 (hdr->rsp.op_ret);
	op_errno = hf_error_to_errno (ntoh32 (hdr->rsp.op_errno));

	STACK_UNWIND (frame, op_ret, op_errno);

	return 0;
}

/*
 * client_unlink_cbk - unlink callback for client protocol
 * @frame: call frame
 * @args: argument dictionary
 *
 * not for external reference
 */

int
client_unlink_cbk (call_frame_t *frame, hf_hdr_common_t *hdr, size_t hdrlen,
                   struct iobuf *iobuf)
{
	hf_fop_unlink_rsp_t *rsp = NULL;
	int32_t              op_ret = 0;
	int32_t              op_errno = 0;

	rsp = hf_param (hdr);

	op_ret   = ntoh32 (hdr->rsp.op_ret);
	op_errno = hf_error_to_errno (ntoh32 (hdr->rsp.op_errno));

	STACK_UNWIND (frame, op_ret, op_errno);

	return 0;
}

/*
 * client_stats_cbk - stats callback for client protocol
 *
 * @frame: call frame
 * @args: argument dictionary
 *
 * not for external reference
 */

int
client_stats_cbk (call_frame_t *frame, hf_hdr_common_t *hdr, size_t hdrlen,
                  struct iobuf *iobuf)
{
	struct xlator_stats  stats = {0,};
	hf_mop_stats_rsp_t  *rsp = NULL;
	char                *buffer = NULL;
	int32_t              op_ret = 0;
	int32_t              op_errno = 0;

	rsp = hf_param (hdr);

	op_ret   = ntoh32 (hdr->rsp.op_ret);
	op_errno = hf_error_to_errno (ntoh32 (hdr->rsp.op_errno));

	if (op_ret >= 0)
	{
		buffer = rsp->buf;

		sscanf (buffer, "%"SCNx64",%"SCNx64",%"SCNx64",%"SCNx64
			",%"SCNx64",%"SCNx64",%"SCNx64",%"SCNx64"\n",
			&stats.nr_files, &stats.disk_usage, &stats.free_disk,
			&stats.total_disk_size, &stats.read_usage,
			&stats.write_usage, &stats.disk_speed,
                        &stats.nr_clients);
	}

	STACK_UNWIND (frame, op_ret, op_errno, &stats);
	return 0;
}

/*
 * client_setobject - create object for client protocol
 * @frame: call frame
 * @this: client protocal xlator structure
 * @path: the ID of object
 * @islmdb: set object on global ns or local ns, default is global ns
 * @object: the object to set
 *
 * external reference through client_protocol_xaltor->fops->setobject
*/
int
client_setobject(call_frame_t *frame, xlator_t *this,
	char *path, int32_t islmdb, object_t *object)
{
	hf_hdr_common_t	*hdr = NULL;
	hf_fop_setobject_req_t *req = NULL;
	size_t			 hdrlen = -1;
	int32_t			 ret = -1;
	size_t			 pathlen = 0;

	pathlen = STRLEN_0 (path);
	
	hf_log (this->name, HF_LOG_TRACE, "SETOBJECT %s ", path);
	
	hdrlen = hf_hdr_len (req, pathlen);
	hdr    = hf_hdr_new (req, pathlen);
	HF_VALIDATE_OR_GOTO (this->name, hdr, unwind);
	
	req = hf_param (hdr);
	strcpy (req->path, path);
	memcpy(&req->object_info, &object->metadata, sizeof(metadata_t));
	
	ret = protocol_client_xfer (frame, this,
					CLIENT_CHANNEL (this, CHANNEL_BULK),
					HF_OP_TYPE_FOP_REQUEST, HF_FOP_SETOBJECT,
					hdr, hdrlen, NULL, 0, NULL);
	
	return ret;
	
unwind:
	
	if (hdr)
		free (hdr);
	STACK_UNWIND (frame, -1, EINVAL, NULL);
	
	return 0;

}


/*
* client_updateobject - update object for client protocol
* @frame: call frame
* @this: client protocal xlator structure
* @path: the ID of object
* @islmdb: update object on global ns or local ns, default is global ns
* @updatebits: update which field of object
* @object: the object to update
*
* external reference through client_protocol_xaltor->fops->updateobject
*/
int
client_updateobject(call_frame_t *frame, xlator_t *this,
	char *path, int32_t islmdb, int32_t updatebits, object_t *object)
{
	hf_hdr_common_t *hdr = NULL;
	hf_fop_updateobject_req_t *req = NULL;
	size_t			 hdrlen = -1;
	int32_t 		 ret = -1;
	size_t			 pathlen = 0;
	
	pathlen = STRLEN_0 (path);
		
	hf_log (this->name, HF_LOG_TRACE, "UPDATEOBJECT %s ", path);
		
	hdrlen = hf_hdr_len (req, pathlen);
	hdr    = hf_hdr_new (req, pathlen);
	HF_VALIDATE_OR_GOTO (this->name, hdr, unwind);
		
	req = hf_param (hdr);
	strcpy (req->path, path);
	req->updatebits = hton32(updatebits);
	memcpy(&req->object_info, &object->metadata, sizeof(metadata_t));
		
	ret = protocol_client_xfer (frame, this,
				CLIENT_CHANNEL (this, CHANNEL_BULK),
				HF_OP_TYPE_FOP_REQUEST, HF_FOP_UPDATEOBJECT,
				hdr, hdrlen, NULL, 0, NULL);
		
	return ret;
		
unwind:
		
	if (hdr)
		free (hdr);
	STACK_UNWIND (frame, -1, EINVAL, NULL);
		
	return 0;
	
}

/*
* client_getobject - get object for client protocol
* @frame: call frame
* @this: client protocal xlator structure
* @path: the ID of object
* @islmdb: get object on global ns or local ns, default is global ns
* @object: the object to get, here most fileds of object are meaningless
*
* external reference through client_protocol_xaltor->fops->getobject
*/
int
client_getobject(call_frame_t *frame, xlator_t *this,
	char *path, int32_t islmdb, object_t *object)
{
	hf_hdr_common_t *hdr = NULL;
	hf_fop_getobject_req_t *req = NULL;
	size_t			 hdrlen = -1;
	int32_t 		 ret = -1;
	size_t			 pathlen = 0;
	client_local_t      *local = NULL;


	local = calloc (1, sizeof (*local));
	HF_VALIDATE_OR_GOTO(this->name, local, unwind);
	local->object = object_ref(object);
	frame->local = local;
	
	pathlen = STRLEN_0 (path);
			
	hf_log (this->name, HF_LOG_TRACE, "GETOBJECT %s ", path);
			
	hdrlen = hf_hdr_len (req, pathlen);
	hdr    = hf_hdr_new (req, pathlen);
	HF_VALIDATE_OR_GOTO (this->name, hdr, unwind);
			
	req = hf_param (hdr);
	strcpy (req->path, path);

	ret = protocol_client_xfer (frame, this,
				CLIENT_CHANNEL (this, CHANNEL_BULK),
				HF_OP_TYPE_FOP_REQUEST, HF_FOP_GETOBJECT,
				hdr, hdrlen, NULL, 0, NULL);
			
	return ret;
			
unwind:
			
	if (hdr)
		free (hdr);
	STACK_UNWIND (frame, -1, EINVAL, NULL);
			
	return 0;
		
}

	
/*
* client_getobject - lookup object for client protocol
* @frame: call frame
* @this: client protocal xlator structure
* @path: the ID of object
* @islmdb: lookup object on global ns or local ns, default is global ns
* @object: the object to lookup, here most fileds of object are meaningless
*
* external reference through client_protocol_xaltor->fops->lookupobject
*/
int
client_lookupobject(call_frame_t *frame, xlator_t *this,
	char *path, int32_t islmdb, object_t *object)
{
	hf_hdr_common_t *hdr = NULL;
	hf_fop_lookupobject_req_t *req = NULL;
	size_t			 hdrlen = -1;
	int32_t 		 ret = -1;
	size_t			 pathlen = 0;
	client_local_t      *local = NULL;


	local = calloc (1, sizeof (*local));
	HF_VALIDATE_OR_GOTO(this->name, local, unwind);
	local->object = object_ref(object);
	frame->local = local;
	
	pathlen = STRLEN_0 (path);
			
	hf_log (this->name, HF_LOG_TRACE, "LOOKUPOBJECT %s ", path);
			
	hdrlen = hf_hdr_len (req, pathlen);
	hdr    = hf_hdr_new (req, pathlen);
	HF_VALIDATE_OR_GOTO (this->name, hdr, unwind);
			
	req = hf_param (hdr);
	strcpy (req->path, path);

	ret = protocol_client_xfer (frame, this,
				CLIENT_CHANNEL (this, CHANNEL_BULK),
				HF_OP_TYPE_FOP_REQUEST, HF_FOP_LOOKUPOBJECT,
				hdr, hdrlen, NULL, 0, NULL);
			
	return ret;
			
unwind:
			
	if (hdr)
		free (hdr);
	STACK_UNWIND (frame, -1, EINVAL, NULL);
			
	return 0;
		
}

	
/*
* client_deleteobject - delete object for client protocol
* @frame: call frame
* @this: client protocal xlator structure
* @path: the ID of object
* @islmdb: delete object on global ns or local ns, default is global ns
*
* external reference through client_protocol_xaltor->fops->deleteobject
*/
int
client_deleteobject(call_frame_t *frame, xlator_t *this,
	char *path, int32_t islmdb, object_t *object)
{
	hf_hdr_common_t *hdr = NULL;
	hf_fop_deleteobject_req_t *req = NULL;
	size_t			 hdrlen = -1;
	int32_t 		 ret = -1;
	size_t			 pathlen = 0;
		
	pathlen = STRLEN_0 (path);
			
	hf_log (this->name, HF_LOG_TRACE, "DELETEOBJECT %s ", path);
			
	hdrlen = hf_hdr_len (req, pathlen);
	hdr    = hf_hdr_new (req, pathlen);
	HF_VALIDATE_OR_GOTO (this->name, hdr, unwind);
			
	req = hf_param (hdr);
	strcpy (req->path, path);

	ret = protocol_client_xfer (frame, this,
				CLIENT_CHANNEL (this, CHANNEL_BULK),
				HF_OP_TYPE_FOP_REQUEST, HF_FOP_DELETEOBJECT,
				hdr, hdrlen, NULL, 0, NULL);
			
	return ret;
			
unwind:
			
	if (hdr)
		free (hdr);
	STACK_UNWIND (frame, -1, EINVAL, NULL);
			
	return 0;
		
}

/*
 * client_setobject_cbk - setobject callback for client protocol
 *
 * @frame: call frame
 * @args: argument dictionary
 *
 * not for external reference
 */

int
client_setobject_cbk (call_frame_t *frame, hf_hdr_common_t *hdr, size_t hdrlen,
				  struct iobuf *iobuf)
{
	hf_fop_setobject_rsp_t *rsp = NULL;
	int32_t 			 op_ret = 0;
	int32_t 			 op_errno = 0;
	int32_t 			 status;

	rsp = hf_param (hdr);

	op_ret	 = ntoh32 (hdr->rsp.op_ret);
	op_errno = hf_error_to_errno (ntoh32 (hdr->rsp.op_errno));
	status = ntoh32(rsp->object_status);

	STACK_UNWIND (frame, op_ret, op_errno, status);
	return 0;
}

/*
 * client_updateobject_cbk - updateobject callback for client protocol
 *
 * @frame: call frame
 * @args: argument dictionary
 *
 * not for external reference
*/
				  
int
client_updateobject_cbk (call_frame_t *frame, hf_hdr_common_t *hdr, size_t hdrlen,
		struct iobuf *iobuf)
{
	hf_fop_updateobject_rsp_t *rsp = NULL;
	int32_t			   op_ret = 0;
	int32_t			   op_errno = 0;
	int32_t			   status;
				  
	rsp = hf_param (hdr);
	op_ret   = ntoh32 (hdr->rsp.op_ret);
	op_errno = hf_error_to_errno (ntoh32 (hdr->rsp.op_errno));
	status = ntoh32(rsp->object_status);
				  
	STACK_UNWIND (frame, op_ret, op_errno, status);
	return 0;
}

/*
 * client_getobject_cbk - getobject callback for client protocol
 *
 * @frame: call frame
 * @args: argument dictionary
 *
 * not for external reference
*/		
int
client_getobject_cbk (call_frame_t *frame, hf_hdr_common_t *hdr, size_t hdrlen,
			  struct iobuf *iobuf)
{
	client_local_t		*local = NULL;
	hf_fop_getobject_rsp_t *rsp = NULL;
	int32_t 			 op_ret = 0;
	int32_t 			 op_errno = 0;
	object_t 			 *object = NULL;

	local = frame->local; frame->local = NULL;
	object = local->object;

	rsp = hf_param (hdr);

	op_ret	 = ntoh32 (hdr->rsp.op_ret);
	op_errno = hf_error_to_errno (ntoh32 (hdr->rsp.op_errno));
	memcpy(&object->metadata, &rsp->object_info, sizeof(metadata_t));

	STACK_UNWIND (frame, op_ret, op_errno, object);
	client_local_wipe(local);
	
	return 0;
}


/*
 * client_lookupobject_cbk - lookupobject callback for client protocol
 *
 * @frame: call frame
 * @args: argument dictionary
 *
 * not for external reference
*/	  
int
client_lookupobject_cbk (call_frame_t *frame, hf_hdr_common_t *hdr, size_t hdrlen,
		struct iobuf *iobuf)
{
	client_local_t	  *local = NULL;
	hf_fop_lookupobject_rsp_t *rsp = NULL;
	int32_t			   op_ret = 0;
	int32_t			   op_errno = 0;
	object_t		*object = NULL;

	local = frame->local; frame->local = NULL;
	object = local->object;

	rsp = hf_param (hdr);
			  
	op_ret   = ntoh32 (hdr->rsp.op_ret);
    op_errno = hf_error_to_errno (ntoh32 (hdr->rsp.op_errno));
	memcpy(&object->metadata, &rsp->object_info, sizeof(metadata_t));
			  
	STACK_UNWIND (frame, op_ret, op_errno, object);			  
	client_local_wipe(local);
	
	return 0;
}

/*
 * client_deleteobject_cbk - deleteobject callback for client protocol
 *
 * @frame: call frame
 * @args: argument dictionary
 *
 * not for external reference
*/	  
int
client_deleteobject_cbk (call_frame_t *frame, hf_hdr_common_t *hdr, size_t hdrlen,
		struct iobuf *iobuf)
{
	hf_fop_deleteobject_rsp_t *rsp = NULL;
	int32_t 		   op_ret = 0;
	int32_t 		   op_errno = 0;
	int32_t 		status = 0;

	rsp = hf_param (hdr);
			  
	op_ret	 = ntoh32 (hdr->rsp.op_ret);
	op_errno = hf_error_to_errno (ntoh32 (hdr->rsp.op_errno));
	status = ntoh32(rsp->object_status);
			  
	STACK_UNWIND (frame, op_ret, op_errno, status); 		  
	
	return 0;
}


/*
 * client_getspec - getspec function for client protocol
 * @frame: call frame
 * @this: client protocol xlator structure
 * @flag:
 *
 * external reference through client_protocol_xlator->fops->getspec
 */

int
client_getspec (call_frame_t *frame, xlator_t *this, const char *key,
                int32_t flag)
{
	hf_hdr_common_t      *hdr = NULL;
	hf_mop_getspec_req_t *req = NULL;
	size_t                hdrlen = -1;
	int                   keylen = 0;
	int                   ret = -1;

	if (key)
		keylen = STRLEN_0(key);

	hdrlen = hf_hdr_len (req, keylen);
	hdr    = hf_hdr_new (req, keylen);
	HF_VALIDATE_OR_GOTO(this->name, hdr, unwind);

	req        = hf_param (hdr);
	req->flags = hton32 (flag);
	req->keylen = hton32 (keylen);
	if (keylen)
		strcpy (req->key, key);

	ret = protocol_client_xfer (frame, this,
				    CLIENT_CHANNEL (this, CHANNEL_BULK),
				    HF_OP_TYPE_MOP_REQUEST, HF_MOP_GETSPEC,
				    hdr, hdrlen, NULL, 0, NULL);

	return ret;
unwind:
	if (hdr)
		free (hdr);
	STACK_UNWIND(frame, -1, EINVAL, NULL);
	return 0;
}

/*
 * client_getspec_cbk - getspec callback for client protocol
 *
 * @frame: call frame
 * @args: argument dictionary
 *
 * not for external reference
 */

int
client_getspec_cbk (call_frame_t *frame, hf_hdr_common_t *hdr, size_t hdrlen,
                    struct iobuf *iobuf)
{
	hf_mop_getspec_rsp_t  *rsp = NULL;
	char                  *spec_data = NULL;
	int32_t                op_ret = 0;
	int32_t                op_errno = 0;
	int32_t                hf_errno = 0;

	op_ret   = ntoh32 (hdr->rsp.op_ret);
	hf_errno = ntoh32 (hdr->rsp.op_errno);
	op_errno = hf_error_to_errno (hf_errno);
	rsp = hf_param (hdr);

	if (op_ret >= 0) {
		spec_data = rsp->spec;
	}

	STACK_UNWIND (frame, op_ret, op_errno, spec_data);
	return 0;
}


int
client_checksum (call_frame_t *frame, xlator_t *this, loc_t *loc, int32_t flag)
{
	hf_hdr_common_t       *hdr = NULL;
	hf_fop_checksum_req_t *req = NULL;
	size_t                 hdrlen = -1;
	int                    ret = -1;

	hdrlen = hf_hdr_len (req, strlen (loc->path) + 1);
	hdr    = hf_hdr_new (req, strlen (loc->path) + 1);
	req    = hf_param (hdr);
	
	req->flag = hton32 (flag);
	strcpy (req->path, loc->path);

	ret = protocol_client_xfer (frame, this,
				    CLIENT_CHANNEL (this, CHANNEL_BULK),
				    HF_OP_TYPE_FOP_REQUEST, HF_FOP_CHECKSUM,
				    hdr, hdrlen, NULL, 0, NULL);

	return ret;
}


int
client_checksum_cbk (call_frame_t *frame, hf_hdr_common_t *hdr, size_t hdrlen,
                     struct iobuf *iobuf)
{
	hf_fop_checksum_rsp_t *rsp = NULL;
	int32_t                op_ret = 0;
	int32_t                op_errno = 0;
	int32_t                hf_errno = 0;
	unsigned char         *fchecksum = NULL;
	unsigned char         *dchecksum = NULL;

	rsp = hf_param (hdr);

	op_ret   = ntoh32 (hdr->rsp.op_ret);
	hf_errno = ntoh32 (hdr->rsp.op_errno);
	op_errno = hf_error_to_errno (hf_errno);

	if (op_ret >= 0) {
		fchecksum = rsp->fchecksum;
	}

	STACK_UNWIND (frame, op_ret, op_errno, fchecksum, dchecksum);
	return 0;
}

/*
 * client_setspec_cbk - setspec callback for client protocol
 * @frame: call frame
 * @args: argument dictionary
 *
 * not for external reference
 */

int
client_setspec_cbk (call_frame_t *frame, hf_hdr_common_t *hdr, size_t hdrlen,
                    struct iobuf *iobuf)
{
	int32_t op_ret = 0;
	int32_t op_errno = 0;

	op_ret   = ntoh32 (hdr->rsp.op_ret);
	op_errno = hf_error_to_errno (ntoh32 (hdr->rsp.op_errno));

	STACK_UNWIND (frame, op_ret, op_errno);

	return 0;
}

/*
 * client_setvolume_cbk - setvolume callback for client protocol
 * @frame:  call frame
 * @args: argument dictionary
 *
 * not for external reference
 */

int
client_setvolume_cbk (call_frame_t *frame, hf_hdr_common_t *hdr, size_t hdrlen,
                      struct iobuf *iobuf)
{
        client_conf_t          *conf = NULL;
	hf_mop_setvolume_rsp_t *rsp = NULL;
	client_connection_t    *conn = NULL;
	hadafs_ctx_t        *ctx = NULL; 
	xlator_t               *this = NULL;
	xlator_list_t          *parent = NULL;
	transport_t            *trans = NULL;
	dict_t                 *reply = NULL;
	char                   *remote_subvol = NULL;
	char                   *remote_error = NULL;
	char                   *process_uuid = NULL;
	int32_t                 ret = -1;
	int32_t                 op_ret   = -1;
    int32_t                 op_errno = EINVAL;
    int32_t                 dict_len = 0;
    transport_t            *peer_trans = NULL;
    uint64_t                peer_trans_int = 0;

	trans = frame->local; frame->local = NULL;
	this  = frame->this;
	conn  = trans->xl_private;
    conf  = this->private;

	rsp = hf_param (hdr);

	op_ret   = ntoh32 (hdr->rsp.op_ret);
	op_errno = hf_error_to_errno (ntoh32 (hdr->rsp.op_errno));

	if ((op_ret < 0) && (op_errno == ENOTCONN)) {
		hf_log (this->name, HF_LOG_DEBUG,
			"setvolume failed (%s)",
			strerror (op_errno));
		goto out;
	}

	reply = dict_new ();
	HF_VALIDATE_OR_GOTO(this->name, reply, out);

	dict_len = ntoh32 (rsp->dict_len);
	ret = dict_unserialize (rsp->buf, dict_len, &reply);
	if (ret < 0) {
		hf_log (frame->this->name, HF_LOG_DEBUG,
			"failed to unserialize buffer(%p) to dictionary",
			rsp->buf);
		goto out;
	}
	
	ret = dict_get_str (reply, "ERROR", &remote_error);
	if (ret < 0) {
		hf_log (this->name, HF_LOG_DEBUG,
			"failed to get ERROR string from reply dictionary");
	}

	ret = dict_get_str (reply, "process-uuid", &process_uuid);
	if (ret < 0) {
		hf_log (this->name, HF_LOG_DEBUG,
			"failed to get 'process-uuid' from reply dictionary");
	}

	if (op_ret < 0) {
		hf_log (trans->xl->name, HF_LOG_DEBUG,
			"SETVOLUME on remote-host failed: %s",
			remote_error ? remote_error : strerror (op_errno));
		errno = op_errno;
                if (op_errno == ESTALE) {
                        parent = trans->xl->parents;
                        while (parent) {
                                parent->xlator->notify (parent->xlator,
                                                        HF_EVENT_VOLFILE_MODIFIED,
                                                        trans->xl);
                                parent = parent->next;
                        }
                }

	} else {
                ret = dict_get_str (this->options, "remote-subvolume",
                                    &remote_subvol);
                if (!remote_subvol) 
                        goto out;

		ctx = this->ctx;
                
		if (process_uuid && !strcmp (ctx->process_uuid,process_uuid)) {
                        ret = dict_get_uint64 (reply, "transport-ptr",
                                               &peer_trans_int);

                        peer_trans = (void *) (long) (peer_trans_int);
			
			hf_log (this->name, HF_LOG_WARNING, 
				"attaching to the local volume '%s'",
				remote_subvol);

                        transport_setpeer (trans, peer_trans);

		}
		
        hf_log (trans->xl->name, HF_LOG_NORMAL,
                        "Connected to %s, attached "
                        "to remote volume '%s'.",
                        trans->peerinfo.identifier, remote_subvol);

		pthread_mutex_lock (&(conn->lock));
		{
			conn->connected = 1;
		}
		pthread_mutex_unlock (&(conn->lock));

		parent = trans->xl->parents;
		while (parent) {
			parent->xlator->notify (parent->xlator,
						HF_EVENT_CHILD_UP,
						trans->xl);
			parent = parent->next;
		}
	}

        conf->connecting = 0;
out:

        if (-1 == op_ret) {
		/* Let the connection/re-connection happen in 
		 * background, for now, don't hang here,
		 * tell the parents that i am all ok..
		 */
		parent = trans->xl->parents;
		while (parent) {
			parent->xlator->notify (parent->xlator,
						HF_EVENT_CHILD_CONNECTING,
						trans->xl);
			parent = parent->next;
		}
                conf->connecting= 1;
        }

	STACK_DESTROY (frame->root);

	if (reply)
		dict_unref (reply);

	return op_ret;
}

/*
 * client_enosys_cbk -
 * @frame: call frame
 *
 * not for external reference
 */

int
client_enosys_cbk (call_frame_t *frame, hf_hdr_common_t *hdr, size_t hdrlen,
                   struct iobuf *iobuf)
{
	STACK_DESTROY (frame->root);
	return 0;
}


void
client_protocol_reconnect (void *trans_ptr)
{
	transport_t         *trans = NULL;
	client_connection_t *conn = NULL;
	struct timeval       tv = {0, 0};
        int32_t              ret = 0;

	trans = trans_ptr;
	conn  = trans->xl_private;
	pthread_mutex_lock (&conn->lock);
	{
		if (conn->reconnect)
			hf_timer_call_cancel (trans->xl->ctx, 
					      conn->reconnect);
		conn->reconnect = 0;

		if (conn->connected == 0) {
			tv.tv_sec = 10;

			hf_log (trans->xl->name, HF_LOG_TRACE,
				"attempting reconnect");
			ret = transport_connect (trans);

			conn->reconnect = 
				hf_timer_call_after (trans->xl->ctx, tv,
						     client_protocol_reconnect,
						     trans);
		} else {
			hf_log (trans->xl->name, HF_LOG_TRACE, 
				"breaking reconnect chain");
		}
	}
	pthread_mutex_unlock (&conn->lock);

        if (ret == -1 && errno != EINPROGRESS) {
		hf_log (trans->xl->name, HF_LOG_ERROR, "reconnect failed after %d tries",
				 conn->connect_count);
                default_notify (trans->xl, HF_EVENT_CHILD_DOWN, NULL);
        }
}

int 
protocol_client_mark_fd_bad (xlator_t *this)
{
        client_conf_t            *conf = NULL;
        client_fd_ctx_t          *tmp = NULL;
        client_fd_ctx_t          *fdctx = NULL;

        conf = this->private;

        pthread_mutex_lock (&conf->mutex);
        {
                list_for_each_entry_safe (fdctx, tmp, &conf->saved_fds,
                                          sfd_pos) {
                        fd_ctx_del (fdctx->fd, this, NULL);
                        list_del_init (&fdctx->sfd_pos);
                        FREE (fdctx);
                }

                INIT_LIST_HEAD(&conf->saved_fds);
        }
	pthread_mutex_unlock (&conf->mutex);
        
        return 0;
}

/*
 * client_protocol_cleanup - cleanup function
 * @trans: transport object
 *
 */

int
protocol_client_cleanup (transport_t *trans)
{
	client_connection_t    *conn = NULL;
	struct saved_frames    *saved_frames = NULL;

	conn = trans->xl_private;
			
	hf_log (trans->xl->name, HF_LOG_TRACE,
		"cleaning up state in transport object %p", trans);

	pthread_mutex_lock (&conn->lock);
	{
		saved_frames = conn->saved_frames;
		conn->saved_frames = saved_frames_new ();

		/* bailout logic cleanup */
		if (conn->timer) {
			hf_timer_call_cancel (trans->xl->ctx, conn->timer);
			conn->timer = NULL;
		}

		if (conn->reconnect == NULL) {
			/* :O This part is empty.. any thing missing? */
		}
	}
	pthread_mutex_unlock (&conn->lock);

	saved_frames_destroy (trans->xl, saved_frames,
			      hf_fops, hf_mops, hf_cbks);

	return 0;
}


/* cbk callbacks */
int
client_releasedir_cbk (call_frame_t *frame, hf_hdr_common_t *hdr,
                       size_t hdrlen, struct iobuf *iobuf)
{
	STACK_DESTROY (frame->root);
	return 0;
}


int
client_release_cbk (call_frame_t *frame, hf_hdr_common_t *hdr, size_t hdrlen,
		    struct iobuf *iobuf)
{
	STACK_DESTROY (frame->root);
	return 0;
}

static hf_op_t hf_fops[] = {
	[HF_FOP_UNLINK]         =  client_unlink_cbk,
	[HF_FOP_STAT]           =  client_stat_cbk,
	[HF_FOP_FSTAT]           =  client_fstat_cbk,
	[HF_FOP_OPEN]           =  client_open_cbk,
	[HF_FOP_READ]           =  client_readv_cbk,
	[HF_FOP_WRITE]          =  client_writev_cbk,
	[HF_FOP_FLUSH]          =  client_flush_cbk,
	[HF_FOP_CHECKSUM]       =  client_checksum_cbk,
	[HF_FOP_SETOBJECT]      =  client_setobject_cbk,
	[HF_FOP_UPDATEOBJECT]   =  client_updateobject_cbk,
	[HF_FOP_GETOBJECT]      =  client_getobject_cbk,
	[HF_FOP_LOOKUPOBJECT]   =  client_lookupobject_cbk,
	[HF_FOP_DELETEOBJECT]   =  client_deleteobject_cbk,
	[HF_FOP_IOCTL]       =  client_ioctl_cbk,
	[HF_FOP_TRUNCATE]      =  client_truncate_cbk,
	[HF_FOP_FTRUNCATE]      =  client_ftruncate_cbk
};

static hf_op_t hf_mops[] = {
	[HF_MOP_SETVOLUME]        =  client_setvolume_cbk,
	[HF_MOP_GETVOLUME]        =  client_enosys_cbk,
	[HF_MOP_STATS]            =  client_stats_cbk,
	[HF_MOP_SETSPEC]          =  client_setspec_cbk,
	[HF_MOP_GETSPEC]          =  client_getspec_cbk,
	[HF_MOP_PING]             =  client_ping_cbk,
};

static hf_op_t hf_cbks[] = {
	[HF_CBK_RELEASE]          = client_release_cbk,
};

/*
 * client_protocol_interpret - protocol interpreter
 * @trans: transport object
 * @blk: data block
 *
 */
int
protocol_client_interpret (xlator_t *this, transport_t *trans,
                           char *hdr_p, size_t hdrlen, struct iobuf *iobuf)
{
	int                  ret = -1;
	call_frame_t        *frame = NULL;
	hf_hdr_common_t     *hdr = NULL;
	uint64_t             callid = 0;
	int                  type = -1;
	int                  op = -1;
	client_connection_t *conn = NULL;

	conn  = trans->xl_private;
	hdr  = (hf_hdr_common_t *)hdr_p;

	type   = ntoh32 (hdr->type);
	op     = ntoh32 (hdr->op);
	callid = ntoh64 (hdr->callid);
	frame  = lookup_frame (trans, op, type, callid);
	if (frame == NULL) {
		hf_log (this->name, HF_LOG_WARNING,
				"no frame for callid=%"PRId64" type=%d op=%d",
				callid, type, op);
		return 0;
	}
	switch (type) {
	case HF_OP_TYPE_FOP_REPLY:
		if ((op > HF_FOP_MAXVALUE) || 
		    (op < 0)) {
			hf_log (trans->xl->name, HF_LOG_WARNING,
				"invalid fop '%d'", op);
		} else {
			ret = hf_fops[op] (frame, hdr, hdrlen, iobuf);
		}
		break;
	case HF_OP_TYPE_MOP_REPLY:
		if ((op > HF_MOP_MAXVALUE) || 
		    (op < 0)) {
			hf_log (trans->xl->name, HF_LOG_WARNING,
				"invalid fop '%d'", op);
		} else {
			ret = hf_mops[op] (frame, hdr, hdrlen, iobuf);
		}
		break;
	case HF_OP_TYPE_CBK_REPLY:
		if ((op > HF_CBK_MAXVALUE) || 
		    (op < 0)) {
			hf_log (trans->xl->name, HF_LOG_WARNING,
				"invalid cbk '%d'", op);
		} else {
			ret = hf_cbks[op] (frame, hdr, hdrlen, iobuf);
		}
		break;
	default:
		hf_log (trans->xl->name, HF_LOG_DEBUG,
			"invalid packet type: %d op %d callid %d", type, op, callid);
		break;
	}
	return ret;
}

/*
 * init - initiliazation function. called during loading of client protocol
 * @this:
 *
 */

int
init (xlator_t *this)
{
	transport_t               *trans = NULL;
	client_conf_t             *conf = NULL;
	client_connection_t       *conn = NULL;
	int32_t                    frame_timeout = 0;
	int32_t                    ping_timeout = 0;
	data_t                    *remote_subvolume = NULL;
	int32_t                    ret = -1;
	int                        i = 0;

	if (this->children) {
		hf_log (this->name, HF_LOG_ERROR,
			"FATAL: client protocol translator cannot have any "
			"subvolumes");
		goto out;
	}
	
	if (!this->parents) {
		hf_log (this->name, HF_LOG_WARNING,
			"Volume is dangling. ");
	}

	remote_subvolume = dict_get (this->options, "remote-subvolume");
	if (remote_subvolume == NULL) {
		hf_log (this->name, HF_LOG_ERROR,
			"Option 'remote-subvolume' is not specified.");
		goto out;
	}

	ret = dict_get_int32 (this->options, "frame-timeout", 
			      &frame_timeout);
	if (ret >= 0) {
		hf_log (this->name, HF_LOG_DEBUG,
			"setting frame-timeout to %d", frame_timeout);
	} else {
		hf_log (this->name, HF_LOG_DEBUG,
			"defaulting frame-timeout to 30mins");
		frame_timeout = 1800;
	}
	
	ret = dict_get_int32 (this->options, "ping-timeout", 
			      &ping_timeout);
	if (ret >= 0) {
		hf_log (this->name, HF_LOG_DEBUG,
			"setting ping-timeout to %d", ping_timeout);
	} else {
		hf_log (this->name, HF_LOG_DEBUG,
			"defaulting ping-timeout to 10");
		ping_timeout = 10;
	}
	
	conf = CALLOC (1, sizeof (client_conf_t));

	LOCK_INIT (&conf->forget.lock);
	pthread_mutex_init (&conf->mutex, NULL);
	INIT_LIST_HEAD (&conf->saved_fds);

	this->private = conf;

	for (i = 0; i < CHANNEL_MAX; i++) {
		trans = transport_load (this->options, this);
		if (trans == NULL) {
			hf_log (this->name, HF_LOG_DEBUG, 
				"Failed to load transport");
			ret = -1;
			goto out;
		}

		conn = CALLOC (1, sizeof (*conn));

		conn->saved_frames = saved_frames_new ();

		conn->callid = 1;

		conn->connect_count = 0;
		conn->frame_timeout = frame_timeout;
		conn->ping_timeout = ping_timeout;

		pthread_mutex_init (&conn->lock, NULL);

		trans->xl_private = conn;
		conf->transport[i] = transport_ref (trans);
	}

#ifdef HF_DARWIN_HOST_OS
	{
		struct rlimit lim;

		lim.rlim_cur = 1048576;
		lim.rlim_max = 1048576;
		
		ret = setrlimit (RLIMIT_NOFILE, &lim);
		if (ret == -1) {
			hf_log (this->name, HF_LOG_WARNING,
				"WARNING: Failed to set 'ulimit -n 1M': %s",
				strerror(errno));
			lim.rlim_cur = 65536;
			lim.rlim_max = 65536;
			
			ret = setrlimit (RLIMIT_NOFILE, &lim);
			if (ret == -1) {
				hf_log (this->name, HF_LOG_DEBUG,
					"Failed to set max open fd to 64k: %s",
					strerror(errno));
			} else {
				hf_log (this->name, HF_LOG_DEBUG,
					"max open fd set to 64k");
			}

		}
	}
#endif
	ret = 0;
out:
	return ret;
}

/*
 * fini - finish function called during unloading of client protocol
 * @this:
 *
 */
void
fini (xlator_t *this)
{
	/* TODO: Check if its enough.. how to call transport's fini () */
	client_conf_t *conf = NULL;
	int i;
	conf = this->private;
    if (conf) {
#ifndef XIAOW20191105
            for(i = 0; i < CHANNEL_MAX; i++) {
                    hf_log (this->name, HF_LOG_DEBUG,
                                    "trans (%p)", conf->transport[i]);
                    transport_destroy(conf->transport[i]);
            }
#endif
            LOCK_DESTROY (&conf->forget.lock);
            FREE (conf);
    }
	this->private = NULL;
	return;
}


int
protocol_client_handshake (xlator_t *this, transport_t *trans)
{
	hf_hdr_common_t        *hdr = NULL;
	hf_mop_setvolume_req_t *req = NULL;
	dict_t                 *options = NULL;
	int32_t                 ret = -1;
	int                     hdrlen = 0;
	int                     dict_len = 0;
	call_frame_t           *fr = NULL;
	char                   *process_uuid_xl;

	options = this->options;
	ret = dict_set_str (options, "protocol-version", HF_PROTOCOL_VERSION);
	if (ret < 0) {
		hf_log (this->name, HF_LOG_DEBUG,
			"failed to set protocol version(%s) in handshake msg",
			HF_PROTOCOL_VERSION);
	}

	asprintf (&process_uuid_xl, "%s-%s", this->ctx->process_uuid,
		  this->name);
	ret = dict_set_dynstr (options, "process-uuid",
			       process_uuid_xl);
	if (ret < 0) {
		hf_log (this->name, HF_LOG_DEBUG,
			"failed to set process-uuid(%s) in handshake msg",
			process_uuid_xl);
	}

        if (this->ctx->cmd_args.volfile_server) {
                if (this->ctx->cmd_args.volfile_id)
                        ret = dict_set_str (options, "volfile-key", 
                                            this->ctx->cmd_args.volfile_id);
                ret = dict_set_uint32 (options, "volfile-checksum", 
                                       this->ctx->volfile_checksum);
        }

	dict_len = dict_serialized_length (options);
	if (dict_len < 0) {
		hf_log (this->name, HF_LOG_DEBUG,
			"failed to get serialized length of dict(%p)",
			options);
		ret = dict_len;
		goto fail;
	}

	hdrlen = hf_hdr_len (req, dict_len);
	hdr    = hf_hdr_new (req, dict_len);
	HF_VALIDATE_OR_GOTO(this->name, hdr, fail);

	req    = hf_param (hdr);

	ret = dict_serialize (options, req->buf);
	if (ret < 0) {
		hf_log (this->name, HF_LOG_DEBUG,
			"failed to serialize dictionary(%p)",
			options);
		goto fail;
	}

	req->dict_len = hton32 (dict_len);
	fr  = create_frame (this, this->ctx->pool);
	HF_VALIDATE_OR_GOTO(this->name, fr, fail);

	fr->local = trans;
	ret = protocol_client_xfer (fr, this, trans,
				    HF_OP_TYPE_MOP_REQUEST, HF_MOP_SETVOLUME,
				    hdr, hdrlen, NULL, 0, NULL);
	return ret;
fail:
	if (hdr)
		free (hdr);
	return ret;
}


int
protocol_client_pollout (xlator_t *this, transport_t *trans)
{
	client_conf_t *conf = NULL;

	conf = trans->xl->private;

	pthread_mutex_lock (&conf->mutex);
	{
		gettimeofday (&conf->last_sent, NULL);
	}
	pthread_mutex_unlock (&conf->mutex);

	return 0;
}


int
protocol_client_pollin (xlator_t *this, transport_t *trans)
{
	client_conf_t *conf = NULL;
	int            ret = -1;
        struct iobuf  *iobuf = NULL;
	char          *hdr = NULL;
	size_t         hdrlen = 0;

	conf = trans->xl->private;

	pthread_mutex_lock (&conf->mutex);
	{
		gettimeofday (&conf->last_received, NULL);
	}
	pthread_mutex_unlock (&conf->mutex);

	ret = transport_receive (trans, &hdr, &hdrlen, &iobuf);

	if (ret == 0)
	{
		ret = protocol_client_interpret (this, trans, hdr, hdrlen,
						 iobuf);
	}

	/* TODO: use mem-pool */
	FREE (hdr);

	return ret;
}


/*
 * client_protocol_notify - notify function for client protocol
 * @this:
 * @trans: transport object
 * @event
 *
 */

int
notify (xlator_t *this, int32_t event, void *data, ...)
{
        int                  i          = 0;
	int                  ret        = -1;
        int                  child_down = 1;
        int                  was_not_down = 0;
	transport_t         *trans      = NULL;
	client_connection_t *conn       = NULL;
        client_conf_t       *conf       = NULL;
        xlator_list_t       *parent = NULL;

        conf = this->private;
	trans = data;

	switch (event) {
	case HF_EVENT_POLLOUT:
	{
		ret = protocol_client_pollout (this, trans);

		break;
	}
	case HF_EVENT_POLLIN:
	{
		ret = protocol_client_pollin (this, trans);

		break;
	}
	/* no break for ret check to happen below */
	case HF_EVENT_POLLERR:
	{
		ret = -1;


		protocol_client_cleanup (trans);

                if (conf->connecting == 0) {
                        /* Let the connection/re-connection happen in 
                         * background, for now, don't hang here,
                         * tell the parents that i am all ok..
                         */
                        parent = trans->xl->parents;
                        while (parent) {
                                parent->xlator->notify (parent->xlator,
                                                        HF_EVENT_CHILD_CONNECTING,
                                                        trans->xl);
                                parent = parent->next;
                        }
                        conf->connecting = 1;
                }

                was_not_down = 0;
                for (i = 0; i < CHANNEL_MAX; i++) {
                        conn = conf->transport[i]->xl_private;
                        if (conn->connected == 1)
                                was_not_down = 1;
                }

                conn = trans->xl_private;
                if (conn->connected) {
                        conn->connected = 0;
                        if (conn->reconnect == 0) {
                                client_protocol_reconnect (trans);
			}
                }

                child_down = 1;
                for (i = 0; i < CHANNEL_MAX; i++) {
                        trans = conf->transport[i];
                        conn = trans->xl_private;
                        if (conn->connected == 1)
                                child_down = 0;
                }
		conn->connect_count ++;

                if ((child_down && was_not_down) ||
			(!was_not_down && conn->connect_count > 2)) {

                        hf_log (this->name, HF_LOG_INFO, "disconnected: connect count %d", conn->connect_count);

			conn->connect_count = 0;
                        protocol_client_mark_fd_bad (this);

                        parent = this->parents;
                        while (parent) {
                                parent->xlator->notify (parent->xlator,
                                                        HF_EVENT_CHILD_DOWN,
                                                        this);
                                parent = parent->next;
                        }
                }
	}
	break;

	case HF_EVENT_PARENT_UP:
	{
		client_conf_t *conf = NULL;
		int            i = 0;
		transport_t   *trans = NULL;

		conf = this->private;
		for (i = 0; i < CHANNEL_MAX; i++) {
			trans = conf->transport[i];
			if (!trans) {
				hf_log (this->name, HF_LOG_DEBUG,
					"transport init failed");
				return -1;
			}

			conn = trans->xl_private;

			hf_log (this->name, HF_LOG_DEBUG,
				"got HF_EVENT_PARENT_UP, attempting connect "
				"on transport");

			client_protocol_reconnect (trans);
		}
	}
	break;

	case HF_EVENT_CHILD_UP:
	{
		char *handshake = NULL;

		ret = dict_get_str (this->options, "disable-handshake", 
				    &handshake);
		hf_log (this->name, HF_LOG_DEBUG, 
			"got HF_EVENT_CHILD_UP");
		if ((ret < 0) ||
		    (strcasecmp (handshake, "on"))) {
			ret = protocol_client_handshake (this, trans);
		} else {
			conn = trans->xl_private;
			conn->connected = 1;
			ret = default_notify (this, event, trans);
		}

		if (ret)
			transport_disconnect (trans);

	}
	break;
	default:
		hf_log (this->name, HF_LOG_DEBUG,
			"got %d, calling default_notify ()", event);

		default_notify (this, event, data);
		break;
	}
	return ret;
}


struct xlator_fops fops = {
	.unlink      = client_unlink,
	.stat	     = client_stat,
	.fstat	     = client_fstat,
	.open        = client_open,
	.readv       = client_readv,
	.writev      = client_writev,
	.flush       = client_flush,
	.setobject   = client_setobject,
	.updateobject = client_updateobject,
	.getobject    = client_getobject,
	.lookupobject = client_lookupobject,
	.deleteobject = client_deleteobject,
	.ioctl		 = client_ioctl,
	.checksum    = client_checksum,
	.truncate    = client_truncate,
	.ftruncate    = client_ftruncate
};

struct xlator_mops mops = {
	.stats     = client_stats,
	.getspec   = client_getspec,
};

struct xlator_cbks cbks = {
	.release    = client_release,
};

struct volume_options options[] = {
 	{ .key   = {"username"}, 
	  .type  = HF_OPTION_TYPE_ANY 
	},
 	{ .key   = {"password"}, 
	  .type  = HF_OPTION_TYPE_ANY 
	},
 	{ .key   = {"transport-type"}, 
	  .value = {"tcp", "socket", "ib-verbs", "unix", "ib-sdp",
            "swnet-verbs", "swnet-verbs/client",
		    "tcp/client", "ib-verbs/client"},
	  .type  = HF_OPTION_TYPE_STR 
	},
 	{ .key   = {"remote-host"}, 
	  .type  = HF_OPTION_TYPE_STR 
	},
 	{ .key   = {"remote-subvolume"}, 
	  .type  = HF_OPTION_TYPE_ANY 
	},
 	{ .key   = {"frame-timeout"}, 
	  .type  = HF_OPTION_TYPE_TIME, 
	  .min   = 5, 
	  .max   = 1013, 
	}, 
	{ .key   = {"ping-timeout"},
	  .type  = HF_OPTION_TYPE_TIME,
	  .min   = 5,
	  .max   = 1013,
	},
	{ .key   = {NULL} },
};
