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
#include <time.h>
#include <sys/uio.h>
#include <sys/resource.h>

#include <libgen.h>
#include <string.h>

#include <stdint.h>
#include <arpa/inet.h>
#include <netdb.h>
#include <netinet/in.h>

#include "transport.h"
#include "fnmatch.h"
#include "xlator.h"
#include "protocol.h"
#include "server-protocol.h"
#include "server-helpers.h"
#include "call-stub.h"
#include "defaults.h"
#include "list.h"
#include "dict.h"
#include "object.h"
#include "compat.h"
#include "compat-errno.h"
#include "fd.h"

static void
protocol_server_reply (call_frame_t *frame, int type, int op,
		hf_hdr_common_t *hdr, size_t hdrlen,
		struct iovec *vector, int count,
		struct iobref *iobref)
{
	server_state_t *state = NULL;
	transport_t    *trans = NULL;
	int             ret = 0;

	state    = CALL_STATE (frame);
	trans    = state->trans;

	hdr->callid = hton64 (frame->root->unique);
	hdr->type   = hton32 (type);
	hdr->op     = hton32 (op);

	ret = transport_submit (trans, (char *)hdr, hdrlen, vector, 
			count, iobref);
	if (ret < 0) {
		hf_log ("protocol/server", HF_LOG_ERROR,
				"frame %"PRId64": failed to submit trans %s op= %d, type= %d",
				frame->root->unique, trans->peerinfo.identifier, op, type);
	}

	STACK_DESTROY (frame->root);

	if (state){
		free_state (state);
	}
}

static inline void
general_stat (struct stat *stbuf)
{
	/* st arguments owned by hadafs */
	stbuf->st_dev = 314315627;
	stbuf->st_rdev = 0;
	stbuf->st_blksize = 4096;
	stbuf->st_nlink = 0;
	stbuf->st_blocks = stbuf->st_size / 512;
}

/*
 * server_unlink_cbk - unlink callback for server protocol
 * @frame: call frame
 * @cookie:
 * @this:
 * @op_ret: return value
 * @op_errno: errno
 *
 * not for external reference
 */
int
server_unlink_cbk (call_frame_t *frame, void *cookie, xlator_t *this,
		int32_t op_ret, int32_t op_errno)
{
	hf_hdr_common_t      *hdr = NULL;
	hf_fop_unlink_rsp_t  *rsp = NULL;
	server_state_t       *state = NULL;
	size_t                hdrlen = 0;
	int32_t               hf_errno = 0;
	server_conf_t        *conf = NULL;
	uint64_t 	   objaddr = 0;
	int32_t 	     ret = -1;

	state = CALL_STATE(frame);

	if (op_ret == 0) {
		hf_log (state->bound_xl->name, HF_LOG_TRACE,
				"%"PRId64": UNLINK_CBK %s (%"PRId64")",
				frame->root->unique, state->loc.path,
				state->loc.object->metadata.lno);
		object_unlink (state->loc.object);
	} 
	else {
		hf_log (this->name, HF_LOG_DEBUG,
				"%"PRId64": UNLINK %s (%"PRId64") ==> %"PRId32" (%s)",
				frame->root->unique, state->loc.path, 
				state->loc.object ? state->loc.object->metadata.lno : 0,
				op_ret, strerror (op_errno));
	}

	hdrlen = hf_hdr_len (rsp, 0);
	hdr    = hf_hdr_new (rsp, 0);
	rsp    = hf_param (hdr);

	hdr->rsp.op_ret = hton32 (op_ret);
	hf_errno        = hf_errno_to_error (op_errno);
	hdr->rsp.op_errno = hton32 (hf_errno);

	protocol_server_reply (frame, HF_OP_TYPE_FOP_REPLY, HF_FOP_UNLINK,
			hdr, hdrlen, NULL, 0, NULL);

	return 0;
}

/*
 * server_ioctl_cbk - flush callback for server protocol
 * @frame: call frame
 * @cookie:
 * @this:
 * @op_ret:
 * @op_errno:
 *
 * not for external reference
 */
int
server_ioctl_cbk (call_frame_t *frame, void *cookie, xlator_t *this,
		int32_t op_ret, int32_t op_errno)
{
	hf_hdr_common_t    *hdr = NULL;
	hf_fop_ioctl_rsp_t *rsp = NULL;
	size_t              hdrlen = 0;
	int32_t             hf_errno = 0;
	server_state_t     *state = NULL;

	state = CALL_STATE(frame);
	if (op_ret < 0) {
		hf_log (this->name, HF_LOG_DEBUG,
				"%"PRId64": IOCTL %"PRId64" (%s) ==> %"PRId32" (%s)",
				frame->root->unique, state->fd_no, 
				state->fd ? state->fd->object->path : 0, op_ret,
				strerror (op_errno));
	}
	hdrlen = hf_hdr_len (rsp, 0);
	hdr    = hf_hdr_new (rsp, 0);
	rsp    = hf_param (hdr);

	hdr->rsp.op_ret = hton32 (op_ret);
	hf_errno        = hf_errno_to_error (op_errno);
	hdr->rsp.op_errno = hton32 (hf_errno);


	protocol_server_reply (frame, HF_OP_TYPE_FOP_REPLY, HF_FOP_IOCTL,
			hdr, hdrlen, NULL, 0, NULL);

	return 0;
}

/*
 * server_release_cbk - rleease callback for server protocol
 * @frame: call frame
 * @cookie:
 * @this:
 * @op_ret:
 * @op_errno:
 *
 * not for external reference
 */
int
server_release_cbk (call_frame_t *frame, void *cookie, xlator_t *this,
	int32_t op_ret, int32_t op_errno)
{
	hf_hdr_common_t      *hdr = NULL;
	hf_cbk_release_rsp_t *rsp = NULL;
	size_t                hdrlen = 0;
	int32_t               hf_errno = 0;

	hdrlen = hf_hdr_len (rsp, 0);
	hdr    = hf_hdr_new (rsp, 0);

	hdr->rsp.op_ret = hton32 (op_ret);
	hf_errno        = hf_errno_to_error (op_errno);
	hdr->rsp.op_errno = hton32 (hf_errno);


	protocol_server_reply (frame, HF_OP_TYPE_CBK_REPLY, HF_CBK_RELEASE,
			hdr, hdrlen, NULL, 0, NULL);

	return 0;
}

/*
 * server_writev_cbk - writev callback for server protocol
 * @frame: call frame
 * @cookie:
 * @this:
 * @op_ret:
 * @op_errno:
 *
 * not for external reference
 */
int
server_writev_cbk (call_frame_t *frame, void *cookie, xlator_t *this,
		int32_t op_ret, int32_t op_errno, struct stat *stbuf)
{
	hf_hdr_common_t    *hdr = NULL;
	hf_fop_write_rsp_t *rsp = NULL;
	server_conf_t      *conf = NULL;
	size_t              hdrlen = 0;
	server_state_t     *state = NULL;
	uint64_t 	   objaddr = 0;
	object_t    *object = NULL;
	int 		ret = 0,flags = 0;

	state = CALL_STATE(frame);

	conf = this->private;

	hdrlen = hf_hdr_len (rsp, 0);
	hdr    = hf_hdr_new (rsp, 0);
	rsp    = hf_param (hdr);

	hdr->rsp.op_ret = hton32 (op_ret);
	hdr->rsp.op_errno = hton32 (hf_errno_to_error (op_errno));

	object = state->fd->object;
	if (op_ret >= 0) {
		hf_stat_from_stat (&rsp->stat, stbuf);
	} else {
		hf_log (this->name, HF_LOG_DEBUG,
				"%"PRId64": WRITEV %"PRId64" (%s) ==> %"PRId32" (%s)",
				frame->root->unique, state->fd_no, 
				state->fd ? state->fd->object->path : 0, op_ret,
				strerror (op_errno));
	}
	protocol_server_reply (frame, HF_OP_TYPE_FOP_REPLY, HF_FOP_WRITE,
			hdr, hdrlen, NULL, 0, NULL);

	return 0;
}


/*
 * server_readv_cbk - readv callback for server protocol
 * @frame: call frame
 * @cookie:
 * @this:
 * @op_ret:
 * @op_errno:
 * @vector:
 * @count:
 *
 * not for external reference
 */
int
server_readv_cbk (call_frame_t *frame, void *cookie, xlator_t *this,
	int32_t op_ret, int32_t op_errno,
	struct iovec *vector, int32_t count, struct stat *stbuf, struct iobref *iobref)
{
	hf_hdr_common_t   *hdr = NULL;
	hf_fop_read_rsp_t *rsp = NULL;
	size_t             hdrlen = 0;
	int32_t            hf_errno = 0;
	server_state_t    *state = NULL;
	server_conf_t      *conf = NULL;
	object_t 	*object = NULL;
	int 		ret = 0, flags = 0;

	conf = this->private;

	state = CALL_STATE(frame);
	hdrlen = hf_hdr_len (rsp, 0);
	hdr    = hf_hdr_new (rsp, 0);
	rsp    = hf_param (hdr);
	if (op_ret >= 0) {
		hf_stat_from_stat (&rsp->stat, stbuf);
	}else{
		hf_log (this->name, HF_LOG_DEBUG,
				"%"PRId64": READV %"PRId64" (%s ==> %"PRId32" (%s)",
				frame->root->unique, state->fd_no, 
				state->fd != NULL?state->fd->object->path:0, op_ret,
				strerror (op_errno));
	}

	hf_log (this->name, HF_LOG_DEBUG,
			"%"PRId64": READV %"PRId64" (%s ==> %"PRId32" (%s)",
			frame->root->unique, state->fd_no, 
			state->fd != NULL?state->fd->object->path:0, op_ret,
			strerror (op_errno));

	hdr->rsp.op_ret = hton32 (op_ret);
	hf_errno        = hf_errno_to_error (op_errno);
	hdr->rsp.op_errno = hton32 (hf_errno);

	protocol_server_reply (frame, HF_OP_TYPE_FOP_REPLY, HF_FOP_READ,
			hdr, hdrlen, vector, count, iobref);

	return 0;
}

/*
 * server_open_cbk - open callback for server
 * @frame: call frame
 * @cookie:
 * @this:  translator structure
 * @op_ret:
 * @op_errno:
 * @fd: file descriptor
 * @object: object structure
 * @stbuf: struct stat of created file
 *
 * not for external reference
 */
int
server_open_cbk (call_frame_t *frame, void *cookie, xlator_t *this,
		int32_t op_ret, int32_t op_errno,
		fd_t *fd, object_t *object, struct stat *stbuf)
{
	server_connection_t *conn = NULL;
	hf_hdr_common_t     *hdr = NULL;
	hf_fop_open_rsp_t   *rsp = NULL;
	server_state_t      *state = NULL;
	server_conf_t       *conf = NULL;
	size_t               hdrlen = 0;
	int32_t              hf_errno = 0;

	conn = SERVER_CONNECTION (frame);
	conf = this->private;

	state = CALL_STATE (frame);

	if (op_ret >= 0) {
		hf_log (state->bound_xl->name, HF_LOG_TRACE,
				"%"PRId64": OPEN  %s (%"PRId64")",
				frame->root->unique, state->loc.path, stbuf->st_ino);

		state->fd_no = hf_fd_unused_get (conn->fdtable, fd);
		op_ret = state->fd_no;
		if ((state->fd_no < 0) || (fd == 0)) {
			op_errno = errno;
		}
		fd_bind (fd);
		fd_ref(fd);
	} else {
		state->fd_no = -1;
		hf_log (this->name, HF_LOG_DEBUG,
				"%"PRId64": OPEN %s (%"PRId64") ==> %"PRId32" (%s)",
				frame->root->unique, state->loc.path, 
				state->loc.object ? state->loc.object->metadata.lno : 0,
				op_ret, strerror (op_errno));
	}

	hdrlen = hf_hdr_len (rsp, 0);
	hdr    = hf_hdr_new (rsp, 0);
	rsp    = hf_param (hdr);

	hdr->rsp.op_ret = hton32 (op_ret);
	hf_errno        = hf_errno_to_error (op_errno);
	hdr->rsp.op_errno = hton32 (hf_errno);
	rsp->fd           = hton64 (state->fd_no);


	if(op_ret >= 0)
		hf_stat_from_stat(&rsp->stat, stbuf);

	protocol_server_reply (frame, HF_OP_TYPE_FOP_REPLY, HF_FOP_OPEN,
			hdr, hdrlen, NULL, 0, NULL);

	return 0;
}

/*NOTE: open object need op permission on object. */
#define SERVER_PERMISSION_CHECK(flags, mode, readperm, writeperm, retval)  \
	do {  \
		if( flags & O_RDWR ){   \
			if( (mode & readperm) && (mode & writeperm) ) \
			retval = 0; \
			else \
			retval = -1; \
		}   \
		else if( flags & O_WRONLY ) {	\
			if( mode & writeperm )   \
			retval = 0;   \
			else   \
			retval = -1;   \
		}   \
		else {	\
			if( mode & readperm )   \
			retval = 0;   \
			else   \
			retval = -1;   \
		}   \ 
	} while(0)

/* If stack->uid & stack->gid have the permission(define in flags) needed 
   by this object defined ? */

inline	int32_t 
server_op_allowed (call_stack_t *stack, int flags, object_t  *object)
{
	int ret = -1;

	if(stack->uid == 0) { // root user
		ret = 0;
		return ret;
	}else if(stack->uid == object->metadata.uid) {
		SERVER_PERMISSION_CHECK(flags,object->metadata.mode, S_IRUSR, S_IWUSR, ret);
	}else if(stack->gid == object->metadata.gid) {
		SERVER_PERMISSION_CHECK(flags, object->metadata.mode, S_IRGRP, S_IWGRP, ret);
	}else {
		SERVER_PERMISSION_CHECK(flags, object->metadata.mode, S_IROTH, S_IWOTH, ret);
	}

	hf_log("server", HF_LOG_TRACE, "uid:%d, gid:%d, ouid:%d, ogid:%d, mode:%o, flags=%d, ret=%d",
			stack->uid, stack->gid, object->metadata.uid, object->metadata.gid, object->metadata.mode, flags, ret);

	return ret;
}


/*
 * server_open - open function for server
 * @frame: call frame
 * @bound_xl: translator this server is bound to
 * @params: parameters dictionary
 *
 * not for external reference
 */
int
server_open (call_frame_t *frame, xlator_t *bound_xl,
		hf_hdr_common_t *hdr, size_t hdrlen,
		struct iobuf *iobuf)
{
	hf_fop_open_req_t   *req = NULL;
	xlator_t            *this = NULL;
	server_state_t      *state = NULL;
	server_conf_t       *conf = NULL;
	size_t               pathlen = 0;
	size_t		     sidlen = 0;
	int32_t		    ret = -1;

	req   = hf_param (hdr);
	state = CALL_STATE(frame);
	this = frame->this;
	conf = this->private;
	pathlen = STRLEN_0(req->path);

	state->path = req->path;
	state->sid = req->path + pathlen;

	sidlen = STRLEN_0(state->sid);
	state->vmp = req->path + pathlen + sidlen;

	state->soffset = ntoh32 (req->soffset);
	state->mode  = ntoh32 (req->mode);
	state->flags = hf_flags_to_flags (ntoh32 (req->flags));

	ret = server_loc_fill (&(state->loc), state, state->path);	
	if(ret < 0) {
		server_open_cbk (frame, NULL, frame->this, -1,
				EINVAL, NULL, 0, NULL);
		return -1;
	}
	state->fd = fd_create(state->loc.object, frame->root->pid);
	if(state->fd == NULL) {
		server_open_cbk (frame, NULL, frame->this, -1,
				EINVAL, NULL, 0, NULL);
		return -1;
	}
	/*
	 * here we craate file with S_IRUSR|S_IWUSR in local storage.
	 * the real mode is in database
	 */
	STACK_WIND (frame, server_open_cbk,
			bound_xl, bound_xl->fops->open,
			&(state->loc), state->flags,
			S_IRUSR|S_IWUSR, state->fd);

	return 0;
}

/*
 * server_readv - readv function for server protocol
 * @frame: call frame
 * @bound_xl:
 * @params: parameter dictionary
 *
 * not for external reference
 */
	int
server_readv (call_frame_t *frame, xlator_t *bound_xl,
		hf_hdr_common_t *hdr, size_t hdrlen,
		struct iobuf *iobuf)
{

	hf_fop_read_req_t   *req = NULL;
	server_state_t      *state = NULL;
	int32_t	ret = -1;

	req = hf_param (hdr);
	state = CALL_STATE (frame);

	state->fd_no  = ntoh64 (req->fd);
	state->size           = ntoh32 (req->size);
	state->offset         = ntoh64 (req->offset);
	ret = server_fd_fill (state->fd, frame, state->path);	
	if(ret < 0) {
			server_readv_cbk (frame, NULL, frame->this, -1,
					EINVAL, NULL, 0, NULL, NULL);
			return -1;
	}
	
	STACK_WIND (frame, server_readv_cbk,
			bound_xl, bound_xl->fops->readv,
			state->fd, state->size, state->offset);

	return 0;
}

/*
 * server_writev - writev function for server
 * @frame: call frame
 * @bound_xl:
 * @params: parameter dictionary
 *
 * not for external reference
 */
	int
server_writev (call_frame_t *frame, xlator_t *bound_xl,
		hf_hdr_common_t *hdr, size_t hdrlen,
		struct iobuf *iobuf)
{
	hf_fop_write_req_t  *req = NULL;
	server_state_t      *state = NULL;
	struct iobref       *iobref = NULL;
	struct iovec      iov = {0, };
	int32_t ret = -1;

	req   = hf_param (hdr);
	state = CALL_STATE (frame);

	state->fd_no = ntoh64 (req->fd);
	state->offset        = ntoh64 (req->offset);
	state->size          = ntoh32 (req->size);

	if (iobuf) {
		iobref = iobref_new ();
		state->iobuf = iobuf;
		iobref_add (iobref, state->iobuf);
		state->iobref = iobref;
		iov.iov_base = state->iobuf->ptr;
		iov.iov_len = state->size;
	}
	ret = server_fd_fill (state->fd, frame, state->path);	
	if(ret < 0) {
			server_writev_cbk (frame, NULL, frame->this, -1,
					EINVAL, NULL);
			return -1;
	}
	STACK_WIND (frame, server_writev_cbk,
				bound_xl, bound_xl->fops->writev,
				state->fd, &iov, 1,
				state->offset, state->iobref);

	return 0;
}

/*
 * server_forget_cbk - forget callback for server protocol
 * not for extenal reference
 */
	int
server_forget (call_frame_t *frame, xlator_t *bound_xl,
		hf_hdr_common_t *hdr, size_t hdrlen,
		struct iobuf *iobuf)
{
	hf_log ("forget", HF_LOG_CRITICAL, "function not implemented");
	return 0;
}

/*
 * server_flush_cbk - flush callback for server protocol
 * @frame: call frame
 * @cookie:
 * @this:
 * @op_ret:
 * @op_errno:
 *
 * not for external reference
*/
int
server_flush_cbk(call_frame_t * frame, void * cookie, xlator_t * this,
	int32_t op_ret, int32_t op_errno, struct stat * stbuf)
{
		hf_hdr_common_t    *hdr = NULL;
		hf_fop_flush_rsp_t *rsp = NULL;
		size_t				hdrlen = 0;
		int32_t 			hf_errno = 0;
		server_state_t	   *state = NULL;
		server_conf_t	  *conf = NULL;
		
		state = CALL_STATE(frame);
		if (op_ret < 0) {
			hf_log (this->name, HF_LOG_DEBUG,
					"%"PRId64": FLUSH %"PRId64" (%s) ==> %"PRId32" (%s)",
					frame->root->unique, state->fd_no, 
					state->fd ? state->fd->object->path : 0, op_ret,
					strerror (op_errno));
		}
		hdrlen = hf_hdr_len (rsp, 0);
		hdr    = hf_hdr_new (rsp, 0);
		rsp    = hf_param (hdr);
		
		hdr->rsp.op_ret = hton32 (op_ret);
		hf_errno		= hf_errno_to_error (op_errno);
		hdr->rsp.op_errno = hton32 (hf_errno);
		
		if(op_ret >= 0)
			hf_stat_from_stat(&rsp->stat, stbuf);
		
		protocol_server_reply (frame, HF_OP_TYPE_FOP_REPLY, HF_FOP_FLUSH,
				hdr, hdrlen, NULL, 0, NULL);
		
		return 0;

}

/*
 * server_flush - flush function for server protocol
 * @frame: call frame
 * @bound_xl:
 * @params: parameter dictionary
 *
 * not for external reference
 */
int
server_flush (call_frame_t *frame, xlator_t *bound_xl,
		hf_hdr_common_t *hdr, size_t hdrlen,
		struct iobuf *iobuf)
{
	hf_fop_flush_req_t *req = NULL;
	server_state_t      *state = NULL;
	int32_t  ret = -1;

	req   = hf_param (hdr);
	state = CALL_STATE (frame);
	
	state->fd_no = ntoh64 (req->fd);
	ret = server_fd_fill (state->fd, frame, state->path);	
	if(ret < 0) {
			server_flush_cbk (frame, NULL, frame->this, -1,
					EINVAL, NULL);
			return -1;
	}
	
	STACK_WIND (frame, server_flush_cbk,
			bound_xl, bound_xl->fops->flush,
			state->fd);
	
	return 0;
}

/*
 * server_release - release function for server protocol
 * @frame: call frame
 * @bound_xl:
 * @params: parameter dictionary
 *
 * not for external reference
 */
	int
server_release (call_frame_t *frame, xlator_t *bound_xl,
		hf_hdr_common_t *hdr, size_t hdrlen,
		struct iobuf *iobuf)
{
	hf_cbk_release_req_t  *req = NULL;
	server_state_t        *state = NULL;
	server_connection_t   *conn = NULL;
	int32_t              ret = -1;

	req = hf_param (hdr);
	state = CALL_STATE(frame);	
	conn = SERVER_CONNECTION(frame);

	state->fd_no = ntoh64 (req->fd);
	ret = server_fd_fill (state->fd, frame, state->path);	
	if(ret < 0) {
			server_flush_cbk (frame, NULL, frame->this, -1,
					EINVAL, NULL);
			return -1;
	}	
	hf_fd_put (conn->fdtable, state->fd_no);

	server_release_cbk (frame, NULL, frame->this, 0, 0);
	
	return 0;
}

/*
 * server_ioctl - ioctl function for server protocol
 * @frame: call frame
 * @bound_xl:
 * @params: parameter dictionary
 *
 * not for external reference
 */

	int
server_ioctl (call_frame_t *frame, xlator_t *bound_xl,
		hf_hdr_common_t *hdr, size_t hdrlen,
		struct iobuf *iobuf)
{
	hf_fop_ioctl_req_t *req = NULL;
	server_state_t      *state = NULL;
	int32_t ret = -1;

	req   = hf_param (hdr);
	state = CALL_STATE (frame);

	state->fd_no = ntoh64 (req->fd);
	state->cmd = ntoh32(req->cmd);

	/* TODO: add more arguments as needed */
	state->arg = 0;
	ret = server_fd_fill (state->fd, frame, state->path);	
	if(ret < 0) {
			server_ioctl_cbk (frame, NULL, frame->this, -1,
					EINVAL);
			return -1;
	} 	
	STACK_WIND (frame, server_ioctl_cbk,
			bound_xl, bound_xl->fops->ioctl,
			state->fd, state->cmd, state->arg);

	return 0;
}

/*
 * server_unlink - unlink function for server protocol
 * @frame: call frame
 * @bound_xl:
 * @params: parameter dictionary
 *
 * not for external reference
 */
int
server_unlink (call_frame_t *frame, xlator_t *bound_xl,
		hf_hdr_common_t *hdr, size_t hdrlen,
		struct iobuf *iobuf)
{
	hf_fop_unlink_req_t *req = NULL;
    xlator_t            *this = NULL;
    server_conf_t       *conf = NULL; 
	server_state_t      *state = NULL;
	int32_t              ret = -1;
	size_t 			    pathlen = 0;

    this = frame->this;
    conf = this->private;
	req   = hf_param (hdr);
	state = CALL_STATE (frame);
	pathlen = STRLEN_0 (req->path);

	state->path = req->path;
	state->sid = req->path + pathlen;
	state->soffset = ntoh32 (req->soffset);

	ret = server_loc_fill (&(state->loc), state, state->path);
	if(ret < 0) {
		server_unlink_cbk (frame, NULL, frame->this, -1,
				EINVAL);
		return -1;
	}  

	STACK_WIND (frame, server_unlink_cbk,
			bound_xl, bound_xl->fops->unlink,
			&(state->loc));
	
	return 0;
}

/*
 * server_fstat_cbk - fstat callback for server protocol
 * @frame: call frame
 * @cookie:
 * @this:
 * @op_ret:
 * @op_errno:
 * @stbuf:
 *
 */
int
server_fstat_cbk (call_frame_t *frame, void *cookie, xlator_t *this,
		int32_t op_ret, int32_t op_errno, struct stat *stbuf)
{
	hf_hdr_common_t    *hdr = NULL;
	hf_fop_fstat_rsp_t *rsp = NULL;
	size_t              hdrlen = 0;
	int32_t             hf_errno = 0;
	server_state_t     *state = NULL;

	hdrlen = hf_hdr_len (rsp, 0);
	hdr    = hf_hdr_new (rsp, 0);
	rsp    = hf_param (hdr);

	hdr->rsp.op_ret = hton32 (op_ret);
	hf_errno        = hf_errno_to_error (op_errno);
	hdr->rsp.op_errno = hton32 (hf_errno);

	if (op_ret == 0) {
		hf_stat_from_stat (&rsp->stat, stbuf);
	} else {
		state = CALL_STATE(frame);
		hf_log (this->name, HF_LOG_DEBUG,
				"%"PRId64": FSTAT %"PRId64" (%s) ==> %"PRId32" (%s)",
				frame->root->unique, state->fd_no,
				state->fd ? state->fd->object->path : 0, op_ret,
				strerror (op_errno));
	}

	protocol_server_reply (frame, HF_OP_TYPE_FOP_REPLY, HF_FOP_FSTAT,
			hdr, hdrlen, NULL, 0, NULL);

	return 0;
}


	int
server_fstat (call_frame_t *frame, xlator_t *bound_xl,
		hf_hdr_common_t *hdr, size_t hdrlen,
		struct iobuf *iobuf)
{
	hf_fop_fstat_req_t  *req = NULL;
	server_state_t      *state = NULL;
	int32_t  ret = -1;

	req   = hf_param (hdr);
	state = CALL_STATE (frame);

	/*
	 * return right file size 
	 */
	state->fd_no   = ntoh64 (req->fd);
	ret = server_fd_fill (state->fd, frame, state->path);	
	if(ret < 0) {
		server_fstat_cbk (frame, NULL, frame->this, -1,
				EINVAL, NULL);
		return -1;
	} 
	STACK_WIND (frame, server_fstat_cbk,
				bound_xl, bound_xl->fops->fstat,
				state->fd);

	return 0;
}

int
server_ftruncate_cbk (call_frame_t *frame, void *cookie, xlator_t *this,
                      int32_t op_ret, int32_t op_errno,
                      struct stat *postbuf)
{
        hf_hdr_common_t        *hdr = NULL;
        hf_fop_ftruncate_rsp_t *rsp = NULL;
        size_t                  hdrlen = 0;
        int32_t                 hf_errno = 0;
        server_state_t         *state = NULL;
		uint64_t 	   objaddr = 0;

        hdrlen = hf_hdr_len (rsp, 0);
        hdr    = hf_hdr_new (rsp, 0);
        rsp    = hf_param (hdr);

        hdr->rsp.op_ret = hton32 (op_ret);
        hf_errno        = hf_errno_to_error (op_errno);
        hdr->rsp.op_errno = hton32 (hf_errno);

        state = CALL_STATE (frame);
        if (op_ret == 0) {
                hf_stat_from_stat (&rsp->poststat, postbuf);
        } else {
               hf_log (this->name, HF_LOG_DEBUG,
                    "%"PRId64": FTRUNCATE %"PRId64" (%"PRId64") ==> %"PRId32" (%s)",
                    frame->root->unique, state->fd_no,
                    state->fd ? state->fd->object->metadata.lno : 0, op_ret,
                    strerror (op_errno));
        }

        protocol_server_reply (frame, HF_OP_TYPE_FOP_REPLY, HF_FOP_FTRUNCATE,
                               hdr, hdrlen, NULL, 0, NULL);

        return 0;
}

int
server_ftruncate (call_frame_t *frame, xlator_t *bound_xl,
                  hf_hdr_common_t *hdr, size_t hdrlen,
                  struct iobuf *iobuf)
{
        hf_fop_ftruncate_req_t  *req = NULL;
        server_state_t          *state = NULL;
		int32_t  ret = -1;

        req = hf_param (hdr);
        state = CALL_STATE (frame);

        state->fd_no  = ntoh64 (req->fd);
	state->offset         = ntoh64 (req->offset);
	ret = server_fd_fill (state->fd, frame, state->path);	
	if(ret < 0) {
		server_ftruncate_cbk (frame, NULL, frame->this, -1,
				EINVAL, NULL);
		return -1;
	} 
		
        STACK_WIND (frame, server_ftruncate_cbk,
                    bound_xl, bound_xl->fops->ftruncate,
                    state->fd, state->offset);

        return 0;
}

int
server_truncate_cbk (call_frame_t *frame, void *cookie, xlator_t *this,
                     int32_t op_ret, int32_t op_errno, 
                     struct stat *postbuf)
{
        hf_hdr_common_t       *hdr = NULL;
        hf_fop_truncate_rsp_t *rsp = NULL;
        server_state_t        *state = NULL;
        size_t                 hdrlen = 0;
        int32_t                hf_errno = 0;
		uint64_t 	   objaddr = 0;

        state = CALL_STATE (frame);

        hdrlen = hf_hdr_len (rsp, 0);
        hdr    = hf_hdr_new (rsp, 0);
        rsp    = hf_param (hdr);

        hdr->rsp.op_ret = hton32 (op_ret);
        hf_errno        = hf_errno_to_error (op_errno);
        hdr->rsp.op_errno = hton32 (hf_errno);

        if (op_ret == 0) {
                hf_stat_from_stat (&rsp->poststat, postbuf);
        } else {
                hf_log (this->name, HF_LOG_DEBUG,
                        "%"PRId64": TRUNCATE %s ==> %"PRId32" (%s)",
                        frame->root->unique, state->loc.path,
                        op_ret, strerror (op_errno));
        }

        protocol_server_reply (frame, HF_OP_TYPE_FOP_REPLY, HF_FOP_TRUNCATE,
                               hdr, hdrlen, NULL, 0, NULL);

        return 0;
}

int
server_truncate (call_frame_t *frame, xlator_t *bound_xl,
                 hf_hdr_common_t *hdr, size_t hdrlen,
                 struct iobuf *iobuf)
{
        hf_fop_truncate_req_t *req = NULL;
        server_state_t        *state = NULL;
		int32_t  ret = -1;
		size_t   pathlen = 0;

        req   = hf_param (hdr);
        state = CALL_STATE (frame);

		state->path  = req->path;
		pathlen = STRLEN_0(state->path);
		state->sid = req->path + pathlen;
		state->soffset = ntoh64 (req->soffset);
		state->offset        = ntoh64 (req->offset);

		ret = server_loc_fill (&(state->loc), state, state->path);	
		if(ret < 0) {
				server_truncate_cbk (frame, NULL, frame->this, -1,
						EINVAL, NULL);
				return -1;
		}  

		STACK_WIND (frame, server_truncate_cbk,
					bound_xl, bound_xl->fops->truncate,
					&state->loc, state->offset);

        return 0;
}


/*
 * server_stat_cbk - stat callback for server protocol
 * @frame: call frame
 * @cookie:
 * @this:
 * @op_ret:
 * @op_errno:
 * @stbuf:
 *
 * not for external reference
 */
	int
server_stat_cbk (call_frame_t *frame, void *cookie, xlator_t *this,
		int32_t op_ret, int32_t op_errno, struct stat *stbuf)
{
	hf_hdr_common_t   *hdr = NULL;
	hf_fop_stat_rsp_t *rsp = NULL;
	server_state_t    *state = NULL;
	size_t             hdrlen = 0;
	//int32_t            hf_errno = 0;

	state  = CALL_STATE (frame);

	hdrlen = hf_hdr_len (rsp, 0);
	hdr    = hf_hdr_new (rsp, 0);
	rsp    = hf_param (hdr);

	hdr->rsp.op_ret = hton32 (op_ret);
	hf_errno_to_error (op_errno);
	hdr->rsp.op_errno = hton32 (hf_errno_to_error (op_errno));

	if (op_ret == 0) {
		hf_stat_from_stat (&rsp->stat, stbuf);
	} else {
		hf_log (this->name, HF_LOG_DEBUG,
				"%"PRId64": STAT %s  ==> %"PRId32" (%s)",
				frame->root->unique, state->loc.path,
				op_ret, strerror (op_errno));

	}

	protocol_server_reply (frame, HF_OP_TYPE_FOP_REPLY, HF_FOP_STAT,
			hdr, hdrlen, NULL, 0, NULL);

	return 0;
}

int
server_stat (call_frame_t *frame, xlator_t *bound_xl,
		hf_hdr_common_t *hdr, size_t hdrlen,
		struct iobuf *iobuf)
{
	hf_fop_stat_req_t *req = NULL;
	server_state_t    *state = NULL;
	xlator_t          *this = NULL;
    server_conf_t     *conf = NULL;
	int32_t		    ret = -1;
	size_t          pathlen = 0;

    this = frame->this;
    conf = this->private;
	req = hf_param (hdr);
    state = CALL_STATE (frame);
    state->path 	     = req->path;

	pathlen = STRLEN_0(state->path);
	state->sid = state->path + pathlen;
	state->soffset = ntoh32 (req->soffset);

    ret = server_loc_fill (&(state->loc), state, state->path);	
	if(ret < 0) {
		server_stat_cbk (frame, NULL, frame->this, -1,
				EINVAL, NULL);
		return -1;
	}  

	STACK_WIND (frame, server_stat_cbk,
			bound_xl, bound_xl->fops->stat,
			&(state->loc));
	
	return 0;
}

/*
 * server_setobject - setobject callback for server protocol
 * @frame: call frame
 * @cookie:
 * @this:
 * @op_ret:
 * @op_errno:
 * @status:
 *
 * not for external reference
*/
int
server_setobject_cbk (call_frame_t *frame, void *cookie, xlator_t *this,
		int32_t op_ret, int32_t op_errno, int32_t status)
{
	hf_hdr_common_t   *hdr = NULL;
	hf_fop_setobject_rsp_t *rsp = NULL;
	server_state_t	  *state = NULL;
	size_t			   hdrlen = 0;
	//int32_t			 hf_errno = 0;

	state  = CALL_STATE (frame);

	hdrlen = hf_hdr_len (rsp, 0);
	hdr    = hf_hdr_new (rsp, 0);
	rsp    = hf_param (hdr);

	hdr->rsp.op_ret = hton32 (op_ret);
	hf_errno_to_error (op_errno);
	hdr->rsp.op_errno = hton32 (hf_errno_to_error (op_errno));
	if(op_ret >= 0) {
		rsp->object_status = hton32(status);
	} else {
		hf_log(this->name, HF_LOG_DEBUG, "set object %s failed %s",
			state->path, strerror(op_errno));
		rsp->object_status = hton32(-1);
	}
	rsp->object_status = hton32(status);

	protocol_server_reply (frame, HF_OP_TYPE_FOP_REPLY, HF_FOP_SETOBJECT,
			hdr, hdrlen, NULL, 0, NULL);

	return 0;
}

int
server_setobject (call_frame_t *frame, xlator_t *bound_xl,
		hf_hdr_common_t *hdr, size_t hdrlen,
		struct iobuf *iobuf)
{
	hf_fop_setobject_req_t *req = NULL;
	server_state_t	  *state = NULL;
	xlator_t		  *this = NULL;
	server_conf_t	  *conf = NULL;
	int32_t 		ret = -1;

	this = frame->this;
	conf = this->private;
	req = hf_param (hdr);
	state = CALL_STATE (frame);
	state->path 		 = req->path;

	ret = server_loc_fill (&(state->loc), state, state->path);	
	if(ret < 0) {
		server_setobject_cbk (frame, NULL, frame->this, -1,
				EINVAL, -1);
		return -1;
	}  
	memcpy(&state->loc.object->metadata, &req->object_info, sizeof(metadata_t));
	
	STACK_WIND (frame, server_setobject_cbk,
			bound_xl, bound_xl->fops->setobject,
			state->path, 1, state->loc.object);
	
	return 0;
}

/*
 * server_updateobject - updateobject callback for server protocol
 * @frame: call frame
 * @cookie:
 * @this:
 * @op_ret:
 * @op_errno:
 * @status:
 *
 * not for external reference
*/
int
server_updateobject_cbk (call_frame_t *frame, void *cookie, xlator_t *this,
		int32_t op_ret, int32_t op_errno, int32_t status)
{
	hf_hdr_common_t   *hdr = NULL;
	hf_fop_updateobject_rsp_t *rsp = NULL;
	server_state_t	  *state = NULL;
	size_t			   hdrlen = 0;
	//int32_t			 hf_errno = 0;

	state  = CALL_STATE (frame);

	hdrlen = hf_hdr_len (rsp, 0);
	hdr    = hf_hdr_new (rsp, 0);
	rsp    = hf_param (hdr);

	hdr->rsp.op_ret = hton32 (op_ret);
	hf_errno_to_error (op_errno);
	hdr->rsp.op_errno = hton32 (hf_errno_to_error (op_errno));
	if(op_ret >= 0) {
		rsp->object_status = hton32(status);
	} else {
		hf_log(this->name, HF_LOG_DEBUG, "update object %s failed %s",
			state->path, strerror(op_errno));
		rsp->object_status = hton32(-1);
	}

	protocol_server_reply (frame, HF_OP_TYPE_FOP_REPLY, HF_FOP_UPDATEOBJECT,
			hdr, hdrlen, NULL, 0, NULL);

	return 0;
}
		
int
server_updateobject (call_frame_t *frame, xlator_t *bound_xl,
		hf_hdr_common_t *hdr, size_t hdrlen,
		struct iobuf *iobuf)
{
	hf_fop_updateobject_req_t *req = NULL;
	server_state_t	  *state = NULL;
	xlator_t		  *this = NULL;
	server_conf_t	  *conf = NULL;
	int32_t 		updatebits = -1;
	int32_t 		ret = -1;

	this = frame->this;
	conf = this->private;
	req = hf_param (hdr);
	state = CALL_STATE (frame);
	state->path 		 = req->path;
	updatebits = hton32(req->updatebits);

	ret = server_loc_fill (&(state->loc), state, state->path);	
	if(ret < 0) {
		server_updateobject_cbk (frame, NULL, frame->this, -1,
				EINVAL, -1);
		return -1;
	}  
	memcpy(&state->loc.object->metadata, &req->object_info, sizeof(metadata_t));
	
	STACK_WIND (frame, server_updateobject_cbk,
			bound_xl, bound_xl->fops->updateobject,
			state->path, 1, updatebits, state->loc.object);
	
	return 0;
}

		
/*
 * server_getobject - getobject callback for server protocol
 * @frame: call frame
 * @cookie:
 * @this:
 * @op_ret:
 * @op_errno:
 * @object:
 *
 * not for external reference
*/
int
server_getobject_cbk (call_frame_t *frame, void *cookie, xlator_t *this,
		int32_t op_ret, int32_t op_errno, object_t *object)
{
	hf_hdr_common_t   *hdr = NULL;
	hf_fop_getobject_rsp_t *rsp = NULL;
	server_state_t	  *state = NULL;
	size_t			   hdrlen = 0;
	//int32_t			 hf_errno = 0;

	state  = CALL_STATE (frame);

	hdrlen = hf_hdr_len (rsp, 0);
	hdr    = hf_hdr_new (rsp, 0);
	rsp    = hf_param (hdr);
		
	hdr->rsp.op_ret = hton32 (op_ret);
	hf_errno_to_error (op_errno);
	hdr->rsp.op_errno = hton32 (hf_errno_to_error (op_errno));
	if(op_ret >= 0) {
		rsp->object_status = hton32(object->location);
		memcpy(&rsp->object_info, &object->metadata, sizeof(metadata_t));
	} else {
		hf_log(this->name, HF_LOG_DEBUG, "get object %s failed %s",
			state->path, strerror(op_errno));
		rsp->object_status = hton32(-1);
		memset(&rsp->object_info, 0, sizeof(rsp->object_info));
	}
		
	protocol_server_reply (frame, HF_OP_TYPE_FOP_REPLY, HF_FOP_GETOBJECT,
			hdr, hdrlen, NULL, 0, NULL);
		
	return 0;
}
				
int
server_getobject (call_frame_t *frame, xlator_t *bound_xl,
		hf_hdr_common_t *hdr, size_t hdrlen,
		struct iobuf *iobuf)
{
	hf_fop_getobject_req_t *req = NULL;
	server_state_t	  *state = NULL;
	xlator_t		  *this = NULL;
	server_conf_t	  *conf = NULL;
	int32_t 		ret = -1;
		
	this = frame->this;
	conf = this->private;
	req = hf_param (hdr);
	state = CALL_STATE (frame);
	state->path = req->path;
		
	ret = server_loc_fill (&(state->loc), state, state->path);	
	if(ret < 0) {
				server_getobject_cbk (frame, NULL, frame->this, -1,
						EINVAL, NULL);
				return -1;
	} 
			
	STACK_WIND (frame, server_getobject_cbk,
			bound_xl, bound_xl->fops->getobject,
			state->path, 1, state->loc.object);
	
	return 0;
}

/*
 * server_lookupobject - lookupobject callback for server protocol
 * @frame: call frame
 * @cookie:
 * @this:
 * @op_ret:
 * @op_errno:
 * @object:
 *
 * not for external reference
*/
int
server_lookupobject_cbk (call_frame_t *frame, void *cookie, xlator_t *this,
		int32_t op_ret, int32_t op_errno, object_t *object)
{
	hf_hdr_common_t   *hdr = NULL;
	hf_fop_lookupobject_rsp_t *rsp = NULL;
	server_state_t	  *state = NULL;
	size_t			   hdrlen = 0;
	//int32_t			 hf_errno = 0;

	state  = CALL_STATE (frame);

	hdrlen = hf_hdr_len (rsp, 0);
	hdr    = hf_hdr_new (rsp, 0);
	rsp    = hf_param (hdr);
				
	hdr->rsp.op_ret = hton32 (op_ret);
	hf_errno_to_error (op_errno);
	hdr->rsp.op_errno = hton32 (hf_errno_to_error (op_errno));
	if(op_ret >= 0) {
		rsp->object_status = hton32(object->location);
		memcpy(&rsp->object_info, &object->metadata, sizeof(metadata_t));
	} else {
		hf_log(this->name, HF_LOG_DEBUG, "lookup object %s failed %s",
			state->path, strerror(op_errno));
		rsp->object_status = hton32(-1);
		memset(&rsp->object_info, 0, sizeof(rsp->object_info));
	}
		
	protocol_server_reply (frame, HF_OP_TYPE_FOP_REPLY, HF_FOP_LOOKUPOBJECT,
			hdr, hdrlen, NULL, 0, NULL);
		
	return 0;
}
				
int
server_lookupobject (call_frame_t *frame, xlator_t *bound_xl,
		hf_hdr_common_t *hdr, size_t hdrlen,
		struct iobuf *iobuf)
{
	hf_fop_lookupobject_req_t *req = NULL;
	server_state_t	  *state = NULL;
	xlator_t		  *this = NULL;
	server_conf_t	  *conf = NULL;
	int32_t 		ret = -1;
		
	this = frame->this;
	conf = this->private;
	req = hf_param (hdr);
	state = CALL_STATE (frame);
	state->path 		 = req->path;
		
	ret = server_loc_fill (&(state->loc), state, state->path);	
	if(ret < 0) {
		server_lookupobject_cbk (frame, NULL, frame->this, -1,
			EINVAL, NULL);
		return -1;
	}  
			
	STACK_WIND (frame, server_lookupobject_cbk,
			bound_xl, bound_xl->fops->lookupobject,
			state->path, 1, state->loc.object);
	
	return 0;
}


/*
 * server_deleteobject - deleteobject callback for server protocol
 * @frame: call frame
 * @cookie:
 * @this:
 * @op_ret:
 * @op_errno:
 * @object:
 *
 * not for external reference
*/
int
server_deleteobject_cbk (call_frame_t *frame, void *cookie, xlator_t *this,
		int32_t op_ret, int32_t op_errno, int32_t status)
{
	hf_hdr_common_t   *hdr = NULL;
	hf_fop_deleteobject_rsp_t *rsp = NULL;
	server_state_t	  *state = NULL;
	size_t			   hdrlen = 0;
	//int32_t			 hf_errno = 0;

	state  = CALL_STATE (frame);

	hdrlen = hf_hdr_len (rsp, 0);
	hdr    = hf_hdr_new (rsp, 0);
	rsp    = hf_param (hdr);
				
	hdr->rsp.op_ret = hton32 (op_ret);
	hf_errno_to_error (op_errno);
	hdr->rsp.op_errno = hton32 (hf_errno_to_error (op_errno));
	if(op_ret >= 0) {
		rsp->object_status = hton32(status);
	} else {
		hf_log(this->name, HF_LOG_DEBUG, "delete object %s failed %s",
			state->path, strerror(op_errno));
		rsp->object_status = hton32(-1);
	}
				
	protocol_server_reply (frame, HF_OP_TYPE_FOP_REPLY, HF_FOP_DELETEOBJECT,
			hdr, hdrlen, NULL, 0, NULL);
		
	return 0;
}
						
int
server_deleteobject (call_frame_t *frame, xlator_t *bound_xl,
		hf_hdr_common_t *hdr, size_t hdrlen,
		struct iobuf *iobuf)
{
	hf_fop_deleteobject_req_t *req = NULL;
	server_state_t	  *state = NULL;
	xlator_t		  *this = NULL;
	server_conf_t	  *conf = NULL;
	int32_t 		ret = -1;
		
	this = frame->this;
	conf = this->private;
	req = hf_param (hdr);
	state = CALL_STATE (frame);
	state->path 		 = req->path;
		
	ret = server_loc_fill (&(state->loc), state, state->path);	
	if(ret < 0) {
		server_deleteobject_cbk (frame, NULL, frame->this, -1,
			EINVAL, -1);
		return -1;
	}  
			
	STACK_WIND (frame, server_deleteobject_cbk,
			bound_xl, bound_xl->fops->deleteobject,
			state->path, 1, state->loc.object);
	
	return 0;
}



/* xxx_MOPS */
	int
_volfile_update_checksum (xlator_t *this, char *key, uint32_t checksum)
{
	server_conf_t       *conf         = NULL;
	struct _volfile_ctx *temp_volfile = NULL;

	conf         = this->private;
	temp_volfile = conf->volfile;

	while (temp_volfile) {
		if ((NULL == key) && (NULL == temp_volfile->key))
			break;
		if ((NULL == key) || (NULL == temp_volfile->key)) {
			temp_volfile = temp_volfile->next;
			continue;
		}
		if (strcmp (temp_volfile->key, key) == 0)
			break;
		temp_volfile = temp_volfile->next;
	}

	if (!temp_volfile) {
		temp_volfile = CALLOC (1, sizeof (struct _volfile_ctx));

		temp_volfile->next  = conf->volfile;
		temp_volfile->key   = (key)? strdup (key): NULL;
		temp_volfile->checksum = checksum;

		conf->volfile = temp_volfile;
		goto out;
	}

	if (temp_volfile->checksum != checksum) {
		hf_log (this->name, HF_LOG_CRITICAL, 
				"the volume file got modified between earlier access "
				"and now, this may lead to inconsistency between "
				"clients, advised to remount client");
		temp_volfile->checksum  = checksum;
	}

out:
	return 0;
}

size_t 
build_volfile_path (xlator_t *this, const char *key, char *path, 
		size_t path_len)
{
	int   ret = -1;
	int   free_filename = 0;
	char *filename = NULL;
	char  data_key[256] = {0,};

	/* Inform users that this option is changed now */
	ret = dict_get_str (this->options, "client-volume-filename", 
			&filename);
	if (ret == 0) {
		hf_log (this->name, HF_LOG_WARNING,
				"option 'client-volume-filename' is changed to "
				"'volume-filename.<key>' which now takes 'key' as an "
				"option to choose/fetch different files from server. "
				"Refer documentation or contact developers for more "
				"info. Currently defaulting to given file '%s'", 
				filename);
	}

	if (key && !filename) {
		sprintf (data_key, "volume-filename.%s", key);
		ret = dict_get_str (this->options, data_key, &filename);
		if (ret < 0) {
			/* Make sure that key doesn't contain 
			 * "../" in path 
			 */
			if (!strstr (key, "../")) {
				asprintf (&filename, "%s/%s.vol", 
						CONFDIR, key);
				free_filename = 1;
			} else {
				hf_log (this->name, HF_LOG_DEBUG,
						"%s: invalid key", key);
			}
		} 
	}

	if (!filename) {
		ret = dict_get_str (this->options, 
				"volume-filename.default", &filename);
		if (ret < 0) {
			hf_log (this->name, HF_LOG_DEBUG,
					"no default volume filename given, "
					"defaulting to %s", DEFAULT_VOLUME_FILE_PATH);

			filename = DEFAULT_VOLUME_FILE_PATH;
		}
	}

	ret = -1;
	if ((filename) && (path_len > strlen (filename))) {
		strcpy (path, filename);
		ret = strlen (filename);
	}

	if (free_filename)
		free (filename);

	return ret;
}

	int 
_validate_volfile_checksum (xlator_t *this, char *key,
		uint32_t checksum)
{        
	char                 filename[ZR_PATH_MAX] = {0,};
	server_conf_t       *conf         = NULL;
	struct _volfile_ctx *temp_volfile = NULL;
	int                  ret          = 0;
	uint32_t             local_checksum = 0;

	conf         = this->private;
	temp_volfile = conf->volfile;

	if (!checksum) 
		goto out;

	if (!temp_volfile) {
		ret = build_volfile_path (this, key, filename, 
				sizeof (filename));
		if (ret <= 0)
			goto out;
		ret = open (filename, O_RDONLY);
		if (-1 == ret) {
			ret = 0;
			hf_log (this->name, HF_LOG_DEBUG,
					"failed to open volume file (%s) : %s",
					filename, strerror (errno));
			goto out;
		}
		get_checksum_for_file (ret, &local_checksum);
		_volfile_update_checksum (this, key, local_checksum);
		close (ret);
	}

	temp_volfile = conf->volfile;
	while (temp_volfile) {
		if ((NULL == key) && (NULL == temp_volfile->key))
			break;
		if ((NULL == key) || (NULL == temp_volfile->key)) {
			temp_volfile = temp_volfile->next;
			continue;
		}
		if (strcmp (temp_volfile->key, key) == 0)
			break;
		temp_volfile = temp_volfile->next;
	}

	if (!temp_volfile)
		goto out;

	if ((temp_volfile->checksum) && 
			(checksum != temp_volfile->checksum)) 
		ret = -1;

out:
	return ret;
}

/* Management Calls */
/*
 * mop_getspec - getspec function for server protocol
 * @frame: call frame
 * @bound_xl:
 * @params:
 *
 */
	int
mop_getspec (call_frame_t *frame, xlator_t *bound_xl,
		hf_hdr_common_t *hdr, size_t hdrlen,
		struct iobuf *iobuf)
{
	hf_hdr_common_t      *_hdr = NULL;
	hf_mop_getspec_rsp_t *rsp = NULL;
	int32_t               ret = -1;
	int32_t               op_errno = ENOENT;
	int32_t               hf_errno = 0;
	int32_t               spec_fd = -1;
	size_t                file_len = 0;
	size_t                _hdrlen = 0;
	char                  filename[ZR_PATH_MAX] = {0,};
	struct stat           stbuf = {0,};
	hf_mop_getspec_req_t *req = NULL;
	uint32_t              checksum = 0;
	//uint32_t              flags  = 0;
	uint32_t              keylen = 0;
	char                 *key = NULL;
	server_conf_t        *conf = NULL;

	req   = hf_param (hdr);
	//flags = ntoh32 (req->flags);
	keylen = ntoh32 (req->keylen);
	if (keylen) {
		key = req->key;
	}

	conf = frame->this->private;

	ret = build_volfile_path (frame->this, key, filename, 
			sizeof (filename));
	if (ret > 0) {
		/* to allocate the proper buffer to hold the file data */
		ret = stat (filename, &stbuf);
		if (ret < 0){
			hf_log (frame->this->name, HF_LOG_ERROR,
					"Unable to stat %s (%s)", 
					filename, strerror (errno));
			goto fail;
		}

		spec_fd = open (filename, O_RDONLY);
		if (spec_fd < 0) {
			hf_log (frame->this->name, HF_LOG_ERROR,
					"Unable to open %s (%s)", 
					filename, strerror (errno));
			goto fail;
		}
		ret = 0;
		file_len = stbuf.st_size;
		if (conf->verify_volfile_checksum) {
			get_checksum_for_file (spec_fd, &checksum);
			_volfile_update_checksum (frame->this, key, checksum);
		}
	} else {
		errno = ENOENT;
	}

fail:
	op_errno = errno;

	_hdrlen = hf_hdr_len (rsp, file_len + 1);
	_hdr    = hf_hdr_new (rsp, file_len + 1);
	rsp     = hf_param (_hdr);

	_hdr->rsp.op_ret = hton32 (ret);
	hf_errno         = hf_errno_to_error (op_errno);
	_hdr->rsp.op_errno = hton32 (hf_errno);

	if (file_len) {
		ret = read (spec_fd, rsp->spec, file_len);
		close (spec_fd);
	}
	protocol_server_reply (frame, HF_OP_TYPE_MOP_REPLY, HF_MOP_GETSPEC,
			_hdr, _hdrlen, NULL, 0, NULL);

	return 0;
}

int
server_checksum_cbk (call_frame_t *frame, void *cookie, xlator_t *this,
		int32_t op_ret, int32_t op_errno,
		uint8_t *fchecksum, uint8_t *dchecksum)
{
	hf_hdr_common_t       *hdr = NULL;
	hf_fop_checksum_rsp_t *rsp = NULL;
	size_t                 hdrlen = 0;
	int32_t                hf_errno = 0;

	hdrlen = hf_hdr_len (rsp, ZR_FILENAME_MAX + 1 + ZR_FILENAME_MAX + 1);
	hdr    = hf_hdr_new (rsp, ZR_FILENAME_MAX + 1 + ZR_FILENAME_MAX + 1);
	rsp    = hf_param (hdr);

	hdr->rsp.op_ret = hton32 (op_ret);
	hf_errno        = hf_errno_to_error (op_errno);
	hdr->rsp.op_errno = hton32 (hf_errno);

	if (op_ret >= 0) {
		memcpy (rsp->fchecksum, fchecksum, ZR_FILENAME_MAX);
		rsp->fchecksum[ZR_FILENAME_MAX] =  '\0';
	} 

	protocol_server_reply (frame, HF_OP_TYPE_FOP_REPLY, HF_FOP_CHECKSUM,
			hdr, hdrlen, NULL, 0, NULL);

	return 0;
}


	int
server_checksum (call_frame_t *frame, xlator_t *bound_xl,
		hf_hdr_common_t *hdr, size_t hdrlen,
		struct iobuf *iobuf)
{
	hf_fop_checksum_req_t *req = NULL;
	server_state_t        *state = NULL;

	req = hf_param (hdr);

	state->path  = req->path;

	hf_log (bound_xl->name, HF_LOG_TRACE,
			"%"PRId64": CHECKSUM %s", 
			frame->root->unique, state->path);

	/* TODO: implement this */
	return 0;
}


/*
 * mop_unlock - unlock management function for server protocol
 * @frame: call frame
 * @bound_xl:
 * @params: parameter dictionary
 *
 */
	int
mop_getvolume (call_frame_t *frame, xlator_t *bound_xl,
		hf_hdr_common_t *hdr, size_t hdrlen,
		struct iobuf *iobuf)
{
	return 0;
}

struct __get_xl_struct {
	const char *name;
	xlator_t *reply;
};

void __check_and_set (xlator_t *each, void *data)
{
	if (!strcmp (each->name,
				((struct __get_xl_struct *) data)->name))
		((struct __get_xl_struct *) data)->reply = each;
}

	static xlator_t *
get_xlator_by_name (xlator_t *some_xl, const char *name)
{
	struct __get_xl_struct get = {
		.name = name,
		.reply = NULL
	};

	xlator_foreach (some_xl, __check_and_set, &get);

	return get.reply;
}


/*
 * mop_setvolume - setvolume management function for server protocol
 * @frame: call frame
 * @bound_xl:
 * @params: parameter dictionary
 *
 */
	int
mop_setvolume (call_frame_t *frame, xlator_t *bound_xl,
		hf_hdr_common_t *req_hdr, size_t req_hdrlen,
		struct iobuf *iobuf)
{
	server_connection_t         *conn = NULL;
	server_conf_t               *conf = NULL;
	hf_hdr_common_t             *rsp_hdr = NULL;
	hf_mop_setvolume_req_t      *req = NULL;
	hf_mop_setvolume_rsp_t      *rsp = NULL;
	peer_info_t                 *peerinfo = NULL;
	int32_t                      ret = -1;
	int32_t                      op_ret = -1;
	int32_t                      op_errno = EINVAL;
	int32_t                      hf_errno = 0;
	dict_t                      *reply = NULL;
	dict_t                      *config_params = NULL;
	dict_t                      *params = NULL;
	char                        *name = NULL;
	char                        *version = NULL;
	char                        *process_uuid = NULL;
	xlator_t                    *xl = NULL;
	transport_t                 *trans = NULL;
	size_t                       rsp_hdrlen = -1;
	size_t                       dict_len = -1;
	size_t                       req_dictlen = -1;
	char                        *msg = NULL;
	char                        *volfile_key = NULL;
	uint32_t                     checksum = 0;
	int32_t                      lru_limit = 1024;

	params = dict_new ();
	reply  = dict_new ();

	req    = hf_param (req_hdr);
	req_dictlen = ntoh32 (req->dict_len);
	ret = dict_unserialize (req->buf, req_dictlen, &params);

	config_params = dict_copy_with_ref (frame->this->options, NULL);
	trans         = TRANSPORT_FROM_FRAME(frame);
	conf          = SERVER_CONF(frame);

	if (ret < 0) {
		ret = dict_set_str (reply, "ERROR",
				"Internal error: failed to unserialize "
				"request dictionary");
		if (ret < 0)
			hf_log (bound_xl->name, HF_LOG_DEBUG,
					"failed to set error msg \"%s\"",
					"Internal error: failed to unserialize "
					"request dictionary");

		op_ret = -1;
		op_errno = EINVAL;
		goto fail;
	}

	ret = dict_get_str (params, "process-uuid", &process_uuid);
	if (ret < 0) {
		ret = dict_set_str (reply, "ERROR",
				"UUID not specified");
		if (ret < 0)
			hf_log (bound_xl->name, HF_LOG_DEBUG,
					"failed to set error msg");

		op_ret = -1;
		op_errno = EINVAL;
		goto fail;
	}


	conn = server_connection_get (frame->this, process_uuid);
	if (trans->xl_private != conn)
		trans->xl_private = conn;

	ret = dict_get_str (params, "protocol-version", &version);
	if (ret < 0) {
		ret = dict_set_str (reply, "ERROR",
				"No version number specified");
		if (ret < 0)
			hf_log (trans->xl->name, HF_LOG_DEBUG,
					"failed to set error msg");

		op_ret = -1;
		op_errno = EINVAL;
		goto fail;
	}

	ret = strcmp (version, HF_PROTOCOL_VERSION);
	if (ret != 0) {
		asprintf (&msg,
				"protocol version mismatch: client(%s) - server(%s)",
				version, HF_PROTOCOL_VERSION);
		ret = dict_set_dynstr (reply, "ERROR", msg);
		if (ret < 0)
			hf_log (trans->xl->name, HF_LOG_DEBUG,
					"failed to set error msg");

		op_ret = -1;
		op_errno = EINVAL;
		goto fail;
	}

	ret = dict_get_str (params,
			"remote-subvolume", &name);
	if (ret < 0) {
		ret = dict_set_str (reply, "ERROR",
				"No remote-subvolume option specified");
		if (ret < 0)
			hf_log (trans->xl->name, HF_LOG_DEBUG,
					"failed to set error msg");

		op_ret = -1;
		op_errno = EINVAL;
		goto fail;
	}

	xl = get_xlator_by_name (frame->this, name);
	if (xl == NULL) {
		asprintf (&msg, "remote-subvolume \"%s\" is not found", name);
		ret = dict_set_dynstr (reply, "ERROR", msg);
		if (ret < 0)
			hf_log (trans->xl->name, HF_LOG_DEBUG,
					"failed to set error msg");

		op_ret = -1;
		op_errno = ENOENT;
		goto fail;
	}

	if (conf->verify_volfile_checksum) {
		ret = dict_get_uint32 (params, "volfile-checksum", &checksum);
		if (ret == 0) {
			ret = dict_get_str (params, "volfile-key", 
					&volfile_key);

			ret = _validate_volfile_checksum (trans->xl, 
					volfile_key, 
					checksum);
			if (-1 == ret) {
				ret = dict_set_str (reply, "ERROR",
						"volume-file checksum "
						"varies from earlier "
						"access");
				if (ret < 0)
					hf_log (trans->xl->name, HF_LOG_DEBUG,
							"failed to set error msg");

				op_ret   = -1;
				op_errno = ESTALE;
				goto fail;
			}
		}
	}


	peerinfo = &trans->peerinfo;
	ret = dict_set_static_ptr (params, "peer-info", peerinfo);
	if (ret < 0)
		hf_log (trans->xl->name, HF_LOG_DEBUG,
				"failed to set peer-info");

	if (conf->auth_modules == NULL) {
		hf_log (trans->xl->name, HF_LOG_ERROR,
				"Authentication module not initialized");
	}

	ret = hf_authenticate (params, config_params, 
			conf->auth_modules);
	if (ret == AUTH_ACCEPT) {
		hf_log (trans->xl->name, HF_LOG_INFO,
				"accepted client from %s",
				peerinfo->identifier);
		op_ret = 0;
		conn->bound_xl = xl;
		ret = dict_set_str (reply, "ERROR", "Success");
		if (ret < 0)
			hf_log (trans->xl->name, HF_LOG_DEBUG,
					"failed to set error msg");
	} else {
		hf_log (trans->xl->name, HF_LOG_ERROR,
				"Cannot authenticate client from %s",
				peerinfo->identifier);
		op_ret = -1;
		op_errno = EACCES;
		ret = dict_set_str (reply, "ERROR", "Authentication failed");
		if (ret < 0)
			hf_log (bound_xl->name, HF_LOG_DEBUG,
					"failed to set error msg");

		goto fail;
	}

	if (conn->bound_xl == NULL) {
		ret = dict_set_str (reply, "ERROR",
				"Check volfile and handshake "
				"options in protocol/client");
		if (ret < 0)
			hf_log (trans->xl->name, HF_LOG_DEBUG, 
					"failed to set error msg");

		op_ret = -1;
		op_errno = EACCES;
		goto fail;
	}

	if ((conn->bound_xl != NULL) &&
			(ret >= 0)                   &&
			(conn->bound_xl->otable == NULL)) {
		/* create object table for this bound_xl, if one doesn't 
		   already exist */
		lru_limit = OBJECT_LRU_LIMIT (frame->this);

		conn->bound_xl->otable = 
			object_table_new (lru_limit,
					conn->bound_xl);
	}

	ret = dict_set_str (reply, "process-uuid", 
			xl->ctx->process_uuid);

	ret = dict_set_uint64 (reply, "transport-ptr",
			((uint64_t) (long) trans));

fail:
	dict_len = dict_serialized_length (reply);
	if (dict_len < 0) {
		hf_log (xl->name, HF_LOG_DEBUG,
				"failed to get serialized length of reply dict");
		op_ret   = -1;
		op_errno = EINVAL;
		dict_len = 0;
	}

	rsp_hdr    = hf_hdr_new (rsp, dict_len);
	rsp_hdrlen = hf_hdr_len (rsp, dict_len);
	rsp = hf_param (rsp_hdr);

	if (dict_len) {
		ret = dict_serialize (reply, rsp->buf);
		if (ret < 0) {
			hf_log (xl->name, HF_LOG_DEBUG,
					"failed to serialize reply dict");
			op_ret = -1;
			op_errno = -ret;
		}
	}
	rsp->dict_len = hton32 (dict_len);

	rsp_hdr->rsp.op_ret = hton32 (op_ret);
	hf_errno = hf_errno_to_error (op_errno);
	rsp_hdr->rsp.op_errno = hton32 (hf_errno);

	protocol_server_reply (frame, HF_OP_TYPE_MOP_REPLY, HF_MOP_SETVOLUME,
		rsp_hdr, rsp_hdrlen, NULL, 0, NULL);

	dict_unref (params);
	dict_unref (reply);
	dict_unref (config_params);

	return 0;
}

/*
 * server_mop_stats_cbk - stats callback for server management operation
 * @frame: call frame
 * @cookie:
 * @this:
 * @op_ret: return value
 * @op_errno: errno
 * @stats:err
 *
 * not for external reference
 */

	int
server_mop_stats_cbk (call_frame_t *frame, void *cookie, xlator_t *this,
		int32_t ret, int32_t op_errno,
		struct xlator_stats *stats)
{
	/* TODO: get this information from somewhere else, not extern */
	hf_hdr_common_t    *hdr = NULL;
	hf_mop_stats_rsp_t *rsp = NULL;
	char                buffer[256] = {0,};
	int64_t             hadafsd_stats_nr_clients = 0;
	size_t              hdrlen = 0;
	size_t              buf_len = 0;
	int32_t             hf_errno = 0;

	if (ret >= 0) {
		sprintf (buffer,
				"%"PRIx64",%"PRIx64",%"PRIx64
				",%"PRIx64",%"PRIx64",%"PRIx64
				",%"PRIx64",%"PRIx64"\n",
				stats->nr_files, stats->disk_usage, stats->free_disk,
				stats->total_disk_size, stats->read_usage,
				stats->write_usage, stats->disk_speed,
				hadafsd_stats_nr_clients);

		buf_len = strlen (buffer);
	}

	hdrlen = hf_hdr_len (rsp, buf_len + 1);
	hdr    = hf_hdr_new (rsp, buf_len + 1);
	rsp    = hf_param (hdr);

	hdr->rsp.op_ret = hton32 (ret);
	hf_errno        = hf_errno_to_error (op_errno);
	hdr->rsp.op_errno = hton32 (hf_errno);

	strcpy (rsp->buf, buffer);

	protocol_server_reply (frame, HF_OP_TYPE_MOP_REPLY, HF_MOP_STATS,
			hdr, hdrlen, NULL, 0, NULL);

	return 0;
}


/*
 * mop_unlock - unlock management function for server protocol
 * @frame: call frame
 * @bound_xl:
 * @params: parameter dictionary
 *
 */
	int
mop_stats (call_frame_t *frame, xlator_t *bound_xl,
		hf_hdr_common_t *hdr, size_t hdrlen,
		struct iobuf *iobuf)
{
	int32_t             flag = 0;
	hf_mop_stats_req_t *req = NULL;

	req = hf_param (hdr);

	flag = ntoh32 (req->flags);

	STACK_WIND (frame, server_mop_stats_cbk,
			bound_xl,
			bound_xl->mops->stats,
			flag);

	return 0;
}


	int
mop_ping (call_frame_t *frame, xlator_t *bound_xl,
		hf_hdr_common_t *hdr, size_t hdrlen,
		struct iobuf *iobuf)
{
	hf_hdr_common_t     *rsp_hdr = NULL;
	hf_mop_ping_rsp_t   *rsp = NULL;
	size_t               rsp_hdrlen = 0;

	rsp_hdrlen = hf_hdr_len (rsp, 0);
	rsp_hdr    = hf_hdr_new (rsp, 0);

	hdr->rsp.op_ret = 0;

	protocol_server_reply (frame, HF_OP_TYPE_MOP_REPLY, HF_MOP_PING,
			rsp_hdr, rsp_hdrlen, NULL, 0, NULL);

	return 0;
}
/*
 * unknown_op_cbk - This function is called when a opcode for unknown 
 *                  type is called. Helps to keep the backward/forward
 *                  compatiblity
 * @frame: call frame
 * @type:
 * @opcode:
 *
 */

	int
unknown_op_cbk (call_frame_t *frame, int32_t type, int32_t opcode)
{
	hf_hdr_common_t    *hdr = NULL;
	hf_fop_flush_rsp_t *rsp = NULL;
	size_t              hdrlen = 0;
	int32_t             hf_errno = 0;

	hdrlen = hf_hdr_len (rsp, 0);
	hdr    = hf_hdr_new (rsp, 0);
	rsp    = hf_param (hdr);

	hdr->rsp.op_ret = hton32 (-1);
	hf_errno        = hf_errno_to_error (ENOSYS);
	hdr->rsp.op_errno = hton32 (hf_errno);

	protocol_server_reply (frame, type, opcode,
			hdr, hdrlen, NULL, 0, NULL);

	return 0;
}

/*
 * get_frame_for_transport - get call frame for specified transport object
 *
 * @trans: transport object
 *
 */
	static call_frame_t *
get_frame_for_transport (transport_t *trans)
{
	call_frame_t         *frame = NULL;
	call_pool_t          *pool = NULL;
	server_connection_t  *conn = NULL;
	server_state_t       *state = NULL;;

	HF_VALIDATE_OR_GOTO("server", trans, out);

	if (trans->xl && trans->xl->ctx)
		pool = trans->xl->ctx->pool;
	HF_VALIDATE_OR_GOTO("server", pool, out);

	frame = create_frame (trans->xl, pool);
	HF_VALIDATE_OR_GOTO("server", frame, out);

	state = CALLOC (1, sizeof (*state));
	HF_VALIDATE_OR_GOTO("server", state, out);

	conn = trans->xl_private;
	if (conn) {
		if (conn->bound_xl)
			state->otable = conn->bound_xl->otable;
		state->bound_xl = conn->bound_xl;
	}

	state->trans = transport_ref (trans);
	state->loc.path = NULL;

	frame->root->trans = conn;
	frame->root->state = state;        /* which socket */
	frame->root->unique = 0;           /* which call */

out:
	return frame;
}

/*
 * get_frame_for_call - create a frame into the capable of
 *                      generating and replying the reply packet by itself.
 *                      By making a call with this frame, the last UNWIND
 *                      function will have all needed state from its
 *                      frame_t->root to send reply.
 * @trans:
 * @blk:
 * @params:
 *
 * not for external reference
 */
	static call_frame_t *
get_frame_for_call (transport_t *trans, hf_hdr_common_t *hdr)
{
	call_frame_t *frame = NULL;

	frame = get_frame_for_transport (trans);

	frame->root->op   = ntoh32 (hdr->op);
	frame->root->type = ntoh32 (hdr->type);

	frame->root->uid         = ntoh32 (hdr->req.uid);
	frame->root->unique      = ntoh64 (hdr->callid);      /* which call */
	frame->root->gid         = ntoh32 (hdr->req.gid);
	frame->root->pid         = ntoh32 (hdr->req.pid);

	return frame;
}

/*
 * prototype of operations function for each of mop and
 * fop at server protocol level
 *
 * @frame: call frame pointer
 * @bound_xl: the xlator that this frame is bound to
 * @params: parameters dictionary
 *
 * to be used by protocol interpret, _not_ for exterenal reference
 */
typedef int32_t (*hf_op_t) (call_frame_t *frame, xlator_t *bould_xl,
		hf_hdr_common_t *hdr, size_t hdrlen,
		struct iobuf *iobuf);


static hf_op_t hf_fops[] = {
	[HF_FOP_UNLINK]       =  server_unlink,
	[HF_FOP_STAT]	      =  server_stat,
	[HF_FOP_FSTAT]	      =  server_fstat,
	[HF_FOP_OPEN]         =  server_open,
	[HF_FOP_READ]         =  server_readv,
	[HF_FOP_WRITE]        =  server_writev,
	[HF_FOP_FLUSH]        =  server_flush,
	[HF_FOP_SETOBJECT]    =  server_setobject,
	[HF_FOP_UPDATEOBJECT] =  server_updateobject,
	[HF_FOP_GETOBJECT]    =  server_getobject,
	[HF_FOP_LOOKUPOBJECT] =  server_lookupobject,
	[HF_FOP_DELETEOBJECT] =  server_deleteobject,
	[HF_FOP_IOCTL]        =  server_ioctl,
	[HF_FOP_CHECKSUM]     =  server_checksum,
	[HF_FOP_TRUNCATE]     =  server_truncate,
	[HF_FOP_FTRUNCATE]     =  server_ftruncate
};



static hf_op_t hf_mops[] = {
	[HF_MOP_SETVOLUME] = mop_setvolume,
	[HF_MOP_GETVOLUME] = mop_getvolume,
	[HF_MOP_STATS]     = mop_stats,
	[HF_MOP_GETSPEC]   = mop_getspec,
	[HF_MOP_PING]      = mop_ping,
};

static hf_op_t hf_cbks[] = {
	[HF_CBK_FORGET]	    = server_forget,
	[HF_CBK_RELEASE]    = server_release,
};

	int
protocol_server_interpret (xlator_t *this, transport_t *trans,
		char *hdr_p, size_t hdrlen, struct iobuf *iobuf)
{
	server_connection_t         *conn = NULL;
	hf_hdr_common_t             *hdr = NULL;
	xlator_t                    *bound_xl = NULL;
	call_frame_t                *frame = NULL;
	peer_info_t                 *peerinfo = NULL;
	int32_t                      type = -1;
	int32_t                      op = -1;
	int32_t                      ret = -1;

	hdr  = (hf_hdr_common_t *)hdr_p;
	type = ntoh32 (hdr->type);
	op   = ntoh32 (hdr->op);

	conn = trans->xl_private;
	if (conn)
		bound_xl = conn->bound_xl;


	peerinfo = &trans->peerinfo;
	switch (type) {
		case HF_OP_TYPE_FOP_REQUEST:
			if ((op < 0) || (op >= HF_FOP_MAXVALUE)) {
				hf_log (this->name, HF_LOG_ERROR,
						"invalid fop %"PRId32" from client %s",
						op, peerinfo->identifier);
				break;
			}
			if (bound_xl == NULL) {
				hf_log (this->name, HF_LOG_ERROR,
						"Received fop %"PRId32" before "
						"authentication.", op);
				break;
			}
			frame = get_frame_for_call (trans, hdr);

			ret = hf_fops[op] (frame, bound_xl, hdr, hdrlen, iobuf);
			break;

		case HF_OP_TYPE_MOP_REQUEST:
			if ((op < 0) || (op >= HF_MOP_MAXVALUE)) {
				hf_log (this->name, HF_LOG_ERROR,
						"invalid mop %"PRId32" from client %s",
						op, peerinfo->identifier);
				break;
			}
			frame = get_frame_for_call (trans, hdr);
			ret = hf_mops[op] (frame, bound_xl, hdr, hdrlen, iobuf);
			break;

		case HF_OP_TYPE_CBK_REQUEST:
			if ((op < 0) || (op >= HF_CBK_MAXVALUE)) {
				hf_log (this->name, HF_LOG_ERROR,
						"invalid cbk %"PRId32" from client %s",
						op, peerinfo->identifier);
				break;
			}
			if (bound_xl == NULL) {
				hf_log (this->name, HF_LOG_ERROR,
						"Received cbk %d before authentication.", op);
				break;
			}

			frame = get_frame_for_call (trans, hdr);
			ret = hf_cbks[op] (frame, bound_xl, hdr, hdrlen, iobuf);
			break;

		default:
			hf_log ("server", HF_LOG_NORMAL, "invalid type %d, op %d",
					type, op);
			break;
	}

	return ret;
}


/*
 * server_nop_cbk - nop callback for server protocol
 * @frame: call frame
 * @cookie:
 * @this:
 * @op_ret: return value
 * @op_errno: errno
 *
 * not for external reference
 */
	int
server_nop_cbk (call_frame_t *frame, void *cookie, xlator_t *this,
		int32_t op_ret, int32_t op_errno)
{
	server_state_t *state = NULL;

	state = CALL_STATE(frame);

	if (state)
		free_state (state);
	STACK_DESTROY (frame->root);
	return 0;
}


	static void
get_auth_types (dict_t *this, char *key, data_t *value, void *data)
{
	dict_t   *auth_dict = NULL;
	char     *saveptr = NULL;
	char     *tmp = NULL;
	char     *key_cpy = NULL;
	int32_t   ret = -1;

	auth_dict = data;
	key_cpy = strdup (key);
	HF_VALIDATE_OR_GOTO("server", key_cpy, out);

	tmp = strtok_r (key_cpy, ".", &saveptr);
	ret = strcmp (tmp, "auth");
	if (ret == 0) {
		tmp = strtok_r (NULL, ".", &saveptr);
		if (strcmp (tmp, "ip") == 0) {
			/* TODO: backward compatibility, remove when 
			   newer versions are available */
			tmp = "addr";
			hf_log ("server", HF_LOG_WARNING, 
					"assuming 'auth.ip' to be 'auth.addr'");
		}
		ret = dict_set_dynptr (auth_dict, tmp, NULL, 0);
		if (ret < 0) {
			hf_log ("server", HF_LOG_DEBUG,
					"failed to dict_set_dynptr");
		} 
	}

	FREE (key_cpy);
out:
	return;
}


	int
validate_auth_options (xlator_t *this, dict_t *dict)
{
	int            ret = -1;
	int            error = 0;
	xlator_list_t *trav = NULL;
	data_pair_t   *pair = NULL;
	char          *saveptr = NULL;
	char          *tmp = NULL;
	char          *key_cpy = NULL;

	trav = this->children;
	while (trav) {
		error = -1;
		for (pair = dict->members_list; pair; pair = pair->next) {
			key_cpy = strdup (pair->key);
			tmp = strtok_r (key_cpy, ".", &saveptr);
			ret = strcmp (tmp, "auth");
			if (ret == 0) {
				/* for module type */
				tmp = strtok_r (NULL, ".", &saveptr); 
				/* for volume name */
				tmp = strtok_r (NULL, ".", &saveptr); 
			}

			if (strcmp (tmp, trav->xlator->name) == 0) {
				error = 0;
				free (key_cpy);
				break;
			}
			free (key_cpy);
		}
		if (-1 == error) {
			hf_log (this->name, HF_LOG_ERROR, 
					"volume '%s' defined as subvolume, but no "
					"authentication defined for the same",
					trav->xlator->name);
			break;
		}
		trav = trav->next;
	}

	return error;
}



/*
 * init - called during server protocol initialization
 *
 * @this:
 *
 */
	int
init (xlator_t *this)
{
	int32_t        ret = -1;
	transport_t   *trans = NULL;
	server_conf_t *conf = NULL;
	data_t        *data = NULL;
	//	char          *nameserver = NULL;
	//	int	      ns_port = -1;

	if (this->children == NULL) {
		hf_log (this->name, HF_LOG_ERROR,
				"protocol/server should have subvolume");
		goto out;
	}

	trans = transport_load (this->options, this);
	if (trans == NULL) {
		hf_log (this->name, HF_LOG_ERROR,
				"failed to load transport");
		goto out;
	}

	ret = transport_listen (trans);
	if (ret == -1) {
		hf_log (this->name, HF_LOG_ERROR,
				"failed to bind/listen on socket");
		goto out;
	}

	conf = CALLOC (1, sizeof (server_conf_t));
	HF_VALIDATE_OR_GOTO(this->name, conf, out);

	INIT_LIST_HEAD (&conf->conns);
	pthread_mutex_init (&conf->mutex, NULL);

	conf->trans = trans;

	conf->auth_modules = dict_new ();
	HF_VALIDATE_OR_GOTO(this->name, conf->auth_modules, out);

	dict_foreach (this->options, get_auth_types, 
			conf->auth_modules);
	ret = validate_auth_options (this, this->options);
	if (ret == -1) {
		// logging already done in validate_auth_options function. 
		goto out;
	}

	ret = hf_auth_init (this, conf->auth_modules);
	if (ret) {
		dict_unref (conf->auth_modules);
		goto out;
	}

	this->private = conf;

	ret = dict_get_int32 (this->options, "object-lru-limit", 
			&conf->object_lru_limit);
	if (ret < 0) {
		conf->object_lru_limit = 1024;
	}

	conf->verify_volfile_checksum = 1;
	data = dict_get (this->options, "verify-volfile-checksum");
	if (data) {
		ret = hf_string2boolean(data->data, 
				&conf->verify_volfile_checksum);
		if (ret != 0) {
			hf_log (this->name, HF_LOG_DEBUG,
					"wrong value for verify-volfile-checksum");
			conf->verify_volfile_checksum = 1;
		}
	}


#ifndef HF_DARWIN_HOST_OS
	{
		struct rlimit lim;

		lim.rlim_cur = 1048576;
		lim.rlim_max = 1048576;

		if (setrlimit (RLIMIT_NOFILE, &lim) == -1) {
			hf_log (this->name, HF_LOG_WARNING,
					"WARNING: Failed to set 'ulimit -n 1M': %s",
					strerror(errno));
			lim.rlim_cur = 65536;
			lim.rlim_max = 65536;

			if (setrlimit (RLIMIT_NOFILE, &lim) == -1) {
				hf_log (this->name, HF_LOG_WARNING,
						"Failed to set max open fd to 64k: %s",
						strerror(errno));
			} else {
				hf_log (this->name, HF_LOG_TRACE,
						"max open fd set to 64k");
			}
		}
	}
#endif
	this->ctx->top = this;

	ret = 0;
out:
	return ret;
}



	int
protocol_server_pollin (xlator_t *this, transport_t *trans)
{
	char                *hdr = NULL;
	size_t               hdrlen = 0;
	int                  ret = -1;
	struct iobuf        *iobuf = NULL;


	ret = transport_receive (trans, &hdr, &hdrlen, &iobuf);

	if (ret == 0)
		ret = protocol_server_interpret (this, trans, hdr, 
				hdrlen, iobuf);
	else
		hf_log ("server-protocol", HF_LOG_ERROR, "receive from %s failed when pollin",
				trans->peerinfo.identifier);

	/* TODO: use mem-pool */
	FREE (hdr);

	return ret;
}


/*
 * fini - finish function for server protocol, called before
 *        unloading server protocol.
 *
 * @this:
 *
 */
	void
fini (xlator_t *this)
{
	server_conf_t *conf = this->private;

	HF_VALIDATE_OR_GOTO(this->name, conf, out);

	if (conf->auth_modules) {
		dict_unref (conf->auth_modules);
	}

	FREE (conf);
	this->private = NULL;
out:
	return;
}

/*
 * server_protocol_notify - notify function for server protocol
 * @this:
 * @trans:
 * @event:
 *
 */
	int
notify (xlator_t *this, int32_t event, void *data, ...)
{
	int          ret = 0;
	transport_t *trans = data;
	peer_info_t *peerinfo = NULL;
	peer_info_t *myinfo = NULL;

	if (trans != NULL) {
		peerinfo = &(trans->peerinfo);
		myinfo = &(trans->myinfo);
	}

	switch (event) {
		case HF_EVENT_POLLIN:
			ret = protocol_server_pollin (this, trans);
			break;
		case HF_EVENT_POLLERR:
			{
				hf_log (trans->xl->name, HF_LOG_INFO, "%s disconnected",
						peerinfo->identifier);

				ret = -1;
				transport_disconnect (trans);
				if (trans->xl_private == NULL) {
					hf_log (this->name, HF_LOG_DEBUG,
							"POLLERR received on (%s) even before "
							"handshake with (%s) is successful",
							myinfo->identifier, peerinfo->identifier);
				} else {
					/*
					 * FIXME: shouldn't we check for return value?
					 * what should be done if cleanup fails?
					 */
					server_connection_cleanup (this, trans->xl_private);
				}
			}
			break;

		case HF_EVENT_TRANSPORT_CLEANUP:
			{
				if (trans->xl_private) {
					server_connection_put (this, trans->xl_private);
				} else {
					hf_log (this->name, HF_LOG_DEBUG,
							"transport (%s) cleaned up even before "
							"handshake with (%s) is successful",
							myinfo->identifier, peerinfo->identifier);
				}
			}
			break;

		default:
			default_notify (this, event, data);
			break;
	}

	return ret;
}


struct xlator_mops mops = {
};

struct xlator_fops fops = {
};

struct xlator_cbks cbks = {
};

struct volume_options options[] = {
	{ .key   = {"transport-type"}, 
		.value = {"tcp", "socket", "ib-verbs", "unix", "ib-sdp", 
			"swnet-verbs", "swnet-verbs/server",
			"tcp/server", "ib-verbs/server"},
		.type  = HF_OPTION_TYPE_STR 
	},
	{ .key   = {"volume-filename.*"}, 
		.type  = HF_OPTION_TYPE_PATH, 
	},
	{ .key   = {"object-lru-limit"},  
		.type  = HF_OPTION_TYPE_INT,
		.min   = 0, 
		.max   = (1 * HF_UNIT_MB)
	},
	{ .key   = {"client-volume-filename"}, 
		.type  = HF_OPTION_TYPE_PATH
	}, 
	{ .key   = {"verify-volfile-checksum"}, 
		.type  = HF_OPTION_TYPE_BOOL
	}, 
	{ .key   = {NULL} },
};
