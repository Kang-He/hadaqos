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

/**
 * xlators/cluster/lta:
 *     - This xlator is one of the main translator in LWFS, which
 *   actually does the clustering work of the file system. One need to 
 *   understand that, lta assumes file to be existing in only one of 
 *   the child node, and directories to be present on all the nodes. 
 *
 * NOTE:
 *   Now, lta has support for global namespace, which is used to keep a 
 * global view of fs's namespace tree. The stat for directories are taken
 * just from the namespace, where as for files, just 'st_ino' is taken from
 * Namespace node, and other stat info is taken from the actual storage node.
 * Also Namespace node helps to keep consistant inode for files across 
 * lwfs (re-)mounts.
 */

#ifndef _CONFIG_H
#define _CONFIG_H
#include "config.h"
#endif

#include "lta.h"
#include "dict.h"
#include "xlator.h"
#include "logging.h"
#include "stack.h"
#include "defaults.h"
#include "common-utils.h"
#include <signal.h>
#include <libgen.h>
#include "compat-errno.h"
#include "compat.h"

#define LTA_CHECK_OBJECT_CTX_AND_UNWIND_ON_ERR(_loc) do { \
  if (!(_loc && _loc->object)) {                            \
    STACK_UNWIND (frame, -1, EINVAL, NULL, NULL, NULL);    \
    return 0;                                              \
  }                                                        \
} while(0)


#define LTA_CHECK_FD_CTX_AND_UNWIND_ON_ERR(_fd) do { \
  if (!(_fd && !fd_ctx_get (_fd, this, NULL))) {       \
    STACK_UNWIND (frame, -1, EBADFD, NULL, NULL);      \
    return 0;                                          \
  }                                                    \
} while(0)

#define LTA_CHECK_FD_AND_UNWIND_ON_ERR(_fd) do { \
  if (!_fd) {                                      \
    STACK_UNWIND (frame, -1, EBADFD, NULL, NULL);  \
    return 0;                                      \
  }                                                \
} while(0)

#define LTA_SYNC_OBJECT_RESUME(frame,this,ret,errno,status) do {\
	lta_local_t *_local = frame->local;				\
	_local->op_ret2 = ret; 					\
	_local->op_errno2 = errno;				\
	_local->object_status = status;				\
	_local->resume_fn(frame, this);				\
} while(0)

inline lta_obj_t *
lta_alloc_lobj(object_t *object, xlator_t *this) 
{
	
	lta_obj_t *lobj = NULL;

	lobj = CALLOC(1, sizeof(lta_obj_t));
	if(lobj == NULL) {
			hf_log(this->name, HF_LOG_ERROR, "Out of Memory");
			return NULL;
	}
	lobj->object = object_ref(object);
	INIT_LIST_HEAD(&lobj->meta_list);
	INIT_LIST_HEAD(&lobj->update_list);
	if(object_ctx_put(object, this, (uint64_t)(long)lobj)) {
			hf_log(this->name, HF_LOG_ERROR, "object %s ctx set failed",
							object->path);
			FREE(lobj);
			return NULL;
	}
	return lobj;
}

int32_t
lta_sync_setobject_cbk(call_frame_t *frame, void *cookie, xlator_t *this,
		int32_t op_ret, int32_t op_errno, int32_t status)
{
	LTA_SYNC_OBJECT_RESUME(frame, this, op_ret, op_errno, status);
	return 0;
}

int32_t
lta_sync_getobject_cbk(call_frame_t *frame, void *cookie, xlator_t *this,
		int32_t op_ret, int32_t op_errno, object_t *object)
{
	LTA_SYNC_OBJECT_RESUME(frame, this, op_ret, op_errno, 0);
	return 0;
}

int32_t
lta_sync_deleteobject_cbk(call_frame_t *frame, void *cookie, xlator_t *this,
		int32_t op_ret, int32_t op_errno, int32_t status)
{
	LTA_SYNC_OBJECT_RESUME(frame, this, op_ret, op_errno, status);
	return 0;
}

inline void
lta_refresh_object(call_frame_t *fr, metadata_t *mt, struct stat *st)
{
	mt->uid = fr->root->uid;
	mt->gid = fr->root->gid;
	mt->mode = st->st_mode;
	mt->lno = st->st_ino;
	mt->size = st->st_size;
	mt->ctime = st->st_ctime;
	mt->atime = st->st_atime;
	mt->mtime = st->st_mtime;
}

int32_t
lta_sync_object_metadata(call_frame_t *frame, lta_resume_fn_t fn, 
    hadafs_fop_t fop)
{
	lta_local_t	  *local = NULL;
	lta_private_t  *priv = NULL;
	xlator_t	  *this  = NULL;
	object_t 	*object = NULL;
	
	local = frame->local;
	local->resume_fn = fn;
	this = frame->this;
	priv = this->private;

	if(local->loc != NULL)
		object = local->loc->object;
	else if(local->fd != NULL)
		object = local->fd->object;
	else
		return -1;

	switch (fop)
	{
		case HF_FOP_SETOBJECT:
			STACK_WIND(frame,
				lta_sync_setobject_cbk,
				priv->ns_xl,
				priv->ns_xl->fops->setobject,
				object->path, 0, object);
			return 0;
		case HF_FOP_UPDATEOBJECT:
			STACK_WIND(frame,
				lta_sync_setobject_cbk,
				priv->ns_xl,
				priv->ns_xl->fops->updateobject,
				object->path, 0, local->updatebits, 
				object);
			return 0;
		case HF_FOP_GETOBJECT:
			STACK_WIND(frame,
				lta_sync_getobject_cbk,
				priv->ns_xl,
				priv->ns_xl->fops->getobject,
				object->path, 0, object);
			return 0;
		case HF_FOP_LOOKUPOBJECT:
			STACK_WIND(frame,
				lta_sync_getobject_cbk,
				priv->ns_xl,
				priv->ns_xl->fops->lookupobject,
				object->path, 0, object);
			return 0;
		case HF_FOP_DELETEOBJECT:
			STACK_WIND(frame,
				lta_sync_deleteobject_cbk,
				priv->ns_xl,
				priv->ns_xl->fops->deleteobject,
				object->path, 0, object);
			return 0;
		default:
			break;
	}
	return 0;
}

/*
 * lta_open_cbk -
 */
int32_t
lta_open_cbk (call_frame_t *frame, xlator_t *this)
{
	lta_local_t *local = NULL;
	lta_private_t *priv = NULL;
	object_t *object = NULL;
	lta_obj_t *lobj = NULL;
	int32_t op_ret, op_errno;

	local = frame->local;
	priv = this->private;
	op_ret = local->op_ret2;
	op_errno = local->op_errno2;
	object = local->loc->object;
	
	if (op_ret >= 0) {
		switch (priv->default_mmode) {
			case ALL_ASYNC:
				LTA_OBJECT_SET_STATUS(object, OBJ_NEWCREATED);
				lobj = lta_alloc_lobj(object, this);
				if(lobj == NULL)
					goto out;
				lta_metaup_add_openfd(lobj, this);
				break;
			case PART_ASYNC:
				LTA_OBJECT_SET_STATUS(object, OBJ_FRESH);
				if(object->location == OBJ_LOCALHOST) {
						lobj = lta_alloc_lobj(object, this);
						if(lobj == NULL)
								goto out;
						lta_metaup_add_openfd(lobj, this);
				}
				break;
			case ALL_SYNC:
				LTA_OBJECT_SET_STATUS(object, OBJ_FRESH);
				break;
		}
	} else {
		hf_log(this->name, HF_LOG_ERROR,
			"object %s OPEN by %s failed due to %s mmode %d status %d location %d",
			local->loc->path, this->name, strerror(local->op_errno2),
			priv->default_mmode, object->status, object->location);
	}
out:	
	frame->local = NULL;
	STACK_UNWIND (frame, op_ret, op_errno, local->fd, object, &local->stbuf);

	LOCAL_WIPE(local);

	return 0;
}

int32_t
lta_open_resume_cbk(call_frame_t *frame, void *cookie, xlator_t *this,
        int32_t op_ret, int32_t op_errno,
        fd_t *fd, object_t *object, struct stat *stbuf)
{
	lta_local_t *local = NULL;
	lta_private_t *priv = NULL;

	local = frame->local;
	priv = this->private;
	local->op_ret1 = op_ret;
	local->op_errno1 = op_errno;
	local->stbuf = *stbuf;
	
	if(op_ret < 0) {
		hf_log(this->name, HF_LOG_ERROR, "object %s open by %s failed due to %s",
			object->path, this->name, strerror(op_errno));
		object->status = OBJ_ERROR;
		lta_open_cbk(frame, this);
		return 0;
	}

	lta_refresh_object(frame, &object->metadata, stbuf);
	switch (priv->default_mmode) {
		case ALL_SYNC:
			lta_sync_object_metadata(frame, lta_open_cbk, HF_FOP_SETOBJECT);
			break;
		case PART_ASYNC:
			if(object->location == OBJ_LOCALHOST) 
				lta_sync_object_metadata(frame, lta_open_cbk, HF_FOP_SETOBJECT);
			else
				lta_open_cbk(frame, this);
			break;
		case ALL_ASYNC:
			lta_open_cbk(frame, this);
			break;
	}
	return 0;
}

int32_t
lta_open_resume(call_frame_t *frame, xlator_t *this)
{
	lta_local_t *local = NULL;
	lta_private_t *priv = NULL;
	xlator_t *xl = NULL;
	object_t *object = NULL;

	local = frame->local;
	object = local->loc->object;
	priv = this->private;
	
	if(!local->op_ret2){
		/*object structure is new, not the object itself is new */
		object->location = OBJ_LOCALHOST;
		xl = priv->local_xl;
		strcpy(object->metadata.lhost, priv->local_xl->name);
	} else if(local->op_ret2 == 1){
		if(!strcmp(priv->local_xl->name, object->metadata.lhost)) {
			object->location = OBJ_LOCALHOST;
			/*object structure is new, not the object itself is new */
			xl = priv->local_xl;
		} else {
			object->location = OBJ_OTHERHOST;
			xl = priv->local_xl;
			xl = priv->global_xl;	
		}
	} else {
		goto err;
	}

	fd_ctx_set (local->fd, this, (uint64_t)(long)xl); 
	
	STACK_WIND (frame,
		lta_open_resume_cbk, 
		xl, xl->fops->open, 
		local->loc, 
		local->flags, 
		local->mode,
		local->fd);
	
	return 0;
err:
	lta_open_cbk(frame, this);
	return 0;	
}

/*
 * lta_open - 
 */
int32_t
lta_open (call_frame_t *frame,
	    xlator_t *this,
	    loc_t *loc,
	    int32_t flags,
	    mode_t mode,
	    fd_t *fd)
{
	
	lta_private_t *priv = this->private;
	lta_local_t *local = NULL;

	LTA_CHECK_OBJECT_CTX_AND_UNWIND_ON_ERR (loc);

	INIT_LOCAL(frame, local);

	local->loc = loc;
	local->fd = fd_ref(fd);
	local->flags = flags;
	local->mode = mode;
	loc->object->ms_mode = priv->default_mmode;

	switch (priv->default_mmode) {
		case ALL_SYNC:
		case PART_ASYNC:
			//not a forwarded request	
			if(strcmp(loc->sid, priv->local_xl->name)) {
				lta_sync_object_metadata(frame, lta_open_resume, 
					HF_FOP_GETOBJECT);
				break;
			} else {
				hf_log(this->name, HF_LOG_TRACE, 
					"OPEN %s by a forwarded request flags %d mode %d",
					loc->path, flags, mode);
			}
		case ALL_ASYNC:
			local->op_ret2 = 1;
			local->op_errno2 = 0;
			sprintf(loc->object->metadata.lhost, priv->local_xl->name);
			lta_open_resume(frame, this);
			break;
	}
	return 0;
}

/*
 * lta_readv_cbk - 
 */
int32_t
lta_readv_cbk (call_frame_t *frame,
		  xlator_t *this)
{
	lta_local_t *local = NULL;
	lta_private_t *priv = NULL;
	object_t *object = NULL;
	int32_t op_ret = 0, op_errno = 0;

	local = frame->local;
	priv = this->private;
	object = local->fd->object;

	if(local->op_ret2 < 0) {
		/*
 		 * if op_ret1 == 0 but op_ret2 != 0, we accept these error, do not give the error
 		 * message to application, only log it. 
 		 * TODO: deal this error according to priv->default_mmode.
 		 *
 		 */
		hf_log(this->name, HF_LOG_ERROR,
			"object %s READV by %s failed due to %s mmode %d status %d location %d",
			object->path, this->name, strerror(local->op_errno2),
			priv->default_mmode, object->status, object->location);
		op_ret = local->op_ret1;
		op_errno = local->op_errno1;
	} else {
		/*TODO: change object->statu using local->object_status */
		op_ret = local->op_ret1;
		object->status = OBJ_FRESH;
	}

	frame->local = NULL;
	STACK_UNWIND (frame, op_ret, op_errno, local->vector, local->count, 
		&local->stbuf, local->iobref);
	LOCAL_WIPE(local);

	return 0;
}

int32_t
lta_readv_resume_cbk (call_frame_t *frame,
		 void *cookie,
		 xlator_t *this,
		 int32_t op_ret,
		 int32_t op_errno,
		 struct iovec *vector,
		 int32_t count,
		 struct stat *stbuf,
		 struct iobref *iobref)
{
	lta_local_t *local = NULL;
	lta_private_t *priv = NULL;
	object_t *object = NULL;

	priv = this->private;
	local = frame->local;
	object = local->fd->object;

	local->op_ret1 = op_ret;
	local->op_errno1 = op_errno;
	local->vector = iov_dup(vector, count);
	local->count = count;
	local->iobref = iobref_ref(iobref);

	if(op_ret < 0) {
		hf_log(this->name, HF_LOG_ERROR,
			"object %s READV by %s failed due to %s",
			object->path, this->name, strerror(op_errno));

		local->op_ret2 = op_ret;
		local->op_errno2 = op_errno;

		lta_readv_cbk(frame, this);
		return 0;
	}
	local->stbuf = *stbuf;
	object->metadata.atime = stbuf->st_atime;
	local->updatebits = UPDATE_ATIME;
	lta_refresh_object(frame, &object->metadata, stbuf);
	switch (priv->default_mmode) {
		case ALL_SYNC:
			if(object->location == OBJ_LOCALHOST)
				lta_sync_object_metadata(frame, lta_readv_cbk, HF_FOP_UPDATEOBJECT);
			else {
				local->op_ret2 = 0;
				local->op_errno2 = 0;
				lta_readv_cbk(frame, this);
			}
			break;
		case PART_ASYNC:
		case ALL_ASYNC:
			LTA_OBJECT_SET_STATUS(object, OBJ_DIRTY);
			local->op_ret2 = 0;
			local->op_errno2 = 0;
	 		lta_readv_cbk(frame, this);
			break;
	}
	return 0;
}

/**
 * lta_readv - 
 */
int32_t
lta_readv (call_frame_t *frame,
	     xlator_t *this,
	     fd_t *fd,
	     size_t size,
	     off_t offset)
{
	LTA_CHECK_FD_CTX_AND_UNWIND_ON_ERR (fd);
	lta_local_t *local = NULL;
	xlator_t *child = NULL;
	uint64_t tmp_child = 0;

	INIT_LOCAL(frame, local);
	fd_ctx_get (fd, this, &tmp_child);

	local->fd = fd_ref(fd);
	local->offset = offset;

	fd_ctx_get (fd, this, &tmp_child);
	child = (xlator_t *)(long)tmp_child;
	if(!child)
	{
		hf_log (this->name, HF_LOG_ERROR, "lta get child xlator failed");
		STACK_UNWIND (frame, -1, EINVAL, NULL, 1, NULL, NULL);
		return 0;
	}

	STACK_WIND (frame,
		    lta_readv_resume_cbk,
		    child,
		    child->fops->readv,
		    fd,
		    size,
		    offset);

	return 0;
}

/*
 * lta_writev_cbk - 
 */
int32_t
lta_writev_cbk (call_frame_t *frame,
		  xlator_t *this)
{
	lta_local_t *local = NULL;
	lta_private_t *priv = NULL;
	object_t *object = NULL;
	int32_t op_ret = 0, op_errno = 0;

	local = frame->local;
	priv = this->private;
	object = local->fd->object;

	if(local->op_ret2 < 0) {
		/*
 		 * op_ret1 == 0 but op_ret2 != 0, we accept these error, do not give the error
 		 * message to application, only log it. 
 		 * TODO: deal this error according to priv->default_mmode.
 		 *
 		 */
		hf_log(this->name, HF_LOG_ERROR,
			"object %s WRITEV by %s failed due to %s mmode %d status %d location %d",
			object->path, this->name, strerror(local->op_errno2),
			priv->default_mmode, object->status, object->location);
		op_ret = local->op_ret1;
		op_ret = local->op_errno1;
	} else {
		op_ret = local->op_ret1;
		switch (priv->default_mmode) {
			case ALL_ASYNC:
			case PART_ASYNC:
				LTA_OBJECT_SET_STATUS(object, OBJ_DIRTY);
				break;
			case ALL_SYNC:
			    LTA_OBJECT_SET_STATUS(object, OBJ_FRESH);
				break;
		}
	}

	frame->local = NULL;
	STACK_UNWIND (frame, op_ret, op_errno, &local->stbuf);
	LOCAL_WIPE(local);

	return 0;
}

int32_t
lta_writev_resume_cbk (call_frame_t *frame,
		  void *cookie,
		  xlator_t *this,
		  int32_t op_ret,
		  int32_t op_errno,
                struct stat *stbuf)
{
	lta_local_t *local = NULL;
	lta_private_t *priv = NULL;
	object_t *object = NULL;

	priv = this->private;
	local = frame->local;
	local->op_ret1 = op_ret;
	local->op_errno1 = op_errno;
	object = local->fd->object;

	if(op_ret < 0) {
		hf_log(this->name, HF_LOG_ERROR,
			"object %s WRITEV by %s failed due to %s",
			object->path, this->name, strerror(op_errno));
		local->op_ret2 = op_ret;
		local->op_errno2 = op_errno;
		lta_writev_cbk(frame, this);

		return 0;
	}
	local->stbuf = *stbuf;
	lta_refresh_object(frame, &object->metadata, stbuf);
	local->updatebits = UPDATE_SIZE | UPDATE_CTIME | UPDATE_MTIME;

	switch (priv->default_mmode) {
		case ALL_SYNC:
			if(object->location == OBJ_LOCALHOST)
				lta_sync_object_metadata(frame, lta_writev_cbk, HF_FOP_UPDATEOBJECT);
			else {
				local->op_ret2 = 0;
				local->op_errno2 = 0;
				lta_writev_cbk(frame, this);
			}
			break;
		case PART_ASYNC:
		case ALL_ASYNC:
			LTA_OBJECT_SET_STATUS(object, OBJ_DIRTY);
			local->op_ret2 = 0;
			local->op_errno2 = 0;
			lta_writev_cbk(frame, this);
			break;
	}

	return 0;
}
/*
 * lta_writev - 
 */
int32_t
lta_writev (call_frame_t *frame,
	      xlator_t *this,
	      fd_t *fd,
	      struct iovec *vector,
	      int32_t count,
	      off_t off,
          struct iobref *iobref)
{
	LTA_CHECK_FD_CTX_AND_UNWIND_ON_ERR (fd);
	lta_local_t *local = NULL;
	xlator_t *child = NULL;
	uint64_t tmp_child = 0;

	INIT_LOCAL(frame, local);
	fd_ctx_get (fd, this, &tmp_child);

	local->fd = fd_ref(fd);
	local->offset = off;

	fd_ctx_get (fd, this, &tmp_child);
	child = (xlator_t *)(long)tmp_child;	
	if(!child)
	{
		hf_log (this->name, HF_LOG_ERROR, "lta get child xlator failed");
		STACK_UNWIND (frame, -1, EINVAL, NULL);
		return 0;
	}

	hf_log (this->name, HF_LOG_TRACE, "lta get child xlator %s",
		child->name);
	STACK_WIND (frame,
		    lta_writev_resume_cbk,
		    child,
		    child->fops->writev,
		    fd,
		    vector,
		    count,
		    off,
             iobref);

	return 0;
}

/*
 * lta_flush_cbk - 
 */
int32_t
lta_flush_cbk (call_frame_t *frame,
		 void *cookie,
		 xlator_t *this,
		 int32_t op_ret,
		 int32_t op_errno,
		 struct stat *stbuf)
{
	STACK_UNWIND (frame, op_ret, op_errno,stbuf);
	return 0;
}

/*
 * lta_flush -
 */
int32_t
lta_flush (call_frame_t *frame,
	     xlator_t *this,
	     fd_t *fd)
{
	LTA_CHECK_FD_CTX_AND_UNWIND_ON_ERR (fd);
	xlator_t *child = NULL;
	uint64_t tmp_child = 0;

	fd_ctx_get (fd, this, &tmp_child);
	child = (xlator_t *)(long)tmp_child;		
	if(!child)
	{
		hf_log (this->name, HF_LOG_ERROR, "lta get child xlator failed");
		STACK_UNWIND (frame, -1, EINVAL);
		return 0;
	}


	STACK_WIND (frame, lta_flush_cbk, child, 
		    child->fops->flush, fd);

	return 0;
}

/*
 * lta_ftruncate_cbk - 
 */
int32_t
lta_ftruncate_cbk(call_frame_t *frame,
		xlator_t *this)
{
	lta_local_t *local = NULL;
	lta_private_t *priv = NULL;
	object_t *object = NULL;
	int32_t op_ret = 0, op_errno = 0;

	local = frame->local;
	priv = this->private;
	object = local->fd->object;

	if(local->op_ret2 < 0) {
		hf_log(this->name, HF_LOG_ERROR,
			"object %s FTRUNCATE by %s failed due to %s mmode %d status %d location %d",
			object->path, this->name, strerror(local->op_errno2),
			priv->default_mmode, object->status, object->location);
		op_ret = local->op_ret1;
		op_errno = local->op_errno1;
	} else {
		op_ret = local->op_ret1;
		switch (priv->default_mmode) {
			case ALL_ASYNC:
			case PART_ASYNC:
				LTA_OBJECT_SET_STATUS(object, OBJ_DIRTY);
				break;
			case ALL_SYNC:
			    LTA_OBJECT_SET_STATUS(object, OBJ_FRESH);
				break;
		}
	}

	frame->local = NULL;
	STACK_UNWIND (frame, op_ret, op_errno, &local->stbuf);
	LOCAL_WIPE(local);

	return 0;
	
}

int32_t
lta_ftruncate_resume_cbk (call_frame_t *frame,
		 void *cookie,
		 xlator_t *this,
		 int32_t op_ret,
		 int32_t op_errno,
		 struct stat *stbuf)
{
	lta_local_t *local = NULL;
	lta_private_t *priv = NULL;
	object_t *object = NULL;

	priv = this->private;
	local = frame->local;
	local->op_ret1 = op_ret;
	local->op_errno1 = op_errno;
	local->stbuf = *stbuf;
	object = local->fd->object;

	if(op_ret < 0) {
		hf_log(this->name, HF_LOG_ERROR,
			"object %s FTRUNCATE by %s failed due to %s",
			object->path, this->name, strerror(op_errno));
		local->op_ret2 = op_ret;
		local->op_errno2 = op_errno;

		lta_ftruncate_cbk(frame, this);
		return 0;
	}
	lta_refresh_object(frame, &object->metadata, stbuf);
	local->updatebits = UPDATE_SIZE | UPDATE_CTIME | UPDATE_MTIME;

	switch (priv->default_mmode) {
		case ALL_SYNC:
			if(object->location == OBJ_LOCALHOST)
				lta_sync_object_metadata(frame, lta_ftruncate_cbk, HF_FOP_UPDATEOBJECT);
			else
				lta_ftruncate_cbk(frame, this);
			break;
		case PART_ASYNC:
		case ALL_ASYNC:
			local->op_ret2 = 0;
			local->op_errno2 = 0;
			lta_ftruncate_cbk(frame, this);
			break;
	}

	return 0;
}
/*
 * lta_ftruncate -
 */
int32_t
lta_ftruncate(call_frame_t *frame, 
		xlator_t *this,
		fd_t *fd,
		off_t offset)
{
	LTA_CHECK_FD_CTX_AND_UNWIND_ON_ERR (fd);

	lta_local_t *local = NULL;
	xlator_t *child = NULL;
	uint64_t tmp_child = 0;

	INIT_LOCAL(frame, local);
	fd_ctx_get (fd, this, &tmp_child);

	local->fd = fd_ref(fd);
	local->offset = offset;

	child = (xlator_t *)(long)tmp_child;		
	if(!child)
	{
		hf_log (this->name, HF_LOG_ERROR, "lta get child xlator failed");
		STACK_UNWIND (frame, -1, EINVAL);
		return 0;
	}


	STACK_WIND (frame, lta_ftruncate_resume_cbk, child, 
		    child->fops->ftruncate, fd, offset);

	return 0;
}
/*
 * lta_ioctl_cbk - 
 */
int32_t
lta_ioctl_cbk (call_frame_t *frame,
		 void *cookie,
		 xlator_t *this,
		 int32_t op_ret,
		 int32_t op_errno)
{
	STACK_UNWIND (frame, op_ret, op_errno);
	return 0;
}

/*
 * lta_ioctl - 
 */
int32_t
lta_ioctl (call_frame_t *frame,
	     xlator_t *this,
	     fd_t *fd,
	     uint32_t cmd,
	     uint64_t arg)
{
	LTA_CHECK_FD_CTX_AND_UNWIND_ON_ERR (fd);
	xlator_t *child = NULL;
	uint64_t tmp_child = 0;

	fd_ctx_get (fd, this, &tmp_child);
	child = (xlator_t *)(long)tmp_child;		
	if(!child)
	{
		hf_log (this->name, HF_LOG_ERROR, "lta get child xlator failed");
		STACK_UNWIND (frame, -1, EINVAL);
		return 0;
	}

	STACK_WIND (frame, lta_ioctl_cbk, child, 
		    child->fops->ioctl, fd, cmd, arg);

	return 0;
}

/*
 * lta_unlink_cbk - 
 */
int32_t
lta_unlink_cbk (call_frame_t *frame, xlator_t *this)
{
	lta_local_t *local = NULL;
	lta_private_t *priv = NULL;
	object_t *object = NULL;
	int32_t op_ret, op_errno;
			 
	local = frame->local;
	priv = this->private;
	op_ret = local->op_ret1;
	op_errno = local->op_errno1;
	object = local->loc->object;
				 
	if (op_ret < 0) {
		hf_log(this->name, HF_LOG_ERROR,
			"object %s UNLINK by %s failed due to %s mmode %d status %d location %d",
			local->loc->path, this->name, strerror(op_errno),
			priv->default_mmode, object->status, object->location);
	} else {
			switch (priv->default_mmode) {
				case ALL_SYNC:
				case PART_ASYNC:
					 LTA_OBJECT_SET_STATUS(object, OBJ_FRESH);
					 break;
				case ALL_ASYNC:
					 break;
			}
	}

	frame->local = NULL;
	STACK_UNWIND (frame, op_ret, op_errno);
	LOCAL_WIPE(local);

	return 0;
}

int32_t
lta_unlink_resume_cbk(call_frame_t *frame,
		  void *cookie,
		  xlator_t *this,
		  int32_t op_ret,
		  int32_t op_errno)
{
	lta_local_t *local = NULL;
	lta_private_t *priv = NULL;
	lta_obj_t *lobj = NULL;
	object_t *object = NULL;

	local = frame->local;
	priv = this->private;
	local->op_ret1 = op_ret;
	local->op_errno1 = op_errno;
	object = local->loc->object;
	
	if(op_ret < 0) {
		hf_log(this->name, HF_LOG_ERROR,
			"object %s UNLINK by %s failed due to %s",
			local->loc->path, this->name, strerror(op_errno));
		local->op_ret2 = op_ret;
		local->op_errno2 = op_errno;

		lta_unlink_cbk(frame, this);
		return 0;
	}
	switch (priv->default_mmode) {
		case ALL_SYNC:
		case PART_ASYNC:
			if(object->location == OBJ_LOCALHOST)
				lta_sync_object_metadata(frame, lta_unlink_cbk, HF_FOP_DELETEOBJECT);
			else {
				local->op_ret2 = 0;
				local->op_errno2 = 0;
				lta_unlink_cbk(frame, this);
			}
			break;
		case ALL_ASYNC:
			lobj = lta_alloc_lobj(object, this);
			if(lobj == NULL) {
				local->op_ret2 = -1;
				local->op_errno2 = EINVAL;
				goto out;
			}
			local->op_ret2 = 0;
			local->op_errno2 = 0;
			lta_metaup_add_openfd(lobj, this);
			LTA_OBJECT_SET_STATUS(object, OBJ_UNLINK);
			lta_unlink_cbk(frame, this);
			break;
	}
	return 0;
out:
	lta_unlink_cbk(frame, this);
	return 0;
}

int32_t
lta_unlink_resume(call_frame_t *frame, xlator_t *this)
{
	lta_local_t *local = NULL;
	lta_private_t *priv = NULL;
	xlator_t *xl = NULL;
	object_t *object = NULL;

	local = frame->local;
	object = local->loc->object;
	priv = this->private;
				  
	if(local->op_ret2 == 1){
		object->status = OBJ_FRESH;
		if(!strcmp(priv->local_xl->name, object->metadata.lhost)) {
			object->location = OBJ_LOCALHOST;
			xl = priv->local_xl;
		} else {
			object->location = OBJ_OTHERHOST;
			xl = priv->global_xl;	
		}
	} else {
		hf_log(this->name, HF_LOG_ERROR,
				"object %s failed by %s failed due to %d %s",
				local->loc->path, this->name, local->op_ret2, strerror(local->op_errno2));

		local->op_ret2 = -1;
		local->op_errno2 = ENOENT;
		goto err;
	}

	STACK_WIND (frame, lta_unlink_resume_cbk, xl, xl->fops->unlink, local->loc);

	return 0;
err:
	lta_unlink_cbk(frame, this);
	return 0;

}

/*
 * lta_unlink - 
 */
int32_t
lta_unlink (call_frame_t *frame,
	      xlator_t *this,
	      loc_t *loc)
{
	lta_private_t *priv        = this->private;
	lta_local_t *local = NULL;

	LTA_CHECK_OBJECT_CTX_AND_UNWIND_ON_ERR (loc);

	INIT_LOCAL(frame, local);
	local->loc = loc;
	loc->object->ms_mode = priv->default_mmode;

	switch (priv->default_mmode) {
		case ALL_SYNC:
		case PART_ASYNC:
			//not a forwarded request
			if(strcmp(loc->sid, priv->local_xl->name)) {
				lta_sync_object_metadata(frame, lta_unlink_resume, 
							HF_FOP_GETOBJECT);
				break;
			} else {
				hf_log(this->name, HF_LOG_TRACE, 
					"UNLINK %s by a forwarded request", loc->path);
			}
		case ALL_ASYNC:
			local->op_ret2 = 1;
			local->op_errno2 = 0;
			sprintf(loc->object->metadata.lhost, priv->local_xl->name);
			lta_unlink_resume(frame, this);
			break;
	}
	return 0;
}

/**
 * lta_fstat_cbk - 
 */
int32_t
lta_fstat_cbk (call_frame_t *frame,
		 void *cookie,
		 xlator_t *this,
		 int32_t op_ret,
		 int32_t op_errno,
		 struct stat *stbuf)
{
	STACK_UNWIND (frame, op_ret, op_errno, stbuf);
	return 0;
}

/**
 * lta_fstat - 
 */
int32_t
lta_fstat (call_frame_t *frame,
	     xlator_t *this,
	     fd_t *fd)
{
	LTA_CHECK_FD_CTX_AND_UNWIND_ON_ERR (fd);
	xlator_t *child = NULL;
	uint64_t tmp_child = 0;

	fd_ctx_get (fd, this, &tmp_child);
	child = (xlator_t *)(long)tmp_child;
	if(!child)
	{
		hf_log (this->name, HF_LOG_ERROR, "lta get child xlator failed");
		STACK_UNWIND (frame, -1, EINVAL, NULL);
		return 0;
	}

	STACK_WIND (frame,
		    lta_fstat_cbk,
		    child,
		    child->fops->fstat,
		    fd);

	return 0;
}

/**
 * lta_stat_cbk -
 */
int32_t
lta_stat_cbk (call_frame_t *frame, void *cookie, xlator_t *this,
                    int32_t op_ret, int32_t op_errno, struct stat *stbuf)
{
	lta_local_t *local = NULL;
			 
	local = frame->local;
				 
	//TODO: is it neccesary to check metadata in ns?
	if (op_ret < 0) {
		hf_log (this->name, HF_LOG_ERROR,
			"%"PRId64": STAT  %s failed %s",
			frame->root->unique, local->loc->path, strerror(op_errno));
	}

	frame->local = NULL;
	STACK_UNWIND (frame, op_ret, op_errno, stbuf);
	LOCAL_WIPE(local);

	return 0;
}

int32_t
lta_stat_resume(call_frame_t *frame, xlator_t *this)
{
	lta_local_t *local = NULL;
	lta_private_t *priv = NULL;
	xlator_t *xl = NULL;
	object_t *object = NULL;
	int32_t op_ret, op_errno;

	local = frame->local;
	object = local->loc->object;
	priv = this->private;
	op_ret = local->op_ret2;
	op_errno = local->op_errno2;
				  
	if(op_ret == 1){
		object->status = OBJ_FRESH;
		if(!strcmp(priv->local_xl->name, object->metadata.lhost)) {
			object->location = OBJ_LOCALHOST;
			xl = priv->local_xl;
		} else {
			object->location = OBJ_OTHERHOST;
			xl = priv->global_xl;	
		}
	} else {
		 op_ret = -1;
		 op_errno = ENOENT;
		 goto err;
	}

	STACK_WIND (frame, lta_stat_cbk, xl, xl->fops->stat, local->loc);

	return 0;
err:
	lta_stat_cbk(frame, NULL, this, op_ret, op_errno, NULL);

	return 0;
}

/**
 * lta_stat - 
 */
int32_t
lta_stat (call_frame_t *frame,
	    xlator_t *this,
	    loc_t *loc)
{
	lta_private_t *priv  = this->private;
	lta_local_t *local = NULL;

	LTA_CHECK_OBJECT_CTX_AND_UNWIND_ON_ERR (loc);

	INIT_LOCAL(frame, local);
	local->loc = loc;
	loc->object->ms_mode = priv->default_mmode;

	switch (priv->default_mmode) {
		case ALL_SYNC:
		case PART_ASYNC:
			if(strcmp(loc->sid, priv->local_xl->name)) {
				lta_sync_object_metadata(frame, lta_stat_resume, 
					HF_FOP_GETOBJECT);
				break;
			} else {
				hf_log(this->name, HF_LOG_TRACE, 
					"STAT %s by a forwarded request", loc->path);
			}
		case ALL_ASYNC:
			local->op_ret2 = 1;
			local->op_errno2 = 0;
			sprintf(loc->object->metadata.lhost, priv->local_xl->name);
			lta_stat_resume(frame, this);
			break;
	}
	return 0;
}

/**
 * lta_truncate_cbk - 
 */
int32_t
lta_truncate_cbk(call_frame_t *frame,
		xlator_t *this)
{
	lta_local_t *local = NULL;
	lta_private_t *priv = NULL;
	object_t *object = NULL;

	local = frame->local;
	priv = this->private;
	object = local->loc->object;
	if(local->op_ret2 < 0) {
		hf_log(this->name, HF_LOG_ERROR,
			"object %s TRUNCATE by %s failed due to %s mmode %d status %d location %d",
			local->loc->path, this->name, strerror(local->op_errno2),
			priv->default_mmode, object->status, object->location);
	} else {
			switch (priv->default_mmode) {
					case ALL_SYNC:
					case PART_ASYNC:
						 LTA_OBJECT_SET_STATUS(object, OBJ_FRESH);
						 break;
					case ALL_ASYNC:
						 break;
			}
	}

	frame->local = NULL;
	STACK_UNWIND (frame, local->op_ret2, local->op_errno2, &local->stbuf);
	LOCAL_WIPE(local);

	return 0;
}

int32_t
lta_truncate_resume_cbk(call_frame_t *frame,
		  void *cookie,
		  xlator_t *this,
		  int32_t op_ret,
		  int32_t op_errno,
		struct stat *stbuf)
{
	lta_local_t *local = NULL;
	lta_private_t *priv = NULL;
	lta_obj_t *lobj = NULL;
	object_t *object = NULL;

	local = frame->local;
	priv = this->private;
	object = local->loc->object;

	local->stbuf = *stbuf;
	local->op_ret1 = op_ret;
	local->op_errno1 = op_errno;
	
	if(op_ret < 0) {
		hf_log(this->name, HF_LOG_ERROR,
			"object %s truncate by %s failed due to %s",
			local->loc->path, this->name, strerror(op_errno));
		local->op_ret2 = op_ret;
		local->op_errno2 = op_errno;
		goto err;

	}

	lta_refresh_object(frame, &object->metadata, stbuf);
	local->updatebits = UPDATE_SIZE | UPDATE_CTIME | UPDATE_MTIME;

	switch (priv->default_mmode) {
		case ALL_SYNC:
		case PART_ASYNC:
			if(object->location == OBJ_LOCALHOST)
				lta_sync_object_metadata(frame, lta_truncate_cbk, HF_FOP_UPDATEOBJECT);
			else {
				local->op_ret2 = 0;
				local->op_errno2 = 0;
				lta_truncate_cbk(frame, this);
			}
			break;
		case ALL_ASYNC:
			lobj = CALLOC(1, sizeof(lta_obj_t));
			if(lobj == NULL) {
				hf_log(this->name, HF_LOG_ERROR, "Out of Memory");
				local->op_ret2 = -1;
				local->op_errno2 = ENOMEM;
				goto err;
			}
			lobj->object = object_ref(object);
			INIT_LIST_HEAD(&lobj->meta_list);
			INIT_LIST_HEAD(&lobj->update_list);
			if(object_ctx_put(object, this, (uint64_t)(long)lobj)) {
				hf_log(this->name, HF_LOG_ERROR, "object %s ctx set failed",
						object->path);
				local->op_ret2 = -1;
				local->op_errno2 = EINVAL;
				goto err;
			}
			local->op_ret2 = 0;
			local->op_errno2 = 0;
			/* using OBJ_CLOSE to tell lta-metaup to update attributes */
			lta_metaup_add_openfd(lobj, this);
			LTA_OBJECT_SET_STATUS(object, OBJ_CLOSE);
			lta_unlink_cbk(frame, this);
			break;
	}
	return 0;
err:

	lta_truncate_cbk(frame, this);
	return 0;	
}

int32_t
lta_truncate_resume(call_frame_t *frame, xlator_t *this)
{
	lta_local_t *local = NULL;
	lta_private_t *priv = NULL;
	xlator_t *xl = NULL;
	object_t *object = NULL;

	local = frame->local;
	object = local->loc->object;
	priv = this->private;
				  
	if(local->op_ret2 == 1){
		object->status = OBJ_FRESH;
		if(!strcmp(priv->local_xl->name, object->metadata.lhost)) {
			object->location = OBJ_LOCALHOST;
			xl = priv->local_xl;
		} else {
			object->location = OBJ_OTHERHOST;
			xl = priv->global_xl;	
		}
	} else {
		 local->op_ret2 = -1;
		 local->op_errno2 = ENOENT;
		 goto err;
	}

	hf_log (this->name, HF_LOG_DEBUG, "lta will send truncate %s to xlator:%s",
		local->loc->path, xl->name);

	STACK_WIND (frame, lta_truncate_resume_cbk, xl, xl->fops->truncate, local->loc, local->offset);

	return 0;
err:
	lta_truncate_cbk(frame, this);

	return 0;
}

/**
 * lta_truncate - 
 */
int32_t
lta_truncate (call_frame_t *frame,
	xlator_t *this,
	loc_t *loc, off_t offset)
{
	lta_private_t *priv  = this->private;
	lta_local_t *local = NULL;

	LTA_CHECK_OBJECT_CTX_AND_UNWIND_ON_ERR (loc);

	INIT_LOCAL(frame, local);
	local->loc = loc;
	local->offset = offset;
	loc->object->ms_mode = priv->default_mmode;

	switch (priv->default_mmode) {
		case ALL_SYNC:
		case PART_ASYNC:
			if(strcmp(loc->sid, priv->local_xl->name)) {
				lta_sync_object_metadata(frame, lta_truncate_resume, 
					HF_FOP_GETOBJECT);
				break;
			} else {
				hf_log(this->name, HF_LOG_TRACE, 
					"TRUNCATE %s by a forwarded request offset", loc->path, offset);
			}
		case ALL_ASYNC:
			local->op_ret2 = 1;
			local->op_errno2 = 0;
			sprintf(loc->object->metadata.lhost, priv->local_xl->name);
			lta_truncate_resume(frame, this);
			break;
	}
	return 0;
}

/**
 * lta_release -
 */
int32_t
lta_release(xlator_t *this,
	fd_t *fd)
{
	object_t *object = fd->object;

	LTA_OBJECT_SET_STATUS(object, OBJ_CLOSE);
	return 0;
}

/*
 * lta provides two kinds of metadata operations, the two kinds
 * is differ from islmdb value, when islmdb is set to 1, then 
 * it is the first kind, otherwise it is the second kind.
 *
 * 1. operation from data managements tools such as hadash
 * 2. operation from client for metadata storage, this only
 *    happened when compute node send these operations.
 */

/*
 *lta_setobject_cbk
 */
 int32_t
 lta_setobject_cbk(call_frame_t *frame, void *cookie, xlator_t *this,
 	int32_t op_ret, int32_t op_errno, int32_t status)
 {
 	STACK_UNWIND(frame, op_ret, op_errno, status);
	return 0;
 }
/**
 * lta_setobject - 
 */
int32_t
lta_setobject (call_frame_t * frame,
		xlator_t *this,
		char *path,
		int32_t islmdb,
		object_t *object)
{
	lta_private_t *priv = this->private;

	xlator_t *ns = NULL;
	if(islmdb == 1)
		ns = priv->local_xl;
	else
		ns = priv->ns_xl;
	
	STACK_WIND(frame,
		lta_setobject_cbk,
		ns,
		ns->fops->setobject,
		path,
		islmdb,
		object);
	return 0;
}

/*
*lta_updateobject_cbk
*/
int32_t
lta_updateobject_cbk(call_frame_t *frame, void *cookie, xlator_t *this,
	int32_t op_ret, int32_t op_errno, int32_t status)
{
	STACK_UNWIND(frame, op_ret, op_errno, status);
	return 0;
}
/**
* lta_updateobject - 
*/
int32_t
lta_updateobject (call_frame_t * frame,
		xlator_t *this,
		char *path,
		int32_t islmdb,
		int32_t updatebits,
		object_t *object)
{
	lta_private_t *priv = this->private;

	xlator_t *ns = NULL;
	if(islmdb == 1)
		ns = priv->local_xl;
	else
		ns = priv->ns_xl;
			
	STACK_WIND(frame,
		lta_updateobject_cbk,
		ns,
		ns->fops->updateobject,
		path,
		islmdb,
		updatebits,
		object);

	return 0;
}

/*
 * lta_getobject_cbk
 */
int32_t
lta_getobject_cbk(call_frame_t *frame, void *cookie, xlator_t *this,
	int32_t op_ret, int32_t op_errno, object_t *object)
{
	STACK_UNWIND(frame, op_ret, op_errno, object);
	return 0;
}
/**
* lta_getobject - 
*/
int32_t
lta_getobject (call_frame_t * frame,
		xlator_t *this,
		char *path,
		int32_t islmdb,
		object_t *object)
{
	lta_private_t *priv = this->private;

	xlator_t *ns = NULL;
	if(islmdb == 1)
		ns = priv->local_xl;
	else
		ns = priv->ns_xl;
			
	STACK_WIND(frame,
		lta_getobject_cbk,
		ns,
		ns->fops->getobject,
		path,
		islmdb,
		object);
	return 0;
}

/*
*lta_lookupobject_cbk
*/
int32_t
lta_lookupobject_cbk(call_frame_t *frame, void *cookie, xlator_t *this,
	int32_t op_ret, int32_t op_errno, object_t *object)
{
	STACK_UNWIND(frame, op_ret, op_errno, object);
	return 0;
}
/**
* lta_lookupobject - 
*/
int32_t
lta_lookupobject (call_frame_t * frame,
		xlator_t *this,
		char *path,
		int32_t islmdb,
		object_t *object)
{
	lta_private_t *priv = this->private;

	xlator_t *ns = NULL;
	if(islmdb == 1)
		ns = priv->local_xl;
	else
		ns = priv->ns_xl;
		
	STACK_WIND(frame,
		lta_lookupobject_cbk,
		ns,
		ns->fops->lookupobject,
		path,
		islmdb,
		object);
	return 0;
}

/*
*lta_deleteobject_cbk
*/
int32_t
lta_deleteobject_cbk(call_frame_t *frame, void *cookie, xlator_t *this,
			int32_t op_ret, int32_t op_errno, int32_t status)
{
	STACK_UNWIND(frame, op_ret, op_errno, status);
	return 0;
}
/**
* lta_deleteobject -
*/
int32_t
lta_deleteobject (call_frame_t * frame,
		xlator_t *this,
		char *path,
		int32_t islmdb,
		object_t *object)
{
	lta_private_t *priv = this->private;
						
	xlator_t *ns = NULL;
	if(islmdb == 1)
		ns = priv->local_xl;
	else
		ns = priv->ns_xl;

	STACK_WIND(frame,
		lta_deleteobject_cbk,
		ns,
		ns->fops->deleteobject,
		path,
		islmdb,
		object);
	return 0;
}

/*
 * init - This function is called first in the xlator, while initializing.
 *   All the config file options are checked and appropriate flags are set.
 *
 * @this - 
 */
int32_t 
init (xlator_t *this)
{
	int32_t       ret;
	xlator_list_t      	*trav      = NULL;
	xlator_t      	*x_trav      = NULL;
	lta_private_t *_private  = NULL; 
	char 		*local_xl = NULL, *ns_xl = NULL;
	data_t 		*mmode_data = NULL;	

	/* Check for number of child nodes, if there is no child nodes, exit */
	if (!this->children) {
		hf_log (this->name, HF_LOG_ERROR,
			"No child nodes specified. check \"subvolumes \" "
			"option in volfile");
		return -1;
	}

  	if (!this->parents) {
		hf_log (this->name, HF_LOG_WARNING,
			"dangling volume. check volfile ");
	}
	
	_private = CALLOC (1, sizeof (*_private));
	ERR_ABORT (_private);
	
	/* update _private structure */
	{
		/* connect to global & local name server */
		ret = dict_get_str (this->options, "global-name-server", &ns_xl);
		if (ret < 0) {
			hf_log (this->name, HF_LOG_ERROR,
					"wrong value for global name-server xlator");
			return -1;
		}
		/* ns xlator should not be a child*/
		_private->ns_xl = NULL;
		x_trav = this->next;
		while (x_trav) {
			if(!strncmp (ns_xl, x_trav->name, strlen(x_trav->name))){
				_private->ns_xl = x_trav;
				hf_log(this->name, HF_LOG_DEBUG, "ns_xl %s xlator %s chosen as ns xl",
					ns_xl, x_trav->name);
				break;
			}
			x_trav = x_trav->next;
		}
		if(_private->ns_xl == NULL) {
			hf_log (this->name, HF_LOG_ERROR,
					"no xlator named %s as global name-server xlator",
			ns_xl);
			return -1;
		}
		/* local stroage xlator should not be a child*/
		_private->local_xl = NULL;
		ret = dict_get_str (this->options, "local-volume", &local_xl);
		x_trav = this->next;
		while (x_trav) {
			if(!strncmp (local_xl, x_trav->name, strlen(x_trav->name))){
				_private->local_xl = x_trav;
				hf_log(this->name, HF_LOG_DEBUG, "%s xlator %s chosen as local xl",
					local_xl, x_trav->name);
				break;
			}
			x_trav = x_trav->next;
		}
		if(_private->local_xl == NULL) {
			hf_log (this->name, HF_LOG_ERROR,
					"no xlator named %s as local storage xlator",
			local_xl);
			return -1;
		}
		/* set default metadata mode */
		mmode_data = dict_get (this->options, "metadata-mode");
		if (!mmode_data) {
			hf_log (this->name, HF_LOG_NORMAL,
				"NO value for metadata async mode, using part_async as default");
			_private->default_mmode = PART_ASYNC;
		} else {
			if(!strcmp(mmode_data->data, "all_async"))
				_private->default_mmode = ALL_ASYNC;
			else if(!strcmp(mmode_data->data, "part_async"))
				_private->default_mmode = PART_ASYNC;
			else if(!strcmp(mmode_data->data, "all_sync"))
				_private->default_mmode = ALL_SYNC;
			else {
				hf_log (this->name, HF_LOG_ERROR,
						"bad value for metadata async mode");
				return -1;
			}
		}
		trav = this->children;
		_private->global_xl = trav->xlator;
	}
	_private->update_worker = CALLOC(1, sizeof(struct lta_metaup_worker_arg));
	if(_private->update_worker == NULL) {
		hf_log (this->name, HF_LOG_ERROR,
				"Out of memory");
		return -1;
	}
	ret = lta_metaup_start(this, _private->update_worker);
	if(ret == -1) {
		hf_log(this->name, HF_LOG_ERROR, 
			"start lta update metadata thread failed");
	}
	/* Now that everything is fine. */
	this->private = (void *)_private;

	return 0;
}

/** 
 * fini  - Free all the allocated memory 
 */
void
fini (xlator_t *this)
{
	lta_private_t *priv = this->private;
	this->private = NULL;
	LOCK_DESTROY (&priv->lock);
	FREE (priv);

	return;
}


struct xlator_fops fops = {
	.open        = lta_open,
	.readv	     = lta_readv,
	.writev      = lta_writev,
	.unlink      = lta_unlink,
	.stat        = lta_stat,
	.truncate    = lta_truncate,
	.fstat       = lta_fstat,
	.flush	     = lta_flush,
	.ftruncate   = lta_ftruncate,
	.setobject   = lta_setobject,
	.getobject   = lta_getobject,
	.updateobject   = lta_updateobject,
	.lookupobject = lta_lookupobject,
	.deleteobject = lta_deleteobject,
	.ioctl	     = lta_ioctl,
};

struct xlator_mops mops = {
};

struct xlator_cbks cbks = {
	.release = lta_release
};

struct volume_options options[] = {
	{ .key   = { "local-volume" },  
	  .type  = HF_OPTION_TYPE_XLATOR 
	},
	{ .key   = {"global-name-server"},
		.type  = HF_OPTION_TYPE_XLATOR
	},
	{ .key   = {"metadata-mode"}, 
	  .value = {"all_async", "part_async", "all_sync"},
	  .type  = HF_OPTION_TYPE_STR
	},
	{ .key   = {NULL} },
};

