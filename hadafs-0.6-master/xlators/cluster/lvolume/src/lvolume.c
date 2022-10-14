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
 * xlators/cluster/lvolume:
 *     - This xlator is one of the main translator in LWFS, which
 *   actually does the clustering work of the file system. One need to 
 *   understand that, lvolume assumes file to be existing in only one of 
 *   the child node, and directories to be present on all the nodes. 
 *
 * NOTE:
 *   Now, lvolume has support for global namespace, which is used to keep a 
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

#include "lvolume.h"
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
	lvolume_local_t *_local = frame->local;				\
	_local->op_ret = ret; 					\
	_local->op_errno = errno;				\
	_local->object_status = status;				\
	_local->resume_fn(frame, this);				\
} while(0)

int32_t
lvolume_sync_setobject_cbk(call_frame_t *frame, void *cookie, xlator_t *this,
		int32_t op_ret, int32_t op_errno, int32_t status)
{
	LTA_SYNC_OBJECT_RESUME(frame, this, op_ret, op_errno, status);
	return 0;
}

int32_t
lvolume_sync_getobject_cbk(call_frame_t *frame, void *cookie, xlator_t *this,
		int32_t op_ret, int32_t op_errno, object_t *object)
{
	LTA_SYNC_OBJECT_RESUME(frame, this, op_ret, op_errno, 0);
	return 0;
}

int32_t
lvolume_sync_deleteobject_cbk(call_frame_t *frame, void *cookie, xlator_t *this,
		int32_t op_ret, int32_t op_errno, int32_t status)
{
	LTA_SYNC_OBJECT_RESUME(frame, this, op_ret, op_errno, status);
	return 0;
}

inline void
lvolume_refresh_object(call_frame_t *fr, metadata_t *mt, struct stat *st)
{
	mt->uid = fr->root->uid;
	mt->gid = fr->root->gid;
	mt->mode = st->st_mode;
	mt->lno = st->st_ino;
}

int32_t
lvolume_sync_object_metadata(call_frame_t *frame, lvolume_resume_fn_t fn, 
    hadafs_fop_t fop)
{
	lvolume_local_t	  *local = NULL;
	lvolume_private_t  *priv = NULL;
	xlator_t	  *this  = NULL;
	
	local = frame->local;
	local->resume_fn = fn;
	this = frame->this;
	priv = this->private;

	switch (fop)
	{
		case HF_FOP_SETOBJECT:
			STACK_WIND(frame,
				lvolume_sync_setobject_cbk,
				priv->ns_xl,
				priv->ns_xl->fops->setobject,
				local->loc->path, 0, local->loc->object);
			return 0;
		case HF_FOP_UPDATEOBJECT:
			STACK_WIND(frame,
				lvolume_sync_setobject_cbk,
				priv->ns_xl,
				priv->ns_xl->fops->updateobject,
				local->loc->path, 0, local->updatebits, 
				local->loc->object);
			return 0;
		case HF_FOP_GETOBJECT:
			STACK_WIND(frame,
				lvolume_sync_getobject_cbk,
				priv->ns_xl,
				priv->ns_xl->fops->getobject,
				local->loc->path, 0, local->loc->object);
			return 0;
		case HF_FOP_LOOKUPOBJECT:
			STACK_WIND(frame,
				lvolume_sync_getobject_cbk,
				priv->ns_xl,
				priv->ns_xl->fops->lookupobject,
				local->loc->path, 0, local->loc->object);
			return 0;
		case HF_FOP_DELETEOBJECT:
			STACK_WIND(frame,
				lvolume_sync_deleteobject_cbk,
				priv->ns_xl,
				priv->ns_xl->fops->deleteobject,
				local->loc->path, 0, local->loc->object);
			return 0;
		default:
			break;
	}
	return 0;
}

/**
 * lvolume_local_wipe - free all the extra allocation of local->* here.
 */
inline void 
lvolume_local_wipe (lvolume_local_t *local)
{

	if(local->fd)
		fd_unref(local->fd);

	local->fd = NULL;

	FREE(local);
}

/**
 * lvolume_open_cbk -
 */
int32_t
lvolume_open_cbk (call_frame_t *frame, xlator_t *this)
{

	lvolume_local_t *local = NULL;
	object_t *object = NULL;
	int32_t op_ret, op_errno;

	local = frame->local;
	op_ret = local->op_ret;
	op_errno = local->op_errno;
	object = local->loc->object;
	
	if (op_ret < 0) {
		hf_log (this->name, HF_LOG_ERROR,
			"%"PRId64": OPEN  %s failed: %s",
			frame->root->unique, object->path, strerror(op_errno));
	}
	
	frame->local = NULL;
	STACK_UNWIND (frame, op_ret, op_errno, local->fd, object, local->stbuf);

	lvolume_local_wipe(local);

	return 0;
}

int32_t
lvolume_open_sync_md(call_frame_t *frame, void *cookie, xlator_t *this,
        int32_t op_ret, int32_t op_errno,
        fd_t *fd, object_t *object, struct stat *stbuf)
{
	lvolume_local_t *local = NULL;

	local = frame->local;
	local->stbuf = stbuf;
	
	if(op_ret < 0) {
		hf_log(this->name, HF_LOG_ERROR, "object %s open by %s failed due to %s",
			object->path, this->name, strerror(op_errno));
		lvolume_open_cbk(frame, this);
		return 0;
	}

	lvolume_refresh_object(frame, &object->metadata, stbuf);
	lvolume_sync_object_metadata(frame, lvolume_open_cbk, HF_FOP_SETOBJECT);

	return 0;
}

/**
 * lvolume_open - 
 */
int32_t
lvolume_open (call_frame_t *frame,
	    xlator_t *this,
	    loc_t *loc,
	    int32_t flags,
	    mode_t mode,
	    fd_t *fd)
{
	
	lvolume_private_t *priv = this->private;
	xlator_t *xl = priv->local_xl;
	lvolume_local_t *local = NULL;

	LTA_CHECK_OBJECT_CTX_AND_UNWIND_ON_ERR (loc);

	INIT_LOCAL(frame, local);

	local->loc = loc;
	local->fd = fd_ref(fd);

	STACK_WIND (frame,
		lvolume_open_sync_md, 
		xl, xl->fops->open, 
		loc, 
		flags, 
		mode,
		fd);

	return 0;
}

/**
 * lvolume_readv_cbk - 
 */
int32_t
lvolume_readv_cbk (call_frame_t *frame,
		 void *cookie,
		 xlator_t *this,
		 int32_t op_ret,
		 int32_t op_errno,
		 struct iovec *vector,
		 int32_t count,
		 struct stat *stbuf,
		 struct iobref *iobref)
{
	STACK_UNWIND (frame, op_ret, op_errno, vector, count, stbuf, iobref);
	return 0;
}

/**
 * lvolume_readv - 
 */
int32_t
lvolume_readv (call_frame_t *frame,
	     xlator_t *this,
	     fd_t *fd,
	     size_t size,
	     off_t offset)
{
	lvolume_private_t *priv = this->private;
	xlator_t *child = priv->local_xl;

	STACK_WIND (frame,
		    lvolume_readv_cbk,
		    child,
		    child->fops->readv,
		    fd,
		    size,
		    offset);

	return 0;
}

/**
 * lvolume_writev_cbk - 
 */
int32_t
lvolume_writev_cbk (call_frame_t *frame,
		  void *cookie,
		  xlator_t *this,
		  int32_t op_ret,
		  int32_t op_errno,
                struct stat *stbuf)
{

	hf_log(this->name, HF_LOG_TRACE, "writev finish %d %d",
		op_ret, op_errno);
	STACK_UNWIND (frame, op_ret, op_errno, stbuf);

	return 0;
}

/**
 * lvolume_writev - 
 */
int32_t
lvolume_writev (call_frame_t *frame,
	      xlator_t *this,
	      fd_t *fd,
	      struct iovec *vector,
	      int32_t count,
	      off_t off,
          struct iobref *iobref)
{
	lvolume_private_t *priv = this->private;
	xlator_t *child = priv->local_xl;

	hf_log(this->name, HF_LOG_TRACE, "writev by %s",
		child->name);

	STACK_WIND (frame,
		    lvolume_writev_cbk,
		    child,
		    child->fops->writev,
		    fd,
		    vector,
		    count,
		    off,
             iobref);

	return 0;
}

/**
 * lvolume_flush_cbk - 
 */
int32_t
lvolume_flush_cbk (call_frame_t *frame,
		 void *cookie,
		 xlator_t *this,
		 int32_t op_ret,
		 int32_t op_errno,
		 struct stat *stbuf)
{
	STACK_UNWIND (frame, op_ret, op_errno,stbuf);
	return 0;
}

/**
 * lvolume_flush -
 */
int32_t
lvolume_flush (call_frame_t *frame,
	     xlator_t *this,
	     fd_t *fd)
{
	lvolume_private_t *priv = this->private;
	xlator_t *child = priv->local_xl;

	STACK_WIND (frame, lvolume_flush_cbk, child, 
		    child->fops->flush, fd);

	return 0;
}

/**
 * lvolume_ftruncate_cbk - 
 */
int32_t
lvolume_ftruncate_cbk (call_frame_t *frame,
		 void *cookie,
		 xlator_t *this,
		 int32_t op_ret,
		 int32_t op_errno,
		 struct stat *stbuf)
{
	STACK_UNWIND (frame, op_ret, op_errno,stbuf);
	return 0;
}
/**
 * lvolume_ftruncate -
 */
int32_t
lvolume_ftruncate(call_frame_t *frame, 
		xlator_t *this,
		fd_t *fd,
		off_t offset)
{
	lvolume_private_t *priv = this->private;
	xlator_t *child = priv->local_xl;

	STACK_WIND (frame, lvolume_ftruncate_cbk, child, 
		    child->fops->ftruncate, fd, offset);

	return 0;
}
/**
 * lvolume_ioctl_cbk - 
 */
int32_t
lvolume_ioctl_cbk (call_frame_t *frame,
		 void *cookie,
		 xlator_t *this,
		 int32_t op_ret,
		 int32_t op_errno)
{
	STACK_UNWIND (frame, op_ret, op_errno);
	return 0;
}

/**
 * lvolume_ioctl - 
 */
int32_t
lvolume_ioctl (call_frame_t *frame,
	     xlator_t *this,
	     fd_t *fd,
	     uint32_t cmd,
	     uint64_t arg)
{
	lvolume_private_t *priv = this->private;
	xlator_t *child = priv->local_xl;

	STACK_WIND (frame, lvolume_ioctl_cbk, child, 
		    child->fops->ioctl, fd, cmd, arg);

	return 0;
}

/**
 * lvolume_unlink_cbk - 
 */
int32_t
lvolume_unlink_cbk (call_frame_t *frame, xlator_t *this)
{

	lvolume_local_t *local = NULL;
	int32_t op_ret, op_errno;
			 
	local = frame->local;
	op_ret = local->op_ret;
	op_errno = local->op_errno;
				 
	if (op_ret < 0) {
		hf_log (this->name, HF_LOG_ERROR,
			"%"PRId64": UNLINK  %s failed due to %s",
			frame->root->unique, local->loc->path, strerror(op_errno));
			 
	}

	frame->local = NULL;
	STACK_UNWIND (frame, op_ret, op_errno);
			 
	lvolume_local_wipe(local);

	return 0;
}

int32_t
lvolume_unlink_sync_md(call_frame_t *frame,
		  void *cookie,
		  xlator_t *this,
		  int32_t op_ret,
		  int32_t op_errno)
{
	lvolume_local_t *local = NULL;

	local = frame->local;
	local->op_ret = op_ret;
	local->op_errno = op_errno;
	
	if(op_ret < 0) {
		hf_log(this->name, HF_LOG_ERROR,
			"object %s unlink by %s failed due to %s",
			local->loc->path, this->name, strerror(op_errno));

		lvolume_unlink_cbk(frame, this);
		return 0;
	}

	lvolume_sync_object_metadata(frame, lvolume_unlink_cbk, HF_FOP_DELETEOBJECT);

	return 0;	
}

/**
 * lvolume_unlink - 
 */
int32_t
lvolume_unlink (call_frame_t *frame,
	      xlator_t *this,
	      loc_t *loc)
{
	lvolume_private_t *priv = this->private;
	xlator_t	*xl = priv->local_xl;
	lvolume_local_t *local = NULL;

	LTA_CHECK_OBJECT_CTX_AND_UNWIND_ON_ERR (loc);

	INIT_LOCAL(frame, local);
	local->loc = loc;

	STACK_WIND (frame, lvolume_unlink_sync_md, xl, xl->fops->unlink, local->loc);
	return 0;
}

/**
 * lvolume_fstat_cbk - 
 */
int32_t
lvolume_fstat_cbk (call_frame_t *frame,
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
 * lvolume_fstat - 
 */
int32_t
lvolume_fstat (call_frame_t *frame,
	     xlator_t *this,
	     fd_t *fd)
{
	lvolume_private_t *priv = this->private;
	xlator_t *child = priv->local_xl;

	STACK_WIND (frame,
		    lvolume_fstat_cbk,
		    child,
		    child->fops->fstat,
		    fd);

	return 0;
}

/**
 * lvolume_stat_cbk -
 */
int32_t
lvolume_stat_cbk (call_frame_t *frame, void *cookie, xlator_t *this,
                    int32_t op_ret, int32_t op_errno, struct stat *stbuf)
{
	lvolume_local_t *local = NULL;
	local = frame->local;
				 
	if (op_ret < 0) {
		hf_log (this->name, HF_LOG_ERROR,
			"%"PRId64": STAT  %s failed due to %s",
			frame->root->unique, local->loc->path, strerror(op_errno));
	}

	frame->local = NULL;
	STACK_UNWIND (frame, op_ret, op_errno, stbuf);
	lvolume_local_wipe(local);

	return 0;
}

/**
 * lvolume_stat - 
 */
int32_t
lvolume_stat(call_frame_t *frame,
	    xlator_t *this,
	    loc_t *loc)
{
	lvolume_private_t *priv = this->private;
	xlator_t *child = priv->local_xl;
	lvolume_local_t *local = NULL;

	LTA_CHECK_OBJECT_CTX_AND_UNWIND_ON_ERR (loc);

	INIT_LOCAL(frame, local);
	local->loc = loc;

	STACK_WIND (frame, lvolume_stat_cbk, child, child->fops->stat, local->loc);

	return 0;
}

/**
 * lvolume_truncate_cbk - 
 */
int32_t
lvolume_truncate_cbk(call_frame_t *frame,
		  void *cookie,
		  xlator_t *this,
		  int32_t op_ret,
		  int32_t op_errno,
		struct stat *stbuf)
{
	lvolume_local_t *local = NULL;

	local = frame->local;
	
	if(op_ret < 0) {
		hf_log(this->name, HF_LOG_ERROR,
			"object %s truncate by %s failed due to %s",
			local->loc->path, this->name, strerror(op_errno));

	}

	frame->local = NULL;
	STACK_UNWIND (frame, op_ret, op_errno, stbuf);
	lvolume_local_wipe(local);

	return 0;	
}

/**
 * lvolume_truncate - 
 */
int32_t
lvolume_truncate (call_frame_t *frame,
	xlator_t *this,
	loc_t *loc, off_t offset)
{
	lvolume_private_t *priv = this->private;
	xlator_t *child = priv->local_xl;
	lvolume_local_t *local = NULL;

	LTA_CHECK_OBJECT_CTX_AND_UNWIND_ON_ERR (loc);

	INIT_LOCAL(frame, local);
	local->loc = loc;

	STACK_WIND (frame, lvolume_truncate_cbk, child, child->fops->truncate, loc, offset);
	return 0;
}

/*
 *lvolume_setobject_cbk
 */
 int32_t
 lvolume_setobject_cbk(call_frame_t *frame, void *cookie, xlator_t *this,
 	int32_t op_ret, int32_t op_errno, int32_t status)
 {
 	STACK_UNWIND(frame, op_ret, op_errno, status);
	return 0;
 }
/**
 * lvolume_setobject - 
 */
int32_t
lvolume_setobject (call_frame_t * frame,
		xlator_t *this,
		char *path,
		int32_t islmdb,
		object_t *object)
{
	lvolume_private_t *priv = this->private;
		
	STACK_WIND(frame,
		lvolume_setobject_cbk,
		priv->ns_xl,
		priv->ns_xl->fops->setobject,
		path,
		islmdb,
		object);
	return 0;
}


/*
*lvolume_updateobject_cbk
*/
int32_t
lvolume_updateobject_cbk(call_frame_t *frame, void *cookie, xlator_t *this,
	int32_t op_ret, int32_t op_errno, int32_t status)
{
	STACK_UNWIND(frame, op_ret, op_errno, status);
	return 0;
}
/**
* lvolume_setobject - 
*/
int32_t
lvolume_updateobject (call_frame_t * frame,
		xlator_t *this,
		char *path,
		int32_t islmdb,
		int32_t updatebits,
		object_t *object)
{
	lvolume_private_t *priv = this->private;
			
	STACK_WIND(frame,
		lvolume_updateobject_cbk,
		priv->ns_xl,
		priv->ns_xl->fops->updateobject,
		path,
		islmdb,
		updatebits,
		object);
		return 0;
}

/*
 *lvolume_setobject_cbk
*/
int32_t
lvolume_getobject_cbk(call_frame_t *frame, void *cookie, xlator_t *this,
	int32_t op_ret, int32_t op_errno, object_t *object)
{
	STACK_UNWIND(frame, op_ret, op_errno, object);
	return 0;
}
/**
* lvolume_setobject - 
*/
int32_t
lvolume_getobject (call_frame_t * frame,
		xlator_t *this,
		char *path,
		int32_t islmdb,
		object_t *object)
{
	lvolume_private_t *priv = this->private;
			
	STACK_WIND(frame,
		lvolume_getobject_cbk,
		priv->ns_xl,
		priv->ns_xl->fops->getobject,
		path,
		islmdb,
		object);
	return 0;
}

/*
*lvolume_lookupobject_cbk
*/
int32_t
lvolume_lookupobject_cbk(call_frame_t *frame, void *cookie, xlator_t *this,
	int32_t op_ret, int32_t op_errno, object_t *object)
{
	STACK_UNWIND(frame, op_ret, op_errno, object);
	return 0;
}
/**
* lvolume_setobject - 
*/
int32_t
lvolume_lookupobject (call_frame_t * frame,
		xlator_t *this,
		char *path,
		int32_t islmdb,
		object_t *object)
{
	lvolume_private_t *priv = this->private;
			
	STACK_WIND(frame,
		lvolume_lookupobject_cbk,
		priv->ns_xl,
		priv->ns_xl->fops->lookupobject,
		path,
		islmdb,
		object);
	return 0;
}

/*
*lvolume_lookupobject_cbk
*/
int32_t
lvolume_deleteobject_cbk(call_frame_t *frame, void *cookie, xlator_t *this,
			int32_t op_ret, int32_t op_errno, int32_t status)
{
	STACK_UNWIND(frame, op_ret, op_errno, status);
	return 0;
}
/**
* lvolume_deleteobject - 
*/
int32_t
lvolume_deleteobject (call_frame_t * frame,
		xlator_t *this,
		char *path,
		int32_t islmdb,
		object_t *object)
{
	lvolume_private_t *priv = this->private;
					
	STACK_WIND(frame,
		lvolume_deleteobject_cbk,
		priv->ns_xl,
		priv->ns_xl->fops->deleteobject,
		path,
		islmdb,
		object);
	return 0;
}

/**
 * notify
 */
int32_t
notify (xlator_t *this,
        int32_t event,
        void *data,
        ...)
{
	default_notify (this, event, data);
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
	int32_t          count     = 0;
	int32_t       ret;
	char 		*ns_xl = NULL;
	xlator_list_t  	*trav      = NULL;
	xlator_t      	*x_trav      = NULL;
	lvolume_private_t *_private  = NULL; 

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
		count = 0;
		trav = this->children;
		/* Get the number of child count */
		while (trav) {
			count++;
			trav = trav->next;
		}
		if (count != 1) {
			hf_log (this->name, HF_LOG_CRITICAL, 
				"You have defined more than one "
				"\"subvolumes\" for lvolume volume. It may not "
				"be the desired config, review your volume "
				"volfile. If this is how you are testing it,"
				" you may hit some performance penalty");
			return -1;
		}
		_private->local_xl = this->children->xlator; 
		/* connect to global & local name server */
		ret = dict_get_str (this->options, "local-name-server", &ns_xl);
		if (ret < 0) {
			hf_log (this->name, HF_LOG_ERROR,
					"No value given for local name-server xlator");
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
					"No xlator named with %s", ns_xl);
			return -1;
		}

		LOCK_INIT (&_private->lock);
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
	lvolume_private_t *priv = this->private;
	this->private = NULL;
	LOCK_DESTROY (&priv->lock);

	FREE (priv);
	return;
}


struct xlator_fops fops = {
	.open        = lvolume_open,
	.readv	     = lvolume_readv,
	.writev      = lvolume_writev,
	.unlink      = lvolume_unlink,
	.stat        = lvolume_stat,
	.truncate    = lvolume_truncate,
	.fstat       = lvolume_fstat,
	.flush	     = lvolume_flush,
	.ftruncate   = lvolume_ftruncate,
	.setobject   = lvolume_setobject,
	.getobject   = lvolume_getobject,
	.updateobject   = lvolume_updateobject,
	.lookupobject = lvolume_lookupobject,
	.deleteobject = lvolume_deleteobject,
	.ioctl	     = lvolume_ioctl,
};

struct xlator_mops mops = {
};

struct xlator_cbks cbks = {
};

struct volume_options options[] = {
	{ .key   = {"local-name-server"},
		.type  = HF_OPTION_TYPE_XLATOR
	},
	{ .key   = {NULL} },
};

