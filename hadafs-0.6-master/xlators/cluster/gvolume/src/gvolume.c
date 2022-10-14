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
 * xlators/cluster/gvolume:
 *     - This xlator is one of the main translator in hadafs, which
 *   actually does the clustering work of the file system. One need to 
 *   understand that, gvolume assumes file to be existing in only one of 
 *   the child node, and directories to be present on all the nodes. 
 *
 * NOTE:
 *   Now, gvolume has support for global namespace, which is used to keep a 
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

#include "gvolume.h"
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

#define GVOLUME_CHECK_OBJECT_CTX_AND_UNWIND_ON_ERR(_loc) do { \
  if (!(_loc && _loc->object)) {                            \
    STACK_UNWIND (frame, -1, EINVAL, NULL, NULL, NULL);    \
    return 0;                                              \
  }                                                        \
} while(0)


#define GVOLUME_CHECK_FD_CTX_AND_UNWIND_ON_ERR(_fd) do { \
  if (!(_fd && !fd_ctx_get (_fd, this, NULL))) {       \
    STACK_UNWIND (frame, -1, EBADFD, NULL, NULL);      \
    return 0;                                          \
  }                                                    \
} while(0)

#define GVOLUME_CHECK_FD_AND_UNWIND_ON_ERR(_fd) do { \
  if (!_fd) {                                      \
    STACK_UNWIND (frame, -1, EBADFD, NULL, NULL);  \
    return 0;                                      \
  }                                                \
} while(0)

/**
 * gvolume_open_cbk -
 */
int32_t
gvolume_open_cbk (call_frame_t *frame, void *cookie, xlator_t *this,
        int32_t op_ret, int32_t op_errno,
        fd_t *fd, object_t *object, struct stat *stbuf)
{

	gvolume_local_t *local = NULL;
	loc_t *loc = NULL;

	local = frame->local;
	loc = local->loc;

	if (op_ret < 0) {
		hf_log (this->name, HF_LOG_ERROR,
			"%"PRId64": OPEN  %s failed: %s",
			frame->root->unique, loc->path, strerror(op_errno));
	} 
	
	frame->local = NULL;
	STACK_UNWIND (frame, op_ret, op_errno, fd, object, stbuf);

	FREE(local);
	return 0;
}

int32_t
gvolume_open (call_frame_t *frame,
	    xlator_t *this,
	    loc_t *loc,
	    int32_t flags,
	    mode_t mode,
	    fd_t *fd)
{
	gvolume_private_t *priv = this->private;
	gvolume_local_t *local = NULL;
	xlator_t *xl = NULL;
	object_t *object = NULL;
	void *tmp = NULL;
	int32_t op_ret, op_errno;

	GVOLUME_CHECK_OBJECT_CTX_AND_UNWIND_ON_ERR (loc);

	priv = this->private;
	object = loc->object;
	INIT_LOCAL(frame, local);
	local->loc = loc;

	op_ret = dict_get_ptr (priv->xl_array, object->metadata.lhost, &tmp);
	if( op_ret != 0 ){
		hf_log (this->name, HF_LOG_ERROR, "%s:gvolume can't find right child xlator by %s", 
				object->path, object->metadata.lhost);
		op_ret = -1;
		op_errno = EINVAL;
		goto err;
	}
	xl = (xlator_t *)tmp;

	//tell xl that this is a forwarded request
	strcpy(loc->sid, strdup(xl->name));

	fd_ctx_set (fd, this, (uint64_t)(long)xl); 
	STACK_WIND (frame,
		gvolume_open_cbk, 
		xl, xl->fops->open, 
		loc, 
		flags, 
		mode,
		fd);
	return 0;	
err:
	gvolume_open_cbk (frame, NULL, this,
        	op_ret, op_errno, NULL, NULL, NULL);
	return 0;
}

/**
 * gvolume_readv_cbk - 
 */
int32_t
gvolume_readv_cbk (call_frame_t *frame,
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
 * gvolume_readv - 
 */
int32_t
gvolume_readv (call_frame_t *frame,
	     xlator_t *this,
	     fd_t *fd,
	     size_t size,
	     off_t offset)
{
	GVOLUME_CHECK_FD_CTX_AND_UNWIND_ON_ERR (fd);
	xlator_t *child = NULL;
	uint64_t tmp_child = 0;

	fd_ctx_get (fd, this, &tmp_child);
	child = (xlator_t *)(long)tmp_child;
	if(!child)
	{
		hf_log (this->name, HF_LOG_ERROR, "gvolume get child xlator failed");
		STACK_UNWIND (frame, -1, EINVAL, NULL, 1, NULL, NULL);
		return 0;
	}

	STACK_WIND (frame,
		    gvolume_readv_cbk,
		    child,
		    child->fops->readv,
		    fd,
		    size,
		    offset);

	return 0;
}

/**
 * gvolume_writev_cbk - 
 */
int32_t
gvolume_writev_cbk (call_frame_t *frame,
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
 * gvolume_writev - 
 */
int32_t
gvolume_writev (call_frame_t *frame,
	      xlator_t *this,
	      fd_t *fd,
	      struct iovec *vector,
	      int32_t count,
	      off_t off,
          struct iobref *iobref)
{
	GVOLUME_CHECK_FD_CTX_AND_UNWIND_ON_ERR (fd);
	xlator_t *child = NULL;
	uint64_t tmp_child = 0;

	fd_ctx_get (fd, this, &tmp_child);
	child = (xlator_t *)(long)tmp_child;	
	if(!child)
	{
		hf_log (this->name, HF_LOG_ERROR, "gvolume get child xlator failed");
		STACK_UNWIND (frame, -1, EINVAL, NULL);
		return 0;
	}

	STACK_WIND (frame,
		    gvolume_writev_cbk,
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
 * gvolume_flush_cbk - 
 */
int32_t
gvolume_flush_cbk (call_frame_t *frame,
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
 * gvolume_flush -
 */
int32_t
gvolume_flush (call_frame_t *frame,
	     xlator_t *this,
	     fd_t *fd)
{
	GVOLUME_CHECK_FD_CTX_AND_UNWIND_ON_ERR (fd);
	xlator_t *child = NULL;
	uint64_t tmp_child = 0;

	fd_ctx_get (fd, this, &tmp_child);
	child = (xlator_t *)(long)tmp_child;		
	if(!child)
	{
		hf_log (this->name, HF_LOG_ERROR, "gvolume get child xlator failed");
		STACK_UNWIND (frame, -1, EINVAL);
		return 0;
	}


	STACK_WIND (frame, gvolume_flush_cbk, child, 
		    child->fops->flush, fd);

	return 0;
}

/**
 * gvolume_ftruncate_cbk - 
 */
int32_t
gvolume_ftruncate_cbk (call_frame_t *frame,
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
 * gvolume_ftruncate -
 */
int32_t
gvolume_ftruncate(call_frame_t *frame, 
		xlator_t *this,
		fd_t *fd,
		off_t offset)
{
	GVOLUME_CHECK_FD_CTX_AND_UNWIND_ON_ERR (fd);
	xlator_t *child = NULL;
	uint64_t tmp_child = 0;

	fd_ctx_get (fd, this, &tmp_child);
	child = (xlator_t *)(long)tmp_child;		
	if(!child)
	{
		hf_log (this->name, HF_LOG_ERROR, "gvolume get child xlator failed");
		STACK_UNWIND (frame, -1, EINVAL);
		return 0;
	}


	STACK_WIND (frame, gvolume_ftruncate_cbk, child, 
		    child->fops->ftruncate, fd, offset);

	return 0;
}
/**
 * gvolume_ioctl_cbk - 
 */
int32_t
gvolume_ioctl_cbk (call_frame_t *frame,
		 void *cookie,
		 xlator_t *this,
		 int32_t op_ret,
		 int32_t op_errno)
{
	STACK_UNWIND (frame, op_ret, op_errno);
	return 0;
}

/**
 * gvolume_ioctl - 
 */
int32_t
gvolume_ioctl (call_frame_t *frame,
	     xlator_t *this,
	     fd_t *fd,
	     uint32_t cmd,
	     uint64_t arg)
{
	GVOLUME_CHECK_FD_CTX_AND_UNWIND_ON_ERR (fd);
	xlator_t *child = NULL;
	uint64_t tmp_child = 0;

	fd_ctx_get (fd, this, &tmp_child);
	child = (xlator_t *)(long)tmp_child;		
	if(!child)
	{
		hf_log (this->name, HF_LOG_ERROR, "gvolume get child xlator failed");
		STACK_UNWIND (frame, -1, EINVAL);
		return 0;
	}

	STACK_WIND (frame, gvolume_ioctl_cbk, child, 
		    child->fops->ioctl, fd, cmd, arg);

	return 0;
}

int32_t
gvolume_unlink_cbk(call_frame_t *frame,
		  void *cookie,
		  xlator_t *this,
		  int32_t op_ret,
		  int32_t op_errno)
{
	gvolume_local_t *local = NULL;
	loc_t *loc = NULL;

	local = frame->local;
	loc = local->loc;

	op_ret = op_ret;
	op_errno = op_errno;
	if(op_ret < 0) {
		hf_log(this->name, HF_LOG_ERROR,
			"object %s unlink by %s failed due to %s",
			loc->path, this->name, strerror(op_errno));
	}

	STACK_UNWIND (frame, op_ret, op_errno);
	return 0;	
}

/**
 * gvolume_unlink - 
 */
int32_t
gvolume_unlink (call_frame_t *frame,
	      xlator_t *this,
	      loc_t *loc)
{
	gvolume_local_t *local = NULL;
	gvolume_private_t *priv = NULL;
	xlator_t *xl = NULL;
	object_t *object = NULL;
	void *tmp = NULL;
	int32_t op_ret, op_errno;

	GVOLUME_CHECK_OBJECT_CTX_AND_UNWIND_ON_ERR (loc);

	priv = this->private;
	INIT_LOCAL(frame, local);
	local->loc = loc;
	object = loc->object;
				  
	op_ret = dict_get_ptr (priv->xl_array, object->metadata.lhost, &tmp);
	if( op_ret != 0 ){
		hf_log (this->name, HF_LOG_ERROR, "%s:gvolume can't find right child xlator by %s", 
				object->path, object->metadata.lhost);
		op_ret = -1;
		op_errno = EINVAL;
		goto err;
	}
	xl = (xlator_t *)tmp;

	//tell xl that this is a forwarded request
	strcpy(loc->sid, strdup(xl->name));

	STACK_WIND (frame, gvolume_unlink_cbk, xl, xl->fops->unlink, loc);
	return 0;
err:
	gvolume_unlink_cbk (frame, NULL, this, op_ret, op_errno);
	return 0;

}

/**
 * gvolume_fstat_cbk - 
 */
int32_t
gvolume_fstat_cbk (call_frame_t *frame,
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
 * gvolume_fstat - 
 */
int32_t
gvolume_fstat (call_frame_t *frame,
	     xlator_t *this,
	     fd_t *fd)
{
	GVOLUME_CHECK_FD_CTX_AND_UNWIND_ON_ERR (fd);
	xlator_t *child = NULL;
	uint64_t tmp_child = 0;

	fd_ctx_get (fd, this, &tmp_child);
	child = (xlator_t *)(long)tmp_child;
	if(!child)
	{
		hf_log (this->name, HF_LOG_ERROR, "gvolume get child xlator failed");
		STACK_UNWIND (frame, -1, EINVAL, NULL);
		return 0;
	}

	STACK_WIND (frame,
		    gvolume_fstat_cbk,
		    child,
		    child->fops->fstat,
		    fd);

	return 0;
}

/**
 * gvolume_stat_cbk -
 */
int32_t
gvolume_stat_cbk (call_frame_t *frame, void *cookie, xlator_t *this,
                    int32_t op_ret, int32_t op_errno, struct stat *stbuf)
{
	gvolume_local_t *local = NULL;
	loc_t *loc = NULL;
			 
	local = frame->local;
	loc = local->loc;
	if (op_ret < 0) {
		hf_log (this->name, HF_LOG_ERROR,
			"%"PRId64": UNLINK  %s failed when delete metadata due to %s",
			frame->root->unique, loc->path, strerror(op_errno));
	}

	frame->local = NULL;
	STACK_UNWIND (frame, op_ret, op_errno, stbuf);
	FREE(local);

	return 0;
}

/**
 * gvolume_stat - 
 */
int32_t
gvolume_stat (call_frame_t *frame,
	    xlator_t *this,
	    loc_t *loc)
{
	gvolume_private_t *priv = NULL;
	gvolume_local_t *local = NULL;
	xlator_t *xl = NULL;
	object_t *object = NULL;
	void *tmp = NULL;
	int32_t op_ret, op_errno;

	INIT_LOCAL(frame, local);
	priv = this->private;
	local->loc = loc;
	object = local->loc->object;
				  
	op_ret = dict_get_ptr (priv->xl_array, object->metadata.lhost, &tmp);
	if( op_ret != 0 ){
		hf_log (this->name, HF_LOG_ERROR, "%s:gvolume can't find right child xlator by %s", 
				object->path, object->metadata.lhost);
		op_ret = -1;
		op_errno = EINVAL;
		goto err;
	}
	xl = (xlator_t *)tmp;

	//tell xl that this is a forwarded request
	strcpy(loc->sid, strdup(xl->name));

	STACK_WIND (frame, gvolume_stat_cbk, xl, xl->fops->stat, local->loc);
	return 0;
err:
	gvolume_stat_cbk(frame, NULL, this, op_ret, op_errno, NULL);
	return 0;
}

/**
 * gvolume_truncate_cbk - 
 */
int32_t
gvolume_truncate_cbk(call_frame_t *frame,
		  void *cookie,
		  xlator_t *this,
		  int32_t op_ret,
		  int32_t op_errno,
		struct stat *stbuf)
{	
	gvolume_local_t *local = NULL;
	loc_t *loc = NULL;

	local = frame->local;
	loc = local->loc;
	
	if(op_ret < 0) {
		hf_log(this->name, HF_LOG_ERROR,
			"object %s truncate by %s failed due to %s",
			loc->path, this->name, strerror(op_errno));

	}

	frame->local = NULL;
	STACK_UNWIND (frame, op_ret, op_errno, stbuf);
	FREE(local);
	
	return 0;	
}

/**
 * gvolume_truncate - 
 */
int32_t
gvolume_truncate (call_frame_t *frame,
	xlator_t *this,
	loc_t *loc, off_t offset)
{
	gvolume_private_t *priv = NULL;
	gvolume_local_t *local = NULL;
	xlator_t *xl = NULL;
	object_t *object = NULL;
	void *tmp = NULL;
	int32_t op_ret, op_errno;

	INIT_LOCAL(frame, local);
	priv = this->private;
	local->loc = loc;
	object = local->loc->object;
				  
	op_ret = dict_get_ptr (priv->xl_array, object->metadata.lhost, &tmp);
	if( op_ret != 0 ){
		hf_log (this->name, HF_LOG_ERROR, "%s:gvolume can't find right child xlator by %s", 
				object->path, object->metadata.lhost);
		op_ret = -1;
		op_errno = EINVAL;
		goto err;
	}
	xl = (xlator_t *)tmp;

	//tell xl that this is a forwarded request
	strcpy(loc->sid, strdup(xl->name));

	hf_log (this->name, HF_LOG_DEBUG, "gvolume will send truncate %s to xlator:%s",
		local->loc->path, xl->name);

	STACK_WIND (frame, gvolume_truncate_cbk, xl, xl->fops->truncate, local->loc, local->offset);
	return 0;
err:
	gvolume_truncate_cbk(frame, NULL, this, op_ret, op_errno, NULL);
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
	uint32_t i = 0;
	xlator_t *trav = NULL;
	xlator_t *child = (xlator_t *)data;

	gvolume_private_t *priv = this->private;
	
	if (!priv) {
		return 0;
	}

	trav = this->children;
	/* Get the number of child count */
	while (trav) {
		if(trav == child)
			break;
		i++;
		trav = trav->next;
	}
	switch (event)
	{
		case HF_EVENT_CHILD_UP:
		{
			LOCK (&priv->lock);
			{
				/* Increment the inode's generation, which is 
				   used for self_heal */
				++priv->num_child_up;
				priv->child_status[i] = 1;
			}
			UNLOCK (&priv->lock);


			if (priv->num_child_up == priv->child_count) {
				default_notify (this, event, data);
				priv->is_up = 1;
			}
		}
		break;
		case HF_EVENT_CHILD_DOWN:
		{
			LOCK (&priv->lock);
			{
				--priv->num_child_up;
				priv->child_status[i] = 0;
			}
			UNLOCK (&priv->lock);

			default_notify (this, event, data);
		}
		break;

		default:
		{
			default_notify (this, event, data);
		}
		break;
	}

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
	int32_t 	 i  = 0;
	xlator_list_t      	*trav      = NULL;
	gvolume_private_t *_private  = NULL; 

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
		
		hf_log (this->name, HF_LOG_DEBUG, 
			"Child node count is %d", count);    

		_private->child_count = count;
		if (count == 1) {
			/* TODO: Should I error out here? */
			hf_log (this->name, HF_LOG_CRITICAL, 
				"WARNING: You have defined only one "
				"\"subvolumes\" for gvolume volume. It may not "
				"be the desired config, review your volume "
				"volfile. If this is how you are testing it,"
				" you may hit some performance penalty");
		}
		_private->child_status = CALLOC (count, sizeof(char));
		if(_private->child_status == NULL) {
			hf_log (this->name, HF_LOG_ERROR, "Out of memory");
			return -1;
		}
		for(i = 0; i <  count; i++) {
			_private->child_status[i] = 0;
		}

		_private->xl_array = dict_new ();
		ERR_ABORT (_private->xl_array);

		trav = this->children;
		while (trav) {
			dict_set_ptr (_private->xl_array, trav->xlator->name, (void *)(trav->xlator));
			trav = trav->next;
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
	gvolume_private_t *priv = this->private;
	this->private = NULL;
	LOCK_DESTROY (&priv->lock);

	FREE (priv->child_status);
	FREE (priv->xl_array);
	FREE (priv);
	return;
}


struct xlator_fops fops = {
	.open        = gvolume_open,
	.readv	     = gvolume_readv,
	.writev      = gvolume_writev,
	.unlink      = gvolume_unlink,
	.stat        = gvolume_stat,
	.truncate    = gvolume_truncate,
	.fstat       = gvolume_fstat,
	.flush	     = gvolume_flush,
	.ftruncate   = gvolume_ftruncate,
	.ioctl	     = gvolume_ioctl,
};

struct xlator_mops mops = {
};

struct xlator_cbks cbks = {
};

struct volume_options options[] = {
	{ .key   = {NULL} },
};

