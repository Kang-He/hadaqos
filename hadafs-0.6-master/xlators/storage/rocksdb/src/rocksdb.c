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
 * xlators/cluster/rdb:
 *     - This xlator is one of the main translator in LWFS, which
 *   actually does the clustering work of the file system. One need to 
 *   understand that, rdb assumes file to be existing in only one of 
 *   the child node, and directories to be present on all the nodes. 
 *
 * NOTE:
 *   Now, rdb has support for global namespace, which is used to keep a 
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

#include <signal.h>
#include <libgen.h>

#include "dict.h"
#include "xlator.h"
#include "logging.h"
#include "stack.h"
#include "defaults.h"
#include "common-utils.h"
#include "compat-errno.h"
#include "compat.h"
#include "name-server.h"

#include "rocksdb.h"

#define RDB_CHECK_OBJECT_AND_UNWIND_ON_ERR(object) do { \
  if (!object) {                            \
    STACK_UNWIND (frame, -1, EINVAL, NULL, NULL, NULL);    \
    return 0;                                              \
  }                                                        \
} while(0)


/**
 * rdb_setobject
 */
int32_t
rdb_setobject (call_frame_t *frame, xlator_t *this,
        char *path, int32_t islmdb, object_t *object)
{
	rdb_private_t *priv = this->private;
	int32_t op_ret = -1, op_errno = 0;
	int32_t status = 0;
	char *err;
	
	RDB_CHECK_OBJECT_AND_UNWIND_ON_ERR(object);

	hf_log(this->name, HF_LOG_TRACE, "setobject: %s %p",
		object->path, object);

	op_ret = ns_setobject(priv->rdc, object, &err);
	if(op_ret < 0) {
		hf_log(this->name, HF_LOG_ERROR, "set object %s to rocksdb failed %s",
			object->path, err);
		op_errno = errno;
		status = -1;
	}

	STACK_UNWIND (frame, op_ret, op_errno, status);

	return 0;
}

/*
 * rdb_updateobject
 */
int32_t
rdb_updateobject (call_frame_t *frame, xlator_t *this,
	char *path, int32_t islmdb, int32_t updatebits, object_t *object)
{
	 rdb_private_t *priv = this->private;
	 int32_t op_ret = -1, op_errno = 0;
	 int32_t status = 0;
	 char *err = NULL;
	 RDB_CHECK_OBJECT_AND_UNWIND_ON_ERR(object);

	hf_log(this->name, HF_LOG_TRACE, "updateobject: %s %p",
		object->path, object);
	op_ret = ns_updateobject(priv->rdc, object, updatebits, &err);
	if(op_ret < 0) {
		hf_log(this->name, HF_LOG_ERROR, "update object %s to rocksdb failed %s",
			object->path, err);
		op_errno = errno;
		status = -1;
	}

	STACK_UNWIND (frame, op_ret, op_errno, status);					   				   
	return 0;
}

/**
* rdb_updateobject
*/
int32_t
rdb_getobject (call_frame_t *frame, xlator_t *this,
	char *path, int32_t islmdb, object_t *object)
{
	rdb_private_t *priv = this->private;
	int32_t op_ret = -1, op_errno = 0;
	char *err = NULL;
	
	RDB_CHECK_OBJECT_AND_UNWIND_ON_ERR(object);	
	
	hf_log(this->name, HF_LOG_TRACE, "getobject: %s %p",
		object->path, object);
	op_ret = ns_getobject(priv->rdc, object, &err);
	if(op_ret < 0) {
		hf_log(this->name, HF_LOG_ERROR, "set object %s to rocksdb failed %s",
			object->path, err);
		op_errno = errno;
	}

	STACK_UNWIND (frame, op_ret, op_errno, object);								   

	return 0;
}


/**
 * rdb_lookupobject - 
 */
int32_t
rdb_lookupobject (call_frame_t *frame, xlator_t *this,
	char *path, int32_t islmdb, object_t *object)
{
	rdb_private_t *priv = this->private;
	int op_ret = -1, op_errno =-1;
	char *err = NULL;
	
	RDB_CHECK_OBJECT_AND_UNWIND_ON_ERR(object);

	hf_log(this->name, HF_LOG_TRACE, "lookupobject: %s %p",
		object->path, object);
	op_ret = ns_lookupobject(priv->rdc, object, &err);
	if(op_ret < 0) {
		hf_log(this->name, HF_LOG_ERROR, "set object %s to rocksdb failed %s",
			object->path, err);
		op_errno = errno;
	}

	STACK_UNWIND (frame, op_ret, op_errno, object);								   	

	return 0;
}

/**
 * rdb_lookupobject - 
 */
int32_t
rdb_deleteobject (call_frame_t *frame,
	xlator_t *this,
	char *path,
	int32_t islmdb,
	object_t *object)
{
	rdb_private_t *priv = this->private;
	int op_ret = -1, op_errno =-1;
	int32_t status = 0;
	char *err = NULL;
		
	RDB_CHECK_OBJECT_AND_UNWIND_ON_ERR(object);

	hf_log(this->name, HF_LOG_TRACE, "delteobject: %s %p",
		path, object);

	op_ret = ns_deleteobject(priv->rdc, path, &err);
	if(op_ret < 0) {
		hf_log(this->name, HF_LOG_ERROR, "set object %s to rocksdb failed %s",
			path, err);
		op_errno = errno;
		status = -1;
	}

	STACK_UNWIND (frame, op_ret, op_errno, status);								   	
		
	return 0;
}

/**
 * notify - when parent sends PARENT_UP, send CHILD_UP event from here
 */
int32_t
notify (xlator_t *this,
		int32_t event,
		void *data,
		...)
{
	switch (event)
	{
		case HF_EVENT_PARENT_UP:
			{
				/* Tell the parent that posix xlator is up */
				default_notify (this, HF_EVENT_CHILD_UP, data);
			}
			break;
		default:
			/* */
			break;
	}
	return 0;
}

/** 
 * init - This function is called first in the xlator, while initializing.
 *   All the config file options are checked and appropriate flags are set.
 *
 * @this - 
 */
int32_t 
init (xlator_t *this)
{
	int32_t      ret = -1, lport;
	rdb_private_t *_private  = NULL; 
	data_t 		*lpath_data  = NULL;	

  	if (!this->parents) {
		hf_log (this->name, HF_LOG_WARNING,
			"dangling volume. check volfile ");
	}
	
	_private = CALLOC (1, sizeof (*_private));
	ERR_ABORT (_private);
	
	/* update _private structure */
	{
		/* connect to global & local name server */
		lpath_data = dict_get (this->options, "rocksdb-path");
		if (!lpath_data) {
			hf_log (this->name, HF_LOG_ERROR,
					"wrong value for local rocksdb path");
				return -1;
		}
		ret = dict_get_int32(this->options, "rocksdb-port", &lport);
		if(ret < 0) {
			hf_log(this->name, HF_LOG_ERROR,
				"wrong value for local rocksdb port");
			return -1;
		}
		_private->rdc = ns_connect(lpath_data->data, lport);
		if(_private->rdc == NULL) {
			hf_log (this->name, HF_LOG_ERROR,
				"connect to rocksdb failed");
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
	rdb_private_t *priv = this->private;
	this->private = NULL;
	LOCK_DESTROY (&priv->lock);

	FREE (priv);
	return;
}


struct xlator_fops fops = {
	.setobject        = rdb_setobject,
	.updateobject	  = rdb_updateobject,
	.getobject        = rdb_getobject,
	.lookupobject     = rdb_lookupobject,
	.deleteobject     = rdb_deleteobject,
};

struct xlator_mops mops = {
};

struct xlator_cbks cbks = {
};

struct volume_options options[] = {
	{ .key	 = {"rocksdb-port"},
		.type  = HF_OPTION_TYPE_INT
	},
	{ .key   = {"rocksdb-path"}, 
	  .type  = HF_OPTION_TYPE_PATH
	},
	{ .key   = {NULL} },
};

