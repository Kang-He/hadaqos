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
 * xlators/cluster/gns:
 *     - This xlator is one of the main translator in LWFS, which
 *   actually does the clustering work of the file system. One need to 
 *   understand that, gns assumes file to be existing in only one of 
 *   the child node, and directories to be present on all the nodes. 
 *
 * NOTE:
 *   Now, gns has support for global namespace, which is used to keep a 
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

#include "gns.h"
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

#define GNS_CHECK_OBJECT_AND_UNWIND_ON_ERR(_obj) do { \
  if (!_obj) {                            \
    STACK_UNWIND (frame, -1, EINVAL, NULL, NULL, NULL);    \
    return 0;                                              \
  }                                                        \
} while(0)

/*
 *gns_setobject_cbk
 */
 int32_t
 gns_setobject_cbk(call_frame_t *frame, void *cookie, xlator_t *this,
 	int32_t op_ret, int32_t op_errno, int32_t status)
 {
 	STACK_UNWIND(frame, op_ret, op_errno, status);
	return 0;
 }
/**
 * gns_setobject - 
 */
int32_t
gns_setobject (call_frame_t * frame,
		xlator_t *this,
		char *path,
		int32_t islmdb,
		object_t *object)
{
	gns_private_t *priv = this->private;
	
	GNS_CHECK_OBJECT_AND_UNWIND_ON_ERR(object);

	xlator_t *ns  = priv->children[object->ono%priv->child_count];

	hf_log(this->name, HF_LOG_TRACE, "setobject %s object %p",
		path, object);

	STACK_WIND(frame,
		gns_setobject_cbk,
		ns,
		ns->fops->setobject,
		path,
		islmdb,
		object);
	return 0;
}


/*
*gns_updateobject_cbk
*/
int32_t
gns_updateobject_cbk(call_frame_t *frame, void *cookie, xlator_t *this,
	int32_t op_ret, int32_t op_errno, int32_t status)
{
	STACK_UNWIND(frame, op_ret, op_errno, status);
	return 0;
}
/**
* gns_setobject - 
*/
int32_t
gns_updateobject (call_frame_t * frame,
		xlator_t *this,
		char *path,
		int32_t islmdb,
		int32_t updatebits,
		object_t *object)
{
	gns_private_t *priv = this->private;
	GNS_CHECK_OBJECT_AND_UNWIND_ON_ERR(object);
			
	xlator_t *ns  = priv->children[object->ono%priv->child_count];

	hf_log(this->name, HF_LOG_TRACE, "updateobject %s object %p",
		path, object);
				
	STACK_WIND(frame,
		gns_updateobject_cbk,
		ns,
		ns->fops->updateobject,
		path,
		islmdb,
		updatebits,
		object);
		return 0;
}

/*
 *gns_setobject_cbk
*/
int32_t
gns_getobject_cbk(call_frame_t *frame, void *cookie, xlator_t *this,
	int32_t op_ret, int32_t op_errno, object_t *object)
{
	STACK_UNWIND(frame, op_ret, op_errno, object);
	return 0;
}
/**
* gns_setobject - 
*/
int32_t
gns_getobject (call_frame_t * frame,
		xlator_t *this,
		char *path,
		int32_t islmdb,
		object_t *object)
{
	gns_private_t *priv = this->private;
	GNS_CHECK_OBJECT_AND_UNWIND_ON_ERR(object);
			
	xlator_t *ns  = priv->children[object->ono%priv->child_count];
	hf_log(this->name, HF_LOG_TRACE, "getobject %s object %p",
		path, object);
				
	STACK_WIND(frame,
		gns_getobject_cbk,
		ns,
		ns->fops->getobject,
		path,
		islmdb,
		object);
	return 0;
}

/*
*gns_lookupobject_cbk
*/
int32_t
gns_lookupobject_cbk(call_frame_t *frame, void *cookie, xlator_t *this,
	int32_t op_ret, int32_t op_errno, object_t *object)
{
	STACK_UNWIND(frame, op_ret, op_errno, object);
	return 0;
}
/**
* gns_setobject - 
*/
int32_t
gns_lookupobject (call_frame_t * frame,
		xlator_t *this,
		char *path,
		int32_t islmdb,
		object_t *object)
{
	gns_private_t *priv = this->private;
	GNS_CHECK_OBJECT_AND_UNWIND_ON_ERR(object);
			
	xlator_t *ns  = priv->children[object->ono%priv->child_count];

	hf_log(this->name, HF_LOG_TRACE, "lookupobject %s object %p",
		path, object);
				
	STACK_WIND(frame,
		gns_lookupobject_cbk,
		ns,
		ns->fops->lookupobject,
		path,
		islmdb,
		object);
	return 0;
}

/*
*gns_lookupobject_cbk
*/
int32_t
gns_deleteobject_cbk(call_frame_t *frame, void *cookie, xlator_t *this,
			int32_t op_ret, int32_t op_errno, int32_t status)
{
	STACK_UNWIND(frame, op_ret, op_errno, status);
	return 0;
}
/**
* gns_deleteobject - 
*/
int32_t
gns_deleteobject (call_frame_t * frame,
		xlator_t *this,
		char *path,
		int32_t islmdb,
		object_t *object)
{
	gns_private_t *priv = this->private;
	GNS_CHECK_OBJECT_AND_UNWIND_ON_ERR(object);
					
	xlator_t *ns  = priv->children[object->ono%priv->child_count];

	hf_log(this->name, HF_LOG_TRACE, "deleteobject %s object %p",
		path, object);

	STACK_WIND(frame,
		gns_deleteobject_cbk,
		ns,
		ns->fops->deleteobject,
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
	uint32_t i = 0;
	xlator_t *trav = NULL;
	xlator_t *child = (xlator_t *)data;

	gns_private_t *priv = this->private;
	
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

			/* Send CHILD_DOWN to upper layer */
			default_notify (this, event, data);
			priv->is_up = 0;
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
	int32_t       ret;
	xlator_list_t *trav      = NULL;
	gns_private_t *_private  = NULL; 

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
				"\"subvolumes\" for gns volume. It may not "
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
		_private->children = CALLOC(count, sizeof(xlator_t *));
		if(_private->children == NULL) {
			hf_log (this->name, HF_LOG_ERROR, "Out of memory");
			return -1;
		}
		i = 0;
		for(trav = this->children; trav; trav = trav->next) {
			_private->children[i++] = trav->xlator;	
		}

	}

	LOCK_INIT(&_private->lock);
	this->private = (void *)_private;

	return 0;
}

/** 
 * fini  - Free all the allocated memory 
 */
void
fini (xlator_t *this)
{
	gns_private_t *priv = this->private;
	this->private = NULL;

	LOCK_DESTROY(&priv->lock);
	FREE (priv->child_status);
	FREE (priv);
	return;
}


struct xlator_fops fops = {
	.setobject   = gns_setobject,
	.getobject   = gns_getobject,
	.updateobject   = gns_updateobject,
	.lookupobject = gns_lookupobject,
	.deleteobject = gns_deleteobject,
};

struct xlator_mops mops = {
};

struct xlator_cbks cbks = {
};

struct volume_options options[] = {
	{ .key   = {NULL} },
};

