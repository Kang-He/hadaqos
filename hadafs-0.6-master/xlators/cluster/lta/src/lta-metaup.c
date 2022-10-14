/*
 *    Copyright (c) 2006-2009 HADA, Inc. <http://www.hada.com>
 *    This file is part of HADAFS.
 *
 *    HADAFS is free software; you can redistribute it and/or modify
 *    it under the terms of the GNU General Public License as published
 *    by the Free Software Foundation; either version 3 of the License,
 *    or (at your option) any later version.
 *
 *    HADAFS is distributed in the hope that it will be useful, but
 *    WITHOUT ANY WARRANTY; without even the implied warranty of
 *    MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the GNU
 *    General Public License for more details.
 *
 *    You should have received a copy of the GNU General Public License
 *    along with this program.  If not, see
 *    <http://www.gnu.org/licenses/>.
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
#include "call-stub.h"
#include "defaults.h"
#include "list.h"
#include "dict.h"
#include "object.h"
#include "compat.h"
#include "compat-errno.h"
#include "lta.h"

lta_obj_t *
lta_metaup_add_openfd(lta_obj_t *lobj, xlator_t *xl)
{
	lta_private_t *priv = xl->private;

	struct lta_metaup_worker_arg  *worker = priv->update_worker;	
	if (!lobj) {
		hf_log ("lta-meta-updater", HF_LOG_ERROR, "openfd is NULL");
		return NULL;
	}

	LOCK (&worker->lock);
	{
		list_add (&lobj->meta_list, &worker->openobjs);
		worker->obj_count++;
	}
	UNLOCK (&worker->lock);

	return lobj;
}

void
lta_metaup_local_wipe(lta_local_t *local)
{
	loc_t *loc = local->loc;
	if(loc) {
		object_unref(loc->object);
		FREE(loc->path);
	}
	FREE(loc);
	LOCAL_WIPE(local);
}
int32_t
lta_metaup_setobject_cbk(call_frame_t *frame, void *cookie, xlator_t *this,
	int32_t op_ret, int32_t op_errno, int32_t status)
{
	lta_local_t *local = NULL;	
	object_t *object = NULL;

	object = local->object;
	LTA_OBJECT_SET_STATUS(object, OBJ_FRESH);
	
	frame->local = NULL;
	STACK_DESTROY (frame->root);

	LOCAL_WIPE(local);

	return 0;
}
int32_t
lta_metaup_setobject(lta_obj_t *lobj, xlator_t *xl)
{
	call_frame_t *frame;
	lta_local_t *local;
	object_t *object = lobj->object;
	lta_private_t *priv = xl->private;
	
	INIT_LOCAL(frame, local);
	local->object = object;

	frame = create_frame(xl, xl->ctx->pool);

	STACK_WIND(frame,
		lta_metaup_setobject_cbk,
		priv->ns_xl,
		priv->ns_xl->fops->setobject,
		object->path, 0, object);

	return 0;
}
int
lta_metaup_updateobject_cbk(call_frame_t *frame, void *cookie, xlator_t *this,
	int32_t op_ret, int32_t op_errno, int32_t status)
{
	lta_local_t *local;

	local = frame->local;
	if(op_ret < 0) {
		hf_log ("lta-meta-updater", HF_LOG_ERROR,
			"updateobject %s failed %s",
			local->object->path, strerror(op_errno));
		LTA_OBJECT_SET_STATUS(local->object, OBJ_ERROR);
	} else {
		hf_log ("lta-meta-updater", HF_LOG_TRACE,
			"updateobject %s success",
			local->object->path, strerror(op_errno));
		LTA_OBJECT_SET_STATUS(local->object, OBJ_FRESH);
	}

	
	frame->local = NULL;
	STACK_DESTROY (frame->root);
	lta_metaup_local_wipe(local);

	return 0;
}

int
lta_metaup_stat_cbk(call_frame_t *frame, void *cookie, xlator_t *this,
		int32_t op_ret, int32_t op_errno, struct stat *buf)
{
	lta_private_t       *priv = NULL;
	lta_local_t 	    *local = NULL;
	object_t	    *object;	
	int ret = 0, updatebits = 0;

	priv = this->private;
	local = frame->local;
	object = local->object;

	if (op_ret >= 0) {
		hf_log ("lta-meta-updater", HF_LOG_TRACE,
			"update_fstat  %s success", object->path);

		object->metadata.size = buf->st_size;
		object->metadata.ctime = buf->st_ctime;
		object->metadata.mtime = buf->st_mtime;
		object->metadata.atime = buf->st_atime;

		updatebits=UPDATE_SIZE|UPDATE_MTIME|UPDATE_ATIME|UPDATE_CTIME;	
		STACK_WIND(frame,
			lta_metaup_updateobject_cbk,
			priv->ns_xl,
			priv->ns_xl->fops->updateobject,
			object->path, 0, updatebits,
			object);
		return 0;

	} else {
		hf_log ("lta-meta-updater", HF_LOG_ERROR,
			"%"PRId64": update_fstat  %s (%"PRId64") failed %s",
			frame->root->unique, object->path, buf->st_ino, strerror(op_errno));
		frame->local = NULL;
		STACK_DESTROY (frame->root);
		lta_metaup_local_wipe(local);
		return -1;
	} 

}

int
lta_metaup_stat(lta_obj_t *lobj, struct lta_metaup_worker_arg  *worker)
{
	lta_local_t *local = NULL;
	call_frame_t *frame = NULL;
	xlator_t *this = worker->xlator;
	lta_private_t *priv = NULL;
	int32_t ret = 0;

	frame = create_frame (this, this->ctx->pool);
	HF_VALIDATE_OR_GOTO("lta_meta_updater", frame, out);
	priv = this->private;

	local = CALLOC(1, sizeof(lta_local_t));
	HF_VALIDATE_OR_GOTO("lta_meta_updater", local, out);
	frame->local = local;
	local->op_ret1 = -1;
	local->op_errno1 = 0;
	local->op_ret2 = -1;
	local->op_errno2 = 0;
	local->object = lobj->object;	

	local->loc = CALLOC(1, sizeof(loc_t));
	HF_VALIDATE_OR_GOTO("lta_meta_updater", local->loc, out);
	local->loc->object = object_ref(lobj->object);
	local->loc->path = strdup(lobj->object->path);
	strcpy(local->loc->sid, strdup(priv->local_xl->name));
	local->loc->soffset = lobj->object->metadata.soffset;

	STACK_WIND (frame, lta_metaup_stat_cbk,
		priv->local_xl,
		priv->local_xl->fops->stat,
		local->loc);
	return 0;
out:
	if(frame)
		STACK_DESTROY (frame->root);
	if(local->loc)
		FREE(local->loc);
	if(local)
		FREE(local);
	return -1;
}

int32_t
lta_metaup_deleteobject_cbk(call_frame_t *frame, void *cookie, xlator_t *this,
	int32_t op_ret, int32_t op_errno, int32_t status)
{
	lta_local_t *local = NULL;
	object_t *object = NULL;

	local = frame->local;
	object = local->object;
	if(op_ret < 0)
			hf_log ("lta-meta-updater", HF_LOG_ERROR,
					"update_delete %s failed %d %s", object->path,
					op_ret, strerror(op_errno));
	else
			hf_log ("lta-meta-updater", HF_LOG_TRACE,
					"update_delete %s success", object->path);

	frame->local = NULL;
	STACK_DESTROY (frame->root);
	object_unref(local->object);
	LOCAL_WIPE(local);

	return 0;
}

int32_t
lta_metaup_deleteobject(lta_obj_t *lobj, xlator_t *xl)
{
	call_frame_t *frame;
	lta_local_t *local = NULL;

	object_t *object = lobj->object;
	lta_private_t *priv = xl->private;
	frame = create_frame (xl, xl->ctx->pool);
	INIT_LOCAL(frame, local);
	local->object = object_ref(object);

	STACK_WIND(frame,
		lta_metaup_deleteobject_cbk,
		priv->ns_xl,
		priv->ns_xl->fops->deleteobject,
		object->path, 0, object);

	return 0;
}

void lta_metaup_scan_openfd( struct lta_metaup_worker_arg  *worker)
{

	struct list_head list_tmp;
	struct list_head list_nouse;
	xlator_t *this = worker->xlator;
	lta_obj_t *lobj = NULL;
	lta_obj_t *tmp = NULL;

	INIT_LIST_HEAD(&list_tmp);
	INIT_LIST_HEAD(&list_nouse);


	LOCK (&worker->lock);
	if (!list_empty (&worker->openobjs)) {
		list_for_each_entry_safe (lobj, tmp, &worker->openobjs, meta_list) {
			if(lobj->object->status == OBJ_MOVED || 
				lobj->object->status == OBJ_UNLINK ||
				lobj->object->status == OBJ_CLOSE) {
				list_del_init(&lobj->meta_list);
				list_add_tail(&lobj->meta_list, &list_nouse);
				worker->obj_count--;
			} else 
				list_add_tail(&lobj->update_list, &list_tmp);
		}
	} else {
		UNLOCK (&worker->lock);
		return;
	}
	UNLOCK (&worker->lock);

	/* update all list_tmp entries */
	if (!list_empty (&list_tmp)) {
		list_for_each_entry_safe (lobj, tmp, &list_tmp, update_list) {
			switch(lobj->object->status) 
			{
				case OBJ_NEWCREATED:
					lta_metaup_setobject(lobj, this);
					break;
				case OBJ_FRESH:
					break;
				case OBJ_DIRTY:
					lta_metaup_stat(lobj, worker);
					break;
				default:
					hf_log("lta-metaup",HF_LOG_ERROR, "fdstat is unkown,what happend???"); 
					break;

			}
			list_del_init(&lobj->update_list);
		}
	}
	/* delete all list_tmp entries */
	if (!list_empty (&list_nouse)) {
		list_for_each_entry_safe (lobj, tmp, &list_nouse, meta_list) {
			switch(lobj->object->status) 
			{
				case OBJ_UNLINK:
					hf_log("server-update", HF_LOG_TRACE,
						"UNLINKED lobject %s saddr_object %p:%p",
						lobj->object->path, lobj, lobj->object);
					lta_metaup_deleteobject(lobj, this);
					break;
				case OBJ_MOVED:
					hf_log("server-update", HF_LOG_TRACE,
						"MOVED lobject %s saddr_object %p:%p",
						lobj->object->path, lobj, lobj->object);
					lta_metaup_deleteobject(lobj, this);
					break;
				case OBJ_CLOSE:
					hf_log("server-update", HF_LOG_TRACE,
						"Closeing %s saddr_object %p:%p",
						lobj->object->path, lobj, lobj->object);
					lta_metaup_stat(lobj, worker);
					break;
			}
			list_del_init(&lobj->meta_list);
			list_del_init(&lobj->update_list);
			object_ctx_del(lobj->object, this, (uint64_t)(long)lobj);
			
			object_unref(lobj->object);
			FREE(lobj);
		}
	}

}

/*
 *  update all open objects metadate to global name server
 * 
 */
void *
lta_metaup_worker(void *data)
{
	struct timeval now;
	struct timespec timeout = {0,};

	struct lta_metaup_worker_arg *worker = data;
	worker->obj_count =0;

	INIT_LIST_HEAD(&worker->openobjs);

	for(;;){
#if 0
		gettimeofday(&now,NULL);
		timeout.tv_nsec = time(NULL) + 500000; 
		//tv_usec*1000000=tv_sec;
		//timeout.tv_sec = now.tv_sec + 1; 
		LOCK(&worker->lock);
		{
			pthread_cond_timedwait (&worker->cond, &worker->lock, &timeout);
		}
		UNLOCK(&worker->lock);
#endif
		usleep(800000);
		lta_metaup_scan_openfd(worker);
		continue;
	}
	pthread_exit(NULL);
}

int
lta_metaup_start(xlator_t *this, struct lta_metaup_worker_arg *worker ){

	int ret = 0;
	worker->xlator = this;
	LOCK_INIT( &worker->lock);
	pthread_cond_init (&worker->cond, NULL);

	ret = pthread_create (&worker->thread, NULL, lta_metaup_worker, worker);
	if (ret == 0) {
		hf_log ("lta-meta-updater", HF_LOG_DEBUG,
				"strared threads to update metadate");
	} else {
		free(worker);
	}

	return ret;
}
