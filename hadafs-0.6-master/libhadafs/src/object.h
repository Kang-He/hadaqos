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

#ifndef _OBJECT_H
#define _OBJECT_H

#ifndef _CONFIG_H
#define _CONFIG_H
#include "config.h"
#endif

#include <stdint.h>
#include <sys/types.h>

struct _object_table;
typedef struct _object_table object_table_t;

struct _object;
typedef struct _object object_t;

#include "list.h"
#include "xlator.h"

struct _object_table {
        pthread_mutex_t    lock;
        size_t             hashsize;    /* bucket size of object hash*/
        char              *name;        /* name of the object table, just for hf_log() */
        xlator_t          *xl;          /* xlator to be called to do purge */
        uint32_t           lru_limit;   /* maximum LRU cache size */
        struct list_head  *object_hash;  /* buckets for object hash table */
        uint32_t           object_count; /* count of objects in active list */
	uint64_t	   gen_ono;
};

//#define ZR_INODE_CTX_VALUE_LEN 2
struct _object_ctx {
	uint64_t key;
	uint64_t value;
};

typedef enum {
	OBJ_LOCALHOST, /* object locate in localhost of hadafs */
	OBJ_OTHERHOST, /* object locate in other host of hadafs */
} object_location_t;

typedef enum {
	OBJ_NOTEXIST,
	OBJ_NEWCREATED, /* object nonexist, newly created, most filed has no meaning */
	OBJ_DIRTY, /* object is dirty, and need to flush to storage */
	OBJ_STALE, /* object is stale, and need fresh from storage */
	OBJ_FRESH, /* object is fresh in memory */
	OBJ_CLOSE,
	OBJ_MOVED,/* object moved from hadafs */
	OBJ_UNLINK,/* object unlinked from hadafs */
	OBJ_ERROR,
} object_status_t;

typedef enum {
          ALL_ASYNC,
          PART_ASYNC,
          ALL_SYNC
} object_metadata_sync_mode_t;

struct metadata {
	char         	vmp[SHORT_NAME];
	char         	sid[SHORT_NAME];
	uint32_t     	soffset;
	int32_t         status;
	char		lhost[SHORT_NAME]; /* location host */
	uint64_t	lno; /* ino on local host file system*/
	char 		ppath[LONG_NAME];
	mode_t 		mode;
	uid_t		uid;
	gid_t 		gid;
	size_t 		size;
	time_t		ctime;
	time_t		mtime;
	time_t		atime; /* all above field store in database */
	//some value to set to ns
//	uint32_t     value_size;
//	char *value;
};

typedef struct metadata metadata_t;

struct _object {
	char		*path; /* unique ID */
	object_location_t  location;
	object_status_t status;
	object_metadata_sync_mode_t ms_mode;
	metadata_t  metadata;
	object_table_t    *table;         /* the table this object belongs to */
	hf_lock_t         lock;
        uint32_t          ref;           /* reference count on this object */
        dict_t           *ctx;           /* per xlator private */
        struct list_head  fd_list;       /* list of open files on this object */
        struct list_head  hash;          /* hash table pointers */
	uint64_t	ono; /* hash ID */

	struct _object_ctx *_ctx;    /* replacement for dict_t *(object->ctx) */
};

object_table_t *
object_table_new (size_t lru_limit, xlator_t *xl);

object_t *
object_new (object_table_t *table, char *path);

object_t *
object_search (object_table_t *table, const char *name);

object_t *
object_ref (object_t *object);

object_t *
object_unref (object_t *object);

int 
object_unlink (object_t *object);

int
object_link (object_t *object);

int
__object_ctx_put (object_t *object, xlator_t *xlator, uint64_t value);

int
object_ctx_put (object_t *object, xlator_t *xlator, uint64_t value);

int
__object_ctx_get (object_t *object, xlator_t *xlator, uint64_t *value);

int 
object_ctx_get (object_t *object, xlator_t *xlator, uint64_t *value);

int 
object_ctx_del (object_t *object, xlator_t *xlator, uint64_t *value);

//int
//object_path_hash_compute (const char *name, uint32_t *hash_p)

#endif /* _OBJECT_H */
