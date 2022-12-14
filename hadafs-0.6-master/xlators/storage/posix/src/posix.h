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

#ifndef _POSIX_H
#define _POSIX_H

#ifndef _CONFIG_H
#define _CONFIG_H
#include "config.h"
#endif

#include <stdio.h>
#include <unistd.h>
#include <sys/types.h>
#include <dirent.h>

#ifdef linux
#ifdef __GLIBC__
#include <sys/fsuid.h>
#else
#include <unistd.h>
#endif
#endif

#ifdef HAVE_SYS_XATTR_H
#include <sys/xattr.h>
#endif

#ifdef HAVE_SYS_EXTATTR_H
#include <sys/extattr.h>
#endif

#include "xlator.h"
#include "object.h"
#include "compat.h"

#define DIR_NUM 32

/**
 * posix_fd - internal structure common to file and directory fd's
 */

struct posix_fd {
	int     fd;      /* fd returned by the kernel */
	int32_t flags;   /* flags for open/creat      */
	mode_t mode;     /* mode for creat            */
	char *  path;    /* used by setdents/getdents */
	 struct list_head list; /* to add to the janitor list */
};

struct posix_private {
	char   *base_path;
	int32_t base_path_length;
	char 	*local_address;

	hf_lock_t lock;

        /* Statistics, provides activity of the server */
	struct xlator_stats stats; 
  
	struct timeval prev_fetch_time;
	struct timeval init_time;

	time_t last_landfill_check;
       int32_t janitor_sleep_duration;
	struct list_head janitor_fds;
       pthread_cond_t janitor_cond;
       pthread_mutex_t janitor_lock;

	int32_t max_read;            /* */
	int32_t max_write;           /* */
	int64_t interval_read;      /* Used to calculate the max_read value */
	int64_t interval_write;     /* Used to calculate the max_write value */
	int64_t read_value;    /* Total read, from init */
	int64_t write_value;   /* Total write, from init */

/*
   In some cases, two exported volumes may reside on the same
   partition on the server. Sending statvfs info for both
   the volumes will lead to erroneous df output at the client,
   since free space on the partition will be counted twice.

   In such cases, user can disable exporting statvfs info
   on one of the volumes by setting this option.
*/
	hf_boolean_t    export_statfs;

	hf_boolean_t    o_direct;     /* always open files in O_DIRECT mode */

        hf_boolean_t    span_devices;

/* 
   decide whether posix_unlink does open (file), unlink (file), close (fd)
   instead of just unlink (file). with the former approach there is no lockout
   of access to parent directory during removal of very large files for the
   entire duration of freeing of data blocks.
*/ 
        hf_boolean_t    background_unlink;

        int             num_devices_to_span;
        dev_t          *st_device;

	/* janitor thread which cleans up /.trash (created by replicate) */
        pthread_t       janitor;
        hf_boolean_t    janitor_present;
        char *          trash_path;
	
};

#define POSIX_BASE_PATH(this) (((struct posix_private *)this->private)->base_path)

#define POSIX_BASE_PATH_LEN(this) (((struct posix_private *)this->private)->base_path_length)

#define MAKE_REAL_PATH(var, this, object) do {                            \
		int i;\
		object_t *otmp = object;\
		sprintf(var, "%s/d%d/%s", POSIX_BASE_PATH(this), otmp->ono%DIR_NUM, otmp->path); \
		for(i = strlen(var)-strlen(otmp->path);i < strlen(var); i++) 	\
			if(var[i] == '/') 				\
				var[i] = '_';				\
        } while (0)
#endif /* _POSIX_H */
