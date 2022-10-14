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

#ifndef _CONFIG_H
#define _CONFIG_H
#include "config.h"
#endif

#ifndef _ROCKSDB_H
#define _ROCKSDB_H

#include "list.h"
#include "xlator.h"


struct rdb_private {
	int32_t max_read; 		   /* */
	int32_t max_write;		   /* */
	int64_t interval_read;	  /* Used to calculate the max_read value */
	int64_t interval_write;	  /* Used to calculate the max_write value */
	int64_t read_value;	 /* Total read, from init */
	int64_t write_value;	 /* Total write, from init */

	hf_lock_t lock;
	ns_context_t *rdc;
};
typedef struct rdb_private rdb_private_t;

#endif /* _ROCKSDB_H */

