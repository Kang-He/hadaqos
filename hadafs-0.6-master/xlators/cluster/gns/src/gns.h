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

#ifndef _GNS_H
#define _GNS_H

#include "list.h"
#include "xlator.h"

struct gns_private {
	int16_t child_count;
	int16_t num_child_up;
	xlator_t **children;
	char    *child_status;
	uint8_t is_up;
	hf_lock_t lock;
};
typedef struct gns_private gns_private_t;

#endif /* _GNS_H */
