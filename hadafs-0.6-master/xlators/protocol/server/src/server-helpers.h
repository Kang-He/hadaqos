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

#ifndef __SERVER_HELPERS_H__
#define __SERVER_HELPERS_H__

#define CALL_STATE(frame)   ((server_state_t *)frame->root->state)

#define BOUND_XL(frame)     ((xlator_t *) CALL_STATE(frame)->bound_xl)

#define TRANSPORT_FROM_FRAME(frame) ((transport_t *) CALL_STATE(frame)->trans)

#define SERVER_CONNECTION(frame)  \
	((server_connection_t *) TRANSPORT_FROM_FRAME(frame)->xl_private)

#define SERVER_CONF(frame) \
	((server_conf_t *)TRANSPORT_FROM_FRAME(frame)->xl->private)

#define TRANSPORT_FROM_XLATOR(this) ((((server_conf_t *)this->private))->trans)

#define INODE_LRU_LIMIT(this)						\
	(((server_conf_t *)(this->private))->inode_lru_limit)

#define IS_ROOT_INODE(inode) (inode == inode->table->root)

#define IS_NOT_ROOT(pathlen) ((pathlen > 2)? 1 : 0)

int32_t
server_loc_fill (loc_t *loc,
	 server_state_t *state,
  	 const char *path);

int32_t
server_fd_fill(fd_t *fd,
	call_frame_t *frame,
	const char *path);

char *
stat_to_str (struct stat *stbuf);

call_frame_t *
server_copy_frame (call_frame_t *frame);

void free_state (server_state_t *state);

void server_loc_wipe (loc_t *loc);
void get_posix_path(object_t *obj);

int32_t
hf_add_locker (struct _lock_table *table, const char *volume,
	       loc_t *loc,
	       fd_t *fd,
	       pid_t pid);

int32_t
hf_del_locker (struct _lock_table *table, const char *volume,
	       loc_t *loc,
	       fd_t *fd,
	       pid_t pid);

#endif /* __SERVER_HELPERS_H__ */
