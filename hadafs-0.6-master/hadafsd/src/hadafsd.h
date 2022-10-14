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

#ifndef __HADAFSD_H__
#define __HADAFSD_H__

#ifndef _CONFIG_H
#define _CONFIG_H
#include "config.h"
#endif

#define DEFAULT_SERVER_VOLUME_FILE            CONFDIR "/hadafsd.vol"
#define DEFAULT_LOG_FILE_DIRECTORY            DATADIR "/log/hadafs"
#define DEFAULT_LOG_LEVEL                     HF_LOG_NORMAL

#define DEFAULT_EVENT_POOL_SIZE            16384

#define ARGP_SERVER_TYPE_GMDB_OPTION        "GMDB"
#define ARGP_SERVER_TYPE_LTA_OPTION        "LTA"

#define ARGP_LOG_LEVEL_NONE_OPTION        "NONE"
#define ARGP_LOG_LEVEL_TRACE_OPTION       "TRACE"
#define ARGP_LOG_LEVEL_CRITICAL_OPTION    "CRITICAL"
#define ARGP_LOG_LEVEL_ERROR_OPTION       "ERROR"
#define ARGP_LOG_LEVEL_WARNING_OPTION     "WARNING"
#define ARGP_LOG_LEVEL_NORMAL_OPTION      "NORMAL"
#define ARGP_LOG_LEVEL_DEBUG_OPTION       "DEBUG"

#define ENABLE_NO_DAEMON_MODE     1
#define ENABLE_DEBUG_MODE         1

#define ZR_MOUNTPOINT_OPT       "mountpoint"
#define ZR_ATTR_TIMEOUT_OPT     "attribute-timeout"
#define ZR_ENTRY_TIMEOUT_OPT    "entry-timeout"
#define ZR_DIRECT_IO_OPT        "direct-io-mode"
#define ZR_STRICT_VOLFILE_CHECK "strict-volfile-check"

enum argp_option_keys {
	ARGP_VOLUME_FILE_KEY = 'f', 
	ARGP_SERVER_TYPE_KEY = 't', 
	ARGP_SERVER_PORT_KEY = 'p', 
	ARGP_LOG_LEVEL_KEY = 'L', 
	ARGP_LOG_FILE_KEY = 'l', 
	ARGP_PID_FILE_KEY = 'P',
	ARGP_NO_DAEMON_KEY = 'N', 
	ARGP_RUN_ID_KEY = 'r', 
	ARGP_DEBUG_KEY = 133, 
	ARGP_VOLFILE_ID_KEY = 143, 
        ARGP_VOLFILE_CHECK_KEY = 144,
};

/* Moved here from fetch-spec.h */
FILE *fetch_spec (hadafs_ctx_t *ctx);
FILE *gen_volfile(char *confile, char *type, int port);

#endif /* __HADAFSD_H__ */
