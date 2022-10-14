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


#ifndef __LOGGING_H__
#define __LOGGING_H__

#ifndef _CONFIG_H
#define _CONFIG_H
#include "config.h"
#endif

#include <stdint.h>
#include <stdio.h>  

#define HF_PRI_FSBLK       PRId64
#define HF_PRI_BLKSIZE     "ld"
#if HF_LINUX_HOST_OS

#  if __WORDSIZE == 64
#    define HF_PRI_SIZET   "lu"
#    define HF_PRI_NLINK   "lu"
#  else
#    define HF_PRI_SIZET   "u"
#    define HF_PRI_NLINK   "u"
#  endif /* __WORDSIZE */

#elif HF_DARWIN_HOST_OS

/* Noticed that size_t and ino_t are different on OSX, need to fix the warnings */
#  define HF_PRI_SIZET     "lu"
#  define HF_PRI_NLINK     "u"

#  undef HF_PRI_FSBLK
#  define HF_PRI_FSBLK     "u"
 
#  undef HF_PRI_BLKSIZE
#  define HF_PRI_BLKSIZE   "u"

#  if __DARWIN_64_BIT_INO_T == 0
#    error '64 bit ino_t is must for HADAFS to work, Compile with "CFLAGS=-D__DARWIN_64_BIT_INO_T"'
#  endif /* __DARWIN_64_BIT_INO_T */

#else /* !LINUX && !DARWIN */

/* BSD and Solaris : Change as per testing there.. */
#  define HF_PRI_SIZET     "lu"
#  define HF_PRI_NLINK     "u"

#endif /* LINUX_OS */

#define HF_PRI_DEV         HF_PRI_FSBLK

typedef enum {
	HF_LOG_NONE,
	HF_LOG_CRITICAL,   /* fatal errors */
	HF_LOG_ERROR,      /* major failures (not necessarily fatal) */
	HF_LOG_WARNING,    /* info about normal operation */
	HF_LOG_INFO,       /* Normal information */
#define HF_LOG_NORMAL HF_LOG_INFO
	HF_LOG_DEBUG,      /* internal errors */
        HF_LOG_TRACE,      /* full trace of operation */
} hf_loglevel_t;

#define HF_LOG_MAX HF_LOG_DEBUG

extern hf_loglevel_t hf_log_loglevel;

#define hf_log(dom, levl, fmt...) do {					\
		if (levl <= hf_log_loglevel)				\
			_hf_log (dom, __FILE__, __FUNCTION__, __LINE__, \
				 levl, ##fmt);				\
		if (0) {						\
			printf (fmt);					\
		}							\
} while (0)

/* Log once in HF_UNIVERSAL_ANSWER times */
#define HF_LOG_OCCASIONALLY(var, args...) if (!(var++%HF_UNIVERSAL_ANSWER)) { \
                hf_log (args);                                                \
        }

#define TIMELOG(key) do{\
        struct timeval tv1;\
        gettimeofday(&tv1, NULL);\
        hf_log("debug", HF_LOG_NORMAL, "timelog %s %ld", \
                key, tv1.tv_sec * 1000000 + tv1.tv_usec);\
        }while(0)

			
void 
hf_log_logrotate (int signum);

int hf_log_init (const char *filename);
void hf_log_cleanup (void);

int
_hf_log (const char *domain, const char *file, const char *function,
	 int32_t line, hf_loglevel_t level, const char *fmt, ...);

void hf_log_lock (void);
void hf_log_unlock (void);

hf_loglevel_t 
hf_log_get_loglevel (void);
void 
hf_log_set_loglevel (hf_loglevel_t level);
void
hf_log_dump_backtrace (char *key);
long long usec(void);

#define HF_DEBUG(xl, format, args...) \
	hf_log ((xl)->name, HF_LOG_DEBUG, format, ##args)
#define HF_INFO(xl, format, args...) \
	hf_log ((xl)->name, HF_LOG_INFO, format, ##args)
#define HF_WARNING(xl, format, args...) \
	hf_log ((xl)->name, HF_LOG_WARNING, format, ##args)
#define HF_ERROR(xl, format, args...) \
	hf_log ((xl)->name, HF_LOG_ERROR, format, ##args)

#endif /* __LOGGING_H__ */
