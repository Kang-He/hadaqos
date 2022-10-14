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

#ifndef _CONFIG_H
#define _CONFIG_H
#include "config.h"
#endif

#include <errno.h>
#include <pthread.h>
#include <stdio.h>
#include <stdarg.h>
#include <time.h>
#include <locale.h>
#include <string.h>
#include <stdlib.h>
#include <execinfo.h>
#include <sys/stat.h>
#include <sys/types.h>
#include <sys/time.h>
#include "logging.h"


static pthread_mutex_t  logfile_mutex;
static char            *filename = NULL;
static uint8_t          logrotate = 0;

static FILE            *logfile = NULL;
static hf_loglevel_t    loglevel = HF_LOG_MAX;

hf_loglevel_t           hf_log_loglevel; /* extern'd */
FILE                   *hf_log_logfile;


void 
hf_log_logrotate (int signum)
{
	logrotate = 1;
}


hf_loglevel_t 
hf_log_get_loglevel (void)
{
	return loglevel;
}


void
hf_log_set_loglevel (hf_loglevel_t level)
{
	hf_log_loglevel = loglevel = level;
}


void 
hf_log_fini (void)
{
	pthread_mutex_destroy (&logfile_mutex);
}


int
hf_log_init (const char *file)
{
    if (hf_log_loglevel == HF_LOG_NONE)
        return 0;

	if (!file){
		fprintf (stderr, "hf_log_init: no filename specified\n");
		return -1;
	}

	pthread_mutex_init (&logfile_mutex, NULL);

	filename = strdup (file);
	if (!filename) {
		fprintf (stderr, "hf_log_init: strdup error\n");
		return -1;
	}

	logfile = fopen (file, "a");
	if (!logfile){
		fprintf (stderr,
			 "hf_log_init: failed to open logfile \"%s\" (%s)\n",
			 file,
			 strerror (errno));
		return -1;
	}
#ifndef XIAOW_20210202
        int fd = fileno(logfile);
            fchmod (fd, 0666);
#endif
	hf_log_logfile = logfile;

	return 0;
}


void 
hf_log_lock (void)
{
	pthread_mutex_lock (&logfile_mutex);
}


void 
hf_log_unlock (void)
{
	pthread_mutex_unlock (&logfile_mutex);
}


void
hf_log_cleanup (void)
{
	pthread_mutex_destroy (&logfile_mutex);
}


int
_hf_log (const char *domain, const char *file, const char *function, int line,
	 hf_loglevel_t level, const char *fmt, ...)
{
	const char  *basename = NULL;
	FILE        *new_logfile = NULL;
	va_list      ap;
	time_t       utime = 0;
	struct tm   *tm = NULL;
	char         timestr[256];
	static char *level_strings[] = {"",  /* NONE */
					"C", /* CRITICAL */
					"E", /* ERROR */
					"W", /* WARNING */
					"N", /* NORMAL */
					"D", /* DEBUG */
                                        "T", /* TRACE */
					""};
  
	if (!domain || !file || !function || !fmt) {
		fprintf (stderr, 
			 "logging: %s:%s():%d: invalid argument\n", 
			 __FILE__, __PRETTY_FUNCTION__, __LINE__);
		return -1;
	}
  
	if (!logfile) {
		fprintf (stderr, "no logfile set\n");
		return (-1);
	}

	if (logrotate) {
		logrotate = 0;

		new_logfile = fopen (filename, "a");
		if (!new_logfile) {
			hf_log ("logrotate", HF_LOG_CRITICAL,
				"failed to open logfile %s (%s)",
				filename, strerror (errno));
			goto log;
		}

		fclose (logfile);
		hf_log_logfile = logfile = new_logfile;
	}

log:
	utime = time (NULL);
	tm    = localtime (&utime);

	if (level > loglevel) {
		goto out;
	}

	pthread_mutex_lock (&logfile_mutex);
	{
		va_start (ap, fmt);

		strftime (timestr, 256, "%Y-%m-%d %H:%M:%S", tm); 

		basename = strrchr (file, '/');
		if (basename)
			basename++;
		else
			basename = file;

                fprintf (logfile, "[%s] %s [%s:%d:%s] %s: ",
                         timestr, level_strings[level],
                         basename, line, function,
                         domain);
      
		vfprintf (logfile, fmt, ap);
		va_end (ap);
		fprintf (logfile, "\n");
		fflush (logfile);
	}
	pthread_mutex_unlock (&logfile_mutex);

out:
	return (0);
}

void 
hf_log_dump_backtrace(char *key)
{
	void *array[200];
	size_t size;

	if(key == NULL)
		return;

	hf_log("back_trace", HF_LOG_NORMAL, "------------start %s------------", key);
#if HAVE_BACKTRACE
	size = backtrace (array, 200);
	backtrace_symbols_fd (&array[1], size-1, fileno(hf_log_logfile));
#endif
	hf_log("back_trace", HF_LOG_NORMAL, "------------end %s------------", key);
}

long long 
usec(void) {
    struct timeval tv;
    gettimeofday(&tv,NULL);
    return (((long long)tv.tv_sec)*1000000)+tv.tv_usec;
}
