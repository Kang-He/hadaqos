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

#ifdef HAVE_BACKTRACE
#include <execinfo.h>
#endif

#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <ctype.h>
#include <errno.h>
#include <limits.h>
#include <unistd.h>
#include <time.h>
#include <locale.h>
#include <sys/socket.h>
#include <netinet/in.h>
#include <arpa/inet.h>
#include <signal.h>

#include "logging.h"
#include "common-utils.h"
#include "revision.h"
#include "hadafs.h"
#include "stack.h"

typedef int32_t (*rw_op_t)(int32_t fd, char *buf, int32_t size);
typedef int32_t (*rwv_op_t)(int32_t fd, const struct iovec *buf, int32_t size);
static hadafs_ctx_t *hf_global_ctx;


struct dnscache6 {
	struct addrinfo *first;
	struct addrinfo *next;
};

int32_t
hf_resolve_ip6 (const char *hostname, 
		uint16_t port, 
		int family, 
		void **dnscache, 
		struct addrinfo **addr_info)
{
	int32_t ret = 0;
	struct addrinfo hints;
	struct dnscache6 *cache = NULL;
	char service[NI_MAXSERV], host[NI_MAXHOST];

	if (!hostname) {
		hf_log ("resolver", HF_LOG_WARNING, "hostname is NULL");
		return -1;
	}

	if (!*dnscache) {
		*dnscache = CALLOC (1, sizeof (struct dnscache6));
	}

	cache = *dnscache;
	if (cache->first && !cache->next) {
		freeaddrinfo(cache->first);
		cache->first = cache->next = NULL;
		hf_log ("resolver", HF_LOG_TRACE,
			"flushing DNS cache");
	}

	if (!cache->first) {
		char *port_str = NULL;
		hf_log ("resolver", HF_LOG_TRACE,
			"DNS cache not present, freshly probing hostname: %s",
			hostname);

		memset(&hints, 0, sizeof(hints));
		hints.ai_family   = family;
		hints.ai_socktype = SOCK_STREAM;
		hints.ai_flags    = AI_ADDRCONFIG;

		asprintf (&port_str, "%d", port);
		if ((ret = getaddrinfo(hostname, port_str, &hints, &cache->first)) != 0) {
			hf_log ("resolver", HF_LOG_ERROR,
				"getaddrinfo failed (%s)", gai_strerror (ret));

			free (*dnscache);
			*dnscache = NULL;
			free (port_str);
			return -1;
		}
		free (port_str);

		cache->next = cache->first;
	}

	if (cache->next) {
		ret = getnameinfo((struct sockaddr *)cache->next->ai_addr,
				  cache->next->ai_addrlen,
				  host, sizeof (host),
				  service, sizeof (service),
				  NI_NUMERICHOST);
		if (ret != 0) {
			hf_log ("resolver",
				HF_LOG_ERROR,
				"getnameinfo failed (%s)", gai_strerror (ret));
			goto err;
		}

		hf_log ("resolver", HF_LOG_TRACE,
			"returning ip-%s (port-%s) for hostname: %s and port: %d",
			host, service, hostname, port);

		*addr_info = cache->next;
	}

	cache->next = cache->next->ai_next;
	if (cache->next) {
		ret = getnameinfo((struct sockaddr *)cache->next->ai_addr,
				  cache->next->ai_addrlen,
				  host, sizeof (host),
				  service, sizeof (service),
				  NI_NUMERICHOST);
		if (ret != 0) {
			hf_log ("resolver",
				HF_LOG_ERROR,
				"getnameinfo failed (%s)", gai_strerror (ret));
			goto err;
		}

		hf_log ("resolver", HF_LOG_TRACE,
			"next DNS query will return: ip-%s port-%s", host, service);
	}

	return 0;

err:
	freeaddrinfo (cache->first);
	cache->first = cache->next = NULL;
	free (cache);
	*dnscache = NULL;
	return -1;
}

char *hf_fop_list[HF_FOP_MAXVALUE];
char *hf_mop_list[HF_MOP_MAXVALUE];
char *hf_cbk_list[HF_CBK_MAXVALUE];

void
hf_global_variable_init()
{

	hf_fop_list[HF_FOP_UNLINK]      = "UNLINK"; /* 0 */
	hf_fop_list[HF_FOP_OPEN]        = "OPEN";
	hf_fop_list[HF_FOP_READ]        = "READ";
	hf_fop_list[HF_FOP_WRITE]       = "WRITE";
	hf_fop_list[HF_FOP_FLUSH]       = "FLUSH";
	hf_fop_list[HF_FOP_CHECKSUM]    = "CHECKSUM";   /* 5 */
	hf_mop_list[HF_MOP_SETVOLUME]   = "SETVOLUME"; /* 0 */
	hf_mop_list[HF_MOP_GETVOLUME]   = "GETVOLUME"; /* 1 */
	hf_mop_list[HF_MOP_STATS]       = "STATS";
	hf_mop_list[HF_MOP_SETSPEC]     = "SETSPEC";
	hf_mop_list[HF_MOP_GETSPEC]     = "GETSPEC";
	hf_mop_list[HF_MOP_PING]        = "PING";

	hf_cbk_list[HF_CBK_FORGET]     = "forget";
	hf_cbk_list[HF_CBK_RELEASE]     = "RELEASE";
	/* Are there any more variables to be included? All global
	   variables initialization should go here */

	return;
}

void
set_global_ctx_ptr (hadafs_ctx_t *ctx)
{
	hf_global_ctx = ctx;
}

/* 
 * Don't use this function other than in hadafsd.c. libhadafsclient does 
 * not set hf_global_ctx since there can be multiple hadafs-contexts 
 * initialized in a single process. Instead access the context from ctx member
 * of the xlator object.
 */

hadafs_ctx_t *
get_global_ctx_ptr (void)
{
	return hf_global_ctx;
}

void 
hf_log_volume_file (FILE *specfp)
{
	extern FILE *hf_log_logfile;
	int          lcount = 0;
	char         data[HF_UNIT_KB];
	
	fseek (specfp, 0L, SEEK_SET);
	
	fprintf (hf_log_logfile, "Given volfile:\n");
	fprintf (hf_log_logfile, 
		 "+---------------------------------------"
		 "---------------------------------------+\n");
	while (fgets (data, HF_UNIT_KB, specfp) != NULL){
		lcount++;
		fprintf (hf_log_logfile, "%3d: %s", lcount, data);
	}
	fprintf (hf_log_logfile, 
		 "\n+---------------------------------------"
		 "---------------------------------------+\n");
	fflush (hf_log_logfile);
	fseek (specfp, 0L, SEEK_SET);
}

static void 
hf_dump_config_flags (int fd)
{

	write (fd, "configuration details:\n", 23);

/* have argp */
#ifdef HAVE_ARGP
	write (fd, "argp 1\n", 7);
#endif

/* ifdef if found backtrace */
#ifdef HAVE_BACKTRACE 
	write (fd, "backtrace 1\n", 12);
#endif

/* Berkeley-DB version has cursor->get() */
#ifdef HAVE_BDB_CURSOR_GET 
	write (fd, "bdb->cursor->get 1\n", 19);
#endif

/* Define to 1 if you have the <db.h> header file. */
#ifdef HAVE_DB_H 
	write (fd, "db.h 1\n", 7);
#endif

/* Define to 1 if you have the <dlfcn.h> header file. */
#ifdef HAVE_DLFCN_H 
	write (fd, "dlfcn 1\n", 8);
#endif

/* define if fdatasync exists */
#ifdef HAVE_FDATASYNC 
	write (fd, "fdatasync 1\n", 12);
#endif

/* Define to 1 if you have the `pthread' library (-lpthread). */
#ifdef HAVE_LIBPTHREAD 
	write (fd, "libpthread 1\n", 13);
#endif

/* define if llistxattr exists */
#ifdef HAVE_LLISTXATTR 
	write (fd, "llistxattr 1\n", 13);
#endif

/* define if found setfsuid setfsgid */
#ifdef HAVE_SET_FSID 
	write (fd, "setfsid 1\n", 10);
#endif

/* define if found spinlock */
#ifdef HAVE_SPINLOCK 
	write (fd, "spinlock 1\n", 11);
#endif

/* Define to 1 if you have the <sys/epoll.h> header file. */
#ifdef HAVE_SYS_EPOLL_H 
	write (fd, "epoll.h 1\n", 10);
#endif

/* Define to 1 if you have the <sys/extattr.h> header file. */
#ifdef HAVE_SYS_EXTATTR_H 
	write (fd, "extattr.h 1\n", 12);
#endif

/* Define to 1 if you have the <sys/xattr.h> header file. */
#ifdef HAVE_SYS_XATTR_H 
	write (fd, "xattr.h 1\n", 10);
#endif

/* define if found st_atim.tv_nsec */
#ifdef HAVE_STRUCT_STAT_ST_ATIM_TV_NSEC
	write (fd, "st_atim.tv_nsec 1\n", 18);
#endif

/* define if found st_atimespec.tv_nsec */
#ifdef HAVE_STRUCT_STAT_ST_ATIMESPEC_TV_NSEC
	write (fd, "st_atimespec.tv_nsec 1\n",23);
#endif

/* Define to the full name and version of this package. */
#ifdef PACKAGE_STRING 
	{
		char msg[128];
		sprintf (msg, "package-string: %s\n", PACKAGE_STRING); 
		write (fd, msg, strlen (msg));
	}
#endif

	return;
}
/* Obtain a backtrace and print it to stdout for debug. */
void
hf_print_backtrace_debug (char *startmsg)
{
	extern FILE *hf_log_logfile; /* don't reset/initialize it, its 
                                        an extern */
	int          fd = 0;
	char         msg[1024] = {0,};

        fd = fileno (hf_log_logfile);

	sprintf (msg, "====== start backtrace %s ======\n", startmsg); 
	write (fd, msg, strlen (msg));
#if HAVE_BACKTRACE
	/* Print 'backtrace' */
	{
		void *array[200];
		size_t size;
    
		size = backtrace (array, 200);
		backtrace_symbols_fd (&array[1], size-1, fd);
		sprintf (msg, "---------\n");
		write (fd, msg, strlen (msg));
	}
	sprintf(msg, "====== end backtrace %s ======", startmsg);
#endif /* HAVE_BACKTRACE */
  
}

/* Obtain a backtrace and print it to stdout. */
/* TODO: It looks like backtrace_symbols allocates memory,
   it may be problem because mostly memory allocation/free causes 'sigsegv' */
void
hf_print_trace (int32_t signum)
{
	extern FILE *hf_log_logfile; /* don't reset/initialize it, its 
                                        an extern */
	int          fd = 0;
	char         msg[1024] = {0,};
	time_t       utime = 0;
	struct 	tm   tmval ;
	char         timestr[256] = {0,};

        fd = fileno (hf_log_logfile);

	/* Pending frames, (if any), list them in order */
	write (fd, "pending frames:\n", 16);
	{
		extern hadafs_ctx_t *hf_global_ctx;
		hadafs_ctx_t *ctx = hf_global_ctx;
		struct list_head *trav = ((call_pool_t *)ctx->pool)->all_frames.next;
		while (trav != (&((call_pool_t *)ctx->pool)->all_frames)) {
			call_frame_t *tmp = (call_frame_t *)(&((call_stack_t *)trav)->frames);
			if ((tmp->root->type == HF_OP_TYPE_FOP_REQUEST) ||
			    (tmp->root->type == HF_OP_TYPE_FOP_REPLY))
				sprintf (msg,"frame : type(%d) op(%s)\n",
					 tmp->root->type, 
					 hf_fop_list[tmp->root->op]);
			if ((tmp->root->type == HF_OP_TYPE_MOP_REQUEST) ||
			    (tmp->root->type == HF_OP_TYPE_MOP_REPLY))
				sprintf (msg,"frame : type(%d) op(%s)\n",
					 tmp->root->type, 
					 hf_mop_list[tmp->root->op]);
			if ((tmp->root->type == HF_OP_TYPE_CBK_REQUEST) ||
			    (tmp->root->type == HF_OP_TYPE_CBK_REPLY))
				sprintf (msg,"frame : type(%d) op(%s)\n",
					 tmp->root->type, 
					 hf_cbk_list[tmp->root->op]);
			
			write (fd, msg, strlen (msg));
			trav = trav->next;
		}
		write (fd, "\n", 1);
	}

	sprintf (msg, "patchset: %s\n", HADAFS_REPOSITORY_REVISION); 
	write (fd, msg, strlen (msg));

	sprintf (msg, "signal received: %d\n", signum); 
	write (fd, msg, strlen (msg));

        {
                /* Dump the timestamp of the crash too, so the previous logs 
                   can be related */
                utime = time (NULL);
                localtime_r (&utime, &tmval);
                strftime (timestr, 256, "%Y-%m-%d %H:%M:%S\n", &tmval); 
                write (fd, "time of crash: ", 15);
                write (fd, timestr, strlen (timestr));
        }

	hf_dump_config_flags (fd);
#if HAVE_BACKTRACE
	/* Print 'backtrace' */
	{
		void *array[200];
		size_t size;
    
		size = backtrace (array, 200);
		backtrace_symbols_fd (&array[1], size-1, fd);
		sprintf (msg, "---------\n");
		write (fd, msg, strlen (msg));
	}
#endif /* HAVE_BACKTRACE */
  
	/* Send a signal to terminate the process */
	signal (signum, SIG_DFL);
	raise (signum);
}

void
trap (void)
{

}

char *
hf_trim (char *string)
{
	register char *s, *t;
  
	if (string == NULL)
	{
		return NULL;
	}
  
	for (s = string; isspace (*s); s++)
		;
  
	if (*s == 0)
		return s;
  
	t = s + strlen (s) - 1;
	while (t > s && isspace (*t))
		t--;
	*++t = '\0';
  
	return s;
}

int 
hf_strsplit (const char *str, const char *delim, 
	     char ***tokens, int *token_count)
{
	char *_running = NULL;
	char *running = NULL;
	char *token = NULL;
	char **token_list = NULL;
	int count = 0;
	int i = 0;
	int j = 0;
  
	if (str == NULL || delim == NULL || tokens == NULL || token_count == NULL)
	{
		return -1;
	}
  
	if ((_running = strdup (str)) == NULL)
	{
		return -1;
	}
	running = _running;
  
	while ((token = strsep (&running, delim)) != NULL)
	{
		if (token[0] != '\0')
			count++;
	}
	free (_running);
  
	if ((_running = strdup (str)) == NULL)
	{
		return -1;
	}
	running = _running;
  
	if ((token_list = CALLOC (count, sizeof (char *))) == NULL)
	{
		free (_running);
		return -1;
	}
  
	while ((token = strsep (&running, delim)) != NULL)
	{
		if (token[0] == '\0')
			continue;
      
		if ((token_list[i++] = strdup (token)) == NULL)
			goto free_exit;
	}
  
	free (_running);
  
	*tokens = token_list;
	*token_count = count;
	return 0;
  
free_exit:
	free (_running);
	for (j = 0; j < i; j++)
	{
		free (token_list[j]);
	}
	free (token_list);
	return -1;
}

int 
hf_volume_name_validate (const char *volume_name)
{
	const char *vname = NULL;
  
	if (volume_name == NULL)
	{
		return -1;
	}
  
	if (!isalpha (volume_name[0]))
	{
		return 1;
	}
  
	for (vname = &volume_name[1]; *vname != '\0'; vname++)
	{
		if (!(isalnum (*vname) || *vname == '_'))
			return 1;
	}
  
	return 0;
}


int 
hf_string2time (const char *str, uint32_t *n)
{
	unsigned long value = 0;
	char *tail = NULL;
	int old_errno = 0;
	const char *s = NULL;
  
	if (str == NULL || n == NULL)
	{
		errno = EINVAL;
		return -1;
	}
  
	for (s = str; *s != '\0'; s++)
	{
		if (isspace (*s))
		{
			continue;
		}
		if (*s == '-')
		{
			return -1;
		}
		break;
	}
  
	old_errno = errno;
	errno = 0;
	value = strtol (str, &tail, 0);
  
	if (errno == ERANGE || errno == EINVAL)
	{
		return -1;
	}
  
	if (errno == 0)
	{
		errno = old_errno;
	}
  
	if (!((tail[0] == '\0') || 
	      ((tail[0] == 's') && (tail[1] == '\0')) ||
	      ((tail[0] == 's') && (tail[1] == 'e') && (tail[2] == 'c') && (tail[3] == '\0'))))
	{
		return -1;
	}
  
	*n = value;
  
	return 0;
}


int 
hf_string2percent (const char *str, uint32_t *n)
{
	unsigned long value = 0;
	char *tail = NULL;
	int old_errno = 0;
	const char *s = NULL;
  
	if (str == NULL || n == NULL)
	{
		errno = EINVAL;
		return -1;
	}
  
	for (s = str; *s != '\0'; s++)
	{
		if (isspace (*s))
		{
			continue;
		}
		if (*s == '-')
		{
			return -1;
		}
		break;
	}
  
	old_errno = errno;
	errno = 0;
	value = strtol (str, &tail, 0);
  
	if (errno == ERANGE || errno == EINVAL)
	{
		return -1;
	}
  
	if (errno == 0)
	{
		errno = old_errno;
	}
  
	if (!((tail[0] == '\0') || 
	      ((tail[0] == '%') && (tail[1] == '\0'))))
	{
		return -1;
	}
  
	*n = value;
  
	return 0;
}


static int 
_hf_string2long (const char *str, long *n, int base)
{
	long value = 0;
	char *tail = NULL;
	int old_errno = 0;
  
	if (str == NULL || n == NULL)
	{
		errno = EINVAL;
		return -1;
	}
  
	old_errno = errno;
	errno = 0;
	value = strtol (str, &tail, base);
  
	if (errno == ERANGE || errno == EINVAL)
	{
		return -1;
	}
  
	if (errno == 0)
	{
		errno = old_errno;
	}

	if (tail[0] != '\0')
	{
		/* bala: invalid integer format */
		return -1;
	}
  
	*n = value;
  
	return 0;
}

static int 
_hf_string2ulong (const char *str, unsigned long *n, int base)
{
	unsigned long value = 0;
	char *tail = NULL;
	int old_errno = 0;
	const char *s = NULL;
  
	if (str == NULL || n == NULL)
	{
		errno = EINVAL;
		return -1;
	}
  
	for (s = str; *s != '\0'; s++)
	{
		if (isspace (*s))
		{
			continue;
		}
		if (*s == '-')
		{
			/* bala: we do not support suffixed (-) sign and 
			   invalid integer format */
			return -1;
		}
		break;
	}
  
	old_errno = errno;
	errno = 0;
	value = strtoul (str, &tail, base);
  
	if (errno == ERANGE || errno == EINVAL)
	{
		return -1;
	}
  
	if (errno == 0)
	{
		errno = old_errno;
	}
  
	if (tail[0] != '\0')
	{
		/* bala: invalid integer format */
		return -1;
	}
  
	*n = value;
  
	return 0;
}

static int 
_hf_string2uint (const char *str, unsigned int *n, int base)
{
	unsigned long value = 0;
	char *tail = NULL;
	int old_errno = 0;
	const char *s = NULL;
  
	if (str == NULL || n == NULL)
	{
		errno = EINVAL;
		return -1;
	}
  
	for (s = str; *s != '\0'; s++)
	{
		if (isspace (*s))
		{
			continue;
		}
		if (*s == '-')
		{
			/* bala: we do not support suffixed (-) sign and 
			   invalid integer format */
			return -1;
		}
		break;
	}
  
	old_errno = errno;
	errno = 0;
	value = strtoul (str, &tail, base);
  
	if (errno == ERANGE || errno == EINVAL)
	{
		return -1;
	}
  
	if (errno == 0)
	{
		errno = old_errno;
	}
  
	if (tail[0] != '\0')
	{
		/* bala: invalid integer format */
		return -1;
	}
  
	*n = (unsigned int)value;
  
	return 0;
}

static int 
_hf_string2double (const char *str, double *n)
{
	double value     = 0.0;
	char   *tail     = NULL;
	int    old_errno = 0;
  
	if (str == NULL || n == NULL) {
		errno = EINVAL;
		return -1;
	}
  
	old_errno = errno;
	errno = 0;
	value = strtod (str, &tail);
  
	if (errno == ERANGE || errno == EINVAL)	{
		return -1;
	}
  
	if (errno == 0)	{
		errno = old_errno;
	}
  
	if (tail[0] != '\0') {
		return -1;
	}
  
	*n = value;
  
	return 0;
}

static int 
_hf_string2longlong (const char *str, long long *n, int base)
{
	long long value = 0;
	char *tail = NULL;
	int old_errno = 0;
  
	if (str == NULL || n == NULL)
	{
		errno = EINVAL;
		return -1;
	}
  
	old_errno = errno;
	errno = 0;
	value = strtoll (str, &tail, base);
  
	if (errno == ERANGE || errno == EINVAL)
	{
		return -1;
	}
  
	if (errno == 0)
	{
		errno = old_errno;
	}
  
	if (tail[0] != '\0')
	{
		/* bala: invalid integer format */
		return -1;
	}
  
	*n = value;
  
	return 0;
}

static int 
_hf_string2ulonglong (const char *str, unsigned long long *n, int base)
{
	unsigned long long value = 0;
	char *tail = NULL;
	int old_errno = 0;
	const char *s = NULL;
  
	if (str == NULL || n == NULL)
	{
		errno = EINVAL;
		return -1;
	}
  
	for (s = str; *s != '\0'; s++)
	{
		if (isspace (*s))
		{
			continue;
		}
		if (*s == '-')
		{
			/* bala: we do not support suffixed (-) sign and 
			   invalid integer format */
			return -1;
		}
		break;
	}
  
	old_errno = errno;
	errno = 0;
	value = strtoull (str, &tail, base);
  
	if (errno == ERANGE || errno == EINVAL)
	{
		return -1;
	}
  
	if (errno == 0)
	{
		errno = old_errno;
	}
  
	if (tail[0] != '\0')
	{
		/* bala: invalid integer format */
		return -1;
	}
  
	*n = value;
  
	return 0;
}

int 
hf_string2long (const char *str, long *n)
{
	return _hf_string2long (str, n, 0);
}

int 
hf_string2ulong (const char *str, unsigned long *n)
{
	return _hf_string2ulong (str, n, 0);
}

int 
hf_string2int (const char *str, int *n)
{
	return _hf_string2long (str, (long *) n, 0);
}

int 
hf_string2uint (const char *str, unsigned int *n)
{
	return _hf_string2uint (str, n, 0);
}

int
hf_string2double (const char *str, double *n)
{
	return _hf_string2double (str, n);
}

int 
hf_string2longlong (const char *str, long long *n)
{
	return _hf_string2longlong (str, n, 0);
}

int 
hf_string2ulonglong (const char *str, unsigned long long *n)
{
	return _hf_string2ulonglong (str, n, 0);
}

int 
hf_string2int8 (const char *str, int8_t *n)
{
	long l = 0L;
	int rv = 0;
  
	rv = _hf_string2long (str, &l, 0);
	if (rv != 0)
		return rv;
  
	if (l >= INT8_MIN && l <= INT8_MAX)
	{
		*n = (int8_t) l;
		return 0;
	}
  
	errno = ERANGE;
	return -1;
}

int 
hf_string2int16 (const char *str, int16_t *n)
{
	long l = 0L;
	int rv = 0;
  
	rv = _hf_string2long (str, &l, 0);
	if (rv != 0)
		return rv;
  
	if (l >= INT16_MIN && l <= INT16_MAX)
	{
		*n = (int16_t) l;
		return 0;
	}
  
	errno = ERANGE;
	return -1;
}

int 
hf_string2int32 (const char *str, int32_t *n)
{
	long l = 0L;
	int rv = 0;
  
	rv = _hf_string2long (str, &l, 0);
	if (rv != 0)
		return rv;
  
	if (l >= INT32_MIN && l <= INT32_MAX)
	{
		*n = (int32_t) l;
		return 0;
	}
  
	errno = ERANGE;
	return -1;
}

int 
hf_string2int64 (const char *str, int64_t *n)
{
	long long l = 0LL;
	int rv = 0;
  
	rv = _hf_string2longlong (str, &l, 0);
	if (rv != 0)
		return rv;
  
	if (l >= INT64_MIN && l <= INT64_MAX)
	{
		*n = (int64_t) l;
		return 0;
	}
  
	errno = ERANGE;
	return -1;
}

int 
hf_string2uint8 (const char *str, uint8_t *n)
{
	unsigned long l = 0L;
	int rv = 0;
  
	rv = _hf_string2ulong (str, &l, 0);
	if (rv != 0)
		return rv;
  
	if (l >= 0 && l <= UINT8_MAX)
	{
		*n = (uint8_t) l;
		return 0;
	}
  
	errno = ERANGE;
	return -1;
}

int 
hf_string2uint16 (const char *str, uint16_t *n)
{
	unsigned long l = 0L;
	int rv = 0;
  
	rv = _hf_string2ulong (str, &l, 0);
	if (rv != 0)
		return rv;
  
	if (l >= 0 && l <= UINT16_MAX)
	{
		*n = (uint16_t) l;
		return 0;
	}
  
	errno = ERANGE;
	return -1;
}

int 
hf_string2uint32 (const char *str, uint32_t *n)
{
	unsigned long l = 0L;
	int rv = 0;
  
	rv = _hf_string2ulong (str, &l, 0);
	if (rv != 0)
		return rv;
  
	if (l >= 0 && l <= UINT32_MAX)
	{
		*n = (uint32_t) l;
		return 0;
	}
  
	errno = ERANGE;
	return -1;
}

int 
hf_string2uint64 (const char *str, uint64_t *n)
{
	unsigned long long l = 0ULL;
	int rv = 0;
  
	rv = _hf_string2ulonglong (str, &l, 0);
	if (rv != 0)
		return rv;
  
	if (l >= 0 && l <= UINT64_MAX)
	{
		*n = (uint64_t) l;
		return 0;
	}
  
	errno = ERANGE;
	return -1;
}

int 
hf_string2ulong_base10 (const char *str, unsigned long *n)
{
	return _hf_string2ulong (str, n, 10);
}

int 
hf_string2uint_base10 (const char *str, unsigned int *n)
{
	return _hf_string2uint (str,  n, 10);
}

int 
hf_string2uint8_base10 (const char *str, uint8_t *n)
{
	unsigned long l = 0L;
	int rv = 0;
  
	rv = _hf_string2ulong (str, &l, 10);
	if (rv != 0)
		return rv;
  
	if (l >= 0 && l <= UINT8_MAX)
	{
		*n = (uint8_t) l;
		return 0;
	}
  
	errno = ERANGE;
	return -1;
}

int 
hf_string2uint16_base10 (const char *str, uint16_t *n)
{
	unsigned long l = 0L;
	int rv = 0;
  
	rv = _hf_string2ulong (str, &l, 10);
	if (rv != 0)
		return rv;
  
	if (l >= 0 && l <= UINT16_MAX)
	{
		*n = (uint16_t) l;
		return 0;
	}
  
	errno = ERANGE;
	return -1;
}

int 
hf_string2uint32_base10 (const char *str, uint32_t *n)
{
	unsigned long l = 0L;
	int rv = 0;
  
	rv = _hf_string2ulong (str, &l, 10);
	if (rv != 0)
		return rv;
  
	if (l >= 0 && l <= UINT32_MAX)
	{
		*n = (uint32_t) l;
		return 0;
	}
  
	errno = ERANGE;
	return -1;
}

int 
hf_string2uint64_base10 (const char *str, uint64_t *n)
{
	unsigned long long l = 0ULL;
	int rv = 0;
  
	rv = _hf_string2ulonglong (str, &l, 10);
	if (rv != 0)
		return rv;
  
	if (l >= 0 && l <= UINT64_MAX)
	{
		*n = (uint64_t) l;
		return 0;
	}
  
	errno = ERANGE;
	return -1;
}

int 
hf_string2bytesize (const char *str, uint64_t *n)
{
	uint64_t value = 0ULL;
	char *tail = NULL;
	int old_errno = 0;
	const char *s = NULL;
  
	if (str == NULL || n == NULL)
	{
		errno = EINVAL;
		return -1;
	}
  
	for (s = str; *s != '\0'; s++)
	{
		if (isspace (*s))
		{
			continue;
		}
		if (*s == '-')
		{
			/* bala: we do not support suffixed (-) sign and 
			   invalid integer format */
			return -1;
		}
		break;
	}
  
	old_errno = errno;
	errno = 0;
	value = strtoull (str, &tail, 10);
  
	if (errno == ERANGE || errno == EINVAL)
	{
		return -1;
	}
  
	if (errno == 0)
	{
		errno = old_errno;
	}
  
	if (tail[0] != '\0')
	{
		if (strcasecmp (tail, HF_UNIT_KB_STRING) == 0)
		{
			value *= HF_UNIT_KB;
		}
		else if (strcasecmp (tail, HF_UNIT_MB_STRING) == 0)
		{
			value *= HF_UNIT_MB;
		}
		else if (strcasecmp (tail, HF_UNIT_GB_STRING) == 0)
		{
			value *= HF_UNIT_GB;
		}
		else if (strcasecmp (tail, HF_UNIT_TB_STRING) == 0)
		{
			value *= HF_UNIT_TB;
		}
		else if (strcasecmp (tail, HF_UNIT_PB_STRING) == 0)
		{
			value *= HF_UNIT_PB;
		}
		else 
		{
			/* bala: invalid integer format */
			return -1;
		}
	}
  
	*n = value;
  
	return 0;
}

int64_t 
hf_str_to_long_long (const char *number)
{
	int64_t unit = 1;
	int64_t ret = 0;
	char *endptr = NULL ;
	if (!number)
		return 0;

	ret = strtoll (number, &endptr, 0);

	if (endptr) {
		switch (*endptr) {
		case 'G':
		case 'g':
			if ((* (endptr + 1) == 'B') ||(* (endptr + 1) == 'b'))
				unit = 1024 * 1024 * 1024;
			break;
		case 'M':
		case 'm':
			if ((* (endptr + 1) == 'B') ||(* (endptr + 1) == 'b'))
				unit = 1024 * 1024;
			break;
		case 'K':
		case 'k':
			if ((* (endptr + 1) == 'B') ||(* (endptr + 1) == 'b'))
				unit = 1024;
			break;
		case '%':
			unit = 1;
			break;
		default:
			unit = 1;
			break;
		}
	}
	return ret * unit;
}

int 
hf_string2boolean (const char *str, hf_boolean_t *b)
{
	if (str == NULL) {
		return -1;
	}
	
	if ((strcasecmp (str, "1") == 0) || 
	    (strcasecmp (str, "on") == 0) || 
	    (strcasecmp (str, "yes") == 0) || 
	    (strcasecmp (str, "true") == 0) || 
	    (strcasecmp (str, "enable") == 0)) {
		*b = _hf_true;
		return 0;
	}
	
	if ((strcasecmp (str, "0") == 0) || 
	    (strcasecmp (str, "off") == 0) || 
	    (strcasecmp (str, "no") == 0) || 
	    (strcasecmp (str, "false") == 0) || 
	    (strcasecmp (str, "disable") == 0)) {
		*b = _hf_false;
		return 0;
	}
	
	return -1;
}


int 
hf_lockfd (int fd)
{
	struct flock fl;
	
	fl.l_type = F_WRLCK;
	fl.l_whence = SEEK_SET;
	fl.l_start = 0;
	fl.l_len = 0;
	
	return fcntl (fd, F_SETLK, &fl);
}


int 
hf_unlockfd (int fd)
{
	struct flock fl;
	
	fl.l_type = F_UNLCK;
	fl.l_whence = SEEK_SET;
	fl.l_start = 0;
	fl.l_len = 0;
	
	return fcntl (fd, F_SETLK, &fl);
}
  
static void
compute_checksum (char *buf, size_t size, uint32_t *checksum)
{
        int  ret = -1;
        char *checksum_buf = NULL;

        checksum_buf = (char *)(checksum);

        if (!(*checksum)) {
                checksum_buf [0] = 0xba;
                checksum_buf [1] = 0xbe;
                checksum_buf [2] = 0xb0;
                checksum_buf [3] = 0x0b;                
        }

        for (ret = 0; ret < (size - 4); ret += 4) {
                checksum_buf[0] ^= (buf[ret]);
                checksum_buf[1] ^= (buf[ret + 1] << 1) ;
                checksum_buf[2] ^= (buf[ret + 2] << 2);
                checksum_buf[3] ^= (buf[ret + 3] << 3);
        }

        for (ret = 0; ret <= (size % 4); ret++) {
                checksum_buf[ret] ^= (buf[(size - 4) + ret] << ret);
        }
        
        return;
}

#define HF_CHECKSUM_BUF_SIZE 1024

int
get_checksum_for_file (int fd, uint32_t *checksum) 
{
        int ret = -1;
        char buf[HF_CHECKSUM_BUF_SIZE] = {0,};

        /* goto first place */
        lseek (fd, 0L, SEEK_SET);
        do {
                ret = read (fd, &buf, HF_CHECKSUM_BUF_SIZE);
                if (ret > 0)
                        compute_checksum (buf, HF_CHECKSUM_BUF_SIZE, 
                                          checksum);
        } while (ret > 0);

        /* set it back */
        lseek (fd, 0L, SEEK_SET);

        return ret;
}
