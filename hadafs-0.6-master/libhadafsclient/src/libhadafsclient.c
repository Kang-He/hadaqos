/*
  Copyright (c) 2008-2009 HADA, Inc. <http://www.hada.com>
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

#ifndef _GNU_SOURCE
#define _GNU_SOURCE
#endif

#include <stdio.h>
#include <errno.h>
#include <libgen.h>
#include <stddef.h>

#include <sys/time.h>
#include <sys/types.h>
#include <sys/stat.h>
#ifdef HF_SOLARIS_HOST_OS
#include <sys/statfs.h>
#endif
#include <unistd.h>
#include <xlator.h>
#include <timer.h>
#include "defaults.h"
#include <time.h>
#include <poll.h>
#include "transport.h"
#include "object.h"
#include "event.h"
#include "libhadafsclient.h"
#include "libhadafsclient-internals.h"
#include "compat.h"
#include "compat-errno.h"
#include <sys/vfs.h>
#include <utime.h>
#include <sys/param.h>
#include <list.h>
#include <stdarg.h>
#include <sys/statvfs.h>
#include "hashfn.h"
#include <sys/select.h>
#include <pwd.h>
#include <string.h>

#define LIBHF_XL_NAME "libhadafsclient"
#define LIBHADAFS_INODE_TABLE_LRU_LIMIT 1000 //14057
#define LIBHF_SENDFILE_BLOCK_SIZE 4096
#define LIBHF_READDIR_BLOCK     4096
#define libhf_path_absolute(path) ((path[0] == '/'))

/* TODO: should be set by API */
#define HADAFS_TMP_SID "hadafs"
#define HADAFS_TMP_SOFFSET 12
#define HADAFS_DEFAULT_MODE 777
#define HADADS_DEFAULT_FLAGS O_RDWR|O_CREAT
#define MAX_HOSTNAME_LEN 64

double sum = 0.0;
int count=0;


#ifndef	SUPPORT_FORTRAN
void hadafs_umount_(){
        hadafs_umount();
}
void hadafs_mount_(char *group, int *i, int *ret, int *len){
        char *cgroup = NULL;
        cgroup = strndup(group,  *len);
        *ret = hadafs_mount(cgroup, *i);
        free(cgroup);
}
#endif


static inline xlator_t *
libhadafs_graph (xlator_t *graph);
int
libhf_realpath_loc_fill (libhadafs_client_ctx_t *ctx, char *link,
                         loc_t *targetloc);
int32_t libhf_client_fstat (libhadafs_client_ctx_t *ctx, 
                    fd_t *fd, 
                    struct stat *buf);

static int first_init = 1;

/* The global list of virtual mount points */
struct {
        struct list_head list;
        int              entries;
}vmplist;


/* Protects the VMP list above. */
pthread_mutex_t vmplock = PTHREAD_MUTEX_INITIALIZER;

/* Ensures only one thread is ever calling hadafs_mount.
 * Since that function internally calls routines which
 * use the yacc parser code using global vars, this process
 * needs to be syncronised.
 */
pthread_mutex_t mountlock = PTHREAD_MUTEX_INITIALIZER;
int relativepaths = 0;

char *
libhf_vmp_virtual_path (int entrylen, const char *path, char *vpath)
{
        /*char    *tmp = NULL;

        tmp = ((char *)(path + (entrylen-1)));
        if (strlen (tmp) > 0) {
                if (tmp[0] != '/') {
                        vpath[0] = '/';
                        vpath[1] = '\0';
                        strcat (&vpath[1], tmp);
                } else
                        strcpy (vpath, tmp);
        } else {
                vpath[0] = '/';
                vpath[1] = '\0';
        }*/
	strcpy (vpath, path);

        return vpath;
}

char *
zr_build_process_uuid ()
{
	char           tmp_str[1024] = {0,};
	char           hostname[256] = {0,};
	struct timeval tv = {0,};
	struct tm      now = {0, };
	char           now_str[32];

	if (-1 == gettimeofday(&tv, NULL)) {
		hf_log ("", HF_LOG_ERROR, 
			"gettimeofday: failed %s",
			strerror (errno));		
	}

	if (-1 == gethostname (hostname, 256)) {
		hf_log ("", HF_LOG_ERROR, 
			"gethostname: failed %s",
			strerror (errno));
	}

	localtime_r (&tv.tv_sec, &now);
	strftime (now_str, 32, "%Y/%m/%d-%H:%M:%S", &now);
	snprintf (tmp_str, 1024, "%s-%d-%s:%ld", 
		  hostname, getpid(), now_str, tv.tv_usec);
	
	return strdup (tmp_str);
}


int32_t
libhf_client_forget (xlator_t *this,
		     object_t *object)
{

        return 0;
}

xlator_t *
libhf_object_to_xlator (object_t *object)
{
        if (!object)
                return NULL;

        if (!object->table)
                return NULL;

        if (!object->table->xl)
                return NULL;

        if (!object->table->xl->ctx)
                return NULL;

        return object->table->xl->ctx->top;
}

libhadafs_client_fd_ctx_t *
libhf_get_fd_ctx (fd_t *fd)
{
        uint64_t                        ctxaddr = 0;
        libhadafs_client_fd_ctx_t    *ctx = NULL;

        HF_VALIDATE_OR_GOTO (LIBHF_XL_NAME, fd, out);

        if (fd_ctx_get (fd, libhf_object_to_xlator (fd->object), &ctxaddr) == -1)
                goto out;

        ctx = (libhadafs_client_fd_ctx_t *)(long)ctxaddr;

out:
        return ctx;
}

libhadafs_client_fd_ctx_t *
libhf_alloc_fd_ctx (libhadafs_client_ctx_t *ctx, fd_t *fd)
{
        libhadafs_client_fd_ctx_t    *fdctx = NULL;
        uint64_t                        ctxaddr = 0;

        fdctx = CALLOC (1, sizeof (*fdctx));
        if (fdctx == NULL) {
                hf_log (LIBHF_XL_NAME, HF_LOG_ERROR,
                        "memory allocation failure");
                fdctx = NULL;
                goto out;
        }

        pthread_mutex_init (&fdctx->lock, NULL);
        fdctx->ctx = ctx;
        ctxaddr = (uint64_t) (long)fdctx;

        fd_ctx_set (fd, libhf_object_to_xlator (fd->object), ctxaddr);
out:
        return fdctx;
}

libhadafs_client_fd_ctx_t *
libhf_del_fd_ctx (fd_t *fd)
{
        uint64_t                        ctxaddr = 0;
        libhadafs_client_fd_ctx_t    *ctx = NULL;

        HF_VALIDATE_OR_GOTO (LIBHF_XL_NAME, fd, out);

        if (fd_ctx_del (fd, libhf_object_to_xlator (fd->object) , &ctxaddr) == -1)
                goto out;

        ctx = (libhadafs_client_fd_ctx_t *)(long)ctxaddr;

out:
        return ctx;
}

inline void
libhf_client_stat2metadata(struct stat *stbuf, metadata_t *m)
{
	m->mode = stbuf->st_mode;
	m->uid = stbuf->st_uid;
	m->gid = stbuf->st_gid;
	m->size = stbuf->st_size;
	m->atime = stbuf->st_atime;
	m->ctime = stbuf->st_ctime;
	m->mtime = stbuf->st_mtime;
	//the follow value is usless
	m->soffset = 0; //useless in client
	m->status = 0;
	strcpy(m->vmp, "123"); //useless in client
	strcpy(m->ppath, "123"); //useless in client
	strcpy(m->sid, "123"); //useless in client
}

inline void
libhf_client_metadata2stat(metadata_t *m, struct stat *stbuf)
{
	stbuf->st_mode = m->mode;
	stbuf->st_uid = m->uid;
	stbuf->st_gid = m->gid;
	stbuf->st_size = m->size;
	stbuf->st_atime = m->atime;
	stbuf->st_ctime = m->ctime;
	stbuf->st_mtime = m->mtime;
}

int32_t
libhf_client_release (xlator_t *this,
		      fd_t *fd)
{
	libhadafs_client_fd_ctx_t *fd_ctx = NULL;
        fd_ctx = libhf_get_fd_ctx (fd);

        libhf_del_fd_ctx (fd);
        if (fd_ctx != NULL) {
                pthread_mutex_destroy (&fd_ctx->lock);
                FREE (fd_ctx);
        }

	return 0;
}

void *poll_proc (void *ptr)
{
#ifdef THREAD_BIND
    cpu_set_t mask;
    CPU_ZERO(&mask);
    CPU_SET(3, &mask);
    if(sched_setaffinity(0, sizeof(mask), &mask) == -1)
        perror("set cpu affinity failed");
#endif
        hadafs_ctx_t *ctx = ptr;
        event_dispatch (ctx->event_pool);

        return NULL;
}

int32_t
xlator_graph_init (xlator_t *xl)
{
        xlator_t *trav = xl;
        int32_t ret = -1;

        while (trav->prev)
                trav = trav->prev;

        while (trav) {
                if (!trav->ready) {
                        ret = xlator_tree_init (trav);
                        if (ret < 0)
                                break;
                }
                trav = trav->next;
        }

        return ret;
}


void
xlator_graph_fini (xlator_t *xl)
{
	xlator_t *trav = xl;
	while (trav->prev)
		trav = trav->prev;

	while (trav) {
		if (!trav->init_succeeded) {
			break;
		}

		xlator_tree_fini (trav);
		trav = trav->next;
	}
}

/* Returns a pointer to the @n'th char matching
 * @c in string @str, starting the search from right or
 * end-of-string, rather than starting from left, as rindex
 * function does.
 */
char *
libhf_rrindex (char *str, int c, int n)
{
        int     len = 0;
        int     occurrence = 0;

        if (str == NULL)
                return NULL;

        len = strlen (str);
        /* Point to last character of string. */
        str += (len - 1);
        while (len > 0) {
                if ((int)*str == c) {
                        ++occurrence;
                        if (occurrence == n)
                                break;
                }
                --len;
                --str;
        }

        return str;
}

char *
libhf_trim_to_prev_dir (char * path)
{
        char    *idx = NULL;
        int      len = 0;

        if (!path)
                return NULL;

        /* Check if we're already at root, if yes
         * then there is no prev dir.
         */
        len = strlen (path);
        if (len == 1)
                return path;

        if (path[len - 1] == '/') {
                path[len - 1] = '\0';
        }

        idx = libhf_rrindex (path, '/', 1);
        /* Move to the char after the / */
        ++idx;
        *idx = '\0';

        return path;
}

/* Performs a lightweight path resolution that only
 * looks for . and  .. and replaces those with the
 * proper names.
 *
 * FIXME: This is a stop-gap measure till we have full
 * fledge path resolution going in here.
 * Function returns path strdup'ed so remember to FREE the
 * string as required.
 */
char *
libhf_resolve_path_light (char *path)
{
        char            *respath = NULL;
        char            *saveptr = NULL;
        char            *tok = NULL;
        char            *mypath = NULL;
        int             len = 0;
        int             addslash = 0;
        char            *savemypath = NULL;

        if (!path)
                goto out;

        if ((path[0] != '/') && (strncmp (path, "./", 2) != 0))
                goto out;

        mypath = strdup (path);
        savemypath = mypath;
        if (strncmp (mypath, "./", 2) == 0) {
                savemypath = mypath;
                mypath++;
        }

        len = strlen (mypath);
        respath = calloc (strlen(mypath) + 1, sizeof (char));
        if (respath == NULL) {
                hf_log (LIBHF_XL_NAME, HF_LOG_ERROR,"Memory allocation failed");
                goto out;
        }

        /* The path only contains a / or a //, so simply add a /
         * and return.
         * This needs special handling because the loop below does
         * not allow us to do so through strtok.
         */
        if (((mypath[0] == '/') && (len == 1))
                        || (strcmp (mypath, "//") == 0)) {
                strcat (respath, "/");
                goto out;
        }

        tok = strtok_r (mypath, "/", &saveptr);
        addslash = 0;
        strcat (respath, "/");
        while (tok) {
                if (addslash) {
                        if ((strcmp (tok, ".") != 0)
                                        && (strcmp (tok, "..") != 0)) {
                                strcat (respath, "/");
                        }
                }

                if ((strcmp (tok, ".") != 0) && (strcmp (tok, "..") != 0)) {
                        strcat (respath, tok);
                        addslash = 1;
                } else if ((strcmp (tok, "..") == 0)) {
                        libhf_trim_to_prev_dir (respath);
                        addslash = 0;
                }

                tok = strtok_r (NULL, "/", &saveptr);
        }

        hf_log (LIBHF_XL_NAME, HF_LOG_DEBUG, "Path: %s, Resolved Path: %s",
                path, respath);
out:
        if (savemypath)
                free (savemypath);
        return respath;
}

void 
libhf_client_loc_wipe (loc_t *loc)
{
	if (loc->path) {
		FREE (loc->path);
	}

	if (loc->object) {
		object_unref (loc->object);
		loc->object = NULL;
	}
	loc->path = NULL;
    loc->soffset = 0;
}


int32_t
libhf_client_loc_fill (loc_t *loc,
		       libhadafs_client_ctx_t *ctx,
		       char *path)
{
	object_t *object = NULL;
	int32_t ret = -1;
	char *mypath = NULL;

	if(loc->path == NULL && path == NULL)
		   return ret;

	if(loc->path == NULL)
		mypath = path;
	else
		mypath = loc->path;

	sprintf(loc->sid,"c"); //loc->sid not vol name 
	loc->soffset = 0;
	object = loc->object;

	if (!object) {
		object = object_new(ctx->otable, mypath);
		if(!object)
				goto fail;

		object_link(object);
	}
	if (object) {
			loc->object = object;
	}
	if (!loc->path) {
			loc->path = strdup(path);
	}
	loc->soffset = 0;
	ret = 0;
fail:
	return ret;
}

/*NOTE: create object need write permission on mntpnt. */
#define LIBHF_CLIENT_PERMISSION_CHECK(flags, mmode, readperm, writeperm, retval)  \
	do {  \
		if(flags & O_RDWR) {   \
			if( (mmode & readperm) && (mmode & writeperm) ) \
				retval = 0; \
			else \
				retval = -1; \
		}   \
		else if(flags & O_WRONLY) { \
			if(mmode & writeperm)\
				retval = 0; \
			else\
				retval = -1; \
		} \
		else { \
			if(mmode & readperm)\
				retval = 0; \
			else \
				retval = -1; \
		} \
		if( flags & O_CREAT ) { \
			if(mmode & writeperm) \
				retval = 0; \
			else \
				retval = -1; \
		} \
	} while(0)
	
/* If ctx->uid & ctx->gid have the permission(define in flags) needed 
    by this mount defined(defineed in loc->mntinfo)? */

int32_t 
libhf_client_op_allowed (libhadafs_client_ctx_t *ctx, int flags)
{
	int ret = -1;
	
	if(ctx->uid == ctx->muid) {
		LIBHF_CLIENT_PERMISSION_CHECK(flags, ctx->mmode, S_IRUSR, S_IWUSR, ret);
	}else if(ctx->gid == ctx->mgid) {
		LIBHF_CLIENT_PERMISSION_CHECK(flags, ctx->mmode, S_IRGRP, S_IWGRP, ret);
	}else {
		LIBHF_CLIENT_PERMISSION_CHECK(flags, ctx->mmode, S_IROTH, S_IWOTH, ret);
	}
	hf_log("libhadafsclient", HF_LOG_TRACE, "uid:%d, gid:%d, muid:%d, mgid:%d, mmode:%o, ret=%d",
			ctx->uid, ctx->gid, ctx->muid, ctx->mgid, ctx->mmode, ret);
    return ret;
}
static call_frame_t *
get_call_frame_for_req (libhadafs_client_ctx_t *ctx, char d)
{
        call_pool_t  *pool = ctx->hf_ctx.pool;
        xlator_t     *this = ctx->hf_ctx.graph;
        call_frame_t *frame = NULL;
  

        frame = create_frame (this, pool);

        frame->root->uid = ctx->uid;
        frame->root->gid = ctx->gid;
        frame->root->pid = ctx->pid;
        frame->root->unique = ctx->counter++;
  
        return frame;
}

void 
libhf_client_fini (xlator_t *this)
{
	FREE (this->private);
        return;
}


int32_t
libhf_client_notify (xlator_t *this, 
                     int32_t event,
                     void *data, 
                     ...)
{
        libhadafs_client_private_t *priv = this->private;

        switch (event)
        {
        case HF_EVENT_CHILD_UP:
                pthread_mutex_lock (&priv->lock);
                {
                        priv->complete = 1;
                        pthread_cond_broadcast (&priv->init_con_established);
                }
                pthread_mutex_unlock (&priv->lock);
                break;

        case HF_EVENT_CHILD_DOWN:
                pthread_mutex_lock (&priv->lock);
                {
			/* failed to connect to server after many tries */
			//priv->complete = -1;
                        pthread_cond_broadcast (&priv->init_con_established);
                }
                pthread_mutex_unlock (&priv->lock);
		break;

        default:
                default_notify (this, event, data);
        }

        return 0;
}

int32_t 
libhf_client_init (xlator_t *this)
{
        return 0;
}

hadafs_handle_t 
hadafs_init (hadafs_init_params_t *init_ctx, uint32_t fakefsid)
{
        libhadafs_client_ctx_t *ctx = NULL;
        libhadafs_client_private_t *priv = NULL;
        FILE *specfp = NULL;
        xlator_t *graph = NULL, *trav = NULL;
        call_pool_t *pool = NULL;
        int32_t ret = 0;
        struct rlimit lim;
	uint32_t xl_count = 0;
        struct timeval tv = {0, };
	struct timespec timeout;
	uint32_t i = 0, max_waited_count = 2;

        if (!init_ctx || (!init_ctx->specfile && !init_ctx->specfp)) {
                errno = EINVAL;
                return NULL;
        }

        ctx = CALLOC (1, sizeof (*ctx));
        if (!ctx) {
		fprintf (stderr, 
			 "libhadafsclient: %s:%s():%d: out of memory\n",
			 __FILE__, __PRETTY_FUNCTION__, __LINE__);

                errno = ENOMEM;
                return NULL;
        }

        ctx->pid = getpid ();
       ctx->uid = geteuid ();
	ctx->gid = getegid ();
	ctx->muid = init_ctx->muid;
	ctx->mgid = init_ctx->mgid;
	ctx->mmode = init_ctx->mmode;
        pthread_mutex_init (&ctx->hf_ctx.lock, NULL);
  
        pool = ctx->hf_ctx.pool = CALLOC (1, sizeof (call_pool_t));
        if (!pool) {
                errno = ENOMEM;
                FREE (ctx);
                return NULL;
        }

        LOCK_INIT (&pool->lock);
        INIT_LIST_HEAD (&pool->all_frames);

	/* FIXME: why is count hardcoded to 16384 */
        ctx->hf_ctx.event_pool = event_pool_new (16384);
        ctx->hf_ctx.page_size  = LIBHF_IOBUF_SIZE;
        ctx->hf_ctx.iobuf_pool = iobuf_pool_new (100 * 1048576,
                                                 ctx->hf_ctx.page_size);

        lim.rlim_cur = RLIM_INFINITY;
        lim.rlim_max = RLIM_INFINITY;
        setrlimit (RLIMIT_CORE, &lim);
        setrlimit (RLIMIT_NOFILE, &lim);

        ctx->hf_ctx.cmd_args.log_level = HF_LOG_WARNING;

        if (init_ctx->logfile)
                ctx->hf_ctx.cmd_args.log_file = strdup (init_ctx->logfile);
        else
                ctx->hf_ctx.cmd_args.log_file = strdup ("/dev/stderr");

        if (init_ctx->loglevel) {
                if (!strncasecmp (init_ctx->loglevel, "DEBUG",
                                  strlen ("DEBUG"))) {
                        ctx->hf_ctx.cmd_args.log_level = HF_LOG_DEBUG;
                } else if (!strncasecmp (init_ctx->loglevel, "WARNING",
                                         strlen ("WARNING"))) {
                        ctx->hf_ctx.cmd_args.log_level = HF_LOG_WARNING;
                } else if (!strncasecmp (init_ctx->loglevel, "CRITICAL",
                                         strlen ("CRITICAL"))) {
                        ctx->hf_ctx.cmd_args.log_level = HF_LOG_CRITICAL;
                } else if (!strncasecmp (init_ctx->loglevel, "NONE",
                                         strlen ("NONE"))) {
                        ctx->hf_ctx.cmd_args.log_level = HF_LOG_NONE;
                } else if (!strncasecmp (init_ctx->loglevel, "ERROR",
                                         strlen ("ERROR"))) {
                        ctx->hf_ctx.cmd_args.log_level = HF_LOG_ERROR;
                } else if (!strncasecmp (init_ctx->loglevel, "TRACE",
                                         strlen ("TRACE"))) {
                        ctx->hf_ctx.cmd_args.log_level = HF_LOG_TRACE;
                } else if (!strncasecmp (init_ctx->loglevel, "NORMAL",
                                         strlen ("NORMAL"))) {
                        ctx->hf_ctx.cmd_args.log_level = HF_LOG_NORMAL;
                } else {
			fprintf (stderr, 
				 "libhadafsclient: %s:%s():%d: Unrecognized log-level \"%s\", possible values are \"DEBUG|WARNING|[ERROR]|CRITICAL|NONE|TRACE\"\n",
                                 __FILE__, __PRETTY_FUNCTION__, __LINE__,
                                 init_ctx->loglevel);
			FREE (ctx->hf_ctx.cmd_args.log_file);
                        FREE (ctx->hf_ctx.pool);
                        FREE (ctx->hf_ctx.event_pool);
                        FREE (ctx);
                        errno = EINVAL;
                        return NULL;
                }
        }

	if (first_init)
        {
                hf_log_set_loglevel (ctx->hf_ctx.cmd_args.log_level);
                ret = hf_log_init (ctx->hf_ctx.cmd_args.log_file);
                if (ret == -1) {
			fprintf (stderr, 
				 "libhadafsclient: %s:%s():%d: failed to open logfile \"%s\"\n", 
				 __FILE__, __PRETTY_FUNCTION__, __LINE__, 
				 ctx->hf_ctx.cmd_args.log_file);
			FREE (ctx->hf_ctx.cmd_args.log_file);
                        FREE (ctx->hf_ctx.pool);
                        FREE (ctx->hf_ctx.event_pool);
                        FREE (ctx);
                        return NULL;
                }

        }

        if (init_ctx->specfile) {
                specfp = fopen (init_ctx->specfile, "r");
                ctx->hf_ctx.cmd_args.volume_file = strdup (init_ctx->specfile);
        } else if (init_ctx->specfp) { 
                specfp = init_ctx->specfp;
                if (fseek (specfp, 0L, SEEK_SET)) {
			fprintf (stderr, 
				 "libhadafsclient: %s:%s():%d: fseek on volume file stream failed (%s)\n",
                                 __FILE__, __PRETTY_FUNCTION__, __LINE__,
                                 strerror (errno));
			FREE (ctx->hf_ctx.cmd_args.log_file);
                        FREE (ctx->hf_ctx.pool);
                        FREE (ctx->hf_ctx.event_pool);
                        FREE (ctx);
                        return NULL;
                }
        }

        if (!specfp) {
		fprintf (stderr, 
			 "libhadafsclient: %s:%s():%d: could not open volfile: %s %s\n", 
			 __FILE__, __PRETTY_FUNCTION__, __LINE__, init_ctx->specfile,
                         strerror (errno));
		FREE (ctx->hf_ctx.cmd_args.log_file);
                FREE (ctx->hf_ctx.cmd_args.volume_file);
                FREE (ctx->hf_ctx.pool);
                FREE (ctx->hf_ctx.event_pool);
                FREE (ctx);
                return NULL;
        }

        if (init_ctx->volume_name) {
                ctx->hf_ctx.cmd_args.volume_name = strdup (init_ctx->volume_name);
        }

	graph = file_to_xlator_tree (&ctx->hf_ctx, specfp);
        if (!graph) {
		fprintf (stderr, 
			 "libhadafsclient: %s:%s():%d: cannot create configuration graph (%s)\n",
			 __FILE__, __PRETTY_FUNCTION__, __LINE__,
                         strerror (errno));

		FREE (ctx->hf_ctx.cmd_args.log_file);
                FREE (ctx->hf_ctx.cmd_args.volume_file);
                FREE (ctx->hf_ctx.cmd_args.volume_name);
                FREE (ctx->hf_ctx.pool);
                FREE (ctx->hf_ctx.event_pool);
                FREE (ctx);
                return NULL;
        }

        if (init_ctx->volume_name) {
                trav = graph;
                while (trav) {
                        if (strcmp (trav->name, init_ctx->volume_name) == 0) {
                                graph = trav;
                                break;
                        }
                        trav = trav->next;
                }
        }

        ctx->hf_ctx.graph = libhadafs_graph (graph);
        if (!ctx->hf_ctx.graph) {
		fprintf (stderr, 
			 "libhadafsclient: %s:%s():%d: graph creation failed (%s)\n",
			 __FILE__, __PRETTY_FUNCTION__, __LINE__,
                         strerror (errno));

		xlator_tree_free (graph);
		FREE (ctx->hf_ctx.cmd_args.log_file);
                FREE (ctx->hf_ctx.cmd_args.volume_file);
                FREE (ctx->hf_ctx.cmd_args.volume_name);
                FREE (ctx->hf_ctx.pool);
                FREE (ctx->hf_ctx.event_pool);
                FREE (ctx);
                return NULL;
        }
        graph = ctx->hf_ctx.graph;
        ctx->hf_ctx.top = graph;

	trav = graph;
	while (trav) {
		xl_count++;  /* Getting this value right is very important */
		trav = trav->next;
	}

	ctx->hf_ctx.xl_count = xl_count + 1;

        priv = CALLOC (1, sizeof (*priv));
        if (!priv) {
		fprintf (stderr, 
			 "libhadafsclient: %s:%s():%d: cannot allocate memory (%s)\n",
			 __FILE__, __PRETTY_FUNCTION__, __LINE__,
                         strerror (errno));

		xlator_tree_free (graph);
		FREE (ctx->hf_ctx.cmd_args.log_file);
                FREE (ctx->hf_ctx.cmd_args.volume_file);
                FREE (ctx->hf_ctx.cmd_args.volume_name);
                FREE (ctx->hf_ctx.pool);
                FREE (ctx->hf_ctx.event_pool);
                 /* object_table_destroy (ctx->otable);  */
                FREE (ctx);
         
                return NULL;
        }

        pthread_cond_init (&priv->init_con_established, NULL);
        pthread_mutex_init (&priv->lock, NULL);

        graph->private = priv;
        ctx->otable = object_table_new (LIBHADAFS_INODE_TABLE_LRU_LIMIT,
                                       graph);
        if (!ctx->otable) {
		fprintf (stderr, 
			 "libhadafsclient: %s:%s():%d: cannot create object table\n",
			 __FILE__, __PRETTY_FUNCTION__, __LINE__);
		xlator_tree_free (graph); 
		FREE (ctx->hf_ctx.cmd_args.log_file);
                FREE (ctx->hf_ctx.cmd_args.volume_file);
                FREE (ctx->hf_ctx.cmd_args.volume_name);

                FREE (ctx->hf_ctx.pool);
                FREE (ctx->hf_ctx.event_pool);
		xlator_tree_free (graph); 
                /* TODO: destroy graph */
                /* object_table_destroy (ctx->otable); */
                FREE (ctx);
         
                return NULL;
        }

	ctx->hf_ctx.process_uuid = zr_build_process_uuid ();

        if (xlator_graph_init (graph) == -1) {
		fprintf (stderr, 
			 "libhadafsclient: %s:%s():%d: graph initialization failed\n",
			 __FILE__, __PRETTY_FUNCTION__, __LINE__);
		xlator_tree_free (graph);
		FREE (ctx->hf_ctx.cmd_args.log_file);
                FREE (ctx->hf_ctx.cmd_args.volume_file);
                FREE (ctx->hf_ctx.cmd_args.volume_name);
                FREE (ctx->hf_ctx.pool);
                FREE (ctx->hf_ctx.event_pool);
                /* TODO: destroy graph */
                /* object_table_destroy (ctx->otable); */
                FREE (ctx);
                return NULL;
        }

	/* Send notify to all translator saying things are ready */
	graph->notify (graph, HF_EVENT_PARENT_UP, graph);

        if (hf_timer_registry_init (&ctx->hf_ctx) == NULL) {
		fprintf (stderr, 
			 "libhadafsclient: %s:%s():%d: timer init failed (%s)\n", 
			 __FILE__, __PRETTY_FUNCTION__, __LINE__,
                         strerror (errno));

		xlator_graph_fini (graph);
		xlator_tree_free (graph);
		FREE (ctx->hf_ctx.cmd_args.log_file);
                FREE (ctx->hf_ctx.cmd_args.volume_file);
                FREE (ctx->hf_ctx.cmd_args.volume_name);

                FREE (ctx->hf_ctx.pool);
                FREE (ctx->hf_ctx.event_pool);
                /* TODO: destroy graph */
                /* object_table_destroy (ctx->otable); */
                FREE (ctx);
                return NULL;
        }

        if ((ret = pthread_create (&ctx->reply_thread, NULL, poll_proc,
                                   (void *)&ctx->hf_ctx))) {
		fprintf (stderr, 
			 "libhadafsclient: %s:%s():%d: reply thread creation failed\n", 
			 __FILE__, __PRETTY_FUNCTION__, __LINE__);
		xlator_graph_fini (graph);
		xlator_tree_free (graph);
		FREE (ctx->hf_ctx.cmd_args.log_file);
                FREE (ctx->hf_ctx.cmd_args.volume_file);
                FREE (ctx->hf_ctx.cmd_args.volume_name);

                FREE (ctx->hf_ctx.pool);
                FREE (ctx->hf_ctx.event_pool);
                /* TODO: destroy graph */
                /* object_table_destroy (ctx->otable); */
                FREE (ctx);
                return NULL;
        }

        pthread_mutex_lock (&priv->lock); 
        {
                while (!priv->complete) {
			i++;
			time (&timeout.tv_sec);
			timeout.tv_sec += 1; /* waiting for 1 seconds */
                        timeout.tv_nsec = 0;
                        pthread_cond_wait (&priv->init_con_established,
                                           &priv->lock);
			if(i == max_waited_count)
				break;
                }
		if(i == max_waited_count) {
			fprintf (stderr, 
					"libhadafsclient: %s:%s():%d: waited for connection timeout(%s)\n", 
					__FILE__, __PRETTY_FUNCTION__, __LINE__,
					strerror (errno));
			pthread_cancel(ctx->reply_thread);
			xlator_graph_fini (graph);
			xlator_tree_free (graph);
			FREE (ctx->hf_ctx.cmd_args.log_file);
			FREE (ctx->hf_ctx.cmd_args.volume_file);
			FREE (ctx->hf_ctx.cmd_args.volume_name);

			FREE (ctx->hf_ctx.pool);
			FREE (ctx->hf_ctx.event_pool);
			/* TODO: destroy graph */
			/* object_table_destroy (ctx->otable); */
			FREE (ctx);
			ctx = NULL;
		}
        }
        pthread_mutex_unlock (&priv->lock);

        /* 
         * wait for some time to allow initialization of all children of 
         * distribute before sending lookup on '/'
         */

        tv.tv_sec = 0;
        tv.tv_usec = (100 * 1000);
       	select (0, NULL, NULL, NULL, &tv);

	first_init = 0;
 
        return ctx;
}

struct vmp_entry *
libhf_init_vmpentry (char *vmp, hadafs_handle_t *vmphandle)
{
        struct vmp_entry        *entry = NULL;
        int                     vmplen = 0;
        int                     appendslash = 0;
        int                     ret = -1;

        entry = CALLOC (1, sizeof (struct vmp_entry));
        if (!entry) {
                hf_log (LIBHF_XL_NAME, HF_LOG_ERROR,"Memory allocation failed");
                return NULL;
        }

        vmplen = strlen (vmp);
        if (vmp[vmplen - 1] != '/') {
                vmplen++;
                appendslash = 1;
        }

        entry->vmp = CALLOC (vmplen + 1, sizeof (char));
        if (!entry->vmp) {
                hf_log (LIBHF_XL_NAME, HF_LOG_ERROR, "Memory allocation "
                        "failed");
                goto free_entry;
        }

        strcpy (entry->vmp, vmp);
        if (appendslash) {
                entry->vmp[vmplen-1] = '/';
                entry->vmp[vmplen] = '\0';
        }
 
        entry->vmplen = vmplen;

        entry->handle = vmphandle;
        INIT_LIST_HEAD (&entry->list);
        hf_log (LIBHF_XL_NAME, HF_LOG_DEBUG, "New VMP entry: %s", vmp);

        ret = 0;

free_entry:
        if (ret == -1) {
                if (entry->vmp)
                        FREE (entry->vmp);
                if (entry)
                        FREE (entry);
                entry = NULL;
        }
        return entry;
}

void
libhf_free_vmp_entry (struct vmp_entry *entry)
{
        FREE (entry->vmp);
        FREE (entry);
}

int
libhf_count_path_components (char *path)
{
        int     compos = 0;
        char    *pathdup = NULL;
        int     len = 0;

        if (!path)
                return -1;

        pathdup = strdup (path);
        if (!pathdup)
                return -1;

        /* Must account for atleast one component in a relative since it starts
         * with a path component.
         */
	if (pathdup[0] != '/')
		compos++;

        len = strlen (pathdup);
        if (pathdup[len - 1] == '/')
                pathdup[len - 1] = '\0';

        path = pathdup;
        while ((path = strchr (path, '/'))) {
                compos++;
                ++path;
        }

        free (pathdup);
        return compos;
}

/* Returns the number of components that match between
 * the VMP and the path. Assumes string1 is vmp entry.
 * Assumes both are absolute paths.
 */
int
libhf_strmatchcount (char *string1, char *string2)
{
        int     matchcount = 0;
        char    *s1dup = NULL, *s2dup = NULL;
        char    *tok1 = NULL, *saveptr1 = NULL;
        char    *tok2 = NULL, *saveptr2 = NULL;

        if ((!string1) || (!string2))
                return 0;

        s1dup = strdup (string1);
        if (!s1dup)
                return 0;

        s2dup  = strdup (string2);
        if (!s2dup)
                goto free_s1;

        string1 = s1dup;
        string2 = s2dup;

        tok1 = strtok_r(string1, "/", &saveptr1);
        tok2 = strtok_r (string2, "/", &saveptr2);
        while (tok1) {
                if (!tok2)
                        break;

                if (strcmp (tok1, tok2) != 0)
                        break;

                matchcount++;
                tok1 = strtok_r(NULL, "/", &saveptr1);
                tok2 = strtok_r (NULL, "/", &saveptr2);
        }

        free (s2dup);
free_s1:
        free (s1dup);
        return matchcount;
}

int
libhf_vmp_entry_match (char *entry, char *path)
{
        return libhf_strmatchcount (entry, path);
}

#define LIBHF_VMP_EXACT          1
#define LIBHF_VMP_LONGESTPREFIX  0
struct vmp_entry *
_libhf_vmp_search_entry (char *path, int searchtype)
{
        struct vmp_entry        *entry = NULL;
        int                     matchcount = 0;
        struct vmp_entry        *maxentry = NULL;
        int                     maxcount = 0;
        int                     vmpcompcount = 0;

        hf_log (LIBHF_XL_NAME, HF_LOG_DEBUG, "VMP Search: path %s, type: %s",
                path, (searchtype == LIBHF_VMP_EXACT)?"Exact":"LongestPrefix");
        if (vmplist.entries == 0) {
                hf_log (LIBHF_XL_NAME, HF_LOG_DEBUG, "Virtual Mount Point "
                        "list is empty.");
                goto out;
        }

        list_for_each_entry(entry, &vmplist.list, list) {
                vmpcompcount = libhf_count_path_components (entry->vmp);
                matchcount = libhf_vmp_entry_match (entry->vmp, path);
                hf_log (LIBHF_XL_NAME, HF_LOG_TRACE, "Candidate VMP:  %s,"
                        " Matchcount: %d", entry->vmp, matchcount);
                if ((matchcount > maxcount) && (matchcount == vmpcompcount)) {
                        maxcount = matchcount;
                        maxentry = entry;
                }
        }

        /* To ensure that the longest prefix matched entry is also an exact
         * match, this is used to check whether duplicate entries are present
         * in the vmplist.
         */
        vmpcompcount = 0;
        if ((searchtype == LIBHF_VMP_EXACT) && (maxentry)) {
                vmpcompcount = libhf_count_path_components (maxentry->vmp);
                matchcount = libhf_count_path_components (path);
                hf_log (LIBHF_XL_NAME, HF_LOG_TRACE, "Exact Check: VMP: %s,"
                        " CompCount: %d, Path: %s, CompCount: %d",
                        maxentry->vmp, vmpcompcount, path, matchcount);
                if (vmpcompcount != matchcount) {
                        hf_log (LIBHF_XL_NAME, HF_LOG_TRACE, "No Match");
                        maxentry = NULL;
                } else
                        hf_log (LIBHF_XL_NAME, HF_LOG_TRACE, "Matches!");
        }

out:        
        return maxentry;
} 

/* Used to search for a exactly matching VMP entry.
 */
struct vmp_entry *
libhf_vmp_search_exact_entry (char *path)
{
        struct vmp_entry        *entry = NULL;

        if (!path)
                goto out;

        pthread_mutex_lock (&vmplock);
        {
                entry = _libhf_vmp_search_entry (path, LIBHF_VMP_EXACT);
        }
        pthread_mutex_unlock (&vmplock);

out:
        if (entry)
                hf_log (LIBHF_XL_NAME, HF_LOG_DEBUG, "VMP Entry found: path :%s"
                        " vmp: %s", path, entry->vmp);
        else
                hf_log (LIBHF_XL_NAME, HF_LOG_DEBUG, "VMP Entry not found: path"
                        ": %s", path);

        return entry;
}


/* Used to search for a longest prefix matching VMP entry.
 */
struct vmp_entry *
libhf_vmp_search_entry (char *path)
{
        struct vmp_entry        *entry = NULL;

        if (!path)
                goto out;

        pthread_mutex_lock (&vmplock);
        {
                entry = _libhf_vmp_search_entry (path, LIBHF_VMP_LONGESTPREFIX);
        }
        pthread_mutex_unlock (&vmplock);

out:
        if (entry)
                hf_log (LIBHF_XL_NAME, HF_LOG_DEBUG, "VMP Entry found: path :%s"
                        " vmp: %s", path, entry->vmp);
        else
                hf_log (LIBHF_XL_NAME, HF_LOG_DEBUG, "VMP Entry not found: path"
                        ": %s", path);

        return entry;
}


struct vmp_entry *
libhf_vmp_first_entry ()
{
        struct vmp_entry        *entry = NULL;

        pthread_mutex_lock (&vmplock);
        {
                if (vmplist.entries == 0) {
                        hf_log (LIBHF_XL_NAME, HF_LOG_DEBUG, "Virtual Mount Point "
                                "list is empty.");
                        goto unlock_out;
                }

                list_for_each_entry (entry, &vmplist.list, list)
                        break;
        }
unlock_out:
        pthread_mutex_unlock (&vmplock);

        return entry;
}


struct vmp_entry *
libhf_vmp_search_entry_vpath (char *path, char *vpath)
{
        struct vmp_entry	*entry = NULL;
        int			vmplen = 0;

        if ((!path) || (!vpath))
                return NULL;

	if (!libhf_path_absolute (path)) {
                if (!relativepaths)
                        goto out;
                else {
                        /* On relativepaths, we assume that all relativepaths
                         * go over the first VMP. It is dangerous but for now
                         * we're assuming relative path support is only needed
                         * for samba. This condition is safe for the assumptions
                         * made in samba about its cwd.
                         */
                        entry = libhf_vmp_first_entry ();
                        /* Relative paths can start with both . and .. */
                        if (strncmp (path, "..", 2) == 0)
                                vmplen = 3;
                        else if (strncmp (path, ".", 1) == 0)
                                vmplen = 1;

                        goto vpath_out;
                }
        }

        entry = libhf_vmp_search_entry ((char *)path);
        if (!entry)
                goto out;

        vmplen = entry->vmplen;

vpath_out:
        if (!entry)
                return NULL;

        libhf_vmp_virtual_path (vmplen, path, vpath);

out:
	return entry;
}


int
libhf_vmp_map_ghandle (char *vmp, hadafs_handle_t *vmphandle)
{
        int                     ret = -1;
        struct vmp_entry        *vmpentry = NULL;

        hf_log (LIBHF_XL_NAME, HF_LOG_DEBUG, "New Entry: %s", vmp);
        vmpentry = libhf_init_vmpentry (vmp, vmphandle);
        if (!vmpentry) {
                hf_log (LIBHF_XL_NAME, HF_LOG_ERROR, "Failed to create VMP"
                        " entry");
                goto out;
        }

        pthread_mutex_lock (&vmplock);
        {
                if (vmplist.entries == 0) {
                        INIT_LIST_HEAD (&vmplist.list);
                }

                list_add_tail (&vmpentry->list, &vmplist.list);
                ++vmplist.entries;
        }
        pthread_mutex_unlock (&vmplock);
        ret = 0;

out:
        return ret;
}

/* Path must be validated already. */
hadafs_handle_t
libhf_vmp_get_ghandle (char * path)
{
        struct vmp_entry        *entry = NULL;

        entry = libhf_vmp_search_entry (path);

        if (entry == NULL)
                return NULL;

        return entry->handle;
}

int
hadafs_mount_old (char *vmp, hadafs_init_params_t *ipars)
{
        hadafs_handle_t      vmphandle = NULL;
        int                     ret = -1;
        char                    *vmp_resolved = NULL;
        struct vmp_entry        *vmp_entry = NULL;
        uint32_t                vmphash = 0;
        
        HF_VALIDATE_OR_GOTO (LIBHF_XL_NAME, vmp, out);
        HF_VALIDATE_OR_GOTO (LIBHF_XL_NAME, ipars, out);

        vmp_resolved = libhf_resolve_path_light (vmp);
        if (!vmp_resolved) {
                hf_log (LIBHF_XL_NAME, HF_LOG_ERROR, "Path compaction failed");
                goto out;
        }
        hf_global_variable_init();
        vmphash = (dev_t)ReallySimpleHash (vmp, strlen (vmp));
        pthread_mutex_lock (&mountlock);
        {
                vmp_entry = libhf_vmp_search_exact_entry (vmp);
                if (vmp_entry) {
                        hf_log (LIBHF_XL_NAME, HF_LOG_DEBUG, "Entry exists");
                        ret = 0;
                        goto unlock;
                }
                vmphandle = hadafs_init (ipars, vmphash);
                if (vmphandle == NULL) {
			ret = -1;
                        errno = EINVAL;
                        hf_log (LIBHF_XL_NAME, HF_LOG_ERROR, "HADAFS context"
                                " init failed");
                        goto unlock;
                }

                ret = libhf_vmp_map_ghandle (vmp_resolved, vmphandle);
                /* Only switch on relativepaths if it is not on already.
                 * The check is there to ensure no one actually adds more than
                 * two VMPs in the conf file and expect relative paths to work.
                 */
                if (ipars->relativepaths && !relativepaths)
                        relativepaths = 1;

                if (ret == -1) {
                        hf_log (LIBHF_XL_NAME, HF_LOG_ERROR, "Failed to map new"
                                " handle: %s", vmp);
                        hadafs_fini (vmphandle);
                }
        }
unlock:
        pthread_mutex_unlock (&mountlock);

out:
        if (vmp_resolved)
                FREE (vmp_resolved);
        return ret;
}
#ifdef XIAOW_180828
int
hadafs_mount ()
{
	hadafs_init_params_t ipars;
	int ret = -1;
	uid_t uid;
	gid_t gid;
	char logfile[1024];
	time_t now;
	char timestamp[256];
	char volfile[256];
	char vmp[256];
    char *username;
    char *userhome;
    char *hostname;
    struct passwd *pwd;

	//memset (&ipars, 0, sizeof (hadafs_init_params_t));
	ipars.muid = getuid();
    pwd = getpwuid(getuid());
    username = getenv("USER");
    userhome = getenv("HOME");
    hostname = getenv("HOSTNAME");
	time(&now);
	strftime (timestamp, 256, "[%b %d %H:%M:%S]", localtime (&now));
	sprintf (logfile, "/tmp/hadafs-%s-%s.log", pwd->pw_name, timestamp);
	sprintf (volfile, "/etc/hadafs/%s.vol", pwd->pw_name);
	sprintf (vmp, "/tmp/%s", pwd->pw_name);
	ipars.mgid = getgid();
    printf("vmp %s volfile %s\n", vmp, volfile);
#if 1
	ipars.mmode = 0700;
	ipars.specfp = NULL;
#else
	if (mode == RW) {
		ipars.mmode = 0700;
	}
	else if (mode == RO) {
		ipars.mmode = 0400;
	}
	else{
                printf ("libhadafsclient wrong mount type %d\n", mode);
		fflush(stdout);
		return ret;
	}
#endif
	ipars.specfile = strdup(volfile);
	ipars.volume_name = strdup("brick");
	ipars.logfile = strdup(logfile);
	ipars.loglevel = strdup("TRACE");
	ret = hadafs_mount_old (vmp, &ipars);
	return ret;
}
#else
char *
get_suffix(char *proxy_file, int id){
        FILE *fd; 
        int node_count = 0, ret = 0;
        int tag2 = 0, dif = 0, i = 0, tmp = 0;
        int node[1024] = {0}, b[128] = {0};
        char sep[]=",", sep_node[]="-";
        char *p_node, *p2_node, *temp_node, *temp2_node, *temp3_node;
        char buf[4096];
        char buf1[32];
        int node_service;
        char *node_id = malloc(16);

        fd = fopen(proxy_file, "r");
        if (fd == NULL){
		printf("proxy_file is %s\n", proxy_file);
                perror("cannot open proxy_file!");
                exit(1);
        }   
        if(fgets(buf, 4096, fd) == NULL){
                perror("cannot read proxy_file node list!");
                exit(1);
        }   
	//printf("buf is %s\n", buf);
        if(fgets(buf1, 32, fd) == NULL){
                perror("cannot read proxy_file node_service!");
                exit(1);
        }
	fclose(fd);
	//printf("node is %s\n", buf1);
        node_service = atoi(buf1);  
        temp_node = strtok_r(buf, sep, &p_node);
	while(temp_node)
        {
                temp3_node = strdupa(temp_node);
                temp2_node = strtok_r(temp3_node,sep_node,&p2_node);
                if (atoi(temp3_node) > tmp)
                        tmp = atoi(p2_node);
                else{
                        printf("proxy_node list illegal!\n");   
                        exit(1);

                }
                while(temp2_node)
                {   
                        node[node_count] = atoi(temp2_node);
                        if(atoi(p2_node) > 0){
                                if(atoi(p2_node) > node[node_count]){
                                        b[tag2] = atoi(p2_node);
                                        dif = b[tag2]-node[node_count]-1;
                                        if(node[node_count])
                                                for(i = 1; i <= dif; i++)
                                                        node[node_count + i]=node[node_count + i- 1]+1;
                                        tag2++;
                                        node_count = node_count+dif;

                                }else{
                                        printf("proxy_node list illegal!\n");
                                        exit(1);
                                }
                        }
                        temp2_node = strtok_r(p2_node,sep_node,&p2_node);
                        node_count++;
                }
                temp_node = strtok_r(p_node,sep,&p_node);
        }
	id = id % (node_count * node_service);
	switch(node_service)
	{
		case 4:
			if((id % (node_count * 4)) >= (node_count * 3)){
				id = id % node_count;
				sprintf(node_id, "%d_%d", node[id], 4);
				return node_id;
			}
		case 3:
			if((id % (node_count * 3)) >= (node_count * 2)){
				id = id % node_count;
				sprintf(node_id, "%d_%d", node[id], 3);
				return node_id;
			}
		case 2:
			if((id % (node_count * 2)) >= node_count){
				id = id % node_count;
				sprintf(node_id, "%d_%d", node[id], 2);
				return node_id;
			}
		case 1:
			id = id % node_count;
			sprintf(node_id, "%d", node[id]);
			break;
		default:
			printf("proxy node_service illegal!\n");
			exit(1);

	}
	return node_id;
}
int check_auth(char *group_auth, char *username){
        FILE *fd; 
        char buf[4096];
    	char auth_file[256];
	sprintf (auth_file, "/home/export/online1/.hadaclient/.%s.auth", group_auth);
        fd = fopen(auth_file, "r");
        if (fd == NULL){
		printf("auth_file is %s\n", group_auth);
                perror("cannot open auth_file!");
                exit(1);
        }   
        if(fgets(buf, 4096, fd) == NULL){
                perror("cannot read auth_file!");
                exit(1);
        }
	if(buf[(strlen(buf))-1] == '\n')
		buf[(strlen(buf))-1] = '\0';
	printf("%s %s %s\n", buf, username, strstr(buf, username));   
	if(!strstr(buf, username))
		return 0;
	else
		return -1;
}

int
hadafs_mount (char *proxy_group, int id)
{
	hadafs_init_params_t ipars;
	int ret = -1;
	uid_t uid;
	gid_t gid;
	struct passwd *pwd;
	char logfile[1024];
	time_t now;
	char timestamp[256];
	char volfile[256];
	char vmp[256];
	char *username;
	char *userhome;
	char hostname[MAX_HOSTNAME_LEN];
    char proxy_file[256];
	char *suffix;
 	long cpuid;
    char *host;
	ipars.muid = getuid();
	//username = getenv("USER");
	username = getenv("USER");
	userhome = getenv("HOME");
	gethostname(hostname, MAX_HOSTNAME_LEN);
        host = strtok(hostname, "vn");
        cpuid = atol(host);
#if 0
	if (check_auth(proxy_group, username) !=0 ){
		if(id == 0)
			printf("user %s access  %s failed: Permission denied\n", username, proxy_group);
		exit(1);
	}
#endif
	
	//sprintf (proxy_file, "/home/export/online1/.hadaclient/%s.txt", proxy_group);
	//suffix = get_suffix(proxy_file, id);
	int dir = cpuid/1024;
	time(&now);
	strftime (timestamp, 256, "[%b-%d-%H-%M-%S]", localtime (&now));
	//sprintf (logfile, "/home/export/online1/.hadaclient/log/%d/hadafs-%s-%d.log", dir, username, cpuid);
	sprintf (logfile, "/var/log/hadafs-client-%d.log", id%6);
	sprintf (volfile, "/users/hys/client.vol");
	sprintf (vmp, "/tmp/vmp");
	ipars.mgid = getgid();
	//printf("volfile is %s\n", logfile);
#if 1
	ipars.mmode = 0700;
	ipars.specfp = NULL;
#else
	if (mode == RW) {
		ipars.mmode = 0700;
	}
	else if (mode == RO) {
		ipars.mmode = 0400;
	}
	else{
                printf ("libhadafsclient wrong mount type %d\n", mode);
		fflush(stdout);
		return ret;
	}
#endif
#ifdef THREAD_BIND
    cpu_set_t mask;
    CPU_ZERO(&mask);
    CPU_SET(1, &mask);
    if(sched_setaffinity(0, sizeof(mask), &mask) == -1)
        perror("set cpu affinity failed");
#endif
	ipars.specfile = strdup(volfile);
	ipars.volume_name = strdup("brick");
	ipars.logfile = strdup(logfile);
	ipars.loglevel = strdup("DEBUG");
	//ipars.loglevel = "NORMAL";
	ret = hadafs_mount_old (vmp, &ipars);
    free(suffix);
	return ret;
}
#endif
inline int
_libhf_umount (char *vmp)
{
        struct vmp_entry *entry= NULL;
        int               ret = -1;

        entry = _libhf_vmp_search_entry (vmp, LIBHF_VMP_EXACT);
        if (entry == NULL) {
                hf_log ("libhadafsclient", HF_LOG_ERROR,
                        "path (%s) not mounted", vmp);
                goto out;
        }

        if (entry->handle == NULL) {
                hf_log ("libhadafsclient", HF_LOG_ERROR,
                        "path (%s) has no corresponding hadafs handle",
                        vmp);
                goto out;
        }

        ret = hadafs_fini (entry->handle);
        list_del_init (&entry->list);
        libhf_free_vmp_entry (entry);

        vmplist.entries--; 

out:
        return ret;
}

inline int
libhf_umount (char *vmp)
{
        int ret = -1;

        pthread_mutex_lock (&vmplock);
        { 
                ret = _libhf_umount (vmp);
        }
        pthread_mutex_unlock (&vmplock);
        
        return ret;
}

int
hadafs_umount ()
{ 
        int    ret = -1; 
        char *vmp_resolved = NULL;
        char *username;
        char vmp[256];

        HF_VALIDATE_OR_GOTO (LIBHF_XL_NAME, vmp, out);

        username = getenv("USER");
        //username = getenv("USER");
        sprintf (vmp, "/tmp/%s", username);
        vmp_resolved = libhf_resolve_path_light (vmp);
        if (!vmp_resolved) {
                hf_log (LIBHF_XL_NAME, HF_LOG_ERROR, "Path compaction failed");
                goto out;
        }

        ret = libhf_umount (vmp_resolved);

out:
        if (vmp_resolved)
                FREE (vmp_resolved);

        return ret;
}

int
hadafs_umount_all (void)
{
        struct vmp_entry *entry = NULL, *tmp = NULL;

        pthread_mutex_lock (&vmplock);
        {
                if (vmplist.entries > 0) {
                        list_for_each_entry_safe (entry, tmp, &vmplist.list,
                                                  list) {
                                /* even if there are errors, continue with other
                                   mounts
                                */
                                _libhf_umount (entry->vmp);
                        }
                }
        }
        pthread_mutex_unlock (&vmplock);
        
        return 0;
}

void
hadafs_reset (void)
{
        INIT_LIST_HEAD (&vmplist.list);
        vmplist.entries = 0;

        memset (&vmplock, 0, sizeof (vmplock));
        pthread_mutex_init (&vmplock, NULL);

	first_init = 1;
}

void 
hadafs_log_lock (void)
{
	hf_log_lock ();
}


void hadafs_log_unlock (void)
{
	hf_log_unlock ();
}


void
libhf_wait_for_frames_unwind (libhadafs_client_ctx_t *ctx)
{
        call_pool_t     *pool = NULL;
        int             canreturn = 0;

        if (!ctx)
                return;

        pool = (call_pool_t *)ctx->hf_ctx.pool;
        while (1) {
                LOCK (&pool->lock);
                {
                        if (pool->cnt == 0) {
                                canreturn = 1;
                                goto unlock_out;
                        }
                }
unlock_out:
                UNLOCK (&pool->lock);

                if (canreturn)
                        break;

                hf_log (LIBHF_XL_NAME, HF_LOG_DEBUG, "Waiting for call frames");
                sleep (1);
        }

        return;
}


int 
hadafs_fini (hadafs_handle_t handle)
{
	libhadafs_client_ctx_t *ctx = handle;

        libhf_wait_for_frames_unwind (ctx);

	FREE (ctx->hf_ctx.cmd_args.log_file);
	FREE (ctx->hf_ctx.cmd_args.volume_file);
	FREE (ctx->hf_ctx.cmd_args.volume_name);
	FREE (ctx->hf_ctx.pool);
    ((struct event_pool *)ctx->hf_ctx.event_pool)->fin = 1;
        /* iobuf_pool_destroy (ctx->hf_ctx.iobuf_pool); */
        ((hf_timer_registry_t *)ctx->hf_ctx.timer)->fin = 1;

	xlator_graph_fini (ctx->hf_ctx.graph);
	xlator_tree_free (ctx->hf_ctx.graph);
	ctx->hf_ctx.graph = NULL;  
#ifdef XIAOW_20200528
        pthread_join (((hf_timer_registry_t *)ctx->hf_ctx.timer)->th, NULL);
        FREE (ctx->hf_ctx.timer);
        pthread_join (ctx->reply_thread, NULL);
        FREE (ctx->hf_ctx.event_pool);
#else
        pthread_cancel (ctx->reply_thread);
#endif
        FREE (ctx);

        return 0;
}

static int32_t
libhf_client_open_cbk (call_frame_t *frame,
                         void *cookie,
                         xlator_t *this,
                         int32_t op_ret,
                         int32_t op_errno,
                         fd_t *fd,
                         object_t *object,
                         struct stat *buf)     
{
        libhf_client_local_t *local = frame->local;

        local->reply_stub = fop_open_cbk_stub (frame, NULL, op_ret, op_errno,
                                                 fd, object, buf);

        LIBHF_REPLY_NOTIFY (local);
        return 0;
}

int 
libhf_client_open (libhadafs_client_ctx_t *ctx,
                    loc_t *loc,
                    fd_t *fd,
                    int flags,
                    mode_t mode)
{
        call_stub_t *stub = NULL;
        int32_t op_ret = 0;
        libhf_client_local_t *local = NULL;
        object_t *libhf_object = NULL;

        LIBHF_CLIENT_FOP (ctx, stub, open, local, loc, flags, mode, fd);
  
        op_ret = stub->args.open_cbk.op_ret;
        errno = stub->args.open_cbk.op_errno;
        	hf_log (LIBHF_XL_NAME, HF_LOG_ERROR, "Open: path %s, status: %d,"
                	" errno: %d (%s)", loc->path, op_ret, errno, strerror(errno));
        if (op_ret == -1)
                goto out;

	libhf_object = stub->args.open_cbk.object;

out:
	call_stub_destroy (stub);
        return op_ret;
}


hadafs_file_t 
hadafs_hlh_open (hadafs_handle_t handle, char *vmp, const char *path, int flags,...)
{
        loc_t loc = {0, };
        long op_ret = -1;
        fd_t *fd = NULL;
	int32_t ret = -1;
	libhadafs_client_ctx_t *ctx = handle;
	char *pathname = NULL;
        mode_t mode = 0;
        va_list ap;
        char *pathres = NULL;

        HF_VALIDATE_OR_GOTO (LIBHF_XL_NAME, ctx, out);
        HF_VALIDATE_ABSOLUTE_PATH_OR_GOTO (LIBHF_XL_NAME, path, out);

	/*TODO: Is this open can be allowed? we could judge using
         * uid=geteuid, gid=getegid and ctx->uid, ctx->gid, ctx->mode */

        pathres = libhf_resolve_path_light ((char *)path);
        if (!pathres) {
                hf_log (LIBHF_XL_NAME, HF_LOG_ERROR, "Path compaction failed");
                goto out;
        }

	loc.path = strdup (pathres);
        ret = libhf_client_loc_fill (&loc, ctx, pathres);
	if (ret == -1) {
		hf_log ("libhadafsclient",
			HF_LOG_ERROR,
			"libhf_client_loc_fill returned -1, returning EINVAL");
		errno = EINVAL;
		goto out;
	}
	memcpy(loc.object->metadata.vmp, vmp, strlen(vmp));
	ret = libhf_client_op_allowed(ctx, flags);
	if(ret == -1){
		hf_log ("libhadafsclient",
			HF_LOG_ERROR, 
			"libhf_client_is_op_allowed returned -1, returning EACCES");
		errno = EACCES;
		goto out;
	}

        fd = fd_create (loc.object, ctx->pid);
        fd->flags = flags;

        if ((flags & O_CREAT) == O_CREAT) {
                va_start (ap, flags);
                mode = va_arg (ap, mode_t);
                va_end (ap);
                op_ret = libhf_client_open(ctx, &loc, fd, flags, mode);
        } else {
                 op_ret = libhf_client_open (ctx, &loc, fd, flags, HADAFS_DEFAULT_MODE);
        }
        if (op_ret == -1) {
                fd_unref (fd);
                fd = NULL;
                goto out;
        }

        if (!libhf_get_fd_ctx (fd)) {
                if (!libhf_alloc_fd_ctx (ctx, fd)) {
                        hf_log (LIBHF_XL_NAME, HF_LOG_ERROR, "Failed to"
                                " allocate fd context");
                        errno = EINVAL;
                        op_ret = -1;
                        goto out;
                }
        }

out:
        libhf_client_loc_wipe (&loc);

	if (pathname) {
		FREE (pathname);
	}

        if (pathres)
                FREE (pathres);

        return fd;
}

hadafs_file_t
hadafs_open (const char *path, int flags, ...)
{
        struct vmp_entry        *entry = NULL;
        char                    vpath[PATH_MAX];
        hadafs_file_t        fh = NULL;
        mode_t                  mode = 0;
        va_list                 ap;
        HF_VALIDATE_OR_GOTO (LIBHF_XL_NAME, path, out);

        entry = libhf_vmp_search_entry_vpath ((char *)path, vpath);
        if (!entry) {
        	hf_log (LIBHF_XL_NAME, HF_LOG_DEBUG, "path %s with no entry matched", path);
                errno = ENODEV;
                goto out;
        }

        if (flags & O_CREAT) {
                va_start (ap, flags);
                mode = va_arg (ap, mode_t);
                va_end (ap);
                fh = hadafs_hlh_open (entry->handle, entry->vmp, vpath, flags, mode);
        } else
                fh = hadafs_hlh_open (entry->handle, entry->vmp, vpath, flags, HADAFS_DEFAULT_MODE);
out:
		hf_log (LIBHF_XL_NAME, HF_LOG_DEBUG, "path %s return %p", vpath, fh);
        return fh;
}

int32_t
libhf_client_flush_cbk (call_frame_t *frame,
                        void *cookie,
                        xlator_t *this,
                        int32_t op_ret,
                        int32_t op_errno,
			struct stat *stbuf)
{
        libhf_client_local_t *local = frame->local;
        
        local->reply_stub = fop_flush_cbk_stub (frame, NULL, op_ret, op_errno, stbuf);
        
        LIBHF_REPLY_NOTIFY (local);
        return 0;
}


int 
libhf_client_flush (libhadafs_client_ctx_t *ctx, fd_t *fd)
{
        call_stub_t *stub;
        int32_t op_ret;
        libhf_client_local_t *local = NULL;

        LIBHF_CLIENT_FOP (ctx, stub, flush, local, fd);
        
        op_ret = stub->args.flush_cbk.op_ret;
        errno = stub->args.flush_cbk.op_errno;
        
	call_stub_destroy (stub);        
        return op_ret;
}

int 
hadafs_flush (hadafs_file_t fd)
{
        int32_t op_ret = -1;
        libhadafs_client_ctx_t *ctx = NULL;
        libhadafs_client_fd_ctx_t *fd_ctx = NULL;

        if (!fd) {
                errno = EINVAL;
		goto out;
        }

        fd_ctx = libhf_get_fd_ctx (fd);
        if (!fd_ctx) {
                hf_log (LIBHF_XL_NAME, HF_LOG_ERROR, "No fd context present");
                errno = EBADF;
                goto out;
        }
        ctx = fd_ctx->ctx;
        CHECK_CTX_VALID(ctx, out);

        op_ret = libhf_client_flush (ctx, (fd_t *)fd);

out:
        return op_ret;
}

int32_t
libhf_client_ioctl_cbk (call_frame_t *frame,
                        void *cookie,
                        xlator_t *this,
                        int32_t op_ret,
                        int32_t op_errno)
{
        libhf_client_local_t *local = frame->local;
        
        local->reply_stub = fop_ioctl_cbk_stub (frame, NULL, op_ret, op_errno);
        
        LIBHF_REPLY_NOTIFY (local);
        return 0;
}


int 
libhf_client_ioctl (libhadafs_client_ctx_t *ctx, fd_t *fd, uint32_t cmd, uint64_t arg)
{
        call_stub_t *stub;
        int32_t op_ret;
        libhf_client_local_t *local = NULL;

        LIBHF_CLIENT_FOP (ctx, stub, ioctl, local, fd, cmd, arg);
        
        op_ret = stub->args.ioctl_cbk.op_ret;
        errno = stub->args.ioctl_cbk.op_errno;
        
	    call_stub_destroy (stub);        
        return op_ret;
}

int 
hadafs_ioctl (hadafs_file_t fd, uint32_t cmd, uint64_t arg)
{
        int32_t op_ret = -1;
        libhadafs_client_ctx_t *ctx = NULL;
        libhadafs_client_fd_ctx_t *fd_ctx = NULL;

        if (!fd) {
                errno = EINVAL;
		goto out;
        }

        fd_ctx = libhf_get_fd_ctx (fd);
        if (!fd_ctx) {
                hf_log (LIBHF_XL_NAME, HF_LOG_ERROR, "No fd context present");
                errno = EBADF;
                goto out;
        }
        ctx = fd_ctx->ctx;
        CHECK_CTX_VALID(ctx, out);

        op_ret = libhf_client_ioctl (ctx, (fd_t *)fd, cmd, arg);
out:
        return op_ret;
}
int 
hadafs_close (hadafs_file_t fd)
{
        int32_t op_ret = -1;
        libhadafs_client_ctx_t *ctx = NULL;
        libhadafs_client_fd_ctx_t *fd_ctx = NULL;

        if (!fd) {
                errno = EINVAL;
		goto out;
        }

        fd_ctx = libhf_get_fd_ctx (fd);
        if (!fd_ctx) {
                hf_log (LIBHF_XL_NAME, HF_LOG_ERROR, "No fd context present");
                errno = EBADF;
                goto out;
        }
        ctx = fd_ctx->ctx;
        CHECK_CTX_VALID(ctx, out);
        op_ret = libhf_client_flush (ctx, (fd_t *)fd);

        fd_unref ((fd_t *)fd);

out:
       return op_ret;
}

#define LIBHF_DO_SETXATTR       1
#define LIBHF_DO_LSETXATTR      2

int32_t
libhf_client_readv_cbk (call_frame_t *frame,
                        void *cookie,
                        xlator_t *this,
                        int32_t op_ret,
                        int32_t op_errno,
                        struct iovec *vector,
                        int32_t count,
                        struct stat *stbuf,
                        struct iobref *iobref)
{
        libhf_client_local_t *local = frame->local;

        local->reply_stub = fop_readv_cbk_stub (frame, NULL, op_ret, op_errno,
                                                vector, count, stbuf, iobref);
        LIBHF_REPLY_NOTIFY (local);
        return 0;
}

int
libhf_client_iobuf_read (libhadafs_client_ctx_t *ctx, fd_t *fd, void *buf,
                         size_t size, off_t offset)
{
    call_stub_t *stub;
        struct iovec *vector;
        int32_t op_ret = -1;
        int count = 0;
        libhf_client_local_t *local = NULL;

        local = CALLOC (1, sizeof (*local));
        ERR_ABORT (local);
        LIBHF_CLIENT_FOP (ctx, stub, readv, local, fd, size, offset);

        op_ret = stub->args.readv_cbk.op_ret;
        errno = stub->args.readv_cbk.op_errno;
        count = stub->args.readv_cbk.count;
        vector = stub->args.readv_cbk.vector;
        if (op_ret > 0) {
                int i = 0;
                op_ret = 0;
                while (size && (i < count)) {
                        int len = (size < vector[i].iov_len) ?
                                size : vector[i].iov_len;
                        memcpy (buf, vector[i++].iov_base, len);
                        buf += len;
                        size -= len;
                        op_ret += len;
                }
        }

        call_stub_destroy (stub);
        return op_ret;

}

ssize_t 
libhf_client_read (libhadafs_client_ctx_t *ctx, 
                   fd_t *fd,
                   void *buf, 
                   size_t size, 
                   off_t offset)
{
	int64_t op_ret = -1;
        ssize_t ret = 0;
        size_t  tmp   = 0;

        while (size != 0) {
                tmp = ((size > LIBHF_IOBUF_SIZE) ? LIBHF_IOBUF_SIZE :
                       size);
                op_ret = libhf_client_iobuf_read (ctx, fd, buf, tmp, offset);
                if (op_ret < 0) {
                        ret = op_ret;
                        break;
                }

                ret += op_ret;

                if (op_ret < tmp)
                        break;

                size -= op_ret;
                offset += op_ret;
                buf = (char *)buf + op_ret;
        }
        return ret;
}

ssize_t 
hadafs_read (hadafs_file_t fd, 
                void *buf, 
                size_t nbytes)
{
        ssize_t op_ret = -1;
        off_t offset = 0;
        libhadafs_client_ctx_t *ctx = NULL;
        libhadafs_client_fd_ctx_t *fd_ctx = NULL;

        if (nbytes < 0) {
                errno = EINVAL;
                goto out;
        }

        if (nbytes == 0) {
                op_ret = 0;
                goto out;
        }

        if (fd == 0) {
                errno = EINVAL;
		goto out;
        }

        fd_ctx = libhf_get_fd_ctx (fd);
        if (!fd_ctx) {
                hf_log (LIBHF_XL_NAME, HF_LOG_ERROR, "No fd context present");
                errno = EBADF;
		goto out;
        }

        pthread_mutex_lock (&fd_ctx->lock);
        {
                ctx = fd_ctx->ctx;
                offset = fd_ctx->offset;
        }
        pthread_mutex_unlock (&fd_ctx->lock);

        CHECK_CTX_VALID(ctx, out);
        op_ret = libhf_client_read (ctx, (fd_t *)fd, buf, nbytes, offset);
        
        if (op_ret > 0) {
                offset += op_ret;
                pthread_mutex_lock (&fd_ctx->lock);
                {
                        fd_ctx->offset = offset;
                }
                pthread_mutex_unlock (&fd_ctx->lock);
        }
out:
        return op_ret;
}


ssize_t
libhf_client_readv (libhadafs_client_ctx_t *ctx, 
                    fd_t *fd,
                    const struct iovec *dst_vector,
                    int dst_count,
                    off_t offset)
{
        call_stub_t *stub = NULL;
        struct iovec *src_vector;
        int src_count = 0;
        ssize_t op_ret = -1;
        libhf_client_local_t *local = NULL;
        size_t size = 0;
        int32_t i = 0;

        for (i = 0; i < dst_count; i++)
        {
                size += dst_vector[i].iov_len;
        }

        local = CALLOC (1, sizeof (*local));
        ERR_ABORT (local);
        LIBHF_CLIENT_FOP (ctx, stub, readv, local, fd, size, offset);

        op_ret = stub->args.readv_cbk.op_ret;
        errno = stub->args.readv_cbk.op_errno;
        src_count = stub->args.readv_cbk.count;
        src_vector = stub->args.readv_cbk.vector;
        if (op_ret > 0) {
                int src = 0, dst = 0;
                off_t src_offset = 0, dst_offset = 0;
    
                while ((size != 0) && (dst < dst_count) && (src < src_count)) {
                        int len = 0, src_len, dst_len;
   
                        src_len = src_vector[src].iov_len - src_offset;
                        dst_len = dst_vector[dst].iov_len - dst_offset;

                        len = (src_len < dst_len) ? src_len : dst_len;
                        if (len > size) {
                                len = size;
                        }

                        memcpy (dst_vector[dst].iov_base + dst_offset, 
				src_vector[src].iov_base + src_offset, len);

                        size -= len;
                        src_offset += len;
                        dst_offset += len;

                        if (src_offset == src_vector[src].iov_len) {
                                src_offset = 0;
                                src++;
                        }

                        if (dst_offset == dst_vector[dst].iov_len) {
                                dst_offset = 0;
                                dst++;
                        }
                }
        }
 
	call_stub_destroy (stub);
        return op_ret;
}


ssize_t 
hadafs_readv (hadafs_file_t fd, const struct iovec *vec, int count)
{
        int32_t op_ret = -1;
        off_t offset = 0;
        libhadafs_client_ctx_t *ctx = NULL;
        libhadafs_client_fd_ctx_t *fd_ctx = NULL;

        if (count < 0) {
                errno = EINVAL;
                goto out;
        }

        if (count == 0) {
                op_ret = 0;
                goto out;
        }

        if (!fd) {
                errno = EINVAL;
		goto out;
        }

        fd_ctx = libhf_get_fd_ctx (fd);
        if (!fd_ctx) {
                errno = EBADF;
		goto out;
        }

        pthread_mutex_lock (&fd_ctx->lock);
        {
                ctx = fd_ctx->ctx;
                offset = fd_ctx->offset;
        }
        pthread_mutex_unlock (&fd_ctx->lock);
        CHECK_CTX_VALID(ctx, out);

        op_ret = libhf_client_readv (ctx, (fd_t *)fd, vec, count, offset);

        if (op_ret > 0) {
                offset += op_ret;
                pthread_mutex_lock (&fd_ctx->lock);
                {
                        fd_ctx->offset = offset;
                }
                pthread_mutex_unlock (&fd_ctx->lock);
        }

out:
        return op_ret;
}

int
libhf_client_writev_cbk (call_frame_t *frame,
                         void *cookie,
                         xlator_t *this,
                         int32_t op_ret,
                         int32_t op_errno,
                         struct stat *stbuf)
{
        libhf_client_local_t *local = frame->local;

        local->reply_stub = fop_writev_cbk_stub (frame, NULL, op_ret, op_errno,
                                                 stbuf);

        LIBHF_REPLY_NOTIFY (local);
        return 0;
}


int
libhf_client_iobuf_write (libhadafs_client_ctx_t *ctx, fd_t *fd, char *addr,
                          size_t size, off_t offset)
{
        struct iobref        *ioref = NULL;
        struct iobuf         *iob = NULL;
        int                   op_ret = -1;
        struct iovec          iov = {0, };
        call_stub_t          *stub = NULL;
        libhf_client_local_t *local = NULL;
	unsigned long tmp_buf;

        HF_VALIDATE_OR_GOTO (LIBHF_XL_NAME, ctx, out);
        HF_VALIDATE_OR_GOTO (LIBHF_XL_NAME, fd, out);
        HF_VALIDATE_OR_GOTO (LIBHF_XL_NAME, addr, out);

        ioref = iobref_new ();
        if (!ioref) {
                hf_log (LIBHF_XL_NAME, HF_LOG_ERROR, "Out of memory");
                goto out;
        }

        iob = iobuf_get (ctx->hf_ctx.iobuf_pool);
        if (!iob) {
                hf_log (LIBHF_XL_NAME, HF_LOG_ERROR, "Out of memory");
                goto out;
        }
        struct timeval  tv_start = {0, };
        struct timeval  tv_stop = {0, };
        double value= 0.0;
        gettimeofday(&tv_start, NULL);
#ifndef XIAOW20181225
        memcpy (iob->ptr, addr, size);
#else
        tmp_buf = iob->ptr;
        iob->ptr = addr;
#endif
        gettimeofday(&tv_stop, NULL);
        value = tv_stop.tv_sec - tv_start.tv_sec;
        value += (tv_stop.tv_usec - tv_start.tv_usec)/1000000.0;
        sum += value;
        count++;
       // if(count%1000==0)
       //     hf_log("xiaow",HF_LOG_ERROR,"memcpy %d use %lf,sum %lf",size, value, sum);
        iobref_add (ioref, iob);

        iov.iov_base = iob->ptr;
        iov.iov_len = size;

        LIBHF_CLIENT_FOP (ctx, stub, writev, local, fd, &iov,
                          1, offset, ioref);

        op_ret = stub->args.writev_cbk.op_ret;
        errno = stub->args.writev_cbk.op_errno;

out:
        if (iob) {
#ifdef XIAOW20181225
		iob->ptr = tmp_buf;
#endif
                iobuf_unref (iob);
        }

        if (ioref) {
                iobref_unref (ioref);
        }

        call_stub_destroy (stub);
        return op_ret;
}

ssize_t
libhf_client_writev (libhadafs_client_ctx_t *ctx, 
                     fd_t *fd, 
                     struct iovec *vector, 
                     int count, 
                     off_t offset)
{
        ssize_t                     op_ret = 0;
        int                     written = 0;
        int                     writesize = 0;
        ssize_t                     size = 0;
        char                   *base = NULL;
        int                     i = 0;

        for (i = 0; i < count; i++) {
                size = vector[i].iov_len;
                base = vector[i].iov_base;
		
                while (size > 0) {
                        writesize = (size > LIBHF_IOBUF_SIZE) ?
                                LIBHF_IOBUF_SIZE : size;

                        written = libhf_client_iobuf_write (ctx, fd, base,
                                                            writesize, offset);

                        if (written == -1)
                                goto out;

                        op_ret += written;
                        base += written;
                        size -= written;
                        offset += written;
                }
        }

out:
        return op_ret;
}


ssize_t 
hadafs_write (hadafs_file_t fd, 
                 const void *buf, 
                 size_t n)
{
        ssize_t op_ret = -1;
        off_t offset = 0;
        struct iovec vector;
        libhadafs_client_ctx_t *ctx = NULL;
        libhadafs_client_fd_ctx_t *fd_ctx = NULL;

        if (n < 0) {
                errno = EINVAL;
                goto out;
        }

        if (n == 0) {
                op_ret = 0;
                goto out;
        }

        if (!fd) {
                errno = EINVAL;
		goto out;
        }

        fd_ctx = libhf_get_fd_ctx (fd);
        if (!fd_ctx) {
                errno = EBADF;
		goto out;
        }

        ctx = fd_ctx->ctx;
        CHECK_CTX_VALID(ctx, out);

        pthread_mutex_lock (&fd_ctx->lock);
        {
                offset = fd_ctx->offset;
        }
        pthread_mutex_unlock (&fd_ctx->lock);

        vector.iov_base = (void *)buf;
        vector.iov_len = n;

        op_ret = libhf_client_writev (ctx,
                                      (fd_t *)fd, 
                                      &vector, 
                                      1, 
                                      offset);

        if (op_ret >= 0) {
                offset += op_ret;
                pthread_mutex_lock (&fd_ctx->lock);
                {
                        fd_ctx->offset = offset;
                }
                pthread_mutex_unlock (&fd_ctx->lock);
        }

out:
        return op_ret;
}

ssize_t 
hadafs_writev (hadafs_file_t fd, 
                  const struct iovec *vector,
                  int count)
{
        ssize_t op_ret = -1;
        off_t offset = 0;
        libhadafs_client_ctx_t *ctx = NULL;
        libhadafs_client_fd_ctx_t *fd_ctx = NULL;

        if (count < 0) {
                errno = EINVAL;
                goto out;
        }

        if (count == 0) {
                op_ret = 0;
                goto out;
        }

        if (!fd) {
                errno = EINVAL;
		goto out;
        }

        fd_ctx = libhf_get_fd_ctx (fd);
        if (!fd_ctx) {
                errno = EBADF;
		goto out;
        }

        ctx = fd_ctx->ctx;
        CHECK_CTX_VALID(ctx, out);

        pthread_mutex_lock (&fd_ctx->lock);
        {
                offset = fd_ctx->offset;
        }
        pthread_mutex_unlock (&fd_ctx->lock);


        op_ret = libhf_client_writev (ctx,
                                      (fd_t *)fd, 
                                      (struct iovec *)vector, 
                                      count,
                                      offset);

        if (op_ret >= 0) {
                offset += op_ret;
                pthread_mutex_lock (&fd_ctx->lock);
                {
                        fd_ctx->offset = offset;
                }
                pthread_mutex_unlock (&fd_ctx->lock);
        }

out:
        return op_ret;
}

off_t
hadafs_lseek (hadafs_file_t fd, off_t offset, int whence)
{
        off_t __offset = 0;
        libhadafs_client_fd_ctx_t *fd_ctx = NULL;
	libhadafs_client_ctx_t *ctx = NULL; 
	int32_t op_ret = -1;

        fd_ctx = libhf_get_fd_ctx (fd);
        if (!fd_ctx) {
                errno = EBADF;
		__offset = -1;
		goto out;
        }

        ctx = fd_ctx->ctx;
        CHECK_CTX_VALID(ctx, out);

        switch (whence)
        {
          case SEEK_SET:
                __offset = offset;
                break;

          case SEEK_CUR:
                pthread_mutex_lock (&fd_ctx->lock);
                {
                        __offset = fd_ctx->offset;
                }
                pthread_mutex_unlock (&fd_ctx->lock);

                __offset += offset;
                break;

          case SEEK_END:
	  {
		off_t end = 0;
		struct stat stbuf = {0, };

		/*TODO:get stbuf.st_size */
		op_ret = libhf_client_fstat(ctx, fd, &stbuf);
		if (op_ret < 0) {
			__offset = -1;
			goto out;
		}
		
		end = stbuf.st_size;
                __offset = end + offset;
	  }
	  break;

	  default:
		hf_log ("libhadafsclient",
			HF_LOG_ERROR,
			"invalid value for whence");
		__offset = -1;
		errno = EINVAL;
		goto out;
          }

          pthread_mutex_lock (&fd_ctx->lock);
          {
                fd_ctx->offset = __offset;
          }
          pthread_mutex_unlock (&fd_ctx->lock);
 
out: 
          return __offset;
}

int32_t
libhf_client_unlink_cbk (call_frame_t *frame, void *cookie, xlator_t *this,
                                int32_t op_ret, int32_t op_errno)
{
        libhf_client_local_t    *local = frame->local;

        local->reply_stub = fop_unlink_cbk_stub (frame, NULL, op_ret,
                                                        op_errno);

        LIBHF_REPLY_NOTIFY (local);
        return 0;
}

int
libhf_client_unlink (libhadafs_client_ctx_t *ctx, loc_t *loc)
{
        int                             op_ret = -1;
        libhf_client_local_t            *local = NULL;
        call_stub_t                     *stub = NULL;

        LIBHF_CLIENT_FOP (ctx, stub, unlink, local, loc);

        op_ret = stub->args.unlink_cbk.op_ret;
        errno = stub->args.unlink_cbk.op_errno;

        hf_log (LIBHF_XL_NAME, HF_LOG_DEBUG, "path %s", loc->path);
        if (op_ret == -1)
                goto out;
	
	//chenxi:20160311
	object_unlink(loc->object);

out:
        call_stub_destroy (stub);
        return op_ret;
}

int
hadafs_hlh_unlink (hadafs_handle_t handle, const char *path)
{
        int32_t                         op_ret = -1;
        loc_t                           loc = {0, };
        libhadafs_client_ctx_t       *ctx = handle;
        char                            *name = NULL;

        HF_VALIDATE_OR_GOTO (LIBHF_XL_NAME, ctx, out);
        HF_VALIDATE_ABSOLUTE_PATH_OR_GOTO (LIBHF_XL_NAME, path, out);

        hf_log (LIBHF_XL_NAME, HF_LOG_DEBUG, "path %s", path);
        loc.path = libhf_resolve_path_light ((char *)path);
        if (!loc.path) {
                hf_log (LIBHF_XL_NAME, HF_LOG_ERROR, "Path compaction failed");
                goto out;
        }
        op_ret = libhf_client_loc_fill (&loc, ctx, loc.path);
	if (op_ret == -1) {
                hf_log ("libhadafsclient", HF_LOG_ERROR,
                                "libhf_client_loc_fill returned -1, "
                                " returning EINVAL");
                errno = EINVAL;
                goto out;
        }
	/*To unlink a object, client have writing permmion for this mntpnt*/
	op_ret = libhf_client_op_allowed(ctx, O_WRONLY);
	if(op_ret == -1){
		hf_log ("libhadafsclient",
			HF_LOG_ERROR, 
			"libhf_client_is_op_allowed returned -1, returning EACCES");
		errno = EACCES;
		goto out;
	}
        op_ret = libhf_client_unlink (ctx, &loc);

out:
        if (name)
                FREE (name);
        libhf_client_loc_wipe (&loc);
        return op_ret;
}

int
hadafs_unlink (const char *path)
{
        struct vmp_entry        *entry = NULL;
        char                    vpath[PATH_MAX];
        int                     op_ret = -1;

        HF_VALIDATE_OR_GOTO (LIBHF_XL_NAME, path, out);

        hf_log (LIBHF_XL_NAME, HF_LOG_DEBUG, "path %s", path);
        entry = libhf_vmp_search_entry_vpath ((char *)path, vpath);
        if (!entry) {
                errno = ENODEV;
                goto out;
        }

        op_ret = hadafs_hlh_unlink (entry->handle, vpath);
out:
        return op_ret;
}

int32_t
libhf_client_truncate_cbk (call_frame_t *frame, void *cookie, xlator_t *this,
                           int32_t op_ret, int32_t op_errno,
                           struct stat *postbuf)
{
        libhf_client_local_t *local = frame->local;

        local->reply_stub = fop_truncate_cbk_stub (frame, NULL, op_ret,
                                                   op_errno, postbuf);

        LIBHF_REPLY_NOTIFY (local);
        return 0;
}

int32_t 
libhf_client_truncate (libhadafs_client_ctx_t *ctx, 
                       loc_t *loc, off_t length)
{
        call_stub_t *stub = NULL;
        int32_t op_ret = 0;
        libhf_client_local_t *local = NULL;

        LIBHF_CLIENT_FOP (ctx, stub, truncate, local, loc, length);
 
        op_ret = stub->args.truncate_cbk.op_ret;
        errno = stub->args.truncate_cbk.op_errno;

        hf_log (LIBHF_XL_NAME, HF_LOG_DEBUG, "path %s, status %d, errno %d",
                loc->path, op_ret, errno);

        if (op_ret == -1) {
                goto out;
        }

	call_stub_destroy (stub);

out:
        return op_ret;
}

int
hadafs_hlh_truncate (hadafs_handle_t handle, const char *path,
                        off_t length)
{
        int32_t op_ret = -1;
        loc_t loc = {0, };
        libhadafs_client_ctx_t *ctx = handle;
		char *pathres = NULL;

        HF_VALIDATE_OR_GOTO (LIBHF_XL_NAME, ctx, out);
        HF_VALIDATE_ABSOLUTE_PATH_OR_GOTO (LIBHF_XL_NAME, path, out);

        pathres = libhf_resolve_path_light ((char *)path);
        if (!pathres) {
                hf_log (LIBHF_XL_NAME, HF_LOG_ERROR, "Path compaction failed");
                goto out;
        }
        loc.path = strdup (pathres);
        if (!loc.path) {
                hf_log (LIBHF_XL_NAME, HF_LOG_ERROR, "strdup failed");
                goto out;
        }

        op_ret = libhf_client_loc_fill (&loc, ctx, pathres);


	if (op_ret == -1) {
		hf_log ("libhadafsclient",
			HF_LOG_ERROR,
			"libhf_client_loc_fill returned -1, returning EINVAL");
		errno = EINVAL;
		goto out;
	}

        op_ret = libhf_client_truncate (ctx, &loc, length);

out:
	if (pathres) {
		FREE (pathres);
	}
        libhf_client_loc_wipe (&loc);

        return op_ret;
}

int
hadafs_truncate (const char *path, off_t length)
{
        int                     op_ret = -1;
        char                    vpath[PATH_MAX];
        struct vmp_entry        *entry = NULL;

        HF_VALIDATE_OR_GOTO (LIBHF_XL_NAME, path, out);

        hf_log (LIBHF_XL_NAME, HF_LOG_DEBUG, "path:%s length:%"PRIu64, path,
                length);
        entry = libhf_vmp_search_entry_vpath ((char *)path, vpath);
        if (!entry) {
                errno = ENODEV;
                goto out;
        }

        op_ret = hadafs_hlh_truncate (entry->handle, vpath, length);
out:
        return op_ret;
}
int
libhf_client_ftruncate_cbk (call_frame_t *frame, void *cookie, xlator_t *xlator
                                ,int32_t op_ret, int32_t op_errno,
                                struct stat *postbuf)
{
        libhf_client_local_t    *local = frame->local;

        local->reply_stub = fop_ftruncate_cbk_stub (frame, NULL, op_ret,
                                                    op_errno, postbuf);

        LIBHF_REPLY_NOTIFY (local);

        return 0;
}

int
libhf_client_ftruncate (libhadafs_client_ctx_t *ctx, fd_t *fd,
                                off_t length)
{
        libhf_client_local_t            *local = NULL;
        call_stub_t                     *stub = NULL;
        int                             op_ret = -1;
        libhadafs_client_fd_ctx_t    *fdctx = NULL;

        if (!(((fd->flags & O_ACCMODE) == O_RDWR)
              || ((fd->flags & O_ACCMODE) == O_WRONLY))) {
                errno = EBADF;
                goto out;
        }

        LIBHF_CLIENT_FOP (ctx, stub, ftruncate, local, fd, length);

        op_ret = stub->args.ftruncate_cbk.op_ret;
        errno = stub->args.ftruncate_cbk.op_errno;

        if (op_ret == -1)
                goto out;


        fdctx = libhf_get_fd_ctx (fd);
        if (!fd) {
                errno = EINVAL;
                op_ret = -1;
                goto out;
        }

        pthread_mutex_lock (&fdctx->lock);
        {
                fdctx->offset = stub->args.ftruncate_cbk.postbuf.st_size;
        }
        pthread_mutex_unlock (&fdctx->lock);

out:
        call_stub_destroy (stub);
        return op_ret;
}

int
hadafs_ftruncate (hadafs_file_t fd, off_t length)
{
        libhadafs_client_fd_ctx_t    *fdctx = NULL;
        int                             op_ret = -1;
        libhadafs_client_ctx_t *ctx;

        HF_VALIDATE_OR_GOTO (LIBHF_XL_NAME, fd, out);

        fdctx = libhf_get_fd_ctx (fd);
        if (!fdctx) {
                hf_log (LIBHF_XL_NAME, HF_LOG_ERROR, "No fd context present");
                errno = EBADF;
                goto out;
        }
        ctx = fdctx->ctx;
        CHECK_CTX_VALID(ctx, out);
        op_ret = libhf_client_ftruncate (ctx, (fd_t *)fd, length);

out:
        return op_ret;
}

static int32_t
libhf_client_fstat_cbk (call_frame_t *frame,
                        void *cookie,
                        xlator_t *this,
                        int32_t op_ret,
                        int32_t op_errno,
                        struct stat *buf)
{  
        libhf_client_local_t *local = frame->local;

        local->reply_stub = fop_fstat_cbk_stub (frame, 
                                                NULL, 
                                                op_ret, 
                                                op_errno, 
                                                buf);

        LIBHF_REPLY_NOTIFY (local);
        return 0;

}


int32_t
libhf_client_fstat (libhadafs_client_ctx_t *ctx, 
                    fd_t *fd, 
                    struct stat *buf)
{
        call_stub_t *stub = NULL;
        int32_t op_ret = 0;
        libhf_client_local_t *local = NULL;

        LIBHF_CLIENT_FOP (ctx, stub, fstat, local, fd);
 
        op_ret = stub->args.fstat_cbk.op_ret;
        errno = stub->args.fstat_cbk.op_errno;

        hf_log (LIBHF_XL_NAME, HF_LOG_DEBUG, "status %d, errno %d", op_ret, errno);

        if (op_ret == 0) {
                if (buf)
                        *buf = stub->args.fstat_cbk.stbuf;
        }
	call_stub_destroy (stub);
        return op_ret;
}


int32_t 
hadafs_fstat (hadafs_file_t fd, struct stat *buf) 
{
        libhadafs_client_ctx_t *ctx;
        fd_t *__fd = (fd_t *)fd;
        libhadafs_client_fd_ctx_t *fd_ctx = NULL;
	 int32_t op_ret = -1;

        if (!fd) {
                errno = EINVAL;
		goto out;
	}

        fd_ctx = libhf_get_fd_ctx (fd);
        if (!fd_ctx) {
                hf_log (LIBHF_XL_NAME, HF_LOG_ERROR, "No fd context present");
                errno = EBADF;
		op_ret = -1;
		goto out;
        }

        ctx = fd_ctx->ctx;
        CHECK_CTX_VALID(ctx, out);
	op_ret = libhf_client_fstat (ctx, __fd, buf);
out:
	return op_ret;
}


int32_t
libhf_client_stat_cbk (call_frame_t *frame,
                       void *cookie,
                       xlator_t *this,
                       int32_t op_ret,
                       int32_t op_errno,
                       struct stat *buf)
{
        libhf_client_local_t *local = frame->local;
        local->reply_stub = fop_stat_cbk_stub (frame, 
                                               NULL, 
                                               op_ret, 
                                               op_errno, 
                                               buf);

        LIBHF_REPLY_NOTIFY (local);
        return 0;
}

int32_t 
libhf_client_stat (libhadafs_client_ctx_t *ctx, 
                   loc_t *loc,
                   struct stat *stbuf)
{
        call_stub_t *stub = NULL;
        int32_t op_ret = 0;
        libhf_client_local_t *local = NULL;

        LIBHF_CLIENT_FOP (ctx, stub, stat, local, loc);

        op_ret = stub->args.stat_cbk.op_ret;
        errno = stub->args.stat_cbk.op_errno;

        hf_log (LIBHF_XL_NAME, HF_LOG_DEBUG, "path %s, status %d, errno %d",
                loc->path, op_ret, errno);

        if (op_ret == 0) {
                if (stbuf)
                        *stbuf = stub->args.stat_cbk.stbuf;
        }

	call_stub_destroy (stub);
        return op_ret;
}


int
hadafs_hlh_stat (hadafs_handle_t handle, const char *path,
                        struct stat *buf)
{
        int32_t op_ret = -1;
	 int32_t ret = -1;
        loc_t loc = {0, };
        libhadafs_client_ctx_t *ctx = handle;
	 char *pathres = NULL;
       
        HF_VALIDATE_OR_GOTO (LIBHF_XL_NAME, ctx, out);
        HF_VALIDATE_ABSOLUTE_PATH_OR_GOTO (LIBHF_XL_NAME, path, out);

        pathres = libhf_resolve_path_light ((char *)path);
        if (!pathres) {
                hf_log (LIBHF_XL_NAME, HF_LOG_ERROR, "Path compaction failed");
                goto out;
        }
        loc.path = strdup (pathres);
        if (!loc.path) {
                hf_log (LIBHF_XL_NAME, HF_LOG_ERROR, "strdup failed");
                goto out;
        }

        ret = libhf_client_loc_fill (&loc, ctx, pathres);
	 if (ret == -1) {
		hf_log ("libhadafsclient",
			HF_LOG_ERROR,
			"libhf_client_loc_fill returned -1, returning EINVAL");
		errno = EINVAL;
		goto out;
	 }

        op_ret = libhf_client_stat (ctx, &loc, buf);
        
out:
	if (pathres) {
		FREE (pathres);
	}

        libhf_client_loc_wipe (&loc);

        return op_ret;

}


int
hadafs_stat (const char *path, struct stat *buf)
{
        struct vmp_entry        *entry = NULL;
        int                     op_ret = -1;
        char                    vpath[PATH_MAX];

        HF_VALIDATE_OR_GOTO (LIBHF_XL_NAME, path, out);
        HF_VALIDATE_OR_GOTO (LIBHF_XL_NAME, buf, out);

        hf_log (LIBHF_XL_NAME, HF_LOG_DEBUG, "path %s", path);

        entry = libhf_vmp_search_entry_vpath ((char *)path, vpath);
        if (!entry) {
                errno = ENODEV;
                goto out;
        }

        op_ret = hadafs_hlh_stat (entry->handle, vpath, buf);
out:
        return op_ret;
}

int32_t
libhf_client_setobject_cbk (call_frame_t *frame,
                       void *cookie,
                       xlator_t *this,
                       int32_t op_ret,
                       int32_t op_errno,
                       object_t *object)
{
        libhf_client_local_t *local = frame->local;
        local->reply_stub = fop_setobject_cbk_stub (frame, 
                                               NULL, 
                                               op_ret, 
                                               op_errno, 
                                               object);

        LIBHF_REPLY_NOTIFY (local);
        return 0;
}

int32_t 
libhf_client_setobject (libhadafs_client_ctx_t *ctx, 
                   loc_t *loc,
                   struct stat *stbuf)
{
		call_stub_t *stub = NULL;
		int32_t op_ret = 0;
		libhf_client_local_t *local = NULL;

		libhf_client_stat2metadata(stbuf, &(loc->object->metadata));
		LIBHF_CLIENT_FOP (ctx, stub, setobject, local, loc->path, 1, loc->object);

		op_ret = stub->args.setobject_cbk.op_ret;
		errno = stub->args.setobject_cbk.op_errno;

		hf_log (LIBHF_XL_NAME, HF_LOG_DEBUG, "path %s, status %d, errno %d",
						loc->path, op_ret, errno);

		call_stub_destroy (stub);
		return op_ret;
}
int
hadafs_hlh_setobject (hadafs_handle_t handle, const char *path,
                        struct stat *buf)
 {
        int32_t op_ret = -1;
	 int32_t ret = -1;
        loc_t loc = {0, };
        libhadafs_client_ctx_t *ctx = handle;
	 char *pathres = NULL;
       
        HF_VALIDATE_OR_GOTO (LIBHF_XL_NAME, ctx, out);

        pathres = libhf_resolve_path_light ((char *)path);
        if (!pathres) {
                hf_log (LIBHF_XL_NAME, HF_LOG_ERROR, "Path compaction failed");
                goto out;
        }
        loc.path = strdup (pathres);
        if (!loc.path) {
                hf_log (LIBHF_XL_NAME, HF_LOG_ERROR, "strdup failed");
                goto out;
        }

        ret = libhf_client_loc_fill (&loc, ctx, pathres);
	 if (ret == -1) {
		hf_log ("libhadafsclient",
			HF_LOG_ERROR,
			"libhf_client_loc_fill returned -1, returning EINVAL");
		errno = EINVAL;
		goto out;
	 }

        op_ret = libhf_client_setobject (ctx, &loc, buf);
        
out:
	if (pathres) {
		FREE (pathres);
	}

        libhf_client_loc_wipe (&loc);

        return op_ret;

}

int
hadafs_setobject (const char *path, struct stat *buf)
{
        struct vmp_entry        *entry = NULL;
        int                     op_ret = -1;
        char                    vpath[PATH_MAX];

        HF_VALIDATE_OR_GOTO (LIBHF_XL_NAME, path, out);
        HF_VALIDATE_OR_GOTO (LIBHF_XL_NAME, buf, out);

        hf_log (LIBHF_XL_NAME, HF_LOG_DEBUG, "path %s", path);

        entry = libhf_vmp_search_entry_vpath ((char *)path, vpath);
        if (!entry) {
                errno = ENODEV;
                goto out;
        }

        op_ret = hadafs_hlh_setobject (entry->handle, vpath, buf);
out:
        return op_ret;
}

int32_t
libhf_client_getobject_cbk (call_frame_t *frame,
                       void *cookie,
                       xlator_t *this,
                       int32_t op_ret,
                       int32_t op_errno,
                       object_t *object)
{
        libhf_client_local_t *local = frame->local;
        local->reply_stub = fop_getobject_cbk_stub (frame, 
                                               NULL, 
                                               op_ret, 
                                               op_errno, 
                                               object);

        LIBHF_REPLY_NOTIFY (local);
        return 0;
}

int32_t 
libhf_client_getobject (libhadafs_client_ctx_t *ctx, 
                   loc_t *loc,
                   struct stat *stbuf)
{
        call_stub_t *stub = NULL;
        int32_t op_ret = 0;
		libhf_client_local_t *local = NULL;

		LIBHF_CLIENT_FOP (ctx, stub, getobject, local, loc->path, 1, loc->object);

        op_ret = stub->args.getobject_cbk.op_ret;
        errno = stub->args.getobject_cbk.op_errno;

        hf_log (LIBHF_XL_NAME, HF_LOG_DEBUG, "path %s, status %d, errno %d",
                loc->path, op_ret, errno);
        if (op_ret == 0) {
				libhf_client_metadata2stat(&(loc->object->metadata), stbuf);
        }
	    call_stub_destroy (stub);
        return op_ret;
}

int
hadafs_hlh_getobject (hadafs_handle_t handle, const char *path,
                        struct stat *buf)
 {
		 int32_t op_ret = -1;
		 int32_t ret = -1;
		 loc_t loc = {0, };
		 libhadafs_client_ctx_t *ctx = handle;
		 char *pathres = NULL;
       
        HF_VALIDATE_OR_GOTO (LIBHF_XL_NAME, ctx, out);

        pathres = libhf_resolve_path_light ((char *)path);
        if (!pathres) {
                hf_log (LIBHF_XL_NAME, HF_LOG_ERROR, "Path compaction failed");
                goto out;
        }
        loc.path = strdup (pathres);
        if (!loc.path) {
                hf_log (LIBHF_XL_NAME, HF_LOG_ERROR, "strdup failed");
                goto out;
        }

		ret = libhf_client_loc_fill (&loc, ctx, pathres);
		if (ret == -1) {
				hf_log ("libhadafsclient",
								HF_LOG_ERROR,
								"libhf_client_loc_fill returned -1, returning EINVAL");
				errno = EINVAL;
				goto out;
		}

		op_ret = libhf_client_getobject (ctx, &loc, buf);

out:
		if (pathres) {
				FREE (pathres);
		}

		libhf_client_loc_wipe (&loc);

		return op_ret;

}

int
hadafs_getobject (const char *path, struct stat *buf)
{
	
        struct vmp_entry        *entry = NULL;
        int                     op_ret = -1;
        char                    vpath[PATH_MAX];

        HF_VALIDATE_OR_GOTO (LIBHF_XL_NAME, path, out);
        HF_VALIDATE_OR_GOTO (LIBHF_XL_NAME, buf, out);

        hf_log (LIBHF_XL_NAME, HF_LOG_DEBUG, "path %s", path);

        entry = libhf_vmp_search_entry_vpath ((char *)path, vpath);
        if (!entry) {
                errno = ENODEV;
                goto out;
        }

        op_ret = hadafs_hlh_setobject (entry->handle, vpath, buf);
out:
        return op_ret;
}

static struct xlator_fops libhf_client_fops = {
};

static struct xlator_mops libhf_client_mops = {
};

static struct xlator_cbks libhf_client_cbks = {
        .forget      = libhf_client_forget,
	.release     = libhf_client_release,
};

static inline xlator_t *
libhadafs_graph (xlator_t *graph)
{
        xlator_t *top = NULL;
        xlator_list_t *xlchild, *xlparent;

        top = CALLOC (1, sizeof (*top));
        ERR_ABORT (top);

        xlchild = CALLOC (1, sizeof(*xlchild));
        ERR_ABORT (xlchild);
        xlchild->xlator = graph;
        top->children = xlchild;
        top->ctx = graph->ctx;
        top->next = graph;
        top->name = strdup (LIBHF_XL_NAME);

        xlparent = CALLOC (1, sizeof(*xlparent));
        xlparent->xlator = top;
        graph->parents = xlparent;
        asprintf (&top->type, LIBHF_XL_NAME);

        top->init = libhf_client_init;
        top->fops = &libhf_client_fops;
        top->mops = &libhf_client_mops;
        top->cbks = &libhf_client_cbks; 
        top->notify = libhf_client_notify;
        top->fini = libhf_client_fini;
        //  fill_defaults (top);

        return top;
}
