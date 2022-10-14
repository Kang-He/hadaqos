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

#include <stdio.h>
#include <string.h>
#include <stdlib.h>
#include <netinet/in.h>
#include <sys/socket.h>
#include <sys/types.h>
#include <sys/resource.h>
#include <sys/file.h>
#include <netdb.h>
#include <signal.h>
#include <libgen.h>

#include <sys/utsname.h>

#include <stdint.h>
#include <pthread.h>
#include <sys/stat.h>
#include <fcntl.h>
#include <time.h>
#include <semaphore.h>
#include <errno.h>

#ifndef _CONFIG_H
#define _CONFIG_H
#include "config.h"
#endif

#ifdef HAVE_MALLOC_H
#include <malloc.h>
#endif

#ifdef HAVE_MALLOC_STATS
#ifdef DEBUG
#include <mcheck.h>
#endif
#endif

#include "xlator.h"
#include "hadafs.h"
#include "compat.h"
#include "logging.h"
#include "dict.h"
#include "protocol.h"
#include "list.h"
#include "timer.h"
#include "hadafsd.h"
#include "stack.h"
#include "revision.h"
#include "common-utils.h"
#include "event.h"

#include <fnmatch.h>

/* using argp for command line parsing */
static char hf_doc[] = "";
static char argp_doc[] = "--volfile-server=SERVER [MOUNT-POINT]\n"       \
                         "--volfile=VOLFILE [MOUNT-POINT]";
const char *argp_program_version = "" \
            PACKAGE_NAME" "PACKAGE_VERSION" built on "__DATE__" "__TIME__ \
            "\nRepository revision: " HADAFS_REPOSITORY_REVISION "\n"  \
            "Copyright (c) 2022-2029 HADA JNS. "             \
            "HADAFS comes with ABSOLUTELY NO WARRANTY.\n"              \
            "You may redistribute copies of HADAFS under the terms of "\
            "the GNU General Public License.";
const char *argp_program_bug_address = "<" PACKAGE_BUGREPORT ">";

error_t parse_opts (int32_t key, char *arg, struct argp_state *_state);

static struct argp_option hf_options[] = {
 	{0, 0, 0, 0, "Basic options:"},
 	{"volfile", ARGP_VOLUME_FILE_KEY, "VOLFILE", 0, 
 	 "File to use as VOLUME_FILE [default: "DEFAULT_SERVER_VOLUME_FILE"]"},
 	{"server-type", ARGP_SERVER_TYPE_KEY, "TYPE", 0, 
 	 "Type of server. Valid options are GMDB and LTA"},
 	{"server-port", ARGP_SERVER_PORT_KEY, "PORT", 0, 
 	 "Listening port number of server"},
 	{"log-level", ARGP_LOG_LEVEL_KEY, "LOGLEVEL", 0, 
 	 "Logging severity.  Valid options are DEBUG, NORMAL, WARNING, ERROR, "
	 "CRITICAL and NONE [default: NORMAL]"},
 	{"log-file", ARGP_LOG_FILE_KEY, "LOGFILE", 0, 
 	 "File to use for logging [default: " 
	 DEFAULT_LOG_FILE_DIRECTORY "/" PACKAGE_NAME ".log" "]"},
 	
 	{0, 0, 0, 0, "Advanced Options:"},
 	{"pid-file", ARGP_PID_FILE_KEY, "PIDFILE", 0, 
 	 "File to use as pid file"},
 	{"no-daemon", ARGP_NO_DAEMON_KEY, 0, 0,
 	 "Run in foreground"},
 	{"run-id", ARGP_RUN_ID_KEY, "RUN-ID", OPTION_HIDDEN,
 	 "Run ID for the process, used by scripts to keep track of process "
	 "they started, defaults to none"},
 	{"debug", ARGP_DEBUG_KEY, 0, 0, 
 	 "Run in debug mode.  This option sets --no-daemon, --log-level "
	 "to DEBUG and --log-file to console"},
 	{0, 0, 0, 0, "Miscellaneous Options:"},
 	{0, }
};


static struct argp argp = { hf_options, parse_opts, argp_doc, hf_doc };

/* Make use of pipe to synchronize daemonization */
int
hf_daemon (int *pipe_fd)
{
        pid_t		pid = -1;
        int             ret = -1;
        int             hf_daemon_buff = 0;

        if (pipe (pipe_fd) < 0) {
                hf_log ("hadafs", HF_LOG_ERROR,
                        "pipe creation error- %s", strerror (errno));
                return -1;
        }

        if ((pid = fork ()) < 0) {
	        hf_log ("hadafs", HF_LOG_ERROR, "fork error: %s",
			strerror (errno));
                return -1;
        } else if (pid != 0) {
                close (pipe_fd[1]);
                ret = read (pipe_fd[0], &hf_daemon_buff,
                            sizeof (int));
                close (pipe_fd[0]);

                if (ret == -1) {
                        hf_log ("hadafs", HF_LOG_ERROR,
                                "read error on pipe- %s", strerror (errno));
                        return ret;
                } else if (ret == 0) {
                        hf_log ("hadafs", HF_LOG_ERROR,
                                "end of file- %s", strerror (errno));
                        return -1;
                } else {
                        if (hf_daemon_buff == 0)
                                exit (EXIT_SUCCESS);
                        else
                                exit (EXIT_FAILURE);
                }
        }

        /*child continues*/
        close (pipe_fd[0]);
	if (daemon (0, 0) == -1) {
		hf_log ("hadafs", HF_LOG_ERROR,
			"unable to run in daemon mode: %s",
			strerror (errno));
		return -1;
	}
        return 0;
}

static void 
_hf_dump_details (int argc, char **argv)
{
        extern FILE *hf_log_logfile;
        int          i = 0;
        char         timestr[256];
        time_t       utime = 0;
        struct tm   *tm = NULL;
	pid_t        mypid = 0;
	struct utsname uname_buf = {{0, }, };
	int            uname_ret = -1;

	utime = time (NULL);
	tm    = localtime (&utime);
	mypid = getpid ();
	uname_ret   = uname (&uname_buf);

        /* Which git? What time? */
        strftime (timestr, 256, "%Y-%m-%d %H:%M:%S", tm); 
	fprintf (hf_log_logfile, 
		 "========================================"
		 "========================================\n");
        fprintf (hf_log_logfile, "Version      : %s %s built on %s %s\n",
                 PACKAGE_NAME, PACKAGE_VERSION, __DATE__, __TIME__);
        fprintf (hf_log_logfile, "git: %s\n",
                 HADAFS_REPOSITORY_REVISION);
        fprintf (hf_log_logfile, "Starting Time: %s\n", timestr);
        fprintf (hf_log_logfile, "Command line : ");
        for (i = 0; i < argc; i++) {
                fprintf (hf_log_logfile, "%s ", argv[i]);
        }

	fprintf (hf_log_logfile, "\nPID          : %d\n", mypid);
	
	if (uname_ret == 0) {
		fprintf (hf_log_logfile, "System name  : %s\n", uname_buf.sysname);
		fprintf (hf_log_logfile, "Nodename     : %s\n", uname_buf.nodename);
		fprintf (hf_log_logfile, "Kernel Release : %s\n", uname_buf.release);
		fprintf (hf_log_logfile, "Hardware Identifier: %s\n", uname_buf.machine);
	}


        fprintf (hf_log_logfile, "\n");
        fflush (hf_log_logfile);
}

static xlator_t *
hf_get_first_xlator (xlator_t *list)
{
        xlator_t *trav = NULL, *head = NULL;
        
        trav = list;
        do {
                if (trav->prev == NULL) {
                        head = trav;
                }
                
                trav = trav->prev;
        } while (trav != NULL);
        
        return head;
}

static FILE *
_get_spec_fp (hadafs_ctx_t *ctx)
{
	int          ret = 0;
	cmd_args_t  *cmd_args = NULL;
	FILE        *specfp = NULL;
	char 	    volfile[LONG_NAME];
	struct stat  statbuf;

	cmd_args = &ctx->cmd_args;
	
	ret = stat (cmd_args->volume_file, &statbuf);
	if (ret == -1) {
		fprintf (stderr, "%s: %s\n", 
			 cmd_args->volume_file, strerror (errno));
		hf_log ("hadafs", HF_LOG_ERROR, 
			"%s: %s", cmd_args->volume_file, strerror (errno));
		return NULL;		
	}
	if (!(S_ISREG (statbuf.st_mode) || S_ISLNK (statbuf.st_mode))) {
		fprintf (stderr, 
			 "provide a valid volume file\n");
		hf_log ("hadafs", HF_LOG_ERROR, 
			"provide a valid volume file");
		return NULL;
	}
#ifdef OLD_VOLUME
       specfp = fopen(cmd_args->volume_file, "r");
#else
       specfp = gen_volfile(cmd_args->volume_file, cmd_args->server_type, 
			cmd_args->volfile_server_port);
	if (specfp == NULL) {
		fprintf (stderr, "volume file %s-%s: %s\n", 
			 cmd_args->volume_file, volfile,
			 strerror (errno));
		hf_log ("hadafs", HF_LOG_ERROR, 
			"volume file %s: %s", 
			cmd_args->volume_file, 
			strerror (errno));
		return NULL;
	}
#if 0
       sprintf(volfile, "/tmp/%s_%s_%d", basename(cmd_args->volume_file), cmd_args->server_type,
		cmd_args->volfile_server_port); 
       specfp = fopen(volfile, "r+");
       if(!specfp) {
		fprintf (stderr, "tmpfile()\n");
		return NULL;
       } 
#endif
#endif
	
	hf_log ("hadafs", HF_LOG_DEBUG, 
		"loading volume file %s", cmd_args->volume_file);
	
	return specfp;
}

static xlator_t *
_parse_spec_fp (hadafs_ctx_t *ctx, 
	       FILE *specfp)
{
        int spec_fd = 0;
	cmd_args_t *cmd_args = NULL;
	xlator_t *tree = NULL, *trav = NULL, *new_tree = NULL;
	
	cmd_args = &ctx->cmd_args;
	
	fseek (specfp, 0L, SEEK_SET);
	
	tree = file_to_xlator_tree (ctx, specfp);
	trav = tree;
	
	if (tree == NULL) {
		fprintf (stderr, 
				"error in parsing volume file %s\n", 
				cmd_args->volume_file);
		hf_log ("hadafs", HF_LOG_ERROR, 
				"error in parsing volume file %s", 
				cmd_args->volume_file);
		return NULL;
	}
	return tree;
}

static int
_log_if_option_is_invalid (xlator_t *xl, data_pair_t *pair)
{
	volume_opt_list_t *vol_opt = NULL;
	volume_option_t   *opt     = NULL;
	int i     = 0;
	int index = 0;
	int found = 0;

	/* Get the first volume_option */
	list_for_each_entry (vol_opt, &xl->volume_options, list) {
		/* Warn for extra option */
		if (!vol_opt->given_opt)
			break;

		opt = vol_opt->given_opt;
		for (index = 0; 
		     ((index < ZR_OPTION_MAX_ARRAY_SIZE) && 
		      (opt[index].key && opt[index].key[0]));  index++)
			for (i = 0; (i < ZR_VOLUME_MAX_NUM_KEY) &&
				     opt[index].key[i]; i++) {
				if (fnmatch (opt[index].key[i],
					     pair->key, 
					     FNM_NOESCAPE) == 0) {
					found = 1;
					break;
				}
			}
	}

	if (!found) {
		hf_log (xl->name, HF_LOG_WARNING,
			"option '%s' is not recognized",
			pair->key);
	}
	return 0;
}

static int 
_xlator_graph_init (xlator_t *xl)
{
	volume_opt_list_t *vol_opt = NULL;
	data_pair_t *pair = NULL;
	xlator_t *trav = NULL;
	int ret = -1;
	
	trav = xl;
	
	while (trav->prev)
		trav = trav->prev;

	/* Validate phase */
	while (trav) {
		/* Get the first volume_option */
		list_for_each_entry (vol_opt, 
				     &trav->volume_options, list) 
			break;
		if ((ret = 
		     validate_xlator_volume_options (trav, 
				     vol_opt->given_opt)) < 0) {
			hf_log (trav->name, HF_LOG_ERROR, 
				"validating translator failed");
			return ret;
		}
		trav = trav->next;
	}

	
	trav = xl;
	while (trav->prev)
		trav = trav->prev;
	/* Initialization phase */
	while (trav) {
		if (!trav->ready) {
			if ((ret = xlator_tree_init (trav)) < 0) {
				hf_log ("hadafs", HF_LOG_ERROR, 
					"initializing translator failed");
				return ret;
			}
		}
		trav = trav->next;
	}
	
	/* No error in this phase, just bunch of warning if at all */
	trav = xl;
	
	while (trav->prev)
		trav = trav->prev;
	
	/* Validate again phase */
	while (trav) {
		pair = trav->options->members_list;
		while (pair) {
			_log_if_option_is_invalid (trav, pair);
			pair = pair->next;
		}
		trav = trav->next;
	}

	return ret;
}

int 
hadafs_graph_init (xlator_t *graph, int fuse) 
{ 
	volume_opt_list_t *vol_opt = NULL;

	if (fuse) {
		/* FUSE needs to be initialized earlier than the 
		   other translators */
		list_for_each_entry (vol_opt, 
				     &graph->volume_options, list) 
			break;
		if (validate_xlator_volume_options (graph, 
					   vol_opt->given_opt) == -1) {
			hf_log (graph->name, HF_LOG_ERROR, 
				"validating translator failed");
			return -1;
		}
		if (graph->init (graph) != 0)
			return -1;
		
		graph->ready = 1;
	}
	if (_xlator_graph_init (graph) == -1)
		return -1;

	/* check server or fuse is given */
	if (graph->ctx->top == NULL) {
		fprintf (stderr, "no valid translator loaded at the top, or"
			 "no mount point given. exiting\n");
		hf_log ("hadafs", HF_LOG_ERROR, 
			"no valid translator loaded at the top or "
			"no mount point given. exiting");
		return -1;
	}

	return 0;
}

static int
hf_remember_xlator_option (struct list_head *options, char *arg)
{
	hadafs_ctx_t         *ctx = NULL;
	cmd_args_t              *cmd_args  = NULL;
	xlator_cmdline_option_t *option = NULL;
	int                      ret = -1;
	char                    *dot = NULL;
	char                    *equals = NULL;

	ctx = get_global_ctx_ptr ();
	cmd_args = &ctx->cmd_args;

	option = CALLOC (1, sizeof (xlator_cmdline_option_t));
	INIT_LIST_HEAD (&option->cmd_args);

	dot = strchr (arg, '.');
	if (!dot)
		goto out;

	option->volume = CALLOC ((dot - arg), sizeof (char));
	strncpy (option->volume, arg, (dot - arg));

	equals = strchr (arg, '=');
	if (!equals)
		goto out;

	option->key = CALLOC ((equals - dot), sizeof (char));
	strncpy (option->key, dot + 1, (equals - dot - 1));

	if (!*(equals + 1))
		goto out;

	option->value = strdup (equals + 1);
	
	list_add (&option->cmd_args, &cmd_args->xlator_options);

	ret = 0;
out:
	if (ret == -1) {
		if (option) {
			if (option->volume)
				FREE (option->volume);
			if (option->key)
				FREE (option->key);
			if (option->value)
				FREE (option->value);

			FREE (option);
		}
	}

	return ret;
}


static void
hf_add_cmdline_options (xlator_t *graph, cmd_args_t *cmd_args)
{
	int                      ret = 0;
	xlator_t                *trav = graph;
	xlator_cmdline_option_t *cmd_option = NULL;

	while (trav) {
		list_for_each_entry (cmd_option, 
				     &cmd_args->xlator_options, cmd_args) {
			if (!fnmatch (cmd_option->volume, 
				      trav->name, FNM_NOESCAPE)) {
				ret = dict_set_str (trav->options, 
						    cmd_option->key, 
						    cmd_option->value);
				if (ret == 0) {
					hf_log ("hadafs", HF_LOG_WARNING,
						"adding option '%s' for "
						"volume '%s' with value '%s'", 
						cmd_option->key, trav->name, 
						cmd_option->value);
				} else {
					hf_log ("hadafs", HF_LOG_WARNING,
						"adding option '%s' for "
						"volume '%s' failed: %s", 
						cmd_option->key, trav->name, 
						strerror (-ret));
				}
			}
		}
		trav = trav->next;
	}
}


error_t 
parse_opts (int key, char *arg, struct argp_state *state)
{
	cmd_args_t *cmd_args = NULL;
	uint32_t    n = 0;

	cmd_args = state->input;
	
	switch (key) {
	case ARGP_VOLUME_FILE_KEY:
		cmd_args->volume_file = strdup (arg);
		break;
		
	case ARGP_LOG_LEVEL_KEY:
		if (strcasecmp (arg, ARGP_LOG_LEVEL_NONE_OPTION) == 0) {
			cmd_args->log_level = HF_LOG_NONE;
			break;
		}
		if (strcasecmp (arg, ARGP_LOG_LEVEL_CRITICAL_OPTION) == 0) {
			cmd_args->log_level = HF_LOG_CRITICAL;
			break;
		}
		if (strcasecmp (arg, ARGP_LOG_LEVEL_ERROR_OPTION) == 0) {
			cmd_args->log_level = HF_LOG_ERROR;
			break;
		}
		if (strcasecmp (arg, ARGP_LOG_LEVEL_WARNING_OPTION) == 0) {
			cmd_args->log_level = HF_LOG_WARNING;
			break;
		}
		if (strcasecmp (arg, ARGP_LOG_LEVEL_NORMAL_OPTION) == 0) {
			cmd_args->log_level = HF_LOG_NORMAL;
			break;
		}
		if (strcasecmp (arg, ARGP_LOG_LEVEL_DEBUG_OPTION) == 0) {
			cmd_args->log_level = HF_LOG_DEBUG;
			break;
		}
		if (strcasecmp (arg, ARGP_LOG_LEVEL_TRACE_OPTION) == 0) {
			cmd_args->log_level = HF_LOG_TRACE;
			break;
		}
		
		argp_failure (state, -1, 0, "unknown log level %s", arg);
		break;
		
	case ARGP_LOG_FILE_KEY:
		cmd_args->log_file = strdup (arg);
		break;
		
	case ARGP_SERVER_PORT_KEY:
		n = 0;
		
		if (hf_string2uint_base10 (arg, &n) == 0) {
			cmd_args->volfile_server_port = n;
			break;
		}
		
		argp_failure (state, -1, 0, 
			      "unknown volfile server port %s", arg);
		break;
	
	case ARGP_SERVER_TYPE_KEY:
		if ((strcasecmp (arg, ARGP_SERVER_TYPE_GMDB_OPTION) == 0) || 
			(strcasecmp (arg, ARGP_SERVER_TYPE_LTA_OPTION) == 0)) {
			cmd_args->server_type = strdup(arg);	
		} else {
			argp_failure (state, -1, 0, "unknown server type %s", arg);
		}
		break;
	case ARGP_PID_FILE_KEY:
		cmd_args->pid_file = strdup (arg);
		break;
		
	case ARGP_NO_DAEMON_KEY:
		cmd_args->no_daemon_mode = ENABLE_NO_DAEMON_MODE;
		break;
		
	case ARGP_RUN_ID_KEY:
		cmd_args->run_id = strdup (arg);
		break;
		
	case ARGP_DEBUG_KEY:
		cmd_args->debug_mode = ENABLE_DEBUG_MODE;
		break;
	}

	return 0;
}


void 
cleanup_and_exit (int signum)
{
	hadafs_ctx_t *ctx = NULL;
	xlator_t        *trav = NULL;

	ctx = get_global_ctx_ptr ();
	
	hf_log ("hadafs", HF_LOG_WARNING, "shutting down");

	if (ctx->pidfp) {
		flock (fileno (ctx->pidfp), LOCK_UN);
		fclose (ctx->pidfp);
		ctx->pidfp = NULL;
	}

	if (ctx->specfp) {
		fclose (ctx->specfp);
		ctx->specfp = NULL;
	}

	if (ctx->cmd_args.pid_file) {
		unlink (ctx->cmd_args.pid_file);
		ctx->cmd_args.pid_file = NULL;
	}
	
	if (ctx->graph) {
		trav = ctx->graph;
		ctx->graph = NULL;
		while (trav) {
			trav->fini (trav);
			trav = trav->next;
		}
		exit (0);
	} else {
		hf_log ("hadafs", HF_LOG_DEBUG, "no graph present");
	}
}


static char *
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

#define HF_SERVER_PROCESS 0
#define HF_CLIENT_PROCESS 1

static uint8_t
hf_get_process_mode (char *exec_name)
{
	char *dup_execname = NULL, *base = NULL;
	uint8_t ret = 0;

	dup_execname = strdup (exec_name);
	base = basename (dup_execname);
	
	if (!strncmp (base, "hadafsd", 10)) {
		ret = HF_SERVER_PROCESS;
	} else {
		ret = HF_CLIENT_PROCESS;
	}
	
	free (dup_execname);

	return ret;
}

void 
set_log_file_path (cmd_args_t *cmd_args)
{
        int   i = 0;
        int   port = 0;
        char *tmp_ptr = NULL;
        char  tmp_str[1024] = {0,};
        
        if (cmd_args->mount_point) {
                for (i = 1; i < strlen (cmd_args->mount_point); i++) {
                        tmp_str[i-1] = cmd_args->mount_point[i];
                        if (cmd_args->mount_point[i] == '/')
                                tmp_str[i-1] = '-';
                }
                asprintf (&cmd_args->log_file, 
                          DEFAULT_LOG_FILE_DIRECTORY "/%s.log",
                          tmp_str);

                goto done;
        } 

        if (cmd_args->volume_file) {
                for (i = 0; i < strlen (cmd_args->volume_file); i++) {
                        tmp_str[i] = cmd_args->volume_file[i];
                        if (cmd_args->volume_file[i] == '/')
                                tmp_str[i] = '-';
                }
                asprintf (&cmd_args->log_file, 
                          DEFAULT_LOG_FILE_DIRECTORY "/%s.log",
                          tmp_str);
                
                goto done;
        }
        
        if (cmd_args->volfile_server) {
                port = 1;
                tmp_ptr = "default";

                if (cmd_args->volfile_server_port)
                        port = cmd_args->volfile_server_port;
                if (cmd_args->volfile_id)
                        tmp_ptr = cmd_args->volfile_id;

                asprintf (&cmd_args->log_file, 
                          DEFAULT_LOG_FILE_DIRECTORY "/%s-%s-%d.log",
                          cmd_args->volfile_server, tmp_ptr, port);
        }

 done:
        return;
}

int 
main (int argc, char *argv[])
{
	hadafs_ctx_t  *ctx = NULL;
	cmd_args_t       *cmd_args = NULL;
	call_pool_t      *pool = NULL;
	struct stat       stbuf;
	char              tmp_logfile[1024] = { 0 };
	char              timestr[256] = { 0 };
	time_t            utime;
	struct tm        *tm = NULL;
	int               ret = 0;
	struct rlimit     lim;
	FILE             *specfp = NULL;
	xlator_t         *graph = NULL;
	xlator_t         *trav = NULL;
	int               xl_count = 0;
	uint8_t           process_mode = 0;
        int               pipe_fd[2];
        int               hf_success = 0;
        int               hf_failure = -1;

        utime = time (NULL);
	ctx = CALLOC (1, sizeof (hadafs_ctx_t));
	ERR_ABORT (ctx);
	process_mode = hf_get_process_mode (argv[0]);
	set_global_ctx_ptr (ctx);
	ctx->process_uuid = zr_build_process_uuid ();
	cmd_args = &ctx->cmd_args;

	/* parsing command line arguments */
	cmd_args->log_level = DEFAULT_LOG_LEVEL;
	
	INIT_LIST_HEAD (&cmd_args->xlator_options);

	argp_parse (&argp, argc, argv, ARGP_IN_ORDER, NULL, cmd_args);

	if (ENABLE_DEBUG_MODE == cmd_args->debug_mode) {
		cmd_args->log_level = HF_LOG_DEBUG;
		cmd_args->log_file = "/dev/stdout";
		cmd_args->no_daemon_mode = ENABLE_NO_DAEMON_MODE;
	}

	if ((cmd_args->volfile_server == NULL) 
	    && (cmd_args->volume_file == NULL)) {
		cmd_args->volume_file = strdup (DEFAULT_SERVER_VOLUME_FILE);
	}

	if (cmd_args->log_file == NULL)
                set_log_file_path (cmd_args);

        //ctx->page_size  = 256 * HF_UNIT_KB;
        ctx->page_size  = 1024 * HF_UNIT_KB;
        ctx->iobuf_pool = iobuf_pool_new (2000 * 1048576, ctx->page_size + 4096);
	ctx->event_pool = event_pool_new (DEFAULT_EVENT_POOL_SIZE);
	ERR_ABORT (ctx->event_pool);
	pthread_mutex_init (&(ctx->lock), NULL);
	pool = ctx->pool = CALLOC (1, sizeof (call_pool_t));
	ERR_ABORT (ctx->pool);
	LOCK_INIT (&pool->lock);
	INIT_LIST_HEAD (&pool->all_frames);

        /* initializing logs */
	if (cmd_args->run_id) {
		ret = stat (cmd_args->log_file, &stbuf);
		/* If its /dev/null, or /dev/stdout, /dev/stderr, 
		 * let it use the same, no need to alter 
		 */
		if (((ret == 0) && 
		     (S_ISREG (stbuf.st_mode) || S_ISLNK (stbuf.st_mode))) || 
		    (ret == -1)) {
			/* Have seperate logfile per run */
			tm = localtime (&utime);
			strftime (timestr, 256, "%Y%m%d.%H%M%S", tm); 
			sprintf (tmp_logfile, "%s.%s.%d", 
				 cmd_args->log_file, timestr, getpid ());
			
			/* Create symlink to actual log file */
			unlink (cmd_args->log_file);
			symlink (tmp_logfile, cmd_args->log_file);
			
			FREE (cmd_args->log_file);
			cmd_args->log_file = strdup (tmp_logfile);
		}
	}
	
	hf_global_variable_init ();

	hf_log_set_loglevel (cmd_args->log_level);

	if (hf_log_init (cmd_args->log_file) == -1) {
		fprintf (stderr, 
			 "failed to open logfile %s.  exiting\n", 
			 cmd_args->log_file);
		return -1;
	}
	
	/* setting up environment  */
	lim.rlim_cur = RLIM_INFINITY;
	lim.rlim_max = RLIM_INFINITY;
	if (setrlimit (RLIMIT_CORE, &lim) == -1) {
		fprintf (stderr, "ignoring %s\n", 
			 strerror (errno));
	}
#ifdef HAVE_MALLOC_STATS
#ifdef DEBUG
	mtrace ();
#endif
	signal (SIGUSR1, (sighandler_t) malloc_stats);
#endif
	signal (SIGSEGV, hf_print_trace);
	signal (SIGABRT, hf_print_trace);
	signal (SIGPIPE, SIG_IGN);
	signal (SIGHUP, hf_log_logrotate);
	signal (SIGTERM, cleanup_and_exit);
	/* This is used to dump details */
	/* signal (SIGUSR2, (sighandler_t) hadafs_stats); */
	
	/* getting and parsing volume file */
	if ((specfp = _get_spec_fp (ctx)) == NULL) {
		/* _get_spec_fp() prints necessary error message  */
		hf_log ("hadafs", HF_LOG_ERROR, "exiting\n");
		argp_help (&argp, stderr, ARGP_HELP_SEE, (char *) argv[0]);
		return -1;
	}

	if ((graph = _parse_spec_fp (ctx, specfp)) == NULL) {
		/* _parse_spec_fp() prints necessary error message */
		fprintf (stderr, "exiting\n");
		hf_log ("hadafs", HF_LOG_ERROR, "exiting");
		return -1;
	}
	ctx->specfp = specfp;
	
	/* check whether MOUNT-POINT argument and fuse volume are given
	 * at same time or not. If not, add argument MOUNT-POINT to graph 
	 * as top volume if given 
	 */
	trav = graph;
	
	while (trav) {
		xl_count++;  /* Getting this value right is very important */
		trav = trav->next;
	}
	
	ctx->xl_count = xl_count + 1;
		
	/* daemonize now */
	if (!cmd_args->no_daemon_mode) {
                if (hf_daemon (pipe_fd) == -1) {
			hf_log ("hadafs", HF_LOG_ERROR,
				"unable to run in daemon mode: %s",
				strerror (errno));
			return -1;
		}
		
		/* we are daemon now */
                _hf_dump_details (argc, argv);
                if (cmd_args->pid_file != NULL) {
                        ctx->pidfp = fopen (cmd_args->pid_file, "a+");
                        if (ctx->pidfp == NULL) {
                                hf_log ("hadafs", HF_LOG_ERROR,
                                        "unable to open pid file %s, %s.",
                                        cmd_args->pid_file,
                                        strerror (errno));
                                if (write (pipe_fd[1], &hf_failure, 
                                           sizeof (int)) < 0) {
                                        hf_log ("hadafs", HF_LOG_ERROR,
                                                "Write on pipe error");
                                }

                                /* do cleanup and exit ?! */
                                return -1;
                        }
                        ret = flock (fileno (ctx->pidfp),
                                     (LOCK_EX | LOCK_NB));
                        if (ret == -1) {
                                hf_log ("hadafs", HF_LOG_ERROR,
                                       "Is another instance of %s running?",
                                        argv[0]);
                                fclose (ctx->pidfp);
                                if (write (pipe_fd[1], &hf_failure, 
                                           sizeof (int)) < 0) {
                                        hf_log ("hadafs", HF_LOG_ERROR,
                                                "Write on pipe error");
                                }

                                return ret;
                        }
                        ret = ftruncate (fileno (ctx->pidfp), 0);
                        if (ret == -1) {
                                hf_log ("hadafs", HF_LOG_ERROR,
                                        "unable to truncate file %s. %s.",
                                        cmd_args->pid_file,
                                        strerror (errno));
                                flock (fileno (ctx->pidfp), LOCK_UN);
                                fclose (ctx->pidfp);
                                if (write (pipe_fd[1], &hf_failure, 
                                           sizeof (int)) < 0) {
                                        hf_log ("hadafs", HF_LOG_ERROR,
                                                "Write on pipe error");
                                }

                                return ret;
                        }

                        /* update pid file, if given */
                        fprintf (ctx->pidfp, "%d\n", getpid ());
                        fflush (ctx->pidfp);
                        /* we close pid file on exit */
                }
        } else {
                /*
                 * Need to have this line twice because PID is different
                 * in daemon and non-daemon cases.
                 */

                _hf_dump_details (argc, argv);
        }

        hf_log_volume_file (ctx->specfp);

	hf_log ("hadafs", HF_LOG_DEBUG, 
		"running in pid %d", getpid ());
	
	hf_timer_registry_init (ctx);

	/* override xlator options with command line options
	 * where applicable 
	 */
	hf_add_cmdline_options (graph, cmd_args);

	ctx->graph = graph;
	if (hadafs_graph_init (graph, 0) != 0) {
		hf_log ("hadafs", HF_LOG_ERROR,
			"translator initialization failed.  exiting");
		if (!cmd_args->no_daemon_mode &&
                    (write (pipe_fd[1], &hf_failure, sizeof (int)) < 0)) {
			hf_log ("hadafs", HF_LOG_ERROR,
                                "Write on pipe failed,"
                                "daemonize problem.exiting: %s",
                                 strerror (errno));
                }

                return -1;
	}


	/* Send PARENT_UP notify to all the translators now */
	graph->notify (graph, HF_EVENT_PARENT_UP, ctx->graph);

	hf_log ("hadafs", HF_LOG_NORMAL, "Successfully started");

	if (!cmd_args->no_daemon_mode &&
            (write (pipe_fd[1], &hf_success, sizeof (int)) < 0)) {
		hf_log ("hadafs", HF_LOG_ERROR,
                        "Write on pipe failed,"
                        "daemonize problem.  exiting: %s",
                         strerror (errno));
		return -1;
	}

        event_dispatch (ctx->event_pool);

	return 0;
}
