#ifndef _CONFIG_H
#define _CONFIG_H
#include "config.h"
#endif

#include "call-stub.h"
#include "hadafs.h"
#include "logging.h"
#include "dict.h"
#include "xlator.h"
#include "io-threads.h"
#include <stdlib.h>
#include <sys/time.h>
#include <time.h>
#include "locking.h"

void *iot_worker (void *arg);
int iot_workers_scale (iot_conf_t *conf);
int __iot_workers_scale (iot_conf_t *conf);

inline void 
update_queue_size(overall_status_t *status, int length)
{
    status->queue_sample = length;        
}

void
record_log(overall_status_t *status, double whole_time, 
                     double exe_time, int type)
{
    /* type 0: read, 1: write, 2: metadata */
    char type_string[3][20] = {"Read", "Write", "Meta"};
    double min_time = 1e-5;
    int i;
    //hf_log("Record_log", HF_LOG_DEBUG, "here1\n");
    for (i = 0; i < 8; i++) {
        if ((whole_time - exe_time) < min_time) { 
            __sync_fetch_and_add(&(status->wait_data[type][i]), 1);
            break;
        }
        min_time *= 10;
    }
    
    min_time = 1e-5;
    for (i = 0; i < 8; i++) {
        if ((exe_time) < min_time) { 
            __sync_fetch_and_add(&(status->exe_data[type][i]), 1);
            break;
        }
        min_time *= 10;
    }

    //status->opt_times++;
    __sync_fetch_and_add(&(status->opt_times), 1);

    if (status->opt_times % REDUCE_TIME == 0) {
        //hf_log("Record_log", HF_LOG_DEBUG, "here2\n");
        for (type = 0; type < 3; type++) {
            hf_log("[Trace]", HF_LOG_NORMAL, 
                   "%s wait: %ld %ld %ld %ld %ld %ld %ld %ld",
                   type_string[type], status->wait_data[type][0], 
                   status->wait_data[type][1], status->wait_data[type][2],
                   status->wait_data[type][3], status->wait_data[type][4],
                   status->wait_data[type][5], status->wait_data[type][6],
                   status->wait_data[type][7]);
            
            hf_log("[Trace]", HF_LOG_NORMAL, 
                   "%s exe: %ld %ld %ld %ld %ld %ld %ld %ld",
                   type_string[type], status->exe_data[type][0], 
                   status->exe_data[type][1], status->exe_data[type][2],
                   status->exe_data[type][3], status->exe_data[type][4],
                   status->exe_data[type][5], status->exe_data[type][6],
                   status->exe_data[type][7]);
            
        }
        hf_log("[Trace]", HF_LOG_NORMAL, "queue length: %ld", 
               status->queue_sample);
    }
}

call_stub_t *
__iot_dequeue (iot_conf_t *conf)
{
        call_stub_t  *stub = NULL;
        int           i = 0;

        for (i = 0; i < IOT_PRI_MAX; i++) {
                if (list_empty (&conf->reqs[i]))
                        continue;
                stub = list_entry (conf->reqs[i].next, call_stub_t, list);
                break;
        }

        if (!stub)
                return NULL;

        conf->queue_size--;
#ifdef TRACE_THREAD
   update_queue_size(pool_status, conf->queue_size);
#endif
        list_del_init (&stub->list);

        return stub;
}


void
__iot_enqueue (iot_conf_t *conf, call_stub_t *stub, int pri)
{
        if (pri < 0 || pri >= IOT_PRI_MAX)
                pri = IOT_PRI_MAX-1;

        list_add_tail (&stub->list, &conf->reqs[pri]);

        conf->queue_size++;

        return;
}


void *
iot_worker (void *data)
{
        iot_conf_t       *conf = NULL;
        xlator_t         *this = NULL;
        call_stub_t      *stub = NULL;
        struct timespec   sleep_till = {0, };
        int               ret = 0;
        char              timeout = 0;
        char              bye = 0;

        conf = data;
        this = conf->this;
        //THIS = this;

        for (;;) {
                sleep_till.tv_sec = time (NULL) + conf->idle_time;

                pthread_mutex_lock (&conf->mutex);
                {
                        while (conf->queue_size == 0) {

                                ret = pthread_cond_timedwait (&conf->cond,
                                                              &conf->mutex,
                                                              &sleep_till);
                                if (ret == ETIMEDOUT)
					break;
                        }
                        stub = __iot_dequeue (conf);
                }
                pthread_mutex_unlock (&conf->mutex);

                if (stub) /* guard against spurious wakeups */
                        call_resume (stub);
        }

        return NULL;
}


int
do_iot_schedule (iot_conf_t *conf, call_stub_t *stub, int pri)
{
        int   ret = 0;

        pthread_mutex_lock (&conf->mutex);
        {
                __iot_enqueue (conf, stub, pri);
                pthread_cond_signal (&conf->cond);
        }
        pthread_mutex_unlock (&conf->mutex);

        return ret;
}


int
iot_schedule_slow (iot_conf_t *conf, call_stub_t *stub)
{
        return do_iot_schedule (conf, stub, IOT_PRI_LO);
}


int
iot_schedule_fast (iot_conf_t *conf, call_stub_t *stub)
{
        return do_iot_schedule (conf, stub, IOT_PRI_HI);
}

int
iot_schedule (iot_conf_t *conf, call_stub_t *stub)
{
        return do_iot_schedule (conf, stub, IOT_PRI_NORMAL);
}


int
iot_open_cbk (call_frame_t *frame, void *cookie, xlator_t *this, int32_t op_ret,
              int32_t op_errno, fd_t *fd, object_t *object, struct stat *stbuf)
{
#ifdef TRACE_THREAD
    struct  timeval time_end;
    int time_create_diff = 0;
    int time_execute_diff = 0;

    gettimeofday(&time_end, NULL);
    trace_info_t *trace_info = frame->local;
    
    if (!trace_info) {
        hf_log(this->name, HF_LOG_ERROR, "trace_info is empty");
    }
    else {
        time_create_diff = 1e6 * (time_end.tv_sec - trace_info->create.tv_sec) + 
                (time_end.tv_usec - trace_info->create.tv_usec);
        time_execute_diff = 1e6 * (time_end.tv_sec - trace_info->execute.tv_sec) + 
                (time_end.tv_usec - trace_info->execute.tv_usec);
        
        record_log(pool_status, time_create_diff / 1.0e6, 
                   time_execute_diff / 1.0e6, 2);
        //hf_log(this->name, HF_LOG_NORMAL, "ino: %lu, whole: %lf, exe: %lf", 
        //       trace_info->ino, time_create_diff / 1.0e6, time_execute_diff / 1.0e6);
    }
#endif
	STACK_UNWIND (frame, op_ret, op_errno, fd, object, stbuf);
	return 0;
}


int
iot_open_wrapper (call_frame_t * frame, xlator_t * this, loc_t *loc,
                  int32_t flags, mode_t mode, fd_t * fd)
{
#ifdef TRACE_THREAD
    trace_info_t *trace_info = frame->local;
    gettimeofday(&(trace_info->execute), NULL);
#endif
	STACK_WIND (frame, iot_open_cbk, FIRST_CHILD (this),
                    FIRST_CHILD (this)->fops->open, loc, flags, mode, fd);
	return 0;
}


int
iot_open (call_frame_t *frame, xlator_t *this, loc_t *loc, int32_t flags,
          mode_t mode, fd_t *fd)
{
        call_stub_t	*stub = NULL;
        int             ret = -1;

#ifdef TRACE_THREAD
    //overall_status_t *overall_status = NULL;
    trace_info_t *trace_info = NULL;
    
    trace_info = (trace_info_t *) CALLOC(1, sizeof(trace_info_t));
    
    gettimeofday(&(trace_info->create), NULL);
   
    frame->local = trace_info;
    //hf_log(this->name, HF_LOG_DEBUG, "here2 %ld", trace_info->ino);
#endif
        stub = fop_open_stub (frame, iot_open_wrapper, loc, flags, mode, fd);
        if (!stub) {
                hf_log (this->name, HF_LOG_ERROR,
                        "cannot create open call stub"
                        "(out of memory)");
                ret = -ENOMEM;
                goto out;
        }

	ret = iot_schedule_fast (this->private, stub);

out:
        if (ret < 0) {
                STACK_UNWIND (frame, -1, -ret, NULL);

                if (stub != NULL) {
                        call_stub_destroy (stub);
                }
        }

	return 0;
}



int
iot_readv_cbk (call_frame_t *frame, void *cookie, xlator_t *this,
               int32_t op_ret, int32_t op_errno, struct iovec *vector,
               int32_t count, struct stat *stbuf, struct iobref *iobref)
{
#ifdef TRACE_THREAD
    struct timeval time_end;
    int time_create_diff = 0;
    int time_execute_diff = 0;

    gettimeofday(&time_end, NULL);
    trace_info_t *trace_info = frame->local;
    
    if (!trace_info) {
        hf_log(this->name, HF_LOG_ERROR, "trace_info is empty");
    }
    else {
        //hf_log(this->name, HF_LOG_DEBUG, "here");
        time_create_diff = 1e6 * (time_end.tv_sec - trace_info->create.tv_sec) + 
                (time_end.tv_usec - trace_info->create.tv_usec);
        time_execute_diff = 1e6 * (time_end.tv_sec - trace_info->execute.tv_sec) + 
                (time_end.tv_usec - trace_info->execute.tv_usec);

        record_log(pool_status, time_create_diff / 1.0e6, 
                   time_execute_diff / 1.0e6, 0);
        //hf_log(this->name, HF_LOG_NORMAL, "ino: %lu, whole: %lf, exe: %lf", 
        //       trace_info->overall_status->ino, time_create_diff / 1.0e6, time_execute_diff / 1.0e6);
    }
#endif
	STACK_UNWIND (frame, op_ret, op_errno, vector, count,
                             stbuf, iobref);

	return 0;
}


int
iot_readv_wrapper (call_frame_t *frame, xlator_t *this, fd_t *fd, size_t size,
                   off_t offset)
{
#ifdef TRACE_THREAD
    trace_info_t *trace_info = frame->local;
    
    if (trace_info != NULL)
        gettimeofday(&(trace_info->execute), NULL);
#endif
	STACK_WIND (frame, iot_readv_cbk,
		    FIRST_CHILD(this),
		    FIRST_CHILD(this)->fops->readv,
		    fd, size, offset);
	return 0;
}


int
iot_readv (call_frame_t *frame, xlator_t *this, fd_t *fd, size_t size,
           off_t offset)
{
	call_stub_t *stub = NULL;
        int         ret = -1;
#ifdef TRACE_THREAD
    trace_info_t *trace_info = NULL;
    trace_info = (trace_info_t*) CALLOC(1, sizeof(trace_info_t));
    
    if (!trace_info)
        hf_log(this->name, HF_LOG_ERROR, "No Mem");
    else {
        //fd_ctx_get(fd, this, &tmp_overall_status);
        //trace_info->overall_status = (overall_status_t *) (long)tmp_overall_status;
        
        if (!pool_status) 
            hf_log (this->name, HF_LOG_ERROR, "File status is empty");
        else {
            gettimeofday(&(trace_info->create), NULL);
            frame->local = trace_info;
        }
    }
#endif

	stub = fop_readv_stub (frame, iot_readv_wrapper, fd, size, offset);
	if (!stub) {
		hf_log (this->name, HF_LOG_ERROR,
	"cannot create readv call stub"
                        "(out of memory)");
                ret = -ENOMEM;
                goto out;
	}

        ret = iot_schedule_slow (this->private, stub);

out:
        if (ret < 0) {
		STACK_UNWIND (frame, -1, -ret, NULL, -1, NULL,
                                     NULL);
                if (stub != NULL) {
                        call_stub_destroy (stub);
                }
        }
	return 0;
}


int
iot_flush_cbk (call_frame_t *frame, void *cookie, xlator_t *this,
               int32_t op_ret, int32_t op_errno, struct stat *stbuf)
{
#ifdef TRACE_THREAD
    struct timeval time_end;
    int time_create_diff = 0;
    int time_execute_diff = 0;

    gettimeofday(&time_end, NULL);
    trace_info_t *trace_info = frame->local;
    
    if (!trace_info) {
        hf_log(this->name, HF_LOG_ERROR, "trace_info is empty");
    }
    else {
        time_create_diff = 1e6 * (time_end.tv_sec - trace_info->create.tv_sec) + 
                (time_end.tv_usec - trace_info->create.tv_usec);
        time_execute_diff = 1e6 * (time_end.tv_sec - trace_info->execute.tv_sec) + 
                (time_end.tv_usec - trace_info->execute.tv_usec);

        record_log(pool_status, time_create_diff / 1.0e6, 
                   time_execute_diff / 1.0e6, 2);
        //hf_log(this->name, HF_LOG_NORMAL, "ino: %lu, whole: %lf, exe: %lf", 
        //       trace_info->ino, time_create_diff / 1.0e6, time_execute_diff / 1.0e6);
    
    }
#endif
	STACK_UNWIND (frame, op_ret, op_errno);
	return 0;
}


int
iot_flush_wrapper (call_frame_t *frame, xlator_t *this, fd_t *fd)
{
#ifdef TRACE_THREAD
    trace_info_t *trace_info = frame->local;
    if (trace_info != NULL)
        gettimeofday(&(trace_info->execute), NULL);
#endif
	STACK_WIND (frame, iot_flush_cbk,
		    FIRST_CHILD(this),
		    FIRST_CHILD(this)->fops->flush,
		    fd);
	return 0;
}


int
iot_flush (call_frame_t *frame, xlator_t *this, fd_t *fd)
{
	call_stub_t *stub = NULL;
        int         ret = -1;

#ifdef TRACE_THREAD
    trace_info_t *trace_info = NULL;
    trace_info = (trace_info_t *) CALLOC(1, sizeof(trace_info_t));

    if (!trace_info)
        hf_log(this->name, HF_LOG_ERROR, "No Mem");
    else {
        gettimeofday(&(trace_info->create), NULL);
        frame->local = trace_info;
    }

#endif
	stub = fop_flush_stub (frame, iot_flush_wrapper, fd);
	if (!stub) {
		hf_log (this->name, HF_LOG_ERROR,
                        "cannot create flush_cbk call stub"
                        "(out of memory)");
                ret = -ENOMEM;
                goto out;
	}

        ret = iot_schedule (this->private, stub);
out:
        if (ret < 0) {
		STACK_UNWIND (frame, -1, -ret);

                if (stub != NULL) {
                        call_stub_destroy (stub);
                }
        }
	return 0;
}



int
iot_writev_cbk (call_frame_t *frame, void *cookie, xlator_t *this,
                int32_t op_ret, int32_t op_errno, 
                struct stat *postbuf)
{
#ifdef TRACE_THREAD
    struct timeval time_end;
    int time_create_diff = 0;
    int time_execute_diff = 0;

    gettimeofday(&time_end, NULL);
    trace_info_t *trace_info = frame->local;
    if (!trace_info) {
        hf_log(this->name, HF_LOG_ERROR, "trace_info is empty");
    }
    else {
        time_create_diff = 1e6 * (time_end.tv_sec - trace_info->create.tv_sec) + 
                (time_end.tv_usec - trace_info->create.tv_usec);
        time_execute_diff = 1e6 * (time_end.tv_sec - trace_info->execute.tv_sec) + 
                (time_end.tv_usec - trace_info->execute.tv_usec);
        
        record_log(pool_status, time_create_diff / 1.0e6, 
                         time_execute_diff / 1.0e6, 1);
    }
#endif
	STACK_UNWIND (frame, op_ret, op_errno, postbuf);
	return 0;
}


int
iot_writev_wrapper (call_frame_t *frame, xlator_t *this, fd_t *fd,
                    struct iovec *vector, int32_t count,
                    off_t offset, struct iobref *iobref)
{
#ifdef TRACE_THREAD
    trace_info_t *trace_info = frame->local;
    gettimeofday(&(trace_info->execute), NULL);
#endif
	STACK_WIND (frame, iot_writev_cbk,
		    FIRST_CHILD(this),
		    FIRST_CHILD(this)->fops->writev,
		    fd, vector, count, offset, iobref);
	return 0;
}


int
iot_writev (call_frame_t *frame, xlator_t *this, fd_t *fd,
            struct iovec *vector, int32_t count, off_t offset,
            struct iobref *iobref)
{
	call_stub_t *stub = NULL;
        int         ret = -1;

#ifdef TRACE_THREAD
    trace_info_t *trace_info = NULL;
    trace_info = (trace_info_t *) CALLOC(1, sizeof(trace_info_t));

    if (!trace_info)
        hf_log(this->name, HF_LOG_ERROR, "No Mem");
    else {
        //fd_ctx_get(fd, this, &tmp_overall_status);
        //trace_info->overall_status = (overall_status_t *) (long)tmp_overall_status;
    
        if (!pool_status) 
            hf_log (this->name, HF_LOG_ERROR, "File status is empty");
        else {
            gettimeofday(&(trace_info->create), NULL);
            frame->local = trace_info;
        }
    }
    //hf_log(this->name, HF_LOG_DEBUG, "here2 %ld", trace_info->ino);
#endif
	stub = fop_writev_stub (frame, iot_writev_wrapper,
				fd, vector, count, offset, iobref);

	if (!stub) {
		hf_log (this->name, HF_LOG_ERROR,
                        "cannot create writev call stub"
                        "(out of memory)");
                ret = -ENOMEM;
                goto out;
	}

        ret = iot_schedule_slow (this->private, stub);
out:
        if (ret < 0) {
		STACK_UNWIND (frame, -1, -ret, NULL, NULL);

                if (stub != NULL) {
                        call_stub_destroy (stub);
                }
        }

	return 0;
}



int
iot_fstat_cbk (call_frame_t *frame, void *cookie, xlator_t *this,
               int32_t op_ret, int32_t op_errno, struct stat *buf)
{
	STACK_UNWIND (frame, op_ret, op_errno, buf);
	return 0;
}


int
iot_fstat_wrapper (call_frame_t *frame, xlator_t *this, fd_t *fd)
{
	STACK_WIND (frame, iot_fstat_cbk,
		    FIRST_CHILD(this),
		    FIRST_CHILD(this)->fops->fstat,
		    fd);
	return 0;
}


int
iot_fstat (call_frame_t *frame, xlator_t *this, fd_t *fd)
{
	call_stub_t *stub = NULL;
        int         ret = -1;

	stub = fop_fstat_stub (frame, iot_fstat_wrapper, fd);
	if (!stub) {
		hf_log (this->name, HF_LOG_ERROR,
                        "cannot create fop_fstat call stub"
                        "(out of memory)");
                ret = -ENOMEM;
                goto out;
	}

        ret = iot_schedule_fast (this->private, stub);
out:
        if (ret < 0) {
		STACK_UNWIND (frame, -1, -ret, NULL);

                if (stub != NULL) {
                        call_stub_destroy (stub);
                }
        }
	return 0;
}



int
iot_unlink_cbk (call_frame_t *frame, void *cookie, xlator_t *this,
		int32_t op_ret, int32_t op_errno)
{
	STACK_UNWIND (frame, op_ret, op_errno);
	return 0;
}


int
iot_unlink_wrapper (call_frame_t *frame, xlator_t *this, loc_t *loc)
{
	STACK_WIND (frame, iot_unlink_cbk,
		    FIRST_CHILD(this),
		    FIRST_CHILD(this)->fops->unlink,
		    loc);
	return 0;
}


int
iot_unlink (call_frame_t *frame, xlator_t *this, loc_t *loc)
{
	call_stub_t *stub = NULL;
        int         ret = -1;

	stub = fop_unlink_stub (frame, iot_unlink_wrapper, loc);
	if (!stub) {
		hf_log (this->name, HF_LOG_ERROR,
                        "cannot create fop_unlink call stub"
                        "(out of memory)");
                ret = -1;
                goto out;
	}

        ret = iot_schedule (this->private, stub);

out:
        if (ret < 0) {
		STACK_UNWIND (frame, -1, -ret, NULL, NULL);

                if (stub != NULL) {
                        call_stub_destroy (stub);
                }
        }

	return 0;
}

/* Do not create work threads dynamic, just create them according to "max_count". */
int
__iot_workers_scale (iot_conf_t *conf)
{
    pthread_t thread;
	int ret = 0;
	int i; 

	hf_log(conf->this->name, HF_LOG_NORMAL, "max_count=%d.",conf->max_count);
	
	for(i=0; i<(conf->max_count); i++){
			ret = pthread_create (&thread, &conf->w_attr, iot_worker, conf);
			if (ret == 0) {
					conf->curr_count++;
					hf_log (conf->this->name, HF_LOG_DEBUG,
									"scaled threads to %d.",
									conf->curr_count);
			} else {
					break;
			}
	}
}

int
iot_workers_scale (iot_conf_t *conf)
{
     int     ret = -1;

     if (conf == NULL) {
             ret = -EINVAL;
             goto out;
     }

     pthread_mutex_lock (&conf->mutex);
     {
             ret = __iot_workers_scale (conf);
     }
     pthread_mutex_unlock (&conf->mutex);

out:
     return ret;
}


void
set_stack_size (iot_conf_t *conf)
{
        int     err = 0;
        size_t  stacksize = IOT_THREAD_STACK_SIZE;

        pthread_attr_init (&conf->w_attr);
        err = pthread_attr_setstacksize (&conf->w_attr, stacksize);
        if (err == EINVAL) {
                hf_log (conf->this->name, HF_LOG_WARNING,
                        "Using default thread stack size");
        }
}

int
init (xlator_t *this)
{
        iot_conf_t      *conf = NULL;
        dict_t          *options = this->options;
        int              thread_count = IOT_DEFAULT_THREADS;
        int              idle_time = IOT_DEFAULT_IDLE;
        int              ret = -1;
        int              i = 0;

	if (!this->children || this->children->next) {
		hf_log ("sw-threads", HF_LOG_ERROR,
			"FATAL: iot not configured with exactly one child");
                goto out;
	}

	if (!this->parents) {
		hf_log (this->name, HF_LOG_WARNING,
			"dangling volume. check volfile ");
	}

	conf = (void *) CALLOC (1, sizeof (*conf));
        if (conf == NULL) {
                hf_log (this->name, HF_LOG_ERROR,
                        "out of memory");
                goto out;
        }

        set_stack_size (conf);

        thread_count = IOT_DEFAULT_THREADS;
#ifdef TRACE_THREAD
    //Alloc the memory for the tracer
    pool_status = (void *) CALLOC(1, sizeof(overall_status_t));
    if (pool_status == NULL) {
        hf_log (this->name, HF_LOG_ERROR,
                "out of memory");
        goto out;
    }

    //Init the tracer
    pool_status->opt_times = 0;
    memset(pool_status->wait_data, 0, sizeof(pool_status->wait_data));
    memset(pool_status->exe_data, 0, sizeof(pool_status->exe_data));
#endif
	if (dict_get (options, "thread-count")) {
                thread_count = data_to_int32 (dict_get (options,
                                                        "thread-count"));
                if (thread_count < IOT_MIN_THREADS) {
                        hf_log ("sw-threads", HF_LOG_WARNING,
                                "Number of threads opted is less then min"
                                "threads allowed scaling it up to min");
                        thread_count = IOT_MIN_THREADS;
                }
                if (thread_count > IOT_MAX_THREADS) {
                        hf_log ("sw-threads", HF_LOG_WARNING,
                                "Number of threads opted is more then max"
                                " threads allowed scaling it down to max");
                        thread_count = IOT_MAX_THREADS;
                }
        }
        conf->max_count = thread_count;

	if (dict_get (options, "idle-time")) {
                idle_time = data_to_int32 (dict_get (options,
                                                     "idle-time"));
                if (idle_time < 0)
                        idle_time = 1;
        }
        conf->idle_time = idle_time;

        conf->this = this;

        for (i = 0; i < IOT_PRI_MAX; i++) {
                INIT_LIST_HEAD (&conf->reqs[i]);
        }

	ret = iot_workers_scale (conf);

        if (ret == -1) {
                hf_log (this->name, HF_LOG_ERROR,
                        "cannot initialize worker threads, exiting init");
                FREE (conf);
                goto out;
        }

	this->private = conf;
        ret = 0;
out:
	return ret;
}


void
fini (xlator_t *this)
{
	iot_conf_t *conf = this->private;

	FREE (conf);

	this->private = NULL;
	return;
}


struct xlator_fops fops = {
	.open        = iot_open,
	.readv       = iot_readv,
	.writev      = iot_writev,
	.flush       = iot_flush,
	.fstat       = iot_fstat,
	.unlink      = iot_unlink,
};

struct xlator_mops mops = {
};

struct xlator_cbks cbks = {
};

struct volume_options options[] = {
	{ .key  = {"thread-count"},
	  .type = HF_OPTION_TYPE_INT,
	  .min  = IOT_MIN_THREADS,
	  .max  = IOT_MAX_THREADS
	},
	{.key   = {"idle-time"},
			.type  = HF_OPTION_TYPE_INT,
			.min   = 1,
			.max   = 0x7fffffff,
	},
	{ .key  = {NULL},
        },
};
