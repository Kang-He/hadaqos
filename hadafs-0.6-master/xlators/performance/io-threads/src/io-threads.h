/*
  Copyright (c) 2006-2010 Lwfs, Inc. <http://www.lwfs.com>
  This file is part of Lwfs.

  Lwfs is free software; you can redistribute it and/or modify
  it under the terms of the GNU Affero General Public License as published
  by the Free Software Foundation; either version 3 of the License,
  or (at your option) any later version.

  Lwfs is distributed in the hope that it will be useful, but
  WITHOUT ANY WARRANTY; without even the implied warranty of
  MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the GNU
  Affero General Public License for more details.

  You should have received a copy of the GNU Affero General Public License
  along with this program.  If not, see
  <http://www.gnu.org/licenses/>.
*/

#ifndef __IOT_H
#define __IOT_H

#ifndef _CONFIG_H
#define _CONFIG_H
#include "config.h"
#endif


#include "compat-errno.h"
#include "hadafs.h"
#include "logging.h"
#include "dict.h"
#include "xlator.h"
#include "common-utils.h"
#include "list.h"
#include <stdlib.h>
#include "locking.h"
#include <semaphore.h>


struct iot_conf;

#define MAX_IDLE_SKEW                   4       /* In secs */
#define skew_sec_idle_time(sec)         ((sec) + (random () % MAX_IDLE_SKEW))
#define IOT_DEFAULT_IDLE                120     /* In secs. */

#define IOT_MIN_THREADS         1
#define IOT_DEFAULT_THREADS     16
#define IOT_MAX_THREADS         64


#define IOT_THREAD_STACK_SIZE   ((size_t)(1024*1024))

#define TRACE_THREAD
//#define PRINT_QUEUE_SIZE
//#define PRI_SCHEDULE
//#define LOW_TIMES 2

#define HIGH_TIMES 8
#define REDUCE_TIME 1000

typedef enum {
        IOT_PRI_HI = 0, /* low latency */
        IOT_PRI_NORMAL, /* normal */
        IOT_PRI_LO,     /* bulk */
        IOT_PRI_MAX,
} iot_pri_t;

struct overall_status {
    volatile uint64_t opt_times;
    volatile uint64_t wait_data[3][20];
    volatile uint64_t exe_data[3][20];
    int64_t queue_sample;
};

typedef struct overall_status overall_status_t;
static overall_status_t *pool_status;

struct trace_info {
    //ino_t ino;
    //overall_status_t *overall_status;
    struct timeval create;
    struct timeval execute;
};

typedef struct trace_info trace_info_t;

struct iot_conf {
        pthread_mutex_t      mutex;
        pthread_cond_t       cond;

        int32_t              max_count;   /* configured maximum */
        int32_t              curr_count;  /* actual number of threads running */
        int32_t              sleep_count;

        int32_t              idle_time;   /* in seconds */

        struct list_head     reqs[IOT_PRI_MAX];

        int                  queue_size;
        pthread_attr_t       w_attr;

        xlator_t            *this;
};

typedef struct iot_conf iot_conf_t;

#endif /* __IOT_H */
