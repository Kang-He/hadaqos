/* -*- mode: c; c-basic-offset: 8; indent-tabs-mode: nil; -*-
 * vim:expandtab:shiftwidth=8:tabstop=8:
 */
/******************************************************************************\
*                                                                              *
*        Copyright (c) 2003, The Regents of the University of California       *
*      See the file COPYRIGHT for a complete copyright notice and license.     *
*                                                                              *
********************************************************************************
*
* Implement of abstract I/O interface for POSIX.
*
\******************************************************************************/

#ifdef HAVE_CONFIG_H
#include "config.h"
#endif

#include <stdio.h>
#include <stdlib.h>
#ifdef __linux__
#include <sys/ioctl.h>          /* necessary for: */
#define __USE_GNU               /* O_DIRECT and */
#include <fcntl.h>              /* IO operations */
#undef __USE_GNU
#endif                          /* __linux__ */
#include <errno.h>
#include <fcntl.h>              /* IO operations */
#include <sys/stat.h>
#include <assert.h>
#ifdef HAVE_LUSTRE_LUSTRE_USER_H
#include <lustre/lustre_user.h>
#endif

#ifdef HAVE_GPFS_H
#include <gpfs.h>
#endif
#ifdef HAVE_GPFS_FCNTL_H
#include <gpfs_fcntl.h>
#endif

#include "ior.h"
#include "aiori.h"
#include "iordef.h"

#ifndef   open64                /* necessary for TRU64 -- */
#define open64  open            /* unlikely, but may pose */
#endif  /* not open64 */                        /* conflicting prototypes */

#ifndef   lseek64               /* necessary for TRU64 -- */
#define lseek64 lseek           /* unlikely, but may pose */
#endif  /* not lseek64 */                        /* conflicting prototypes */

#ifndef   O_BINARY              /* Required on Windows    */
#define O_BINARY 0
#endif

#include "libhadafsclient.h"
#include "hadafs_ioctl.h"

/**************************** P R O T O T Y P E S *****************************/
static void *POSIX_Create(char *, IOR_param_t *);
static void *POSIX_Open(char *, IOR_param_t *);
static IOR_offset_t POSIX_Xfer(int, void *, IOR_size_t *,
                               IOR_offset_t, IOR_param_t *);
static void POSIX_Close(void *, IOR_param_t *);
static void POSIX_Delete(char *, IOR_param_t *);
static void POSIX_SetVersion(IOR_param_t *);
static void POSIX_Fsync(void *, IOR_param_t *);
static IOR_offset_t POSIX_GetFileSize(IOR_param_t *, MPI_Comm, char *);

/************************** D E C L A R A T I O N S ***************************/

ior_aiori_t posix_aiori = {
        "POSIX",
        POSIX_Create,
        POSIX_Open,
        POSIX_Xfer,
        POSIX_Close,
        POSIX_Delete,
        POSIX_SetVersion,
        POSIX_Fsync,
        POSIX_GetFileSize
};

/***************************** F U N C T I O N S ******************************/

void set_o_direct_flag(int *fd)
{
/* note that TRU64 needs O_DIRECTIO, SunOS uses directio(),
   and everyone else needs O_DIRECT */
#ifndef O_DIRECT
#ifndef O_DIRECTIO
        WARN("cannot use O_DIRECT");
#define O_DIRECT 000000
#else                           /* O_DIRECTIO */
#define O_DIRECT O_DIRECTIO
#endif                          /* not O_DIRECTIO */
#endif                          /* not O_DIRECT */

        *fd |= __O_DIRECT;
}

#ifdef HAVE_GPFS_FCNTL_H
void gpfs_free_all_locks(int fd)
{
        int rc;
        struct {
                gpfsFcntlHeader_t header;
                gpfsFreeRange_t release;
        } release_all;
        release_all.header.totalLength = sizeof(release_all);
        release_all.header.fcntlVersion = GPFS_FCNTL_CURRENT_VERSION;
        release_all.header.fcntlReserved = 0;

        release_all.release.structLen = sizeof(release_all.release);
        release_all.release.structType = GPFS_FREE_RANGE;
        release_all.release.start = 0;
        release_all.release.length = 0;

        rc = gpfs_fcntl(fd, &release_all);
        if (verbose >= VERBOSE_0 && rc != 0) {
                EWARN("gpfs_fcntl release all locks hint failed.");
        }
}
void gpfs_access_start(int fd, IOR_offset_t length, IOR_param_t *param, int access)
{
        int rc;
        struct {
                gpfsFcntlHeader_t header;
                gpfsAccessRange_t access;
        } take_locks;

        take_locks.header.totalLength = sizeof(take_locks);
        take_locks.header.fcntlVersion = GPFS_FCNTL_CURRENT_VERSION;
        take_locks.header.fcntlReserved = 0;

        take_locks.access.structLen = sizeof(take_locks.access);
        take_locks.access.structType = GPFS_ACCESS_RANGE;
        take_locks.access.start = param->offset;
        take_locks.access.length = length;
        take_locks.access.isWrite = (access == WRITE);

        rc = gpfs_fcntl(fd, &take_locks);
        if (verbose >= VERBOSE_2 && rc != 0) {
                EWARN("gpfs_fcntl access range hint failed.");
        }
}

void gpfs_access_end(int fd, IOR_offset_t length, IOR_param_t *param, int access)
{
        int rc;
        struct {
                gpfsFcntlHeader_t header;
                gpfsFreeRange_t free;
        } free_locks;


        free_locks.header.totalLength = sizeof(free_locks);
        free_locks.header.fcntlVersion = GPFS_FCNTL_CURRENT_VERSION;
        free_locks.header.fcntlReserved = 0;

        free_locks.free.structLen = sizeof(free_locks.free);
        free_locks.free.structType = GPFS_FREE_RANGE;
        free_locks.free.start = param->offset;
        free_locks.free.length = length;

        rc = gpfs_fcntl(fd, &free_locks);
        if (verbose >= VERBOSE_2 && rc != 0) {
                EWARN("gpfs_fcntl free range hint failed.");
        }
}

#endif

/*
 * Creat and open a file through the POSIX interface.
 */
static void *POSIX_Create(char *testFileName, IOR_param_t * param)
{
        int fd_oflag = O_BINARY;
        hadafs_file_t *fd;
        
        fd = (hadafs_file_t *)malloc(sizeof(hadafs_file_t));
        if (fd == NULL)
                ERR("Unable to malloc file descriptor");

        if (param->useO_DIRECT == TRUE)
                set_o_direct_flag(&fd_oflag);

                //fd_oflag |= O_CREAT | O_RDWR;
                fd_oflag |= O_CREAT | O_RDWR | O_SYNC;
                *fd = hadafs_open(testFileName, fd_oflag, 0664);
                if (*fd < 0)
                        ERR("hadafs_open() failed");
#ifndef XIAOW
                int arg = 0; 
                hadafs_ioctl(*fd, HADAFS_IOS_SETMC, arg);
                //hadafs_ioctl(*fd, HADAFS_IOC_SETMC, arg);
#endif

        return ((void *)fd);
}

/*
 * Open a file through the POSIX interface.
 */
static void *POSIX_Open(char *testFileName, IOR_param_t * param)
{
        int fd_oflag = O_BINARY;
        hadafs_file_t *fd;

        fd = (hadafs_file_t *)malloc(sizeof(hadafs_file_t));
        if (fd == NULL)
                ERR("Unable to malloc file descriptor");
#if 0
        if (param->useO_DIRECT == TRUE)
                set_o_direct_flag(&fd_oflag);
#endif

        fd_oflag |= O_RDWR;
        //fd_oflag |= O_RDWR | O_SYNC;
        *fd = hadafs_open(testFileName, fd_oflag);
        if (*fd < 0)
                ERR("hadafs_open failed");

#ifndef XIAOW
                int arg = 0; 
                hadafs_ioctl(*fd, HADAFS_IOS_SETMC, arg);
                //hadafs_ioctl(*fd, HADAFS_IOC_SETMC, arg);
#endif

        return ((void *)fd);
}

/*
 * Write or read access to file using the POSIX interface.
 */
static IOR_offset_t POSIX_Xfer(int access, void *file, IOR_size_t * buffer,
                               IOR_offset_t length, IOR_param_t * param)
{
        int xferRetries = 0;
        long long remaining = (long long)length;
        char *ptr = (char *)buffer;
        long long rc;
        hadafs_file_t fd;

        fd = *(hadafs_file_t *)file;


#ifndef NODISK
        /* seek to offset */
        if (hadafs_lseek(fd, param->offset, SEEK_SET) == -1)
                ERR("hadafs_lseek() failed");
#endif

        while (remaining > 0) {
                /* write/read file */
                if (access == WRITE) {  /* WRITE */
                        if (verbose >= VERBOSE_4) {
                                fprintf(stdout,
                                        "task %d writing to offset %lld\n",
                                        rank,
                                        param->offset + length - remaining);
                        }
                        rc = hadafs_write(fd, ptr, remaining);
                        if (rc == -1)
                                ERR("write() failed");
                        if (param->fsyncPerWrite == TRUE)
                                POSIX_Fsync(&fd, param);
                } else {        /* READ or CHECK */
                        if (verbose >= VERBOSE_4) {
                                fprintf(stdout,
                                        "task %d reading from offset %lld\n",
                                        rank,
                                        param->offset + length - remaining);
                        }
                        rc = hadafs_read(fd, ptr, remaining);
                        if (rc == 0)
                                ERR("read() returned EOF prematurely");
                        if (rc == -1)
                                ERR("read() failed");
                }
                if (rc < remaining) {
                        fprintf(stdout,
                                "WARNING: Task %d, partial %s, %lld of %lld bytes at offset %lld\n",
                                rank,
                                access == WRITE ? "write()" : "read()",
                                rc, remaining,
                                param->offset + length - remaining);
                        if (param->singleXferAttempt == TRUE)
                                MPI_CHECK(MPI_Abort(MPI_COMM_WORLD, -1),
                                          "barrier error");
                        if (xferRetries > MAX_RETRY)
                                ERR("too many retries -- aborting");
                }
                assert(rc >= 0);
                assert(rc <= remaining);
                remaining -= rc;
                ptr += rc;
                xferRetries++;
        }
        return (length);
}

/*
 * Perform fsync().
 */
static void POSIX_Fsync(void *fd, IOR_param_t * param)
{
        if (fsync(*(int *)fd) != 0)
                EWARN("fsync() failed");
}

/*
 * Close a file through the POSIX interface.
 */
static void POSIX_Close(void *fd, IOR_param_t * param)
{
        if (hadafs_close(*(hadafs_file_t *)fd) != 0)
                ERR("hadafs_close() failed");
        free(fd);
}

/*
 * Delete a file through the POSIX interface.
 */
static void POSIX_Delete(char *testFileName, IOR_param_t * param)
{
        char errmsg[256];
        sprintf(errmsg, "[RANK %03d]: unlink() of file \"%s\" failed\n",
                rank, testFileName);
        if (hadafs_unlink(testFileName) != 0)
                EWARN(errmsg);
        //fprintf(stdout, "unlink testfile %s\n", testFileName);
}

/*
 * Determine api version.
 */
static void POSIX_SetVersion(IOR_param_t * test)
{
        //strcpy(test->apiVersion, test->api);
        strcpy(test->apiVersion, "hadafs");
}

/*
 * Use POSIX stat() to return aggregate file size.
 */
static IOR_offset_t POSIX_GetFileSize(IOR_param_t * test, MPI_Comm testComm,
                                      char *testFileName)
{
        struct stat stat_buf;
        IOR_offset_t aggFileSizeFromStat, tmpMin, tmpMax, tmpSum;

        if (hadafs_stat(testFileName, &stat_buf) != 0) {
                ERR("stat() failed");
        }
#ifdef XIAOW
        fprintf(stdout, "stat_buf.st_size is %ld\n", stat_buf.st_size);
#endif
        aggFileSizeFromStat = stat_buf.st_size;

        if (test->filePerProc == TRUE) {
                MPI_CHECK(MPI_Allreduce(&aggFileSizeFromStat, &tmpSum, 1,
                                        MPI_LONG_LONG_INT, MPI_SUM, testComm),
                          "cannot total data moved");
                aggFileSizeFromStat = tmpSum;
        } else {
                MPI_CHECK(MPI_Allreduce(&aggFileSizeFromStat, &tmpMin, 1,
                                        MPI_LONG_LONG_INT, MPI_MIN, testComm),
                          "cannot total data moved");
                MPI_CHECK(MPI_Allreduce(&aggFileSizeFromStat, &tmpMax, 1,
                                        MPI_LONG_LONG_INT, MPI_MAX, testComm),
                          "cannot total data moved");
                if (tmpMin != tmpMax) {
                        if (rank == 0) {
                                WARN("inconsistent file size by different tasks");
                        }
                        /* incorrect, but now consistent across tasks */
                        aggFileSizeFromStat = tmpMin;
                }
        }

        return (aggFileSizeFromStat);
}
