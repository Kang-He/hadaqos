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

#ifndef _COMMON_UTILS_H
#define _COMMON_UTILS_H

#ifndef _CONFIG_H
#define _CONFIG_H
#include "config.h"
#endif

#include <stdint.h>
#include <sys/uio.h>
#include <netdb.h>
#include <stdlib.h>
#include <string.h>
#include <assert.h>
#include <pthread.h>
#ifndef HF_BSD_HOST_OS
#include <alloca.h>
#endif 

void trap (void);

#define HF_UNIVERSAL_ANSWER 42    /* :O */

/* To solve type punned error */
#define VOID(ptr) ((void **) ((void *) ptr))

#include "logging.h"
#include "hadafs.h"
#include "locking.h"
#include "mem-pool.h"


#define min(a,b) ((a)<(b)?(a):(b))
#define max(a,b) ((a)>(b)?(a):(b))
#define roof(a,b) ((((a)+(b)-1)/((b)?(b):1))*(b))
#define floor(a,b) (((a)/((b)?(b):1))*(b))


#define HF_UNIT_KB    1024ULL
#define HF_UNIT_MB    1048576ULL
#define HF_UNIT_GB    1073741824ULL
#define HF_UNIT_TB    1099511627776ULL
#define HF_UNIT_PB    1125899906842624ULL

#define HF_UNIT_KB_STRING    "KB"
#define HF_UNIT_MB_STRING    "MB"
#define HF_UNIT_GB_STRING    "GB"
#define HF_UNIT_TB_STRING    "TB"
#define HF_UNIT_PB_STRING    "PB"


#define ERR_ABORT(ptr)				\
	if (ptr == NULL)  {			\
		abort ();			\
	}                     

enum _hf_boolean 
{
	_hf_false = 0, 
	_hf_true = 1
};

typedef enum _hf_boolean hf_boolean_t;

void hf_global_variable_init(void);
void set_global_ctx_ptr (hadafs_ctx_t *ctx);
hadafs_ctx_t *get_global_ctx_ptr (void);

in_addr_t hf_resolve_ip (const char *hostname, void **dnscache);

void hf_log_volume_file (FILE *specfp);
void hf_print_trace (int32_t signal);
void hf_print_backtrace_debug (char *startmsg);

extern char *hf_fop_list[HF_FOP_MAXVALUE];
extern char *hf_mop_list[HF_MOP_MAXVALUE];
extern char *hf_cbk_list[HF_CBK_MAXVALUE];

#define VECTORSIZE(count) (count * (sizeof (struct iovec)))

#define STRLEN_0(str) (strlen(str) + 1)
#define VALIDATE_OR_GOTO(arg,label)   do {				\
		if (!arg) {						\
			errno = EINVAL;					\
			hf_log ((this ? this->name : "(Govinda! Govinda!)"), \
				HF_LOG_ERROR,				\
				"invalid argument: " #arg);		\
			goto label;					\
		}							\
	} while (0); 

#define HF_VALIDATE_OR_GOTO(name,arg,label)   do {		\
		if (!arg) {					\
			errno = EINVAL;   			\
			hf_log (name, HF_LOG_ERROR,		\
				"invalid argument: " #arg);	\
			goto label;				\
		}						\
	} while (0); 

#define HF_VALIDATE_OR_GOTO_WITH_ERROR(name, arg, label, errno, error) do { \
                if (!arg) {                                                 \
                        errno = error;                                      \
                        hf_log (name, HF_LOG_ERROR,                         \
                                "invalid argument: " #arg);                 \
                        goto label;                                         \
                }                                                           \
        }while (0);

#define HF_VALIDATE_ABSOLUTE_PATH_OR_GOTO(name,arg,label)       \
        do {                                                    \
                HF_VALIDATE_OR_GOTO (name, arg, label);         \
                if ((arg[0]) != '/') {                          \
                        errno = EINVAL;                         \
			hf_log (name, HF_LOG_ERROR,	        \
				"invalid argument: " #arg);	\
                        goto label;                             \
                }                                               \
	} while (0);

#define HF_FILE_CONTENT_REQUESTED(_xattr_req,_content_limit) \
	(dict_get_uint64 (_xattr_req, "hadafs.content", _content_limit) == 0)

static inline void
iov_free (struct iovec *vector, int count)
{
	int i;

	for (i = 0; i < count; i++)
		FREE (vector[i].iov_base);

	FREE (vector);
}


static inline int
iov_length (const struct iovec *vector, int count)
{
	int     i = 0;
	size_t  size = 0;

	for (i = 0; i < count; i++)
		size += vector[i].iov_len;

	return size;
}


static inline struct iovec *
iov_dup (struct iovec *vector, int count)
{
	int           bytecount = 0;
	int           i;
	struct iovec *newvec = NULL;

	bytecount = (count * sizeof (struct iovec));
	newvec = MALLOC (bytecount);
	if (!newvec)
		return NULL;

	for (i = 0; i < count; i++) {
		newvec[i].iov_len  = vector[i].iov_len;
		newvec[i].iov_base = vector[i].iov_base;
	}

	return newvec;
}


static inline int
iov_subset (struct iovec *orig, int orig_count,
	    off_t src_offset, off_t dst_offset,
	    struct iovec *new)
{
	int    new_count = 0;
	int    i;
	off_t  offset = 0;
	size_t start_offset = 0;
	size_t end_offset = 0;


	for (i = 0; i < orig_count; i++) {
		if ((offset + orig[i].iov_len < src_offset)
		    || (offset > dst_offset)) {
			goto not_subset;
		}

		if (!new) {
			goto count_only;
		}

		start_offset = 0;
		end_offset = orig[i].iov_len;

		if (src_offset >= offset) {
			start_offset = (src_offset - offset);
		}

		if (dst_offset <= (offset + orig[i].iov_len)) {
			end_offset = (dst_offset - offset);
		}

		new[new_count].iov_base = orig[i].iov_base + start_offset;
		new[new_count].iov_len = end_offset - start_offset;

	count_only:
		new_count++;

	not_subset:
		offset += orig[i].iov_len;
	}

	return new_count;
}


static inline void
iov_unload (char *buf, const struct iovec *vector, int count)
{
	int i;
	int copied = 0;

	for (i = 0; i < count; i++) {
		memcpy (buf + copied, vector[i].iov_base, vector[i].iov_len);
		copied += vector[i].iov_len;
	}
}


static inline int
mem_0filled (const char *buf, size_t size)
{
	int i = 0;
	int ret = 0;

	for (i = 0; i < size; i++) {
		ret = buf[i];
		if (ret)
			break;
	}

	return ret;
}


static inline int
iov_0filled (struct iovec *vector, int count)
{
	int i = 0;
	int ret = 0;

	for (i = 0; i < count; i++) {
		ret = mem_0filled (vector[i].iov_base, vector[i].iov_len);
		if (ret)
			break;
	}

	return ret;
}


static inline void *
memdup (const void *ptr, size_t size)
{
	void *newptr = NULL;

	newptr = MALLOC (size);
	if (!newptr)
		return NULL;

	memcpy (newptr, ptr, size);
	return newptr;
}


char *hf_trim (char *string);
int hf_strsplit (const char *str, const char *delim, 
		 char ***tokens, int *token_count);
int hf_volume_name_validate (const char *volume_name);

int hf_string2long (const char *str, long *n);
int hf_string2ulong (const char *str, unsigned long *n);
int hf_string2int (const char *str, int *n);
int hf_string2uint (const char *str, unsigned int *n);
int hf_string2double (const char *str, double *n);
int hf_string2longlong (const char *str, long long *n);
int hf_string2ulonglong (const char *str, unsigned long long *n);

int hf_string2int8 (const char *str, int8_t *n);
int hf_string2int16 (const char *str, int16_t *n);
int hf_string2int32 (const char *str, int32_t *n);
int hf_string2int64 (const char *str, int64_t *n);
int hf_string2uint8 (const char *str, uint8_t *n);
int hf_string2uint16 (const char *str, uint16_t *n);
int hf_string2uint32 (const char *str, uint32_t *n);
int hf_string2uint64 (const char *str, uint64_t *n);

int hf_string2ulong_base10 (const char *str, unsigned long *n);
int hf_string2uint_base10 (const char *str, unsigned int *n);
int hf_string2uint8_base10 (const char *str, uint8_t *n);
int hf_string2uint16_base10 (const char *str, uint16_t *n);
int hf_string2uint32_base10 (const char *str, uint32_t *n);
int hf_string2uint64_base10 (const char *str, uint64_t *n);

int hf_string2bytesize (const char *str, uint64_t *n);

int hf_string2boolean (const char *str, hf_boolean_t *b);
int hf_string2percent (const char *str, uint32_t *n);
int hf_string2time (const char *str, uint32_t *n);

int hf_lockfd (int fd);
int hf_unlockfd (int fd);

int get_checksum_for_file (int fd, uint32_t *checksum);

#endif /* _COMMON_UTILS_H */

