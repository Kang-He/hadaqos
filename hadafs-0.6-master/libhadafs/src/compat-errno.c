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

#ifndef _CONFIG_H
#define _CONFIG_H
#include "config.h"
#endif

#include <stdint.h>

#include "compat-errno.h"


static int32_t hf_error_to_errno_array[1024]; 
static int32_t hf_errno_to_error_array[1024];

static int32_t hf_compat_errno_init_done;

#ifdef HF_SOLARIS_HOST_OS
static void 
init_compat_errno_arrays ()
{
/*  	ENOMSG	35	/ * No message of desired type		*/
  hf_error_to_errno_array[HF_ERROR_CODE_NOMSG] = ENOMSG;
  hf_errno_to_error_array[ENOMSG] = HF_ERROR_CODE_NOMSG;

/*  	EIDRM	36	/ * Identifier removed			*/
  hf_error_to_errno_array[HF_ERROR_CODE_IDRM] = EIDRM;
  hf_errno_to_error_array[EIDRM] = HF_ERROR_CODE_IDRM;

/*  	ECHRNG	37	/ * Channel number out of range		*/
  hf_error_to_errno_array[HF_ERROR_CODE_CHRNG] = ECHRNG;
  hf_errno_to_error_array[ECHRNG] = HF_ERROR_CODE_CHRNG;

/*  	EL2NSYNC 38	/ * Level 2 not synchronized		*/
  hf_error_to_errno_array[HF_ERROR_CODE_L2NSYNC] = EL2NSYNC;
  hf_errno_to_error_array[EL2NSYNC] = HF_ERROR_CODE_L2NSYNC;

/*  	EL3HLT	39	/ * Level 3 halted			*/
  hf_error_to_errno_array[HF_ERROR_CODE_L3HLT] = EL3HLT;
  hf_errno_to_error_array[EL3HLT] = HF_ERROR_CODE_L3HLT;

/*  	EL3RST	40	/ * Level 3 reset			*/
  hf_error_to_errno_array[HF_ERROR_CODE_L3RST] = EL3RST;
  hf_errno_to_error_array[EL3RST] = HF_ERROR_CODE_L3RST;

/*  	ELNRNG	41	/ * Link number out of range		*/
  hf_error_to_errno_array[HF_ERROR_CODE_LNRNG] = ELNRNG;
  hf_errno_to_error_array[ELNRNG] = HF_ERROR_CODE_LNRNG;

/*  	EUNATCH 42	/ * Protocol driver not attached		*/
  hf_error_to_errno_array[HF_ERROR_CODE_UNATCH] = EUNATCH;
  hf_errno_to_error_array[EUNATCH] = HF_ERROR_CODE_UNATCH;

/*  	ENOCSI	43	/ * No CSI structure available		*/
  hf_error_to_errno_array[HF_ERROR_CODE_NOCSI] = ENOCSI;
  hf_errno_to_error_array[ENOCSI] = HF_ERROR_CODE_NOCSI;

/*  	EL2HLT	44	/ * Level 2 halted			*/
  hf_error_to_errno_array[HF_ERROR_CODE_L2HLT] = EL2HLT;
  hf_errno_to_error_array[EL2HLT] = HF_ERROR_CODE_L2HLT;

/*  	EDEADLK	45	/ * Deadlock condition.			*/
  hf_error_to_errno_array[HF_ERROR_CODE_DEADLK] = EDEADLK;
  hf_errno_to_error_array[EDEADLK] = HF_ERROR_CODE_DEADLK;

/*  	ENOLCK	46	/ * No record locks available.		*/
  hf_error_to_errno_array[HF_ERROR_CODE_NOLCK] = ENOLCK;
  hf_errno_to_error_array[ENOLCK] = HF_ERROR_CODE_NOLCK;

/*  	ECANCELED 47	/ * Operation canceled			*/
  hf_error_to_errno_array[HF_ERROR_CODE_CANCELED] = ECANCELED;
  hf_errno_to_error_array[ECANCELED] = HF_ERROR_CODE_CANCELED;

/*  	ENOTSUP	48	/ * Operation not supported		*/
  hf_error_to_errno_array[HF_ERROR_CODE_NOTSUPP] = ENOTSUP;
  hf_errno_to_error_array[ENOTSUP] = HF_ERROR_CODE_NOTSUPP;

/* Filesystem Quotas */
/*  	EDQUOT	49	/ * Disc quota exceeded			*/
  hf_error_to_errno_array[HF_ERROR_CODE_DQUOT] = EDQUOT;
  hf_errno_to_error_array[EDQUOT] = HF_ERROR_CODE_DQUOT;

/* Convergent Error Returns */
/*  	EBADE	50	/ * invalid exchange			*/
  hf_error_to_errno_array[HF_ERROR_CODE_BADE] = EBADE;
  hf_errno_to_error_array[EBADE] = HF_ERROR_CODE_BADE;
/*  	EBADR	51	/ * invalid request descriptor		*/
  hf_error_to_errno_array[HF_ERROR_CODE_BADR] = EBADR;
  hf_errno_to_error_array[EBADR] = HF_ERROR_CODE_BADR;
/*  	EXFULL	52	/ * exchange full			*/
  hf_error_to_errno_array[HF_ERROR_CODE_XFULL] = EXFULL;
  hf_errno_to_error_array[EXFULL] = HF_ERROR_CODE_XFULL;
/*  	ENOANO	53	/ * no anode				*/
  hf_error_to_errno_array[HF_ERROR_CODE_NOANO] = ENOANO;
  hf_errno_to_error_array[ENOANO] = HF_ERROR_CODE_NOANO;
/*  	EBADRQC	54	/ * invalid request code			*/
  hf_error_to_errno_array[HF_ERROR_CODE_BADRQC] = EBADRQC;
  hf_errno_to_error_array[EBADRQC] = HF_ERROR_CODE_BADRQC;
/*  	EBADSLT	55	/ * invalid slot				*/
  hf_error_to_errno_array[HF_ERROR_CODE_BADSLT] = EBADSLT;
  hf_errno_to_error_array[EBADSLT] = HF_ERROR_CODE_BADSLT;
/*  	EDEADLOCK 56	/ * file locking deadlock error		*/
/* This is same as EDEADLK on linux */
  hf_error_to_errno_array[HF_ERROR_CODE_DEADLK] = EDEADLOCK;
  hf_errno_to_error_array[EDEADLOCK] = HF_ERROR_CODE_DEADLK;

/*  	EBFONT	57	/ * bad font file fmt			*/
  hf_error_to_errno_array[HF_ERROR_CODE_BFONT] = EBFONT;
  hf_errno_to_error_array[EBFONT] = HF_ERROR_CODE_BFONT;

/* Interprocess Robust Locks */
/*  	EOWNERDEAD	58	/ * process died with the lock */
  hf_error_to_errno_array[HF_ERROR_CODE_OWNERDEAD] = EOWNERDEAD;
  hf_errno_to_error_array[EOWNERDEAD] = HF_ERROR_CODE_OWNERDEAD;
/*  	ENOTRECOVERABLE	59	/ * lock is not recoverable */
  hf_error_to_errno_array[HF_ERROR_CODE_NOTRECOVERABLE] = ENOTRECOVERABLE;
  hf_errno_to_error_array[ENOTRECOVERABLE] = HF_ERROR_CODE_NOTRECOVERABLE;

/* stream problems */
/*  	ENOSTR	60	/ * Device not a stream			*/
  hf_error_to_errno_array[HF_ERROR_CODE_NOSTR] = ENOSTR;
  hf_errno_to_error_array[ENOSTR] = HF_ERROR_CODE_NOSTR;
/*  	ENODATA	61	/ * no data (for no delay io)		*/
  hf_error_to_errno_array[HF_ERROR_CODE_NODATA] = ENODATA;
  hf_errno_to_error_array[ENODATA] = HF_ERROR_CODE_NODATA;
/*  	ETIME	62	/ * timer expired			*/
  hf_error_to_errno_array[HF_ERROR_CODE_TIME] = ETIME;
  hf_errno_to_error_array[ETIME] = HF_ERROR_CODE_TIME;
/*  	ENOSR	63	/ * out of streams resources		*/
  hf_error_to_errno_array[HF_ERROR_CODE_NOSR] = ENOSR;
  hf_errno_to_error_array[ENOSR] = HF_ERROR_CODE_NOSR;

/*  	ENONET	64	/ * Machine is not on the network	*/
  hf_error_to_errno_array[HF_ERROR_CODE_NONET] = ENONET;
  hf_errno_to_error_array[ENONET] = HF_ERROR_CODE_NONET;
/*  	ENOPKG	65	/ * Package not installed		*/
  hf_error_to_errno_array[HF_ERROR_CODE_NOPKG] = ENOPKG;
  hf_errno_to_error_array[ENOPKG] = HF_ERROR_CODE_NOPKG;
/*  	EREMOTE	66	/ * The object is remote			*/
  hf_error_to_errno_array[HF_ERROR_CODE_REMOTE] = EREMOTE;
  hf_errno_to_error_array[EREMOTE] = HF_ERROR_CODE_REMOTE;
/*  	ENOLINK	67	/ * the link has been severed		*/
  hf_error_to_errno_array[HF_ERROR_CODE_NOLINK] = ENOLINK;
  hf_errno_to_error_array[ENOLINK] = HF_ERROR_CODE_NOLINK;
/*  	EADV	68	/ * advertise error			*/
  hf_error_to_errno_array[HF_ERROR_CODE_ADV] = EADV;
  hf_errno_to_error_array[EADV] = HF_ERROR_CODE_ADV;
/*  	ESRMNT	69	/ * srmount error			*/
  hf_error_to_errno_array[HF_ERROR_CODE_SRMNT] = ESRMNT;
  hf_errno_to_error_array[ESRMNT] = HF_ERROR_CODE_SRMNT;

/*  	ECOMM	70	/ * Communication error on send		*/
  hf_error_to_errno_array[HF_ERROR_CODE_COMM] = ECOMM;
  hf_errno_to_error_array[ECOMM] = HF_ERROR_CODE_COMM;
/*  	EPROTO	71	/ * Protocol error			*/
  hf_error_to_errno_array[HF_ERROR_CODE_PROTO] = EPROTO;
  hf_errno_to_error_array[EPROTO] = HF_ERROR_CODE_PROTO;

/* Interprocess Robust Locks */
/*  	ELOCKUNMAPPED	72	/ * locked lock was unmapped */
  hf_error_to_errno_array[HF_ERROR_CODE_LOCKUNMAPPED] = ELOCKUNMAPPED;
  hf_errno_to_error_array[ELOCKUNMAPPED] = HF_ERROR_CODE_LOCKUNMAPPED;

/*  	ENOTACTIVE 73	/ * Facility is not active		*/
  hf_error_to_errno_array[HF_ERROR_CODE_NOTACTIVE] = ENOTACTIVE;
  hf_errno_to_error_array[ENOTACTIVE] = HF_ERROR_CODE_NOTACTIVE;
/*  	EMULTIHOP 74	/ * multihop attempted			*/
  hf_error_to_errno_array[HF_ERROR_CODE_MULTIHOP] = EMULTIHOP;
  hf_errno_to_error_array[EMULTIHOP] = HF_ERROR_CODE_MULTIHOP;
/*  	EBADMSG 77	/ * trying to read unreadable message	*/
  hf_error_to_errno_array[HF_ERROR_CODE_BADMSG] = EBADMSG;
  hf_errno_to_error_array[EBADMSG] = HF_ERROR_CODE_BADMSG;
/*  	ENAMETOOLONG 78	/ * path name is too long		*/
  hf_error_to_errno_array[HF_ERROR_CODE_NAMETOOLONG] = ENAMETOOLONG;
  hf_errno_to_error_array[ENAMETOOLONG] = HF_ERROR_CODE_NAMETOOLONG;
/*  	EOVERFLOW 79	/ * value too large to be stored in data type */
  hf_error_to_errno_array[HF_ERROR_CODE_OVERFLOW] = EOVERFLOW;
  hf_errno_to_error_array[EOVERFLOW] = HF_ERROR_CODE_OVERFLOW;
/*  	ENOTUNIQ 80	/ * given log. name not unique		*/
  hf_error_to_errno_array[HF_ERROR_CODE_NOTUNIQ] = ENOTUNIQ;
  hf_errno_to_error_array[ENOTUNIQ] = HF_ERROR_CODE_NOTUNIQ;
/*  	EBADFD	81	/ * f.d. invalid for this operation	*/
  hf_error_to_errno_array[HF_ERROR_CODE_BADFD] = EBADFD;
  hf_errno_to_error_array[EBADFD] = HF_ERROR_CODE_BADFD;
/*  	EREMCHG	82	/ * Remote address changed		*/
  hf_error_to_errno_array[HF_ERROR_CODE_REMCHG] = EREMCHG;
  hf_errno_to_error_array[EREMCHG] = HF_ERROR_CODE_REMCHG;

/* shared library problems */
/*  	ELIBACC	83	/ * Can't access a needed shared lib.	*/
  hf_error_to_errno_array[HF_ERROR_CODE_LIBACC] = ELIBACC;
  hf_errno_to_error_array[ELIBACC] = HF_ERROR_CODE_LIBACC;
/*  	ELIBBAD	84	/ * Accessing a corrupted shared lib.	*/
  hf_error_to_errno_array[HF_ERROR_CODE_LIBBAD] = ELIBBAD;
  hf_errno_to_error_array[ELIBBAD] = HF_ERROR_CODE_LIBBAD;
/*  	ELIBSCN	85	/ * .lib section in a.out corrupted.	*/
  hf_error_to_errno_array[HF_ERROR_CODE_LIBSCN] = ELIBSCN;
  hf_errno_to_error_array[ELIBSCN] = HF_ERROR_CODE_LIBSCN;
/*  	ELIBMAX	86	/ * Attempting to link in too many libs.	*/
  hf_error_to_errno_array[HF_ERROR_CODE_LIBMAX] = ELIBMAX;
  hf_errno_to_error_array[ELIBMAX] = HF_ERROR_CODE_LIBMAX;
/*  	ELIBEXEC 87	/ * Attempting to exec a shared library.	*/
  hf_error_to_errno_array[HF_ERROR_CODE_LIBEXEC] = ELIBEXEC;
  hf_errno_to_error_array[ELIBEXEC] = HF_ERROR_CODE_LIBEXEC;
/*  	EILSEQ	88	/ * Illegal byte sequence.		*/
  hf_error_to_errno_array[HF_ERROR_CODE_ILSEQ] = EILSEQ;
  hf_errno_to_error_array[EILSEQ] = HF_ERROR_CODE_ILSEQ;
/*  	ENOSYS	89	/ * Unsupported file system operation	*/
  hf_error_to_errno_array[HF_ERROR_CODE_NOSYS] = ENOSYS;
  hf_errno_to_error_array[ENOSYS] = HF_ERROR_CODE_NOSYS;
/*  	ELOOP	90	/ * Symbolic link loop			*/
  hf_error_to_errno_array[HF_ERROR_CODE_LOOP] = ELOOP;
  hf_errno_to_error_array[ELOOP] = HF_ERROR_CODE_LOOP;
/*  	ERESTART 91	/ * Restartable system call		*/
  hf_error_to_errno_array[HF_ERROR_CODE_RESTART] = ERESTART;
  hf_errno_to_error_array[ERESTART] = HF_ERROR_CODE_RESTART;
/*  	ESTRPIPE 92	/ * if pipe/FIFO, don't sleep in stream head */
  hf_error_to_errno_array[HF_ERROR_CODE_STRPIPE] = ESTRPIPE;
  hf_errno_to_error_array[ESTRPIPE] = HF_ERROR_CODE_STRPIPE;
/*  	ENOTEMPTY 93	/ * directory not empty			*/
  hf_error_to_errno_array[HF_ERROR_CODE_NOTEMPTY] = ENOTEMPTY;
  hf_errno_to_error_array[ENOTEMPTY] = HF_ERROR_CODE_NOTEMPTY;
/*  	EUSERS	94	/ * Too many users (for UFS)		*/
  hf_error_to_errno_array[HF_ERROR_CODE_USERS] = EUSERS;
  hf_errno_to_error_array[EUSERS] = HF_ERROR_CODE_USERS;

/* BSD Networking Software */
	/* argument errors */
/*  	ENOTSOCK	95	/ * Socket operation on non-socket */
  hf_error_to_errno_array[HF_ERROR_CODE_NOTSOCK] = ENOTSOCK;
  hf_errno_to_error_array[ENOTSOCK] = HF_ERROR_CODE_NOTSOCK;
/*  	EDESTADDRREQ	96	/ * Destination address required */
  hf_error_to_errno_array[HF_ERROR_CODE_DESTADDRREQ] = EDESTADDRREQ;
  hf_errno_to_error_array[EDESTADDRREQ] = HF_ERROR_CODE_DESTADDRREQ;
/*  	EMSGSIZE	97	/ * Message too long */
  hf_error_to_errno_array[HF_ERROR_CODE_MSGSIZE] = EMSGSIZE;
  hf_errno_to_error_array[EMSGSIZE] = HF_ERROR_CODE_MSGSIZE;
/*  	EPROTOTYPE	98	/ * Protocol wrong type for socket */
  hf_error_to_errno_array[HF_ERROR_CODE_PROTOTYPE] = EPROTOTYPE;
  hf_errno_to_error_array[EPROTOTYPE] = HF_ERROR_CODE_PROTOTYPE;
/*  	ENOPROTOOPT	99	/ * Protocol not available */
  hf_error_to_errno_array[HF_ERROR_CODE_NOPROTOOPT] = ENOPROTOOPT;
  hf_errno_to_error_array[ENOPROTOOPT] = HF_ERROR_CODE_NOPROTOOPT;
/*  	EPROTONOSUPPORT	120	/ * Protocol not supported */
  hf_error_to_errno_array[HF_ERROR_CODE_PROTONOSUPPORT] = EPROTONOSUPPORT;
  hf_errno_to_error_array[EPROTONOSUPPORT] = HF_ERROR_CODE_PROTONOSUPPORT;
/*  	ESOCKTNOSUPPORT	121	/ * Socket type not supported */
  hf_error_to_errno_array[HF_ERROR_CODE_SOCKTNOSUPPORT] = ESOCKTNOSUPPORT;
  hf_errno_to_error_array[ESOCKTNOSUPPORT] = HF_ERROR_CODE_SOCKTNOSUPPORT;

/*  	EOPNOTSUPP	122	/ * Operation not supported on socket */
  hf_error_to_errno_array[HF_ERROR_CODE_OPNOTSUPP] = EOPNOTSUPP;
  hf_errno_to_error_array[EOPNOTSUPP] = HF_ERROR_CODE_OPNOTSUPP;
/*  	EPFNOSUPPORT	123	/ * Protocol family not supported */
  hf_error_to_errno_array[HF_ERROR_CODE_PFNOSUPPORT] = EPFNOSUPPORT;
  hf_errno_to_error_array[EPFNOSUPPORT] = HF_ERROR_CODE_PFNOSUPPORT;
/*  	EAFNOSUPPORT	124	/ * Address family not supported by */
				/* protocol family */
  hf_error_to_errno_array[HF_ERROR_CODE_AFNOSUPPORT] = EAFNOSUPPORT;
  hf_errno_to_error_array[EAFNOSUPPORT] = HF_ERROR_CODE_AFNOSUPPORT;
/*  	EADDRINUSE	125	/ * Address already in use */
  hf_error_to_errno_array[HF_ERROR_CODE_ADDRINUSE] = EADDRINUSE;
  hf_errno_to_error_array[EADDRINUSE] = HF_ERROR_CODE_ADDRINUSE;
/*  	EADDRNOTAVAIL	126	/ * Can't assign requested address */
                                /* operational errors */
  hf_error_to_errno_array[HF_ERROR_CODE_ADDRNOTAVAIL] = EADDRNOTAVAIL;
  hf_errno_to_error_array[EADDRNOTAVAIL] = HF_ERROR_CODE_ADDRNOTAVAIL;
/*  	ENETDOWN	127	/ * Network is down */
  hf_error_to_errno_array[HF_ERROR_CODE_NETDOWN] = ENETDOWN;
  hf_errno_to_error_array[ENETDOWN] = HF_ERROR_CODE_NETDOWN;
/*  	ENETUNREACH	128	/ * Network is unreachable */
  hf_error_to_errno_array[HF_ERROR_CODE_NETUNREACH] = ENETUNREACH;
  hf_errno_to_error_array[ENETUNREACH] = HF_ERROR_CODE_NETUNREACH;
/*  	ENETRESET	129	/ * Network dropped connection because */
				/* of reset */
  hf_error_to_errno_array[HF_ERROR_CODE_NETRESET] = ENETRESET;
  hf_errno_to_error_array[ENETRESET] = HF_ERROR_CODE_NETRESET;
/*  	ECONNABORTED	130	/ * Software caused connection abort */
  hf_error_to_errno_array[HF_ERROR_CODE_CONNABORTED] = ECONNABORTED;
  hf_errno_to_error_array[ECONNABORTED] = HF_ERROR_CODE_CONNABORTED;
/*  	ECONNRESET	131	/ * Connection reset by peer */
  hf_error_to_errno_array[HF_ERROR_CODE_CONNRESET] = ECONNRESET;
  hf_errno_to_error_array[ECONNRESET] = HF_ERROR_CODE_CONNRESET;
/*  	ENOBUFS		132	/ * No buffer space available */
  hf_error_to_errno_array[HF_ERROR_CODE_NOBUFS] = ENOBUFS;
  hf_errno_to_error_array[ENOBUFS] = HF_ERROR_CODE_NOBUFS;
/*  	EISCONN		133	/ * Socket is already connected */
  hf_error_to_errno_array[HF_ERROR_CODE_ISCONN] = EISCONN;
  hf_errno_to_error_array[EISCONN] = HF_ERROR_CODE_ISCONN;
/*  	ENOTCONN	134	/ * Socket is not connected */
  hf_error_to_errno_array[HF_ERROR_CODE_NOTCONN] = ENOTCONN;
  hf_errno_to_error_array[ENOTCONN] = HF_ERROR_CODE_NOTCONN;
/* XENIX has 135 - 142 */
/*  	ESHUTDOWN	143	/ * Can't send after socket shutdown */
  hf_error_to_errno_array[HF_ERROR_CODE_SHUTDOWN] = ESHUTDOWN;
  hf_errno_to_error_array[ESHUTDOWN] = HF_ERROR_CODE_SHUTDOWN;
/*  	ETOOMANYREFS	144	/ * Too many references: can't splice */
  hf_error_to_errno_array[HF_ERROR_CODE_TOOMANYREFS] = ETOOMANYREFS;
  hf_errno_to_error_array[ETOOMANYREFS] = HF_ERROR_CODE_TOOMANYREFS;
/*  	ETIMEDOUT	145	/ * Connection timed out */
  hf_error_to_errno_array[HF_ERROR_CODE_TIMEDOUT] = ETIMEDOUT;
  hf_errno_to_error_array[ETIMEDOUT] = HF_ERROR_CODE_TIMEDOUT;

/*  	ECONNREFUSED	146	/ * Connection refused */
  hf_error_to_errno_array[HF_ERROR_CODE_CONNREFUSED] = ECONNREFUSED;
  hf_errno_to_error_array[ECONNREFUSED] = HF_ERROR_CODE_CONNREFUSED;
/*  	EHOSTDOWN	147	/ * Host is down */
  hf_error_to_errno_array[HF_ERROR_CODE_HOSTDOWN] = EHOSTDOWN;
  hf_errno_to_error_array[EHOSTDOWN] = HF_ERROR_CODE_HOSTDOWN;
/*  	EHOSTUNREACH	148	/ * No route to host */
  hf_error_to_errno_array[HF_ERROR_CODE_HOSTUNREACH] = EHOSTUNREACH;
  hf_errno_to_error_array[EHOSTUNREACH] = HF_ERROR_CODE_HOSTUNREACH;
/*  	EALREADY	149	/ * operation already in progress */
  hf_error_to_errno_array[HF_ERROR_CODE_ALREADY] = EALREADY;
  hf_errno_to_error_array[EALREADY] = HF_ERROR_CODE_ALREADY;
/*  	EINPROGRESS	150	/ * operation now in progress */
  hf_error_to_errno_array[HF_ERROR_CODE_INPROGRESS] = EINPROGRESS;
  hf_errno_to_error_array[EINPROGRESS] = HF_ERROR_CODE_INPROGRESS;

/* SUN Network File System */
/*  	ESTALE		151	/ * Stale NFS file handle */
  hf_error_to_errno_array[HF_ERROR_CODE_STALE] = ESTALE;
  hf_errno_to_error_array[ESTALE] = HF_ERROR_CODE_STALE;

  return ;
}
#endif /* HF_SOLARIS_HOST_OS */

#ifdef HF_DARWIN_HOST_OS
static void 
init_compat_errno_arrays ()
{
  /*    EDEADLK         11              / * Resource deadlock would occur */
  hf_error_to_errno_array[HF_ERROR_CODE_DEADLK] = EDEADLK;
  hf_errno_to_error_array[EDEADLK] = HF_ERROR_CODE_DEADLK;

  /*    EAGAIN          35              / * Try Again */
  hf_error_to_errno_array[HF_ERROR_CODE_AGAIN] = EAGAIN;
  hf_errno_to_error_array[EAGAIN] = HF_ERROR_CODE_AGAIN;
  
  /*	EINPROGRESS	36	        / * Operation now in progress */
  hf_error_to_errno_array[HF_ERROR_CODE_INPROGRESS] = EINPROGRESS;
  hf_errno_to_error_array[EINPROGRESS] = HF_ERROR_CODE_INPROGRESS;

  /*	EALREADY	37		/ * Operation already in progress */
  hf_error_to_errno_array[HF_ERROR_CODE_ALREADY] = EALREADY;
  hf_errno_to_error_array[EALREADY] = HF_ERROR_CODE_ALREADY;
  
  /*	ENOTSOCK	38		/ * Socket operation on non-socket */
  hf_error_to_errno_array[HF_ERROR_CODE_NOTSOCK] = ENOTSOCK;
  hf_errno_to_error_array[ENOTSOCK] = HF_ERROR_CODE_NOTSOCK;
  
  /*	EDESTADDRREQ	39		/ * Destination address required */
  hf_error_to_errno_array[HF_ERROR_CODE_DESTADDRREQ] = EDESTADDRREQ;
  hf_errno_to_error_array[EDESTADDRREQ] = HF_ERROR_CODE_DESTADDRREQ;
  
  /*	EMSGSIZE	40		/ * Message too long */
  hf_error_to_errno_array[HF_ERROR_CODE_MSGSIZE] = EMSGSIZE;
  hf_errno_to_error_array[EMSGSIZE] = HF_ERROR_CODE_MSGSIZE;
  
  /*	EPROTOTYPE	41		/ * Protocol wrong type for socket */
  hf_error_to_errno_array[HF_ERROR_CODE_PROTOTYPE] = EPROTOTYPE;
  hf_errno_to_error_array[EPROTOTYPE] = HF_ERROR_CODE_PROTOTYPE;
  
  /*	ENOPROTOOPT	42		/ * Protocol not available */
  hf_error_to_errno_array[HF_ERROR_CODE_NOPROTOOPT] = ENOPROTOOPT;
  hf_errno_to_error_array[ENOPROTOOPT] = HF_ERROR_CODE_NOPROTOOPT;
  
  /*	EPROTONOSUPPORT	43		/ * Protocol not supported */
  hf_error_to_errno_array[HF_ERROR_CODE_PROTONOSUPPORT] = EPROTONOSUPPORT;
  hf_errno_to_error_array[EPROTONOSUPPORT] = HF_ERROR_CODE_PROTONOSUPPORT;
  
  /*	ESOCKTNOSUPPORT	44		/ * Socket type not supported */
  hf_error_to_errno_array[HF_ERROR_CODE_SOCKTNOSUPPORT] = ESOCKTNOSUPPORT;
  hf_errno_to_error_array[ESOCKTNOSUPPORT] = HF_ERROR_CODE_SOCKTNOSUPPORT;

  /*	EOPNOTSUPP	45		/ * Operation not supported */
  hf_error_to_errno_array[HF_ERROR_CODE_OPNOTSUPP] = EOPNOTSUPP;
  hf_errno_to_error_array[EOPNOTSUPP] = HF_ERROR_CODE_OPNOTSUPP;

  /*	EPFNOSUPPORT	46		/ * Protocol family not supported */
  hf_error_to_errno_array[HF_ERROR_CODE_PFNOSUPPORT] = EPFNOSUPPORT;
  hf_errno_to_error_array[EPFNOSUPPORT] = HF_ERROR_CODE_PFNOSUPPORT;

  /*	EAFNOSUPPORT	47		/ * Address family not supported by protocol family */
  hf_error_to_errno_array[HF_ERROR_CODE_AFNOSUPPORT] = EAFNOSUPPORT;
  hf_errno_to_error_array[EAFNOSUPPORT] = HF_ERROR_CODE_AFNOSUPPORT;

  /*	EADDRINUSE	48		/ * Address already in use */
  hf_error_to_errno_array[HF_ERROR_CODE_ADDRINUSE] = EADDRINUSE;
  hf_errno_to_error_array[EADDRINUSE] = HF_ERROR_CODE_ADDRINUSE;

  /*	EADDRNOTAVAIL	49		/ * Can't assign requested address */
  hf_error_to_errno_array[HF_ERROR_CODE_ADDRNOTAVAIL] = EADDRNOTAVAIL;
  hf_errno_to_error_array[EADDRNOTAVAIL] = HF_ERROR_CODE_ADDRNOTAVAIL;

  /*	ENETDOWN	50		/ * Network is down */
  hf_error_to_errno_array[HF_ERROR_CODE_NETDOWN] = ENETDOWN;
  hf_errno_to_error_array[ENETDOWN] = HF_ERROR_CODE_NETDOWN;

  /*	ENETUNREACH	51		/ * Network is unreachable */
  hf_error_to_errno_array[HF_ERROR_CODE_NETUNREACH] = ENETUNREACH;
  hf_errno_to_error_array[ENETUNREACH] = HF_ERROR_CODE_NETUNREACH;

  /*	ENETRESET	52		/ * Network dropped connection on reset */
  hf_error_to_errno_array[HF_ERROR_CODE_NETRESET] = ENETRESET;
  hf_errno_to_error_array[ENETRESET] = HF_ERROR_CODE_NETRESET;

  /*	ECONNABORTED	53		/ * Software caused connection abort */
  hf_error_to_errno_array[HF_ERROR_CODE_CONNABORTED] = ECONNABORTED;
  hf_errno_to_error_array[ECONNABORTED] = HF_ERROR_CODE_CONNABORTED;

  /*	ECONNRESET	54		/ * Connection reset by peer */
  hf_error_to_errno_array[HF_ERROR_CODE_CONNRESET] = ECONNRESET;
  hf_errno_to_error_array[ECONNRESET] = HF_ERROR_CODE_CONNRESET;
  
  /*	ENOBUFS		55		/ * No buffer space available */
  hf_error_to_errno_array[HF_ERROR_CODE_NOBUFS] = ENOBUFS;
  hf_errno_to_error_array[ENOBUFS] = HF_ERROR_CODE_NOBUFS;

  /*	EISCONN		56		/ * Socket is already connected */
  hf_error_to_errno_array[HF_ERROR_CODE_ISCONN] = EISCONN;
  hf_errno_to_error_array[EISCONN] = HF_ERROR_CODE_ISCONN;

  /*	ENOTCONN	57		/ * Socket is not connected */
  hf_error_to_errno_array[HF_ERROR_CODE_NOTCONN] = ENOTCONN;
  hf_errno_to_error_array[ENOTCONN] = HF_ERROR_CODE_NOTCONN;

  /*	ESHUTDOWN	58		/ * Can't send after socket shutdown */
  hf_error_to_errno_array[HF_ERROR_CODE_SHUTDOWN] = ESHUTDOWN;
  hf_errno_to_error_array[ESHUTDOWN] = HF_ERROR_CODE_SHUTDOWN;

  /*	ETOOMANYREFS	59		/ * Too many references: can't splice */
  hf_error_to_errno_array[HF_ERROR_CODE_TOOMANYREFS] = ETOOMANYREFS;
  hf_errno_to_error_array[ETOOMANYREFS] = HF_ERROR_CODE_TOOMANYREFS;

  /*	ETIMEDOUT	60		/ * Operation timed out */
  hf_error_to_errno_array[HF_ERROR_CODE_TIMEDOUT] = ETIMEDOUT;
  hf_errno_to_error_array[ETIMEDOUT] = HF_ERROR_CODE_TIMEDOUT;

  /*	ECONNREFUSED	61		/ * Connection refused */
  hf_error_to_errno_array[HF_ERROR_CODE_CONNREFUSED] = ECONNREFUSED;
  hf_errno_to_error_array[ECONNREFUSED] = HF_ERROR_CODE_CONNREFUSED;

  /*	ELOOP		62		/ * Too many levels of symbolic links */
  hf_error_to_errno_array[HF_ERROR_CODE_LOOP] = ELOOP;
  hf_errno_to_error_array[ELOOP] = HF_ERROR_CODE_LOOP;

  /*	ENAMETOOLONG	63		/ * File name too long */
  hf_error_to_errno_array[HF_ERROR_CODE_NAMETOOLONG] = ENAMETOOLONG;
  hf_errno_to_error_array[ENAMETOOLONG] = HF_ERROR_CODE_NAMETOOLONG;

  /*	EHOSTDOWN	64		/ * Host is down */
  hf_error_to_errno_array[HF_ERROR_CODE_HOSTDOWN] = EHOSTDOWN;
  hf_errno_to_error_array[EHOSTDOWN] = HF_ERROR_CODE_HOSTDOWN;

  /*	EHOSTUNREACH	65		/ * No route to host */
  hf_error_to_errno_array[HF_ERROR_CODE_HOSTUNREACH] = EHOSTUNREACH;
  hf_errno_to_error_array[EHOSTUNREACH] = HF_ERROR_CODE_HOSTUNREACH;

  /*	ENOTEMPTY	66		/ * Directory not empty */
  hf_error_to_errno_array[HF_ERROR_CODE_NOTEMPTY] = ENOTEMPTY;
  hf_errno_to_error_array[ENOTEMPTY] = HF_ERROR_CODE_NOTEMPTY;

  /*	EPROCLIM	67		/ * Too many processes */
  hf_error_to_errno_array[HF_ERROR_CODE_PROCLIM] = EPROCLIM;
  hf_errno_to_error_array[EPROCLIM] = HF_ERROR_CODE_PROCLIM;

  /*	EUSERS		68		/ * Too many users */
  hf_error_to_errno_array[HF_ERROR_CODE_USERS] = EUSERS;
  hf_errno_to_error_array[EUSERS] = HF_ERROR_CODE_USERS;

  /*	EDQUOT		69		/ * Disc quota exceeded */
  hf_error_to_errno_array[HF_ERROR_CODE_DQUOT] = EDQUOT;
  hf_errno_to_error_array[EDQUOT] = HF_ERROR_CODE_DQUOT;

  /*	ESTALE		70		/ * Stale NFS file handle */
  hf_error_to_errno_array[HF_ERROR_CODE_STALE] = ESTALE;
  hf_errno_to_error_array[ESTALE] = HF_ERROR_CODE_STALE;

  /*	EREMOTE		71		/ * Too many levels of remote in path */
  hf_error_to_errno_array[HF_ERROR_CODE_REMOTE] = EREMOTE;
  hf_errno_to_error_array[EREMOTE] = HF_ERROR_CODE_REMOTE;

  /*	EBADRPC		72		/ * RPC struct is bad */
  hf_error_to_errno_array[HF_ERROR_CODE_BADRPC] = EBADRPC;
  hf_errno_to_error_array[EBADRPC] = HF_ERROR_CODE_BADRPC;

  /*	ERPCMISMATCH	73		/ * RPC version wrong */
  hf_error_to_errno_array[HF_ERROR_CODE_RPCMISMATCH] = ERPCMISMATCH;
  hf_errno_to_error_array[ERPCMISMATCH] = HF_ERROR_CODE_RPCMISMATCH;

  /*	EPROGUNAVAIL	74		/ * RPC prog. not avail */
  hf_error_to_errno_array[HF_ERROR_CODE_PROGUNAVAIL] = EPROGUNAVAIL;
  hf_errno_to_error_array[EPROGUNAVAIL] = HF_ERROR_CODE_PROGUNAVAIL;

  /*	EPROGMISMATCH	75		/ * Program version wrong */
  hf_error_to_errno_array[HF_ERROR_CODE_PROGMISMATCH] = EPROGMISMATCH;
  hf_errno_to_error_array[EPROGMISMATCH] = HF_ERROR_CODE_PROGMISMATCH;

  /*	EPROCUNAVAIL	76		/ * Bad procedure for program */
  hf_error_to_errno_array[HF_ERROR_CODE_PROCUNAVAIL] = EPROCUNAVAIL;
  hf_errno_to_error_array[EPROCUNAVAIL] = HF_ERROR_CODE_PROCUNAVAIL;

  /*	ENOLCK		77		/ * No locks available */
  hf_error_to_errno_array[HF_ERROR_CODE_NOLCK] = ENOLCK;
  hf_errno_to_error_array[ENOLCK] = HF_ERROR_CODE_NOLCK;

  /*	ENOSYS		78		/ * Function not implemented */
  hf_error_to_errno_array[HF_ERROR_CODE_NOSYS] = ENOSYS;
  hf_errno_to_error_array[ENOSYS] = HF_ERROR_CODE_NOSYS;

  /*	EFTYPE		79		/ * Inappropriate file type or format */
  hf_error_to_errno_array[HF_ERROR_CODE_FTYPE] = EFTYPE;
  hf_errno_to_error_array[EFTYPE] = HF_ERROR_CODE_FTYPE;

  /*	EAUTH		80		/ * Authentication error */
  hf_error_to_errno_array[HF_ERROR_CODE_AUTH] = EAUTH;
  hf_errno_to_error_array[EAUTH] = HF_ERROR_CODE_AUTH;

  /*	ENEEDAUTH	81		/ * Need authenticator */
  hf_error_to_errno_array[HF_ERROR_CODE_NEEDAUTH] = ENEEDAUTH;
  hf_errno_to_error_array[ENEEDAUTH] = HF_ERROR_CODE_NEEDAUTH;
/* Intelligent device errors */
/*  	EPWROFF		82	/ * Device power is off */
  hf_error_to_errno_array[HF_ERROR_CODE_PWROFF] = EPWROFF;
  hf_errno_to_error_array[EPWROFF] = HF_ERROR_CODE_PWROFF;
/*  	EDEVERR		83	/ * Device error, e.g. paper out */
  hf_error_to_errno_array[HF_ERROR_CODE_DEVERR] = EDEVERR;
  hf_errno_to_error_array[EDEVERR] = HF_ERROR_CODE_DEVERR;
 
  /*	EOVERFLOW	84		/ * Value too large to be stored in data type */
  hf_error_to_errno_array[HF_ERROR_CODE_OVERFLOW] = EOVERFLOW;
  hf_errno_to_error_array[EOVERFLOW] = HF_ERROR_CODE_OVERFLOW;

/* Program loading errors */
/*   EBADEXEC	85	/ * Bad executable */
  hf_error_to_errno_array[HF_ERROR_CODE_BADEXEC] = EBADEXEC;
  hf_errno_to_error_array[EBADEXEC] = HF_ERROR_CODE_BADEXEC;

/*   EBADARCH	86	/ * Bad CPU type in executable */
  hf_error_to_errno_array[HF_ERROR_CODE_BADARCH] = EBADARCH;
  hf_errno_to_error_array[EBADARCH] = HF_ERROR_CODE_BADARCH;

/*   ESHLIBVERS	87	/ * Shared library version mismatch */
  hf_error_to_errno_array[HF_ERROR_CODE_SHLIBVERS] = ESHLIBVERS;
  hf_errno_to_error_array[ESHLIBVERS] = HF_ERROR_CODE_SHLIBVERS;

/*   EBADMACHO	88	/ * Malformed Macho file */
  hf_error_to_errno_array[HF_ERROR_CODE_BADMACHO] = EBADMACHO;
  hf_errno_to_error_array[EBADMACHO] = HF_ERROR_CODE_BADMACHO;

#if 0
  /*    EDOOFUS		88		/ * Programming error */
  hf_error_to_errno_array[HF_ERROR_CODE_DOOFUS] = EDOOFUS;
  hf_errno_to_error_array[EDOOFUS] = HF_ERROR_CODE_DOOFUS;
#endif

  /*  	ECANCELED	89		/ * Operation canceled */
  hf_error_to_errno_array[HF_ERROR_CODE_CANCELED] = ECANCELED;
  hf_errno_to_error_array[ECANCELED] = HF_ERROR_CODE_CANCELED;

  /*   EIDRM		90		/ * Identifier removed */
  hf_error_to_errno_array[HF_ERROR_CODE_IDRM] = EIDRM;
  hf_errno_to_error_array[EIDRM] = HF_ERROR_CODE_IDRM;
  /*   ENOMSG		91		/ * No message of desired type */   
  hf_error_to_errno_array[HF_ERROR_CODE_NOMSG] = ENOMSG;
  hf_errno_to_error_array[ENOMSG] = HF_ERROR_CODE_NOMSG;

  /*   EILSEQ		92		/ * Illegal byte sequence */
  hf_error_to_errno_array[HF_ERROR_CODE_ILSEQ] = EILSEQ;
  hf_errno_to_error_array[EILSEQ] = HF_ERROR_CODE_ILSEQ;

  /*   ENOATTR		93		/ * Attribute not found */
  hf_error_to_errno_array[HF_ERROR_CODE_NOATTR] = ENOATTR;
  hf_errno_to_error_array[ENOATTR] = HF_ERROR_CODE_NOATTR;

  /*   EBADMSG		94		/ * Bad message */
  hf_error_to_errno_array[HF_ERROR_CODE_BADMSG] = EBADMSG;
  hf_errno_to_error_array[EBADMSG] = HF_ERROR_CODE_BADMSG;

  /*   EMULTIHOP	95		/ * Reserved */
  hf_error_to_errno_array[HF_ERROR_CODE_MULTIHOP] = EMULTIHOP;
  hf_errno_to_error_array[EMULTIHOP] = HF_ERROR_CODE_MULTIHOP;

  /*  	ENODATA		96		/ * No message available on STREAM */
  hf_error_to_errno_array[HF_ERROR_CODE_NEEDAUTH] = ENEEDAUTH;
  hf_errno_to_error_array[ENEEDAUTH] = HF_ERROR_CODE_NEEDAUTH;

  /*   ENOLINK		97		/ * Reserved */
  hf_error_to_errno_array[HF_ERROR_CODE_NOLINK] = ENOLINK;
  hf_errno_to_error_array[ENOLINK] = HF_ERROR_CODE_NOLINK;

  /*   ENOSR		98		/ * No STREAM resources */
  hf_error_to_errno_array[HF_ERROR_CODE_NOSR] = ENOSR;
  hf_errno_to_error_array[ENOSR] = HF_ERROR_CODE_NOSR;

  /*   ENOSTR		99		/ * Not a STREAM */
  hf_error_to_errno_array[HF_ERROR_CODE_NOSTR] = ENOSTR;
  hf_errno_to_error_array[ENOSTR] = HF_ERROR_CODE_NOSTR;

/*  	EPROTO		100		/ * Protocol error */
  hf_error_to_errno_array[HF_ERROR_CODE_PROTO] = EPROTO;
  hf_errno_to_error_array[EPROTO] = HF_ERROR_CODE_PROTO;
/*   ETIME		101		/ * STREAM ioctl timeout */
  hf_error_to_errno_array[HF_ERROR_CODE_TIME] = ETIME;
  hf_errno_to_error_array[ETIME] = HF_ERROR_CODE_TIME;

/* This value is only discrete when compiling __DARWIN_UNIX03, or KERNEL */
/*  	EOPNOTSUPP	102		/ * Operation not supported on socket */
  hf_error_to_errno_array[HF_ERROR_CODE_OPNOTSUPP] = EOPNOTSUPP;
  hf_errno_to_error_array[EOPNOTSUPP] = HF_ERROR_CODE_OPNOTSUPP;

/*   ENOPOLICY	103		/ * No such policy registered */
  hf_error_to_errno_array[HF_ERROR_CODE_NOPOLICY] = ENOPOLICY;
  hf_errno_to_error_array[ENOPOLICY] = HF_ERROR_CODE_NOPOLICY;

  return ;
}
#endif /* HF_DARWIN_HOST_OS */

#ifdef HF_BSD_HOST_OS
static void 
init_compat_errno_arrays ()
{
  /* Quite a bit of things changed in FreeBSD - current */

  /*    EAGAIN          35              / * Try Again */
  hf_error_to_errno_array[HF_ERROR_CODE_AGAIN] = EAGAIN;
  hf_errno_to_error_array[EAGAIN] = HF_ERROR_CODE_AGAIN;

  /*    EDEADLK         11              / * Resource deadlock would occur */
  hf_error_to_errno_array[HF_ERROR_CODE_DEADLK] = EDEADLK;
  hf_errno_to_error_array[EDEADLK] = HF_ERROR_CODE_DEADLK;
  
  /*	EINPROGRESS	36	        / * Operation now in progress */
  hf_error_to_errno_array[HF_ERROR_CODE_INPROGRESS] = EINPROGRESS;
  hf_errno_to_error_array[EINPROGRESS] = HF_ERROR_CODE_INPROGRESS;

  /*	EALREADY	37		/ * Operation already in progress */
  hf_error_to_errno_array[HF_ERROR_CODE_ALREADY] = EALREADY;
  hf_errno_to_error_array[EALREADY] = HF_ERROR_CODE_ALREADY;
  
  /*	ENOTSOCK	38		/ * Socket operation on non-socket */
  hf_error_to_errno_array[HF_ERROR_CODE_NOTSOCK] = ENOTSOCK;
  hf_errno_to_error_array[ENOTSOCK] = HF_ERROR_CODE_NOTSOCK;
  
  /*	EDESTADDRREQ	39		/ * Destination address required */
  hf_error_to_errno_array[HF_ERROR_CODE_DESTADDRREQ] = EDESTADDRREQ;
  hf_errno_to_error_array[EDESTADDRREQ] = HF_ERROR_CODE_DESTADDRREQ;
  
  /*	EMSGSIZE	40		/ * Message too long */
  hf_error_to_errno_array[HF_ERROR_CODE_MSGSIZE] = EMSGSIZE;
  hf_errno_to_error_array[EMSGSIZE] = HF_ERROR_CODE_MSGSIZE;
  
  /*	EPROTOTYPE	41		/ * Protocol wrong type for socket */
  hf_error_to_errno_array[HF_ERROR_CODE_PROTOTYPE] = EPROTOTYPE;
  hf_errno_to_error_array[EPROTOTYPE] = HF_ERROR_CODE_PROTOTYPE;
  
  /*	ENOPROTOOPT	42		/ * Protocol not available */
  hf_error_to_errno_array[HF_ERROR_CODE_NOPROTOOPT] = ENOPROTOOPT;
  hf_errno_to_error_array[ENOPROTOOPT] = HF_ERROR_CODE_NOPROTOOPT;
  
  /*	EPROTONOSUPPORT	43		/ * Protocol not supported */
  hf_error_to_errno_array[HF_ERROR_CODE_PROTONOSUPPORT] = EPROTONOSUPPORT;
  hf_errno_to_error_array[EPROTONOSUPPORT] = HF_ERROR_CODE_PROTONOSUPPORT;
  
  /*	ESOCKTNOSUPPORT	44		/ * Socket type not supported */
  hf_error_to_errno_array[HF_ERROR_CODE_SOCKTNOSUPPORT] = ESOCKTNOSUPPORT;
  hf_errno_to_error_array[ESOCKTNOSUPPORT] = HF_ERROR_CODE_SOCKTNOSUPPORT;

  /*	EOPNOTSUPP	45		/ * Operation not supported */
  hf_error_to_errno_array[HF_ERROR_CODE_OPNOTSUPP] = EOPNOTSUPP;
  hf_errno_to_error_array[EOPNOTSUPP] = HF_ERROR_CODE_OPNOTSUPP;

  /*	EPFNOSUPPORT	46		/ * Protocol family not supported */
  hf_error_to_errno_array[HF_ERROR_CODE_PFNOSUPPORT] = EPFNOSUPPORT;
  hf_errno_to_error_array[EPFNOSUPPORT] = HF_ERROR_CODE_PFNOSUPPORT;

  /*	EAFNOSUPPORT	47		/ * Address family not supported by protocol family */
  hf_error_to_errno_array[HF_ERROR_CODE_AFNOSUPPORT] = EAFNOSUPPORT;
  hf_errno_to_error_array[EAFNOSUPPORT] = HF_ERROR_CODE_AFNOSUPPORT;

  /*	EADDRINUSE	48		/ * Address already in use */
  hf_error_to_errno_array[HF_ERROR_CODE_ADDRINUSE] = EADDRINUSE;
  hf_errno_to_error_array[EADDRINUSE] = HF_ERROR_CODE_ADDRINUSE;

  /*	EADDRNOTAVAIL	49		/ * Can't assign requested address */
  hf_error_to_errno_array[HF_ERROR_CODE_ADDRNOTAVAIL] = EADDRNOTAVAIL;
  hf_errno_to_error_array[EADDRNOTAVAIL] = HF_ERROR_CODE_ADDRNOTAVAIL;

  /*	ENETDOWN	50		/ * Network is down */
  hf_error_to_errno_array[HF_ERROR_CODE_NETDOWN] = ENETDOWN;
  hf_errno_to_error_array[ENETDOWN] = HF_ERROR_CODE_NETDOWN;

  /*	ENETUNREACH	51		/ * Network is unreachable */
  hf_error_to_errno_array[HF_ERROR_CODE_NETUNREACH] = ENETUNREACH;
  hf_errno_to_error_array[ENETUNREACH] = HF_ERROR_CODE_NETUNREACH;

  /*	ENETRESET	52		/ * Network dropped connection on reset */
  hf_error_to_errno_array[HF_ERROR_CODE_NETRESET] = ENETRESET;
  hf_errno_to_error_array[ENETRESET] = HF_ERROR_CODE_NETRESET;

  /*	ECONNABORTED	53		/ * Software caused connection abort */
  hf_error_to_errno_array[HF_ERROR_CODE_CONNABORTED] = ECONNABORTED;
  hf_errno_to_error_array[ECONNABORTED] = HF_ERROR_CODE_CONNABORTED;

  /*	ECONNRESET	54		/ * Connection reset by peer */
  hf_error_to_errno_array[HF_ERROR_CODE_CONNRESET] = ECONNRESET;
  hf_errno_to_error_array[ECONNRESET] = HF_ERROR_CODE_CONNRESET;
  
  /*	ENOBUFS		55		/ * No buffer space available */
  hf_error_to_errno_array[HF_ERROR_CODE_NOBUFS] = ENOBUFS;
  hf_errno_to_error_array[ENOBUFS] = HF_ERROR_CODE_NOBUFS;

  /*	EISCONN		56		/ * Socket is already connected */
  hf_error_to_errno_array[HF_ERROR_CODE_ISCONN] = EISCONN;
  hf_errno_to_error_array[EISCONN] = HF_ERROR_CODE_ISCONN;

  /*	ENOTCONN	57		/ * Socket is not connected */
  hf_error_to_errno_array[HF_ERROR_CODE_NOTCONN] = ENOTCONN;
  hf_errno_to_error_array[ENOTCONN] = HF_ERROR_CODE_NOTCONN;

  /*	ESHUTDOWN	58		/ * Can't send after socket shutdown */
  hf_error_to_errno_array[HF_ERROR_CODE_SHUTDOWN] = ESHUTDOWN;
  hf_errno_to_error_array[ESHUTDOWN] = HF_ERROR_CODE_SHUTDOWN;

  /*	ETOOMANYREFS	59		/ * Too many references: can't splice */
  hf_error_to_errno_array[HF_ERROR_CODE_TOOMANYREFS] = ETOOMANYREFS;
  hf_errno_to_error_array[ETOOMANYREFS] = HF_ERROR_CODE_TOOMANYREFS;

  /*	ETIMEDOUT	60		/ * Operation timed out */
  hf_error_to_errno_array[HF_ERROR_CODE_TIMEDOUT] = ETIMEDOUT;
  hf_errno_to_error_array[ETIMEDOUT] = HF_ERROR_CODE_TIMEDOUT;

  /*	ECONNREFUSED	61		/ * Connection refused */
  hf_error_to_errno_array[HF_ERROR_CODE_CONNREFUSED] = ECONNREFUSED;
  hf_errno_to_error_array[ECONNREFUSED] = HF_ERROR_CODE_CONNREFUSED;

  /*	ELOOP		62		/ * Too many levels of symbolic links */
  hf_error_to_errno_array[HF_ERROR_CODE_LOOP] = ELOOP;
  hf_errno_to_error_array[ELOOP] = HF_ERROR_CODE_LOOP;

  /*	ENAMETOOLONG	63		/ * File name too long */
  hf_error_to_errno_array[HF_ERROR_CODE_NAMETOOLONG] = ENAMETOOLONG;
  hf_errno_to_error_array[ENAMETOOLONG] = HF_ERROR_CODE_NAMETOOLONG;

  /*	EHOSTDOWN	64		/ * Host is down */
  hf_error_to_errno_array[HF_ERROR_CODE_HOSTDOWN] = EHOSTDOWN;
  hf_errno_to_error_array[EHOSTDOWN] = HF_ERROR_CODE_HOSTDOWN;

  /*	EHOSTUNREACH	65		/ * No route to host */
  hf_error_to_errno_array[HF_ERROR_CODE_HOSTUNREACH] = EHOSTUNREACH;
  hf_errno_to_error_array[EHOSTUNREACH] = HF_ERROR_CODE_HOSTUNREACH;

  /*	ENOTEMPTY	66		/ * Directory not empty */
  hf_error_to_errno_array[HF_ERROR_CODE_NOTEMPTY] = ENOTEMPTY;
  hf_errno_to_error_array[ENOTEMPTY] = HF_ERROR_CODE_NOTEMPTY;

  /*	EPROCLIM	67		/ * Too many processes */
  hf_error_to_errno_array[HF_ERROR_CODE_PROCLIM] = EPROCLIM;
  hf_errno_to_error_array[EPROCLIM] = HF_ERROR_CODE_PROCLIM;

  /*	EUSERS		68		/ * Too many users */
  hf_error_to_errno_array[HF_ERROR_CODE_USERS] = EUSERS;
  hf_errno_to_error_array[EUSERS] = HF_ERROR_CODE_USERS;

  /*	EDQUOT		69		/ * Disc quota exceeded */
  hf_error_to_errno_array[HF_ERROR_CODE_DQUOT] = EDQUOT;
  hf_errno_to_error_array[EDQUOT] = HF_ERROR_CODE_DQUOT;

  /*	ESTALE		70		/ * Stale NFS file handle */
  hf_error_to_errno_array[HF_ERROR_CODE_STALE] = ESTALE;
  hf_errno_to_error_array[ESTALE] = HF_ERROR_CODE_STALE;

  /*	EREMOTE		71		/ * Too many levels of remote in path */
  hf_error_to_errno_array[HF_ERROR_CODE_REMOTE] = EREMOTE;
  hf_errno_to_error_array[EREMOTE] = HF_ERROR_CODE_REMOTE;

  /*	EBADRPC		72		/ * RPC struct is bad */
  hf_error_to_errno_array[HF_ERROR_CODE_BADRPC] = EBADRPC;
  hf_errno_to_error_array[EBADRPC] = HF_ERROR_CODE_BADRPC;

  /*	ERPCMISMATCH	73		/ * RPC version wrong */
  hf_error_to_errno_array[HF_ERROR_CODE_RPCMISMATCH] = ERPCMISMATCH;
  hf_errno_to_error_array[ERPCMISMATCH] = HF_ERROR_CODE_RPCMISMATCH;

  /*	EPROGUNAVAIL	74		/ * RPC prog. not avail */
  hf_error_to_errno_array[HF_ERROR_CODE_PROGUNAVAIL] = EPROGUNAVAIL;
  hf_errno_to_error_array[EPROGUNAVAIL] = HF_ERROR_CODE_PROGUNAVAIL;

  /*	EPROGMISMATCH	75		/ * Program version wrong */
  hf_error_to_errno_array[HF_ERROR_CODE_PROGMISMATCH] = EPROGMISMATCH;
  hf_errno_to_error_array[EPROGMISMATCH] = HF_ERROR_CODE_PROGMISMATCH;

  /*	EPROCUNAVAIL	76		/ * Bad procedure for program */
  hf_error_to_errno_array[HF_ERROR_CODE_PROCUNAVAIL] = EPROCUNAVAIL;
  hf_errno_to_error_array[EPROCUNAVAIL] = HF_ERROR_CODE_PROCUNAVAIL;

  /*	ENOLCK		77		/ * No locks available */
  hf_error_to_errno_array[HF_ERROR_CODE_NOLCK] = ENOLCK;
  hf_errno_to_error_array[ENOLCK] = HF_ERROR_CODE_NOLCK;

  /*	ENOSYS		78		/ * Function not implemented */
  hf_error_to_errno_array[HF_ERROR_CODE_NOSYS] = ENOSYS;
  hf_errno_to_error_array[ENOSYS] = HF_ERROR_CODE_NOSYS;

  /*	EFTYPE		79		/ * Inappropriate file type or format */
  hf_error_to_errno_array[HF_ERROR_CODE_FTYPE] = EFTYPE;
  hf_errno_to_error_array[EFTYPE] = HF_ERROR_CODE_FTYPE;

  /*	EAUTH		80		/ * Authentication error */
  hf_error_to_errno_array[HF_ERROR_CODE_AUTH] = EAUTH;
  hf_errno_to_error_array[EAUTH] = HF_ERROR_CODE_AUTH;

  /*	ENEEDAUTH	81		/ * Need authenticator */
  hf_error_to_errno_array[HF_ERROR_CODE_NEEDAUTH] = ENEEDAUTH;
  hf_errno_to_error_array[ENEEDAUTH] = HF_ERROR_CODE_NEEDAUTH;

  /*	EIDRM		82		/ * Identifier removed */
  hf_error_to_errno_array[HF_ERROR_CODE_IDRM] = EIDRM;
  hf_errno_to_error_array[EIDRM] = HF_ERROR_CODE_IDRM;

  /*	ENOMSG		83		/ * No message of desired type */
  hf_error_to_errno_array[HF_ERROR_CODE_NOMSG] = ENOMSG;
  hf_errno_to_error_array[ENOMSG] = HF_ERROR_CODE_NOMSG;

  /*	EOVERFLOW	84		/ * Value too large to be stored in data type */
  hf_error_to_errno_array[HF_ERROR_CODE_OVERFLOW] = EOVERFLOW;
  hf_errno_to_error_array[EOVERFLOW] = HF_ERROR_CODE_OVERFLOW;

  /*	ECANCELED	85		/ * Operation canceled */
  hf_error_to_errno_array[HF_ERROR_CODE_CANCELED] = ECANCELED;
  hf_errno_to_error_array[ECANCELED] = HF_ERROR_CODE_CANCELED;

  /*	EILSEQ		86		/ * Illegal byte sequence */
  hf_error_to_errno_array[HF_ERROR_CODE_ILSEQ] = EILSEQ;
  hf_errno_to_error_array[EILSEQ] = HF_ERROR_CODE_ILSEQ;

  /*	ENOATTR		87		/ * Attribute not found */
  hf_error_to_errno_array[HF_ERROR_CODE_NOATTR] = ENOATTR;
  hf_errno_to_error_array[ENOATTR] = HF_ERROR_CODE_NOATTR;
  
  /*    EDOOFUS		88		/ * Programming error */
  hf_error_to_errno_array[HF_ERROR_CODE_DOOFUS] = EDOOFUS;
  hf_errno_to_error_array[EDOOFUS] = HF_ERROR_CODE_DOOFUS;

  /*	EBADMSG		89		/ * Bad message */
  hf_error_to_errno_array[HF_ERROR_CODE_BADMSG] = EBADMSG;
  hf_errno_to_error_array[EBADMSG] = HF_ERROR_CODE_BADMSG;

  /*	EMULTIHOP	90		/ * Multihop attempted */
  hf_error_to_errno_array[HF_ERROR_CODE_MULTIHOP] = EMULTIHOP;
  hf_errno_to_error_array[EMULTIHOP] = HF_ERROR_CODE_MULTIHOP;

  /*	ENOLINK		91		/ * Link has been severed */
  hf_error_to_errno_array[HF_ERROR_CODE_NOLINK] = ENOLINK;
  hf_errno_to_error_array[ENOLINK] = HF_ERROR_CODE_NOLINK;

  /*	EPROTO		92		/ * Protocol error */
  hf_error_to_errno_array[HF_ERROR_CODE_PROTO] = EPROTO;
  hf_errno_to_error_array[EPROTO] = HF_ERROR_CODE_PROTO;


  return ;
}
#endif /* HF_BSD_HOST_OS */

#ifdef HF_LINUX_HOST_OS
static void 
init_compat_errno_arrays ()
{
  /* Things are fine. Everything should work seemlessly on GNU/Linux machines */
  return ;
}
#endif /* HF_LINUX_HOST_OS */


static void
init_errno_arrays ()
{
  int i;
  for (i=0; i < HF_ERROR_CODE_UNKNOWN; i++) {
    hf_errno_to_error_array[i] = i;
    hf_error_to_errno_array[i] = i;
  }
  /* Now change the order if it needs to be. */
  init_compat_errno_arrays();

  return;
}

int32_t 
hf_errno_to_error (int32_t op_errno)
{
  if (!hf_compat_errno_init_done) {
    init_errno_arrays ();
    hf_compat_errno_init_done = 1;
  }

  if ((op_errno > HF_ERROR_CODE_SUCCESS) && (op_errno < HF_ERROR_CODE_UNKNOWN))
    return hf_errno_to_error_array[op_errno];

  return op_errno;
}


int32_t 
hf_error_to_errno (int32_t error)
{
  if (!hf_compat_errno_init_done) {
    init_errno_arrays ();
    hf_compat_errno_init_done = 1;
  }

  if ((error > HF_ERROR_CODE_SUCCESS) && (error < HF_ERROR_CODE_UNKNOWN))
    return hf_error_to_errno_array[error];

  return error;
}

