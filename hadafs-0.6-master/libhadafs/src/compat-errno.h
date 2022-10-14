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

#ifndef __COMPAT_ERRNO_H__
#define __COMPAT_ERRNO_H__

#ifndef _CONFIG_H
#define _CONFIG_H
#include "config.h"
#endif

#include <errno.h>

#define HF_ERROR_CODE_SUCCESS         0
#define HF_ERROR_CODE_UNKNOWN         1024
#define HF_ERRNO_UNKNOWN              1024

#define HF_ERROR_CODE_PERM            1      /* Operation not permitted */
#define HF_ERROR_CODE_NOENT           2      /* No such file or directory */
#define HF_ERROR_CODE_SRCH            3      /* No such process */
#define HF_ERROR_CODE_INTR            4      /* Interrupted system call */
#define HF_ERROR_CODE_IO              5      /* I/O error */
#define HF_ERROR_CODE_NXIO            6      /* No such device or address */
#define HF_ERROR_CODE_2BIG            7      /* Argument list too long */
#define HF_ERROR_CODE_NOEXEC          8      /* Exec format error */
#define HF_ERROR_CODE_BADF            9      /* Bad file number */
#define HF_ERROR_CODE_CHILD          10      /* No child processes */
#define HF_ERROR_CODE_AGAIN          11      /* Try again */
#define HF_ERROR_CODE_NOMEM          12      /* Out of memory */
#define HF_ERROR_CODE_ACCES          13      /* Permission denied */
#define HF_ERROR_CODE_FAULT          14      /* Bad address */
#define HF_ERROR_CODE_NOTBLK         15      /* Block device required */
#define HF_ERROR_CODE_BUSY           16      /* Device or resource busy */
#define HF_ERROR_CODE_EXIST          17      /* File exists */
#define HF_ERROR_CODE_XDEV           18      /* Cross-device link */
#define HF_ERROR_CODE_NODEV          19      /* No such device */
#define HF_ERROR_CODE_NOTDIR         20      /* Not a directory */
#define HF_ERROR_CODE_ISDIR          21      /* Is a directory */
#define HF_ERROR_CODE_INVAL          22      /* Invalid argument */
#define HF_ERROR_CODE_NFILE          23      /* File table overflow */
#define HF_ERROR_CODE_MFILE          24      /* Too many open files */
#define HF_ERROR_CODE_NOTTY          25      /* Not a typewriter */
#define HF_ERROR_CODE_TXTBSY         26      /* Text file busy */
#define HF_ERROR_CODE_FBIG           27      /* File too large */
#define HF_ERROR_CODE_NOSPC          28      /* No space left on device */
#define HF_ERROR_CODE_SPIPE          29      /* Illegal seek */
#define HF_ERROR_CODE_ROFS           30      /* Read-only file system */
#define HF_ERROR_CODE_MLINK          31      /* Too many links */
#define HF_ERROR_CODE_PIPE           32      /* Broken pipe */
#define HF_ERROR_CODE_DOM            33      /* Math argument out of domain of func */
#define HF_ERROR_CODE_RANGE          34      /* Math result not representable */
#define HF_ERROR_CODE_DEADLK         35      /* Resource deadlock would occur */
#define HF_ERROR_CODE_NAMETOOLONG    36      /* File name too long */
#define HF_ERROR_CODE_NOLCK          37      /* No record locks available */
#define HF_ERROR_CODE_NOSYS          38      /* Function not implemented */
#define HF_ERROR_CODE_NOTEMPTY       39      /* Directory not empty */
#define HF_ERROR_CODE_LOOP           40      /* Too many symbolic links encountered */

#define HF_ERROR_CODE_NOMSG          42      /* No message of desired type */
#define HF_ERROR_CODE_IDRM           43      /* Identifier removed */
#define HF_ERROR_CODE_CHRNG          44      /* Channel number out of range */
#define HF_ERROR_CODE_L2NSYNC        45      /* Level 2 not synchronized */
#define HF_ERROR_CODE_L3HLT          46      /* Level 3 halted */
#define HF_ERROR_CODE_L3RST          47      /* Level 3 reset */
#define HF_ERROR_CODE_LNRNG          48      /* Link number out of range */
#define HF_ERROR_CODE_UNATCH         49      /* Protocol driver not attached */
#define HF_ERROR_CODE_NOCSI          50      /* No CSI structure available */
#define HF_ERROR_CODE_L2HLT          51      /* Level 2 halted */
#define HF_ERROR_CODE_BADE           52      /* Invalid exchange */
#define HF_ERROR_CODE_BADR           53      /* Invalid request descriptor */
#define HF_ERROR_CODE_XFULL          54      /* Exchange full */
#define HF_ERROR_CODE_NOANO          55      /* No anode */
#define HF_ERROR_CODE_BADRQC         56      /* Invalid request code */
#define HF_ERROR_CODE_BADSLT         57      /* Invalid slot */
#define HF_ERROR_CODE_BFONT          59      /* Bad font file format */
#define HF_ERROR_CODE_NOSTR          60      /* Device not a stream */
#define HF_ERROR_CODE_NODATA         61      /* No data available */
#define HF_ERROR_CODE_TIME           62      /* Timer expired */
#define HF_ERROR_CODE_NOSR           63      /* Out of streams resources */
#define HF_ERROR_CODE_NONET          64      /* Machine is not on the network */
#define HF_ERROR_CODE_NOPKG          65      /* Package not installed */
#define HF_ERROR_CODE_REMOTE         66      /* Object is remote */
#define HF_ERROR_CODE_NOLINK         67      /* Link has been severed */
#define HF_ERROR_CODE_ADV            68      /* Advertise error */
#define HF_ERROR_CODE_SRMNT          69      /* Srmount error */
#define HF_ERROR_CODE_COMM           70      /* Communication error on send */
#define HF_ERROR_CODE_PROTO          71      /* Protocol error */
#define HF_ERROR_CODE_MULTIHOP       72      /* Multihop attempted */
#define HF_ERROR_CODE_DOTDOT         73      /* RFS specific error */
#define HF_ERROR_CODE_BADMSG         74      /* Not a data message */
#define HF_ERROR_CODE_OVERFLOW       75      /* Value too large for defined data type */
#define HF_ERROR_CODE_NOTUNIQ        76      /* Name not unique on network */
#define HF_ERROR_CODE_BADFD          77      /* File descriptor in bad state */
#define HF_ERROR_CODE_REMCHG         78      /* Remote address changed */
#define HF_ERROR_CODE_LIBACC         79      /* Can not access a needed shared library */
#define HF_ERROR_CODE_LIBBAD         80      /* Accessing a corrupted shared library */
#define HF_ERROR_CODE_LIBSCN         81      /* .lib section in a.out corrupted */
#define HF_ERROR_CODE_LIBMAX         82      /* Attempting to link in too many shared libraries */
#define HF_ERROR_CODE_LIBEXEC        83      /* Cannot exec a shared library directly */
#define HF_ERROR_CODE_ILSEQ          84      /* Illegal byte sequence */
#define HF_ERROR_CODE_RESTART        85      /* Interrupted system call should be restarted */
#define HF_ERROR_CODE_STRPIPE        86      /* Streams pipe error */
#define HF_ERROR_CODE_USERS          87      /* Too many users */
#define HF_ERROR_CODE_NOTSOCK        88      /* Socket operation on non-socket */
#define HF_ERROR_CODE_DESTADDRREQ    89      /* Destination address required */
#define HF_ERROR_CODE_MSGSIZE        90      /* Message too long */
#define HF_ERROR_CODE_PROTOTYPE      91      /* Protocol wrong type for socket */
#define HF_ERROR_CODE_NOPROTOOPT     92      /* Protocol not available */
#define HF_ERROR_CODE_PROTONOSUPPORT 93      /* Protocol not supported */
#define HF_ERROR_CODE_SOCKTNOSUPPORT 94      /* Socket type not supported */
#define HF_ERROR_CODE_OPNOTSUPP      95      /* Operation not supported on transport endpoint */
#define HF_ERROR_CODE_PFNOSUPPORT    96      /* Protocol family not supported */
#define HF_ERROR_CODE_AFNOSUPPORT    97      /* Address family not supported by protocol */
#define HF_ERROR_CODE_ADDRINUSE      98      /* Address already in use */
#define HF_ERROR_CODE_ADDRNOTAVAIL   99      /* Cannot assign requested address */
#define HF_ERROR_CODE_NETDOWN        100     /* Network is down */
#define HF_ERROR_CODE_NETUNREACH     101     /* Network is unreachable */
#define HF_ERROR_CODE_NETRESET       102     /* Network dropped connection because of reset */
#define HF_ERROR_CODE_CONNABORTED    103     /* Software caused connection abort */
#define HF_ERROR_CODE_CONNRESET      104     /* Connection reset by peer */
#define HF_ERROR_CODE_NOBUFS         105     /* No buffer space available */
#define HF_ERROR_CODE_ISCONN         106     /* Transport endpoint is already connected */
#define HF_ERROR_CODE_NOTCONN        107     /* Transport endpoint is not connected */
#define HF_ERROR_CODE_SHUTDOWN       108     /* Cannot send after transport endpoint shutdown */
#define HF_ERROR_CODE_TOOMANYREFS    109     /* Too many references: cannot splice */
#define HF_ERROR_CODE_TIMEDOUT       110     /* Connection timed out */
#define HF_ERROR_CODE_CONNREFUSED    111     /* Connection refused */
#define HF_ERROR_CODE_HOSTDOWN       112     /* Host is down */
#define HF_ERROR_CODE_HOSTUNREACH    113     /* No route to host */
#define HF_ERROR_CODE_ALREADY        114     /* Operation already in progress */
#define HF_ERROR_CODE_INPROGRESS     115     /* Operation now in progress */
#define HF_ERROR_CODE_ALREADY        114     /* Operation already in progress */
#define HF_ERROR_CODE_INPROGRESS     115     /* Operation now in progress */
#define HF_ERROR_CODE_STALE          116     /* Stale NFS file handle */
#define HF_ERROR_CODE_UCLEAN         117     /* Structure needs cleaning */
#define HF_ERROR_CODE_NOTNAM         118     /* Not a XENIX named type file */
#define HF_ERROR_CODE_NAVAIL         119     /* No XENIX semaphores available */
#define HF_ERROR_CODE_ISNAM          120     /* Is a named type file */
#define HF_ERROR_CODE_REMOTEIO       121     /* Remote I/O error */
#define HF_ERROR_CODE_DQUOT          122     /* Quota exceeded */
#define HF_ERROR_CODE_NOMEDIUM       123     /* No medium found */
#define HF_ERROR_CODE_MEDIUMTYPE     124     /* Wrong medium type */
#define HF_ERROR_CODE_CANCELED       125     /* Operation Canceled */
#define HF_ERROR_CODE_NOKEY          126     /* Required key not available */
#define HF_ERROR_CODE_KEYEXPIRED     127     /* Key has expired */
#define HF_ERROR_CODE_KEYREVOKED     128     /* Key has been revoked */
#define HF_ERROR_CODE_KEYREJECTED    129     /* Key was rejected by service */

/* for robust mutexes */
#define HF_ERROR_CODE_OWNERDEAD      130     /* Owner died */
#define HF_ERROR_CODE_NOTRECOVERABLE 131     /* State not recoverable */



/* Should never be seen by user programs */
#define HF_ERROR_CODE_RESTARTSYS     512
#define HF_ERROR_CODE_RESTARTNOINTR  513
#define HF_ERROR_CODE_RESTARTNOHAND  514     /* restart if no handler.. */
#define HF_ERROR_CODE_NOIOCTLCMD     515     /* No ioctl command */
#define HF_ERROR_CODE_RESTART_RESTARTBLOCK 516 /* restart by calling sys_restart_syscall */

/* Defined for the NFSv3 protocol */
#define HF_ERROR_CODE_BADHANDLE      521     /* Illegal NFS file handle */
#define HF_ERROR_CODE_NOTSYNC        522     /* Update synchronization mismatch */
#define HF_ERROR_CODE_BADCOOKIE      523     /* Cookie is stale */
#define HF_ERROR_CODE_NOTSUPP        524     /* Operation is not supported */
#define HF_ERROR_CODE_TOOSMALL       525     /* Buffer or request is too small */
#define HF_ERROR_CODE_SERVERFAULT    526     /* An untranslatable error occurred */
#define HF_ERROR_CODE_BADTYPE        527     /* Type not supported by server */
#define HF_ERROR_CODE_JUKEBOX        528     /* Request initiated, but will not complete before timeout */
#define HF_ERROR_CODE_IOCBQUEUED     529     /* iocb queued, will get completion event */
#define HF_ERROR_CODE_IOCBRETRY      530     /* iocb queued, will trigger a retry */

/* Darwin OS X */
#define HF_ERROR_CODE_NOPOLICY   701
#define HF_ERROR_CODE_BADMACHO   702
#define HF_ERROR_CODE_PWROFF     703
#define HF_ERROR_CODE_DEVERR     704
#define HF_ERROR_CODE_BADARCH    705
#define HF_ERROR_CODE_BADEXEC    706
#define HF_ERROR_CODE_SHLIBVERS  707



/* Solaris */
/*  	ENOTACTIVE 73	/ * Facility is not active		*/
#define HF_ERROR_CODE_NOTACTIVE   801 
/*  	ELOCKUNMAPPED	72	/ * locked lock was unmapped */
#define HF_ERROR_CODE_LOCKUNMAPPED 802

/* BSD system */
#define HF_ERROR_CODE_PROCLIM	        901		/* Too many processes */
#define HF_ERROR_CODE_BADRPC		902		/* RPC struct is bad */
#define HF_ERROR_CODE_RPCMISMATCH	903		/* RPC version wrong */
#define HF_ERROR_CODE_PROGUNAVAIL	904		/* RPC prog. not avail */
#define HF_ERROR_CODE_PROGMISMATCH	905		/* Program version wrong */
#define HF_ERROR_CODE_PROCUNAVAIL	905		/* Bad procedure for program */
#define HF_ERROR_CODE_FTYPE		906		/* Inappropriate file type or format */
#define HF_ERROR_CODE_AUTH		907		/* Authentication error */
#define HF_ERROR_CODE_NEEDAUTH	        908		/* Need authenticator */
#define HF_ERROR_CODE_DOOFUS		909		/* Programming error */

#define HF_ERROR_CODE_NOATTR		HF_ERROR_CODE_NODATA		/* Attribute not found */

/* Either one of enodata or enoattr will be there in system */
#ifndef ENOATTR
#define ENOATTR ENODATA
#endif /* ENOATTR */

#ifndef ENODATA
#define ENODATA ENOATTR
#endif /* ENODATA */

#ifndef EBADFD
#define EBADFD EBADRPC
#endif /* EBADFD */

/* These functions are defined for all the OS flags, but content will 
 * be different for each OS flag. 
 */
int32_t hf_errno_to_error (int32_t op_errno);
int32_t hf_error_to_errno (int32_t error);

#endif /* __COMPAT_ERRNO_H__ */
