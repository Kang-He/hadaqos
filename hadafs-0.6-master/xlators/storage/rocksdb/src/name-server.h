#ifndef _NAME_SERVER_H
#define _NAME_SERVER_H

#include <rocksdb/c.h>

#include "hadafs.h"
#include "common-utils.h"
#include "xlator.h"

#define MAX_PATH_LEN 1024
#define DBPath "/var/rocksdb/dbsets"
#define DBBackupPath "/var/rocksdb/dbsets_backup"

typedef enum {
	RDC_INIT,
	RDC_CONECTED,
	RDC_DISCON
} rdc_status_t;

struct _ns_context {
	rocksdb_t *rdc_db;
	char rdc_dbpath[SHORT_NAME];
	char rdc_dbbackuppath[SHORT_NAME];
	int rdc_port;
	rdc_status_t rdc_status;
	rocksdb_backup_engine_t *rdc_be;
	rocksdb_options_t *rdc_options;
	rocksdb_writeoptions_t *rdc_writeoptions;
	rocksdb_readoptions_t *rdc_readoptions;
};


typedef struct _ns_context ns_context_t;

extern ns_context_t *ns_connect (char *ns_addr, int32_t ns_port);
extern int32_t ns_disconnect (ns_context_t *rdc);
extern int32_t ns_lookupobject (ns_context_t *rdc, object_t *obj, char **err);
extern int32_t ns_getobject(ns_context_t *rdc, object_t *obj, char **err);
extern int32_t ns_setobject (ns_context_t *rdc, object_t *obj, char **err);
extern int32_t ns_updateobject (ns_context_t *rdc, object_t *obj, int16_t updatebits, char **err);
extern int32_t ns_deleteobject(ns_context_t *rdc, char *path, char **err);

#endif
