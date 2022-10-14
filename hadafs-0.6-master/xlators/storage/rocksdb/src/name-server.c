#include <stdio.h>
#include <stdlib.h>
#include <sys/types.h>
#include <sys/stat.h>
#include <sys/time.h>
#include <fcntl.h>
#include <string.h>
#include <libgen.h>
#include <time.h>
#include <inttypes.h>
#include <unistd.h>
#include <pthread.h>
#include <errno.h>
#include <assert.h>

#include "name-server.h"
#include "logging.h"
#include "hadafs.h"
#include "common-utils.h"
#include "name-server.h"

void objvaluecopy(object_t *dest, object_t *src)
{
    if (dest == NULL || src == NULL)
        return;
    memcpy(&dest->metadata, &src->metadata, sizeof(metadata_t));
}


void
ns_dump_metadata(object_t *obj)
{
	metadata_t *m = &obj->metadata;	
	hf_log("metadata",HF_LOG_NORMAL,
		"object %s, metadata:VMP %s, SID %s, soffset %d, status %d, lhost %s, lno %ld, ppath %s",
		obj->path,
		m->vmp, m->sid, m->soffset, m->status, m->lhost, m->lno, m->ppath);

}

ns_context_t *
rd_db_init (char *dbpath, int32_t ns_port)
{
	ns_context_t *rdc = NULL;
	rdc = CALLOC(1, sizeof(ns_context_t));
	if(rdc == NULL) {
		return NULL;
	}

	rdc->rdc_db = NULL;
	sprintf(rdc->rdc_dbpath, "%s", dbpath);
	sprintf(rdc->rdc_dbbackuppath, "%s_%04d",rdc->rdc_dbpath, ns_port);
	rdc->rdc_port = ns_port;
	rdc->rdc_status = RDC_INIT;
	rdc->rdc_be = NULL;
	rdc->rdc_writeoptions = NULL;
	rdc->rdc_readoptions = NULL;

	return rdc;
}

int32_t
ns_db_destory (ns_context_t *rdc)
{
	if (rdc == NULL)
		return 0;

	if(rdc->rdc_writeoptions)
		rocksdb_writeoptions_destroy(rdc->rdc_writeoptions);
	if(rdc->rdc_readoptions)
		rocksdb_readoptions_destroy(rdc->rdc_readoptions);
	if(rdc->rdc_options)
		rocksdb_options_destroy(rdc->rdc_options);
	if(rdc->rdc_be)
		rocksdb_backup_engine_close(rdc->rdc_be);
	if(rdc->rdc_db)
		rocksdb_close(rdc->rdc_db);

	FREE(rdc);
	return 0;
}

ns_context_t *
ns_connect (char *db_addr, int32_t db_port)
{
	ns_context_t *rdc = NULL;
	char *err = NULL; 
	long cpus = 0;

	rdc = rd_db_init(db_addr, db_port);
	if(rdc == NULL)
		return rdc;

	cpus = sysconf(_SC_NPROCESSORS_ONLN);
	rdc->rdc_options = rocksdb_options_create();
	// Set # of online cores
	rocksdb_options_increase_parallelism(rdc->rdc_options, (int)(cpus / 8));
	rocksdb_options_optimize_level_style_compaction(rdc->rdc_options, 1048576);
	rocksdb_options_set_create_if_missing(rdc->rdc_options, 1);

	/* first connect addr */
	rdc->rdc_db = rocksdb_open(rdc->rdc_options, rdc->rdc_dbpath, &err);
	if(err) {
		hf_log("name-server", HF_LOG_ERROR, "connected to rocksdb %s failed %s",
				rdc->rdc_dbpath, err);
		return NULL;
	}

	rdc->rdc_writeoptions= rocksdb_writeoptions_create();
	rdc->rdc_readoptions= rocksdb_readoptions_create();
	rdc->rdc_status = RDC_CONECTED;
	return rdc;
}

int32_t 
ns_reconnect (ns_context_t *rdc)
{
	if(rdc == NULL)
		return -1;

	ns_connect(rdc->rdc_dbpath, rdc->rdc_port);
	return 0; 
} 
int32_t
ns_disconnect (ns_context_t *rdc)
{
	if(rdc == NULL)
		return -1;

	ns_db_destory(rdc);
	return 0;
}


/*
 * -1: error
 * 0: not found
 * 1: found
 */
int32_t
ns_getobject(ns_context_t *rdc, object_t *obj, char **err)
{
	char object_key[1024] = "\0";
	size_t mdsize = 0;
	char *err_str = NULL;
	metadata_t *value = NULL;
	
	if(rdc == NULL || obj == NULL)
		return -1;
	
	sprintf(object_key, "f:%s", obj->path);
	value = rocksdb_get(rdc->rdc_db, rdc->rdc_readoptions, 
			object_key, strlen(object_key), &mdsize, &err_str); 
	if(err_str) {
		err = &err_str;
		return -1;
	}
	if(value == NULL) {
		return 0;
	}
	memcpy(&obj->metadata, value, sizeof(metadata_t));
	obj->status = OBJ_FRESH;

	return 1;
}
/*
 * -1: error
 * 0: not found
 * 1: found
 */
int32_t
ns_lookupobject (ns_context_t *rdc, object_t *obj, char **err)
{
	char object_key[1024] = "\0";
	int found = -1;
	size_t mdsize;
	metadata_t *value = NULL;
	char *err_str = NULL;

	if(rdc == NULL || obj == NULL)
		return -1;

	sprintf(object_key, "f:%s", obj->path);
	value = rocksdb_get(rdc->rdc_db, rdc->rdc_readoptions, 
			object_key, strlen(object_key),&mdsize, &err_str); 
	if(err_str != NULL) {
		err = &err_str;
		return -1;
	}
	if(value == NULL)
		return 0;

	return 1;
}

int32_t
ns_setobject (ns_context_t *rdc, object_t *obj, char **err)
{
	char object_key[1024] = "\0";
	char *err_str = NULL;
	
	if(rdc == NULL || obj == NULL)
		return -1;


	sprintf(object_key, "f:%s",obj->path);
	rocksdb_put(rdc->rdc_db, rdc->rdc_writeoptions, object_key, strlen(object_key),
		&obj->metadata, sizeof(metadata_t), &err_str);
	if(err_str) {
		err = &err_str;
		return -1;
	}

	return 0;
}

int32_t
ns_updateobject (ns_context_t *rdc, object_t *obj, int16_t updatebits, char **err)
{

	return ns_setobject(rdc, obj, err);
}

int32_t
ns_deleteobject(ns_context_t *rdc, char *path, char **err)
{
	char *err_str = NULL;
	char object_key[1024] = "\0";
	
	if(rdc == NULL || path == NULL)
		return -1;
	
	sprintf(object_key, "f:%s", path);
	rocksdb_delete(rdc->rdc_db, rdc->rdc_writeoptions, object_key, strlen(object_key),
		&err_str);
	if(err_str) {
		err = &err_str;
		return -1;
	}

	return 0;
}
#if 0
int main(void)
{
	int ret = 0, i = 0;
	struct stat st;
	object_t obj;
	ns_context_t *rdc = NULL;
	time_t time1, time2;
        struct timeval tv1, tv2, tv3;
	unsigned long sum = 0, sum_1 = 0;
	char base[100]="/tmp/uname/dir2/file2";

	ret = stat("/var/log/messages", &st);
	if(ret < 0) {
		printf("stat file error\n");
		return -1;
	}
	rdc = ns_connect("/tmp/db_test", 23);
	time(&time1);
	for(i=0;i<=100000;i++) {
		obj.path = calloc(128, sizeof(char));
		sprintf(obj.path, "%s_%d", base, i);
		obj.vmp = NULL;
		obj.sid = NULL;
		obj.soffset = 0;
		obj.ppath = NULL;
		obj.lhost = "host1";
		obj.lno = st.st_ino;
		obj.size = st.st_size;
		obj.uid = st.st_uid;
		obj.gid = st.st_gid;
		obj.mode = st.st_mode;
		obj.atime = st.st_atime;
		obj.ctime = st.st_ctime;
		obj.mtime = st.st_mtime;
		gettimeofday(&tv1, NULL);
		ret = lns_isexist_object(rdc, &obj);
		if(ret < 0) {
			printf("isexist object failed\n");
			return -1;
		}
		gettimeofday(&tv2, NULL);
		ret = ns_set_object(rdc, &obj);
		if(ret < 0) {
			printf("set object failed\n");
			return -1;
		}
		gettimeofday(&tv3, NULL);
		sum += (tv2.tv_sec - tv1.tv_sec)*1000000+tv2.tv_usec-tv1.tv_usec;
		sum_1 += (tv3.tv_sec - tv2.tv_sec)*1000000+tv3.tv_usec-tv2.tv_usec;
	}
	time(&time2);
	printf("finish set tes %ld %ld %ld, t %f, avg %f\n", time2 - time1, sum, sum_1, sum/100000.0, sum_1/100000.0);

	ns_rd_disconnect(rdc);

	return 0;	
}
#endif
