#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <ctype.h>
#include <errno.h>
#include <unistd.h>
#include <fcntl.h>
#include <sys/types.h>
#include <unistd.h>

#include "list.h"
#include "hadafs.h"
#include "xlator.h"
#include "logging.h"

#define MAX_BUF_SIZE 256
#define MAX_NODE_NUM 1024
#define MAX_CONTENT_SIZE 32768
#define MAX_LIST_SIZE 32768
#define MAX_DIR_LEN 64
#define MAX_SERVER_NUM 4
#define MAX_PREFIX_LEN 4
#define MAX_HOSTNAME_LEN 64

#define HF_VALIDATE(arg)   do {		\
	if (!arg) {					\
		hf_log ("genvol", HF_LOG_ERROR,		\
				"out of memory: " #arg);	\
	}						\
} while (0); 

typedef struct genvol_conf
{
	struct list_head volargs;
	struct list_head ipmap;
} genvol_conf_t;

typedef struct vol_conf 
{
	char  *value;
	char  *key;
	struct list_head list;
} vol_conf_t;

typedef struct ip_map
{
	char  *hostname;
	char  *ip1;
	struct list_head list;
} ip_map_t;

/*
void *
__wrap_malloc (size_t c)
{
		printf ("malloc called with %zu\n", c);
		return __real_malloc (c);
}

void *
__wrap_free (void *ptr)
{
		printf ("free called with %p\n", ptr);
		return __real_free (ptr);
}
*/

char *
trim(char *str){
	char *tmp, *str1, *str2;

	str1 = strdup(str);
	str2 = str1;

	while (isspace(*str1)) str1++;
	tmp = str1 + strlen(str1) - 1;
	while (isspace(*tmp) && tmp > str1){
		*tmp = '\0';
		tmp--;
	}
	snprintf(str, strlen(str1)+1, "%s", str1);
	free(str2);
	return str;
}

int 
hostname_id_get(char *str){
	
	while (!isdigit(*str)) str++;
	return atoi(str);
}

int 
integer_len(int n){
	int len = 1;
	while(n/10){
		len++;
		n /= 10;
	}
	return len;
}

char *
fill_zeros(int id, int n){
	int len = 0;
	char zero[MAX_HOSTNAME_LEN];
	char *str = NULL;
	
	len = n - integer_len(id);
	memset(zero, '0', MAX_HOSTNAME_LEN);

	str = (char *)malloc(sizeof(char)*MAX_HOSTNAME_LEN);
	HF_VALIDATE(str);
	zero[len] = '\0';
	snprintf(str, n+1, "%s%d", zero, id);	
	return str;
}

int 
split_nodes_alpha(char *idrange, char serverlist[][MAX_HOSTNAME_LEN]){

	char *token1, *token2, *save_ptr1, *save_ptr2, *idtmp;
	int begin = 0, end = 0, i = 0, k = 0, idlen = 0;
	char prefix[MAX_PREFIX_LEN];
	char *filltmp = NULL;
	int ret = 0;

	if (!idrange){
		hf_log("genvol", HF_LOG_ERROR, "idrange is NULL");
		exit(-1);
	}else
		idtmp = strdup(idrange);
	
	token1 = strtok_r(idtmp, ",", &save_ptr1);
	
	while(token1){
		token2 = strtok_r(token1, "-", &save_ptr2);
		i = 0;
		while (!isdigit(token2[i])) i++;
		snprintf(prefix, i+1, "%s", token2);
		idlen = strlen(token2) - strlen(prefix);
		begin = atoi(token2+i);
		token2 = strtok_r(NULL, "-", &save_ptr2);
		if (token2)
			end = hostname_id_get(token2);
		else
			end = begin;
		for ( i=begin; i<=end; i++,k++ ){
			filltmp = fill_zeros(i, idlen);
			sprintf(serverlist[k], "%s%s", prefix, filltmp);
			free(filltmp);
			ret++;
		}
		token1 = strtok_r(NULL, ",", &save_ptr1);
	}
	if (idtmp) free(idtmp);
	return ret; 
}

char * 
ipmap_ip_get(genvol_conf_t *conf, char *hostname){
	ip_map_t *tmp = NULL;
	list_for_each_entry(tmp, &conf->ipmap, list){
		assert(tmp);
		//printf("hostname=%s\n", hostname);
		if (!strcasecmp(tmp->hostname, hostname)){
			//printf("%s:%s\n", tmp->hostname, hostname);
			return tmp->ip1;
		}
	}
	hf_log("genvol", HF_LOG_ERROR, "not find %s and ip in hosts\n", hostname);
	return NULL;
}

char *
conf_value_get(genvol_conf_t *conf, char *key){

	vol_conf_t *node = NULL;

	list_for_each_entry(node, &conf->volargs, list){
		if ( !strcasecmp(node->key, key) ){
			return node->value;
		}
	}
	return NULL;
}

int 
inidrange(char serverlist[][MAX_HOSTNAME_LEN], int count, char *hostname){
	int i = 0;
	//test
	for (i=0; i<count; i++){
		hf_log("inidrange", HF_LOG_ERROR, "serverlist[%d] = %s", i,serverlist[i]);
	}
	//test
	for (i=0; i<count; i++){
		if (!strncmp(serverlist[i], hostname, strlen(hostname)))
			return 1;
	}
	return 0;
}

unsigned long  
str2size(char *str){
	char *ptr = NULL;
	unsigned long ret = 0;

	if ((ptr = strchr(str, 'K')) || (ptr = strchr(str, 'k'))) 
		ret = atoi(str) * 1024UL;
	else if ((ptr = strchr(str, 'M')) || (ptr = strchr(str, 'm'))) 
		ret = atoi(str) * 1024UL * 1024UL;
	else if ((ptr = strchr(str, 'G')) || (ptr = strchr(str, 'g'))) 
	{
		ret = atoi(str) * 1024UL * 1024UL * 1024UL;
	}
	else if ((ptr = strchr(str, 'T')) || (ptr = strchr(str, 't'))) 
		ret = atoi(str) * 1024UL * 1024UL * 1024UL * 1024UL;
	else 
		ret = atoi(str);				
	return ret;
}

void 
free_conf(genvol_conf_t *args_conf){

	vol_conf_t   *volargs = NULL;
	vol_conf_t   *tmp1     = NULL;
	ip_map_t *ipmap    = NULL;
	ip_map_t *tmp2     = NULL;

	list_for_each_entry_safe(volargs, tmp1, &args_conf->volargs, list){
		if(volargs->key) free(volargs->key);
		if(volargs->value) free(volargs->value);
		list_del_init(&volargs->list);
		free(volargs);
	}

	list_for_each_entry_safe(ipmap, tmp2, &args_conf->ipmap, list){
		if(ipmap->hostname) free(ipmap->hostname);
		if(ipmap->ip1) free(ipmap->ip1);
		list_del_init(&ipmap->list);
		free(ipmap);
		ipmap = NULL;
	}
	free(args_conf);
}

void
parse_hosts_getip(char *path, genvol_conf_t *args_conf){

	ip_map_t *node;
	char hostname[MAX_HOSTNAME_LEN], ip1[16];
	char buf[MAX_BUF_SIZE];
	char *tmp = NULL;

	FILE *fp = fopen(path, "r");
	if (!fp){
		hf_log("genvol", HF_LOG_ERROR, "open hosts <%s> error, %s\n", 
				path, strerror(errno));
		exit(-1);
	}

	while (fgets(buf, MAX_BUF_SIZE, fp) != NULL){
		tmp = trim(buf);
		//tmp[strlen(tmp)-1] = '\0';
		if (strlen(tmp) > 0 && tmp[0] != '#' && tmp[0] != ':'){

			node = (ip_map_t *)malloc(sizeof(ip_map_t));
			HF_VALIDATE(node);
			INIT_LIST_HEAD(&node->list);

			node->hostname = (char *)malloc(sizeof(char) * MAX_HOSTNAME_LEN);
			HF_VALIDATE(node->hostname);
			node->ip1 = (char *)malloc(sizeof(char) * 16);
			HF_VALIDATE(node->ip1);

			sscanf(tmp, "%s%s", ip1, hostname);
			snprintf(node->hostname, strlen(hostname)+1, "%s", hostname);
			node->hostname = trim(node->hostname);
			snprintf(node->ip1, strlen(ip1)+1, "%s", ip1);
			node->ip1 = trim(node->ip1);
			//printf("%s:%s\n", node->hostname, node->ip1);

			list_add_tail(&node->list, &args_conf->ipmap);
		}
		memset(buf, 0, MAX_BUF_SIZE);
	}

	fclose(fp);
}

void 
parse_init_args(char *conffile, genvol_conf_t *args_conf){

	char buf[MAX_BUF_SIZE];
	vol_conf_t *node;
	char *tmp = NULL;
	int i = 0;

	FILE *fp = fopen(conffile, "r");
	if (!fp){
		hf_log("genvol", HF_LOG_ERROR, "open initial configure file %s error, %s\n", 
				conffile, strerror(errno));
		exit(-1);
	}

	memset(buf, 0, MAX_BUF_SIZE);

	/* init vol_conf_t */
	while (fgets(buf, MAX_BUF_SIZE, fp) != NULL){
		tmp = trim(buf);
		//tmp[strlen(tmp)-1] = '\0';
		if (strlen(tmp) > 0 && tmp[0] != '#'){
			for (i = 0; i < strlen(tmp); i++){
				if (tmp[i] == '='){

					node = (vol_conf_t *)malloc(sizeof(vol_conf_t));
					assert(node != NULL);
					HF_VALIDATE(node);
					INIT_LIST_HEAD(&node->list);

					node->key = (char *)malloc(sizeof(char) * 16);
					HF_VALIDATE(node->key);

					node->value = (char *)malloc(sizeof(char) * 4 * MAX_DIR_LEN);
					HF_VALIDATE(node->value);

					snprintf(node->key, i+1, "%s", tmp);
					node->key = trim(node->key);
					snprintf(node->value, strlen(tmp) - i, "%s", tmp+i+1);
					node->value = trim(node->value);

					list_add_tail(&node->list, &args_conf->volargs);

					break;
				}
			}
		}
		memset(buf, 0, MAX_BUF_SIZE);
	}

	fclose(fp);
}

void 
volconf_insert(genvol_conf_t *conf, char *key, char *value){
	vol_conf_t *node = NULL;

	node = (vol_conf_t *)malloc(sizeof(vol_conf_t));
	HF_VALIDATE(node);
	node->key = (char *)malloc(sizeof(char) * 16);
	HF_VALIDATE(node->key);
	node->value = (char *)malloc(sizeof(char) * 4 * MAX_DIR_LEN);
	//node->value = (char *)malloc(sizeof(char) * 64);
	HF_VALIDATE(node->value);
	INIT_LIST_HEAD(&node->list);

	snprintf(node->key, strlen(key)+1, "%s", key);
	snprintf(node->value, strlen(value)+1, "%s", value);
	list_add_tail(&node->list, &conf->volargs);
}

void
hostname_get(char *hostname){
	int ret = -1, i = 0;
	ret = gethostname(hostname, MAX_HOSTNAME_LEN);
	if (ret != 0){
		hf_log("genvol", HF_LOG_ERROR, "gethostname error");
		exit(-1);
	}
	for (i=0; i<strlen(hostname); i++){
		//new
		if (hostname[i] == '-'){//找到-的位置
			int j=i;
			for(;j<(strlen(hostname)-1);j++){				
				hostname[j] = hostname[j+1];
				if(hostname[j] == '.'){
					hostname[i] = '\0';
				}			
			}
		}
		//new
		
		//old
		// if (hostname[i] == '.')
		// 	hostname[i] = '\0';
		//old
	}
}

void
vol_write(FILE *fp, char *str){
	int ret = -1;
	assert(fp);
	if ((ret = fwrite(str, strlen(str), 1, fp)) < 0){
		hf_log("genvol", HF_LOG_ERROR, "write error, %s", strerror(errno));
		exit(-1);
	}
	memset(str, 0, MAX_CONTENT_SIZE);
}

FILE *
gen_volfile(char *confile, char *type, int port){
	FILE *fp = NULL;
	char *dirp = NULL, *netprotocol = NULL, *gmdbp = NULL, *ltap = NULL;
	char *metamode = NULL, *idrange = NULL, *tmp = NULL, *iphosts = NULL;
	char serverlist[MAX_NODE_NUM][MAX_HOSTNAME_LEN];
	char gmdblist[MAX_LIST_SIZE], gdatalist[MAX_LIST_SIZE];
	char gmdblist_tmp[32], gdatalist_tmp[32];
	int  lta_port[MAX_SERVER_NUM], gmdb_port[MAX_SERVER_NUM];
	int  iothread = 0, sernums = 0;
	int  i = 0, j = 0, flag = 0, count = 0;
	int  nodecount = 0, rank = -1, need_free = 0;
	char *volcontent = NULL, *ip = NULL;
	char *dirprefix[MAX_SERVER_NUM];
	char *token = NULL, *save_ptr = NULL, hostname[MAX_HOSTNAME_LEN];
	char *sw_device = NULL;
	unsigned long memcache = 0UL;

	genvol_conf_t *args_conf;

	args_conf = (genvol_conf_t *)malloc(sizeof(genvol_conf_t));
	if(!args_conf){
		hf_log("genvol", HF_LOG_ERROR, "out of memory");
		return NULL;
	}
	INIT_LIST_HEAD(&args_conf->volargs);
	INIT_LIST_HEAD(&args_conf->ipmap);
	
	parse_init_args(confile, args_conf);

	gmdbp = conf_value_get(args_conf, "gmdb_port");
	if (gmdbp){
		tmp   = strdup(gmdbp);
		if (tmp){
			token = strtok_r(tmp, ",", &save_ptr);
			count = 0;
			while(token){
				gmdb_port[count] = atoi(token);
				token = strtok_r(NULL, ",", &save_ptr);
				count++;
			}
		}
	} else {
		hf_log("genvol", HF_LOG_ERROR, "gmdb_port is not specified");
		return NULL;
	}
	if(tmp) free(tmp);

	sernums = count;

	ltap = conf_value_get(args_conf, "lta_port");
	if (ltap){
		tmp  = strdup(ltap);
		if (tmp){
			token = strtok_r(tmp, ",", &save_ptr);
			count = 0;
			while(token){
				lta_port[count] = atoi(token);
				token = strtok_r(NULL, ",", &save_ptr);
				count++;
			}
		}
	} else {
		hf_log("genvol", HF_LOG_ERROR, "lta_port is not specified");
		return NULL;
	}
	if(tmp) free(tmp);

	if (sernums != count){
		hf_log("genvol", HF_LOG_ERROR, "the number of lta_port and gmdb_port is different");
		return NULL;
	}

	for (i=0; i<sernums; i++){
		dirprefix[i] = (char *)malloc(sizeof(char) * MAX_DIR_LEN);
		HF_VALIDATE(dirprefix[i]);
	}
	dirp = conf_value_get(args_conf, "directory");
	if (dirp){
		tmp  = strdup(dirp);
		if (tmp) {
			token = strtok_r(tmp, ",", &save_ptr);
			count = 0;
			while(token){
				snprintf(dirprefix[count], strlen(token)+1, "%s", trim(token));
				token = strtok_r(NULL, ",", &save_ptr);
				count++;
				if ( count >= sernums)
					break;
			}
		}
	}else{
		hf_log("genvol", HF_LOG_ERROR, "export directory is not specified");
		return NULL;
	}
	if(tmp) free(tmp);
	
	netprotocol = conf_value_get(args_conf, "netprotocol");
	if (!netprotocol){
		volconf_insert(args_conf, "netprotocol", "socket");
		netprotocol = conf_value_get(args_conf, "netprotocol");
	}

	sw_device = conf_value_get(args_conf, "swnet_device");
	if (!sw_device){
		volconf_insert(args_conf, "swnet_device", "swnet_0");
		sw_device = conf_value_get(args_conf, "swnet_device");
	}
		
	metamode = conf_value_get(args_conf, "metamode");
	if (!metamode){
		volconf_insert(args_conf, "metamode", "part_async");
		metamode    = conf_value_get(args_conf, "metamode");
	}

	idrange = conf_value_get(args_conf, "idrange");
	if (!idrange) {
		hf_log("genvol", HF_LOG_ERROR, "server range not specified");
	}

	iphosts = conf_value_get(args_conf, "hosts");
	if (!iphosts) {
		volconf_insert(args_conf, "hosts", "/etc/hosts");
		iphosts = conf_value_get(args_conf, "hosts");
		hf_log("genvol", HF_LOG_WARNING, "use default host: /etc/hosts");
	}

	parse_hosts_getip(iphosts, args_conf);

	// get rank
	if (type == NULL){
		type = (char *)malloc(sizeof(char)*8);
		HF_VALIDATE(type);
		need_free = 1;
		for (i=0; i<sernums; i++){
			if (port == gmdb_port[i]){
				rank = i + 1;
				snprintf(type, 5, "%s", "gmdb");
				break;
			} else if (port == lta_port[i]){
				rank = i + 1;
				snprintf(type, 4, "%s", "lta");
				break;
			}
		}
	} else if (! strncasecmp(type, "gmdb", 4)){
		for (i=0; i<sernums; i++){
			if (gmdb_port[i] == port){
				rank = i + 1;
				break;
			}
		}
	} else if (! strncasecmp(type, "lta", 3)){
		for (i=0; i<sernums; i++){
			if (lta_port[i] == port){
				rank = i + 1;
				break;
			}
		}
	}
		for (i=0; i<sernums; i++){
		hf_log("genvol", HF_LOG_ERROR, "the port is %d, %d",
					gmdb_port[i], lta_port[i]);
		}

	if (rank == -1){
		hf_log("genvol", HF_LOG_ERROR, "the port %d is not in port list",
					port);
		//return NULL;
		rank = 1;
	}

	nodecount = split_nodes_alpha(idrange, serverlist);
	
	tmp = conf_value_get(args_conf, "iothread");
	if (!tmp) iothread = 0; else iothread = atoi(tmp);

	tmp = conf_value_get(args_conf, "memcache");
	if (!tmp)
		memcache = 0UL;
	else {
		memcache = str2size(tmp);	
	}

	hostname_get(hostname);
	flag = inidrange(serverlist, nodecount, hostname);
	
	if (!flag){
		hf_log("genvol", HF_LOG_ERROR, "%s is not in idrange", hostname);
		return NULL;
	}

	volcontent = (char *)malloc(sizeof(char) * MAX_CONTENT_SIZE);
	HF_VALIDATE(volcontent);

	memset(volcontent, 0, sizeof(char) * MAX_CONTENT_SIZE);
	memset(gmdblist, 0, MAX_LIST_SIZE);
	memset(gdatalist, 0, MAX_LIST_SIZE);

	/* make tmpfile */
#if TMPFILE
	fp = tmpfile();
#else
	char filename[1024]="\0";
	sprintf(filename, "/tmp/%s_%s_%d", basename(confile), type, port);
	fp = fopen(filename, "w+");
#endif
        if(fp == NULL) {
			free_conf(args_conf);
			return NULL;
        }
	/* generate gmdb.conf */
	if ((type && !strncasecmp(type, "gmdb", 4))){

		sprintf(volcontent, "\
volume gmdb\n\
    type storage/rocksdb\n\
    option rocksdb-path %s/hadagmdb-%d\n\
    option rocksdb-port %d\n\
end-volume\n\n",
		dirprefix[rank-1], rank, gmdb_port[rank-1]);	
		
		vol_write(fp, volcontent);

		if (!strncmp(netprotocol, "swnet", 5)){
			sprintf(volcontent, "\
volume server\n\
    type protocol/server\n\
    option transport-type swnet-verbs\n\
    option transport.swnet-verbs.device-name %s\n\
    option transport.swnet-verbs.listen-port %d\n\
	option transport.swnet-verbs.rdma-rgmem-size 513MB\n\
    option transport.swnet-verbs.rdma-addr-count 5\n\
    subvolumes gmdb\n\
    option auth.addr.gmdb.allow *\n\
end-volume", 
			sw_device, gmdb_port[rank-1]);	

		}else{
			sprintf(volcontent, "\
volume server\n\
    type protocol/server\n\
    option transport-type socket\n\
    option transport.socket.listen-port %d\n\
    subvolumes gmdb\n\
    option auth.addr.gmdb.allow *\n\
end-volume", 
			gmdb_port[rank-1]);	
		}

		vol_write(fp, volcontent);

		fflush(fp);
		fseek(fp, 0, SEEK_SET);

		if (need_free) free(type);
		free_conf(args_conf);
		free(volcontent);
		for (i=0; i<sernums; i++) free(dirprefix[i]);

		return fp;
	}

	/* generate lta.conf */

	/* gmdb brick */
	for (j=0; j<sernums; j++){
		for ( i=0; i<nodecount; i++){
			ip = ipmap_ip_get(args_conf, serverlist[i]);
			memset(gmdblist_tmp, 0, 32);
			sprintf(gmdblist_tmp, " gmdb-%s-%d", serverlist[i], j+1);	
			strcat(gmdblist, gmdblist_tmp);
			if (!strncmp(netprotocol, "swnet", 5)){
				sprintf(volcontent, "\
volume gmdb-%s-%d\n\
    type protocol/client\n\
    option transport-type swnet-verbs\n\
    option transport.swnet-verbs.device-name %s\n\
    option transport.swnet-verbs.rdma-rgmem-size 6MB\n\
	option transport.swnet-verbs.rdma-addr-count 5\n\
    option remote-port %d\n\
    option ping-timeout 900\n\
    option remote-host %s\n\
    option remote-subvolume gmdb\n\
end-volume\n\n",
				serverlist[i], j+1, sw_device, gmdb_port[j], ip);	
			}else{
				sprintf(volcontent, "\
volume gmdb-%s-%d\n\
    type protocol/client\n\
    option transport-type %s\n\
    option remote-port %d\n\
    option ping-timeout 900\n\
    option remote-host %s\n\
    option remote-subvolume gmdb\n\
end-volume\n\n",
				serverlist[i], j+1, netprotocol, gmdb_port[j], ip);	
			}
			vol_write(fp, volcontent);
		}
	}

	/* gns brick */
	sprintf(volcontent, "\
volume gns\n\
    type cluster/gns\n\
    subvolumes %s\n\
end-volume\n", 
	gmdblist);

	vol_write(fp, volcontent);

	/* gdata brick */
	for (j=0; j<sernums; j++){
		for ( i=0; i<nodecount; i++){
			if (strncmp(serverlist[i], hostname, strlen(hostname)) || rank-1 != j){
				ip = ipmap_ip_get(args_conf, serverlist[i]);
				memset(gdatalist_tmp, 0, 32);
				sprintf(gdatalist_tmp, " gdata-%s-%d", serverlist[i], j+1);
				strcat(gdatalist, gdatalist_tmp);

				if (!strncmp(netprotocol, "swnet", 5)){
					sprintf(volcontent, "\n\
volume gdata-%s-%d\n\
    type protocol/client\n\
    option transport-type swnet-verbs\n\
    option transport.swnet-verbs.device-name %s\n\
    option transport.swnet-verbs.rdma-rgmem-size 6MB\n\
    option transport.swnet-verbs.rdma-addr-count 5\n\
    option remote-port %d\n\
    option ping-timeout 900\n\
    option remote-host %s\n\
    option remote-subvolume lta\n\
end-volume\n",
					serverlist[i], j+1, sw_device, lta_port[j], ip);	
				}else{
					sprintf(volcontent, "\n\
volume gdata-%s-%d\n\
    type protocol/client\n\
    option transport-type %s\n\
    option remote-port %d\n\
    option ping-timeout 900\n\
    option remote-host %s\n\
    option remote-subvolume lta\n\
end-volume\n",
					serverlist[i], j+1, netprotocol, lta_port[j], ip);	

				}
				vol_write(fp, volcontent);
			}
		}
	}

	/* posix brick */
	sprintf(volcontent, "\n\
volume brick\n\
    type storage/posix\n\
    option directory %s/hadaexport\n\
end-volume\n",
	dirprefix[rank-1]);

	vol_write(fp, volcontent);

	/* TODO: memcache,swthread brick */
	if (memcache)
		sprintf(volcontent, "\n\
volume memcache\n\
    type performance/mem-cache\n\
    option flush-behind 1\n\
    option cache-size %ld\n\
    option log-file /tmp/hadafs-memcache%d.log\n\
    option thread-count 4\n\
    subvolumes brick\n\
end-volume\n",
		memcache, rank);

	vol_write(fp, volcontent);

	if (iothread && memcache)
		sprintf(volcontent, "\n\
volume iothread\n\
    type performance/io-threads\n\
    option thread-count %d\n\
    subvolumes memcache\n\
end-volume\n",
		iothread);
	else if (iothread)
		sprintf(volcontent, "\n\
volume iothread\n\
    type performance/io-threads\n\
    option thread-count %d\n\
    subvolumes brick\n\
end-volume\n",
		iothread);

	vol_write(fp, volcontent);

	sprintf(volcontent, "\n\
volume lns\n\
    type storage/rocksdb\n\
    option rocksdb-path %s/hadalmdb-%d\n\
    option rocksdb-port %d\n\
end-volume\n",
    dirprefix[rank-1], rank, lta_port[rank-1]);

	vol_write(fp, volcontent);

	/* local gdata brick */
	if (iothread)
		sprintf(volcontent, "\n\
volume gdata-%s-%d\n\
    type cluster/lvolume\n\
    option local-name-server lns\n\
    subvolumes iothread\n\
end-volume\n",
		hostname, rank);
	else if (memcache)
		sprintf(volcontent, "\n\
volume gdata-%s-%d\n\
    type cluster/lvolume\n\
    option local-name-server lns\n\
    subvolumes memcache\n\
end-volume\n",
		hostname, rank);
	else
		sprintf(volcontent, "\n\
volume gdata-%s-%d\n\
    type cluster/lvolume\n\
    option local-name-server lns\n\
    subvolumes brick\n\
end-volume\n",
		hostname, rank);

	vol_write(fp, volcontent);

	/* lta brick */
	sprintf(volcontent, "\n\
volume gvolume\n\
    type cluster/gvolume\n\
    subvolumes gdata-node-1\n\
end-volume\n\
\n\
volume lta\n\
    type cluster/lta\n\
    option global-name-server gns\n\
    option local-volume gdata-%s-%d\n\
    option metadata-mode %s\n\
    subvolumes gvolume\n\
end-volume\n", hostname, rank, metamode);

	vol_write(fp, volcontent);

	/* server brick */
	if (!strncmp(netprotocol, "swnet", 5)){
		sprintf(volcontent, "\n\
volume server\n\
    type protocol/server\n\
    option transport-type swnet-verbs\n\
    option transport.swnet-verbs.device-name %s\n\
    option transport.swnet-verbs.listen-port %d\n\
    option transport.swnet-verbs.rdma-rgmem-size 513MB\n\
    option transport.swnet-verbs.rdma-addr-count 5\n\
    subvolumes lta\n\
    option auth.addr.lta.allow *\n\
end-volume", 
		sw_device, lta_port[rank-1]);
			
	}else{
		sprintf(volcontent, "\n\
volume server\n\
    type protocol/server\n\
    option transport-type socket\n\
    option transport.socket.listen-port %d\n\
    subvolumes lta\n\
    option auth.addr.lta.allow *\n\
end-volume", 
		lta_port[rank-1]);
	}

	vol_write(fp, volcontent);

	if (need_free) free(type);
	fflush(fp);
	fseek(fp, 0, SEEK_SET);
	free(volcontent);
	free_conf(args_conf);
	for (i=0; i<sernums; i++) free(dirprefix[i]);

	return fp;
}

#if 0
int main(int argc, char* argv[]){

	FILE *file1 = NULL, *file2 = NULL;
	char buf[131072];
	int ret;
	int port;
	int port2 = 9200, port1 = 8800;
	if (argc != 2){
		printf("please specify port\n");
		exit(-1); 
	}
	port = atoi(argv[1]);
	printf("port = %d\n", port);
	//file1 = gen_volfile("init.conf", "gmdb", port1);
	file2 = gen_volfile("init.conf", "lta", port2);
	//file2 = gen_volfile("init.conf", NULL, port);
	/*
	ret = fread(buf, 131072, 1, file1);
	printf("file=%p, ret=%d, errno=%s, buf=\n%s\n", file1, ret, strerror(errno), buf);
	fclose(file1);
	*/
	ret = fread(buf, 131072, 1, file2);
	printf("file=%p, ret=%d, errno=%s, buf=\n%s\n", file2, ret, strerror(errno), buf);
	fclose(file2);

	return 0;
}
#endif
