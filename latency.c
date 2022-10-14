#include <mpi.h> 
#include <stdio.h> 
#include <stdlib.h> 
#include <assert.h> 
#include <math.h>
#include <sys/types.h>
#include <sys/stat.h>
#include <fcntl.h>
#include <string.h>
#include <unistd.h>
#include <dirent.h>
#include <errno.h>
#include <time.h>
#include <sys/time.h>

#include "libhadafsclient.h"

void hadafs_env_init(int id){

if ((hadafs_mount ("hexbtest",id)) == -1) {
    char hostname[64]={0,};
        if (-1 == gethostname (hostname, 256))

                printf("VMP mounting failed rank is %d\n",id );
        else
                printf("VMP mounting failed %s rank is %d\n",hostname, id );

                exit(-1);
        }

    //fprintf(stdout, "mount succeed, continue!\n");
    //    //fflush(stdout);
}


int main(int argc, char **argv)
{
    hadafs_file_t fh = NULL;
    hadafs_file_t fr = NULL;
    int i, j, ret;
    int nodeCount;
    MPI_Group worldgroup, testgroup;
    int rank = 0;
    int size;
    struct timeval tv1, tv2;
    double time;
    long lmtime=0, gmsum, max, min;
    char file_path[256];
    struct stat st;
    memset(file_path,0, 256);

    MPI_Init(&argc, &argv);
    MPI_Comm_rank(MPI_COMM_WORLD, &rank);
    MPI_Comm_size(MPI_COMM_WORLD, &size);
    MPI_Barrier(MPI_COMM_WORLD);
    gettimeofday(&tv1, NULL);
    //hadafs_env_init(rank);
    hadafs_env_init(rank%16);
    //sprintf(file_path, "/tmp/root/file%04d", rank);
    //ret = hadafs_stat(file_path, &st);
    //ret = hadafs_unlink(file_path);
    //fh = hadafs_open(file_path, O_CREAT|O_RDWR);
    //hadafs_close(fh);	
    //ret = hadafs_unlink(file_path);
    gettimeofday(&tv2, NULL);
    lmtime += (tv2.tv_sec - tv1.tv_sec)*1000000+tv2.tv_usec-tv1.tv_usec;
    MPI_Reduce(&lmtime, &gmsum, 1, MPI_LONG, MPI_SUM, 0, MPI_COMM_WORLD);
    MPI_Reduce(&lmtime, &max, 1, MPI_LONG, MPI_MAX, 0, MPI_COMM_WORLD);
    MPI_Reduce(&lmtime, &min, 1, MPI_LONG, MPI_MIN, 0, MPI_COMM_WORLD);
    if(rank == 0) {
	    printf("size: %d avg: %lf max %ld min %ld\n", size, gmsum*1.0/size, max, min);	
    }
    MPI_Finalize();
    hadafs_umount();
    return 0;   
}

