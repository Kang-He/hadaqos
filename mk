mpicc -g -olatency latency.c -lm ../hadafs_client/libhadafsclient.a -lpthread -lswverbs -I.
mpicc -g -ojdebug_like jdebug_like.c -lm ../hadafs_client/libhadafsclient.a -lpthread -lswverbs -I.
