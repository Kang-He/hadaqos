# Installation Instructions
*************************

## 1. Install Rocksdb

###  install bzip2, bzip2-devel, lz4, lz4-devel, zlib, zlib-devel
```
yum install bzip2
yum install bzip2-devel
yum install lz4
yum install lz4-devel
yum install zlib
yum install zlib-devel
```
### install zstd
```
cd your-zstd-source-path #version >= 1.3.2 is OK
make 
make install
```
### install rocksdb
```
cd your-rocksdb-path
make
make install
```
2. Install hadafs

Run ./configure after untaring the package.

```
bash# ./configure
HADAFS configure summary
===========================
Infiniband verbs   : yes
swnet verbs   : yes
epoll IO multiplex : yes
libhadafsclient : yes
argp-standalone    : no

```
Now just run 'make' and later run 'make install' to install the package.
```
 bash# make 
 bash# make install
```
Installation complete :-)
```
bash# hadafs --version
hadafs 0.6 built on Jun 23 2022 21:00:57
Repository revision: v0.6
Copyright (c) 2022-2029 HADA JNS. HADAFS comes with ABSOLUTELY NO WARRANTY.
You may redistribute copies of HADAFS under the terms of the GNU General Public License.

```

Make sure your version is the latest from the release, and the one you 
just installed :-)