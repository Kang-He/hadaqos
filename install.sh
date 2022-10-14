cp -r lib64/* /usr/local/lib64
cp -r rocksdb /usr/local/include/
cp gflagslib/libgflags* /usr/local/lib64/
cp -r gflagsinclude/gflags /usr/local/include/
yum -y install snappy snappy-devel
yum -y install zlib zlib-devel
yum -y install bzip2 bzip2-devel
yum -y install lz4-devel
yum -y install gflags
cd zstd-1.1.3
make install
cd ..
ldconfig

cd hadafs-0.6-master
sh autogen.sh
./configure
make
make install #you can find hadafsd in /usr/local/sbin

cp hosts /tmp/
mkdir -p /usr/local/etc/hadafs
cp server.vol /usr/local/etc/hadafs

#please edit server.vol and hosts with your enviroments setting
#don't forget to put hosts in the right directory define in server.vol

#then you can start hadafsd, see hadafsd --help
/usr/local/sbin/hadafsd -f /usr/local/etc/hadafs/server.vol -l /var/log/hadafs/server-portNUM.log -LTRACE -t GMDB|LTA
