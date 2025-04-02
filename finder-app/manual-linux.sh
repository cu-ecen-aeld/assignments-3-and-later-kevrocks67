#!/bin/bash
# Script outline to install and build kernel.
# Author: Siddhant Jajoo.

set -e
set -u

OUTDIR=/tmp/aeld
KERNEL_REPO=git://git.kernel.org/pub/scm/linux/kernel/git/stable/linux-stable.git
KERNEL_VERSION=v5.15.163
BUSYBOX_VERSION=1_33_1
FINDER_APP_DIR=$(realpath $(dirname $0))
ARCH=arm64
CROSS_COMPILE=aarch64-none-linux-gnu-

if [ $# -lt 1 ]
then
	echo "Using default directory ${OUTDIR} for output"
else
	OUTDIR=$1
	echo "Using passed directory ${OUTDIR} for output"
fi

mkdir -p ${OUTDIR}

cd "$OUTDIR"
if [ ! -d "${OUTDIR}/linux-stable" ]; then
    #Clone only if the repository does not exist.
	echo "CLONING GIT LINUX STABLE VERSION ${KERNEL_VERSION} IN ${OUTDIR}"
	git clone ${KERNEL_REPO} --depth 1 --single-branch --branch ${KERNEL_VERSION}
fi
if [ ! -e ${OUTDIR}/linux-stable/arch/${ARCH}/boot/Image ]; then
    cd linux-stable
    echo "Checking out version ${KERNEL_VERSION}"
    git checkout ${KERNEL_VERSION}

    # Add your kernel build steps here
    make ARCH=${ARCH} CROSS_COMPILE=${CROSS_COMPILE} mrproper
    make ARCH=${ARCH} CROSS_COMPILE=${CROSS_COMPILE} defconfig
    make ARCH=${ARCH} CROSS_COMPILE=${CROSS_COMPILE} -j$(nproc) all
    # make ARCH=${ARCH} CROSS_COMPILE=${CROSS_COMPILE} -j$(nproc) modules
    make ARCH=${ARCH} CROSS_COMPILE=${CROSS_COMPILE} -j$(nproc) dtbs
fi

echo "Adding the Image in outdir"
cp ${OUTDIR}/linux-stable/arch/${ARCH}/boot/Image ${OUTDIR}/Image

echo "Creating the staging directory for the root filesystem"
cd "$OUTDIR"
if [ -d "${OUTDIR}/rootfs" ]
then
	echo "Deleting rootfs directory at ${OUTDIR}/rootfs and starting over"
    sudo rm  -rf ${OUTDIR}/rootfs
fi

mkdir -pv ${OUTDIR}/rootfs/{bin,dev,etc,home,lib,lib64,proc,sbin,sys,tmp}
mkdir -pv ${OUTDIR}/rootfs/usr/{bin,lib,sbin}
mkdir -pv ${OUTDIR}/rootfs/var/log

cd "$OUTDIR"
if [ ! -d "${OUTDIR}/busybox" ]
then
git clone git://busybox.net/busybox.git
    cd busybox
    git checkout ${BUSYBOX_VERSION}
    #  Configure busybox
    make ARCH=${ARCH} CROSS_COMPILE=${CROSS_COMPILE} distclean
    make ARCH=${ARCH} CROSS_COMPILE=${CROSS_COMPILE} defconfig
else
    cd busybox
fi

# Make and install busybox
make ARCH=${ARCH} CROSS_COMPILE=${CROSS_COMPILE} -j$(nproc)
make CONFIG_PREFIX=${OUTDIR}/rootfs ARCH=${ARCH} CROSS_COMPILE=${CROSS_COMPILE} install

# Clean and build the writer utility
cd ${FINDER_APP_DIR}
make clean
make CROSS_COMPILE=$CROSS_COMPILE build

echo "Library dependencies"
sysroot=$(${CROSS_COMPILE}gcc -print-sysroot)
prog_interpreter=$(${CROSS_COMPILE}readelf -a ${FINDER_APP_DIR}/writer | grep "program interpreter" | awk '{print $NF}' | cut -d ']' -f1 | awk -F/ '{print $NF}')
shared_libs=$(${CROSS_COMPILE}readelf -a ${FINDER_APP_DIR}/writer | grep "Shared library" | awk -F'[][]' '{print $2}')
shared_libs_sh=$(${CROSS_COMPILE}readelf -a ${OUTDIR}/rootfs/bin/sh | grep "Shared library" | awk -F'[][]' '{print $2}')

prog_interpreter_path=$(find $sysroot -type f -name $prog_interpreter)
cp -a $prog_interpreter_path $OUTDIR/rootfs/$(echo $prog_interpreter_path | awk -F'/' '{n = NF; print $(n-1)"/"$n}')

for shared_lib in $shared_libs;do
    lib_path=$(find $sysroot -type f -name $shared_lib)
    cp -a $lib_path $OUTDIR/rootfs/$(echo $lib_path | awk -F'/' '{n = NF; print $(n-1)"/"$n}')
done

for shared_lib in $shared_libs_sh;do
    lib_path=$(find $sysroot -type f -name $shared_lib)
    cp -a $lib_path $OUTDIR/rootfs/$(echo $lib_path | awk -F'/' '{n = NF; print $(n-1)"/"$n}')
done

# Make device nodes
sudo mknod -m 666 ${OUTDIR}/rootfs/dev/null c 1 3
sudo mknod -m 600 ${OUTDIR}/rootfs/dev/console c 5 1

# Copy the finder related scripts and executables to the /home directory
# on the target rootfs
cp -ar ${FINDER_APP_DIR}/../conf ${OUTDIR}/rootfs/home/
cp -ar ${FINDER_APP_DIR}/finder.sh ${OUTDIR}/rootfs/home/
cp -ar ${FINDER_APP_DIR}/finder-test.sh ${OUTDIR}/rootfs/home/
cp -ar ${FINDER_APP_DIR}/writer ${OUTDIR}/rootfs/home/
cp -ar ${FINDER_APP_DIR}/autorun-qemu.sh ${OUTDIR}/rootfs/home/

# Chown the root directory
sudo chown -R root:root ${OUTDIR}/rootfs

# Create initramfs.cpio.gz
cd ${OUTDIR}/rootfs
find . | cpio -H newc -ov --owner root:root > ${OUTDIR}/initramfs.cpio
cd ${OUTDIR}
gzip -f initramfs.cpio
