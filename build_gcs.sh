#!/bin/bash

CurrDir=$(cd "$(dirname "$0")"; pwd)

echo "" && echo "" && echo ""
OP=build
TEE_PLATFORM=amd
#RESOURCE_PROVIDER=kbs
if [ $1 ]; then
  OP=$1
  shift
fi
if [ $1 ]; then
  TEE_PLATFORM=$1
  shift
fi

RESOURCE_PROVIDER=${RESOURCE_PROVIDER:-"kbs"}

SourceDir=phf@10.12.32.132://home/phf/phf_dell/security-compute/code6/coco-guest-components
#TargetRootDir?=/home/cfs/work/herve.pang/cc/kata-containers
#export TargetRootDir=xxx
echo TargetRootDir=${TargetRootDir}
ROOTFS_DIR=${TargetRootDir}/target/initrd_dir

echo OP=${OP}
echo TEE_PLATFORM=${TEE_PLATFORM}

#
LIBC=musl
ARCH=$(uname -m)
DESTDIR=${ROOTFS_DIR}/usr/local/bin

#else ifeq ($(TEE_PLATFORM), amd)
#  LIBC = gnu
#  KBC = cc_kbc_snp,online_sev_kbc
#  ifeq ($(NO_RESOURCE_PROVIDER), true)
#    RESOURCE_PROVIDER :=
#  else
#    RESOURCE_PROVIDER = sev,kbs
#  endif
#endif
if [ ${TEE_PLATFORM} == 'amd' ]; then
  LIBC=musl
  KBC=cc_kbc_snp,online_sev_kbc,cc_kbc,sample_kbc
  RESOURCE_PROVIDER=kbs # sev,kbs
fi

DEBUG=

echo DEBUG=${DEBUG}
echo ARCH=${ARCH}
echo LIBC=${LIBC}
echo KBC=${KBC}
echo DESTDIR=${DESTDIR}
echo RESOURCE_PROVIDER=${RESOURCE_PROVIDER}

#
echo "" && echo "" && echo ""
rm -f ${ROOTFS_DIR}/usr/local/bin/attestation-agent
rm -f ${ROOTFS_DIR}/usr/local/bin/confidential-data-hub
rm -f ${ROOTFS_DIR}/usr/local/bin/api-server-rest

#make clean
#make TEE_PLATFORM=${TEE_PLATFORM} \
#  LIBC=${LIBC} \
#  ARCH=${ARCH} \
#  DESTDIR=${DESTDIR}

cd attestation-agent
rm -f ../target/x86_64-unknown-linux-${LIBC}/release/attestation-agent
make ttrpc=true \
  ARCH=${ARCH} \
  LIBC=${LIBC} \
  KBC=${KBC}
ls -al ../target/x86_64-unknown-linux-${LIBC}/release/attestation-agent
cp ../target/x86_64-unknown-linux-${LIBC}/release/attestation-agent ${ROOTFS_DIR}/usr/local/bin/
make install DESTDIR="${ROOTFS_DIR}/usr/local/bin/"
cd ..

cd confidential-data-hub
rm -f ../target/x86_64-unknown-linux-${LIBC}/release/confidential-data-hub
make RESOURCE_PROVIDER=${RESOURCE_PROVIDER} \
  LIBC=${LIBC}
ls -al ../target/x86_64-unknown-linux-${LIBC}/release/confidential-data-hub
cp ../target/x86_64-unknown-linux-${LIBC}/release/confidential-data-hub ${ROOTFS_DIR}/usr/local/bin/
make install DESTDIR="${ROOTFS_DIR}/usr/local/bin/"
cd ..

cd api-server-rest
rm -f ../target/x86_64-unknown-linux-${LIBC}/release/api-server-rest
make ARCH=${ARCH} \
  LIBC=${LIBC}
ls -al ../target/x86_64-unknown-linux-${LIBC}/release/api-server-rest
cp ../target/x86_64-unknown-linux-${LIBC}/release/api-server-rest ${ROOTFS_DIR}/usr/local/bin/
make install DESTDIR="${ROOTFS_DIR}/usr/local/bin/"
cd ..

echo "" && echo "" && echo ""
if [ -s ${ROOTFS_DIR}/usr/local/bin/attestation-agent ]; then
	echo "compile attestation-agent succ ."
else
    echo "ERROR: compile attestation-agent fail !"
    #exit 1;
fi
#strip ${ROOTFS_DIR}/usr/local/bin/attestation-agent

if [ -s ${ROOTFS_DIR}/usr/local/bin/confidential-data-hub ]; then
	echo "compile confidential-data-hub succ ."
else
    echo "ERROR: compile confidential-data-hub fail !"
    #exit 1;
fi
#strip ${ROOTFS_DIR}/usr/local/bin/confidential-data-hub

if [ -s ${ROOTFS_DIR}/usr/local/bin/api-server-rest ]; then
	echo "compile api-server-rest succ ."
else
    echo "ERROR: compile api-server-rest fail !"
    #exit 1;
fi
#strip ${ROOTFS_DIR}/usr/local/bin/api-server-rest

#
cd ${CurrDir}/
echo "" && echo "" && echo ""
exit 0
#end.
