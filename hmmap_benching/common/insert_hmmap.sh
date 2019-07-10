#!/bin/bash
#
# insert_hmmap.sh - script to load hmmap
#
# SPDX-License-Identifier: GPL-2.0-only
#
# Copyright (c) 2019 Western Digital Corporation or its affiliates
#

USAGE="insert_hmmap.sh device_size cache_size backend_device backend_path"

if [ $# -ne 4 ]; then
	echo $USAGE
	exit
fi

DEVICE_SIZE=$1
CACHE_SIZE=$2
BACKEND_DEVICE=$3
BACKEND_PATH=$4

pushd .
cd ../../hmmap_mod/
cp *.ko /lib/modules/`uname -r`/
depmod -a
modprobe hmmap device_size=${DEVICE_SIZE} cache_size=${CACHE_SIZE} \
backend_device="${BACKEND_DEVICE}" backend_path="${BACKEND_PATH}"
DEV_NODE=`dmesg | grep "hmmap: added device" | tail -n 1 | awk '{print $NF}' | \
awk -F ":" '{print $1}'`
mknod /dev/hmmap c ${DEV_NODE} 0
popd
../common/hmmap_print_sections.sh 
