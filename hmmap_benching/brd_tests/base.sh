#!/bin/bash
#
# base.sh - block ram disk hmmap benching script
#
# SPDX-License-Identifier: GPL-2.0-only
#
# Copyright (c) 2019 Western Digital Corporation or its affiliates
#

USAGE="base.sh DEVICE_SIZE CACHE_SIZE NUMA_NODE THREADS ITERS"

if [ $# -ne 5 ]
    then
        echo $USAGE
    exit
fi

DEVICE_SIZE=$1
CACHE_SIZE=$2
NUMA_NODE=$3
THREADS=$4
ITERS=$5

TARGET_DEVICE="/dev/ram0"
BRD_SIZE=$((DEVICE_SIZE/1024))


modprobe brd rd_nr=1 rd_size=${BRD_SIZE} max_part=1
numactl --cpunodebind=${NUMA_NODE} dd if=/dev/zero of=${TARGET_DEVICE} \
bs=1048576 count=$((DEVICE_SIZE/1048576))
../blkdev_tests/base.sh ${TARGET_DEVICE} ${DEVICE_SIZE} ${CACHE_SIZE} \
${NUMA_NODE} ${THREADS} ${ITERS}
rmmod brd
