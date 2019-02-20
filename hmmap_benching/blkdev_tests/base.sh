#!/bin/bash
#
# base.sh - run tests against a given block device
#
# SPDX-License-Identifier: GPL-2.0-only
#
# Copyright (c) 2019 Western Digital Corporation or its affiliates
#

USAGE="base.sh TARGET_DEVICE DEVICE_SIZE CACHE_SIZE NUMA_NODE THREADS ITERS"

if [ $# -ne 6 ]
    then
        echo $USAGE
    exit
fi

TARGET_DEVICE=$1
DEVICE_SIZE=$2
CACHE_SIZE=$3
NUMA_NODE=$4
THREADS=$5
ITERS=$6

TARGET=($(echo ${TARGET_DEVICE} | tr "/" "\n"))
TARGET=${TARGET[1]}

../common/power.sh
../common/cgroup.sh ${CACHE_SIZE}
../common/clean_hmmap.sh
numactl --cpunodebind=${NUMA_NODE} ../common/insert_hmmap.sh ${DEVICE_SIZE} \
${CACHE_SIZE} block_backend ${TARGET_DEVICE}
echo 128 > /sys/kernel/hmmap/two_level/evict_list_size
echo 0 | tee /sys/block/${TARGET}/queue/read_ahead_kb
mkdir results
# Iterate over from num_threads down to 0 in powers of two
while [ $((THREADS)) -ne 0 ]
do
	# Run the hmmap tests
	../common/run_tests.sh ${DEVICE_SIZE} hmmap ${NUMA_NODE} \
	${THREADS} ${ITERS} ""
	# Run the same test using the page cache
	cgexec -g memory:test ../common/run_tests.sh ${DEVICE_SIZE} ${TARGET} \
	${NUMA_NODE} ${THREADS} ${ITERS} ""
	
	THREADS=$((THREADS/2))
done
# Save the results based on the time we finish
mv results `date "+%F-%T"`_${TARGET}_${DEVICE_SIZE}_${CACHE_SIZE}
../common/clean_hmmap.sh

