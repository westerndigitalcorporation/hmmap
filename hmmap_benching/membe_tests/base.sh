#!/bin/bash
#
# run tests against the mem_backend
#
# SPDX-License-Identifier: GPL-2.0-only
#

USAGE="./base.sh DEVICE_SIZE CACHE_SIZE NUMA_NODE THREADS ITERS"

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

TARGET_DEVICE="/dev/blah"

../common/power.sh
../common/cgroup.sh ${CACHE_SIZE}
../common/clean_hmmap.sh

numactl --cpunodebind=${NUMA_NODE} ../common/insert_hmmap.sh ${DEVICE_SIZE} \
${CACHE_SIZE} mem_backend ${TARGET_DEVICE}
echo 64 > /sys/kernel/hmmap/two_level/evict_list_size

mkdir results
while [ $((THREADS)) -ne 0 ]
do
	# Run the hmmap tests
	../common/run_tests.sh ${DEVICE_SIZE} hmmap ${NUMA_NODE} \
	${THREADS} ${ITERS} ""
	echo 1 > /sys/kernel/hmmap/hmmap/hmmap_dev_dax
	# Run the hmmap dax tests
	../common/run_tests.sh ${DEVICE_SIZE} hmmap ${NUMA_NODE} \
	${THREADS} ${ITERS} dax
	echo 1 > /sys/kernel/hmmap/hmmap/hmmap_dev_wrprotect
	# Run the hmmap wrprotect dax tests
	../common/run_tests.sh ${DEVICE_SIZE} hmmap ${NUMA_NODE} \
	${THREADS} ${ITERS} wrprotect

	echo 0 > /sys/kernel/hmmap/hmmap/hmmap_dev_dax
	echo 0 > /sys/kernel/hmmap/hmmap/hmmap_dev_wrprotect

	THREADS=$((THREADS/2))
done
# Save the results based on the time we finish
mv results `date "+%F-%T"`_${TARGET}_${DEVICE_SIZE}_${CACHE_SIZE}
../common/clean_hmmap.sh



