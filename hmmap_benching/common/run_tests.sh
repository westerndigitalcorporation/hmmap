#!/bin/bash
#
# run_tests.sh - script to run user_access benchmark
#
# SPDX-License-Identifier: GPL-2.0-only
#
# Copyright (c) 2019 Western Digital Corporation or its affiliates
#

USAGE="run_tests.sh DEVICE_SIZE TARGET NUMA_NODE THREADS ITERS INFO"

if [ $# -ne 6 ]
	then 
		echo $USAGE
	exit
fi

BYTES=$1
TARGET=$2
NUMA_NODE=$3
THREADS=$4
ITERS=$5
INFO=$6

RAND_BYTES=$(((BYTES/4096)*8))
if [[ -z "${INFO// }" ]]
then
	OUTPUT_TARGET=${TARGET}
else
	OUTPUT_TARGET="${TARGET}_${INFO}"
fi

# Run the benchmark assumes you are in the userspace directory of user_swap
for ITER in `seq 1 ${ITERS}`;
do
	echo 3 | tee /proc/sys/vm/drop_caches
	numactl --cpunodebind=${NUMA_NODE} \
	../../userspace/user_access /dev/${TARGET} \
	${BYTES} 0 ${BYTES} 0 ${THREADS} 1 0 | \
	tee -a results/${OUTPUT_TARGET}.${THREADS}.seq.out
done

for ITER in `seq 1 ${ITERS}`;
do
	echo 3 | tee /proc/sys/vm/drop_caches
	numactl --cpunodebind=${NUMA_NODE} \
	../../userspace/user_access /dev/${TARGET} ${BYTES} 1 \
	${RAND_BYTES} 0 ${THREADS} 1 0 | \
	tee -a results/${OUTPUT_TARGET}.${THREADS}.rand.out
done
