#!/bin/bash
#
# power.sh - set cpu scaling governor to performance
#
# SPDX-License-Identifier: GPL-2.0-only
#
# Copyright (c) 2019 Western Digital Corporation or its affiliates
#

NUM_CPUS=`nproc --all`

for CPU in `seq 0 $((NUM_CPUS-1))`; 
do
	echo performance | tee /sys/devices/system/cpu/cpu${CPU}/cpufreq/scaling_governor
done
