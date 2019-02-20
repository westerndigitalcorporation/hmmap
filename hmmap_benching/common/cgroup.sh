#!/bin/bash
#
# cgroup.sh - cgroup init script
#
# SPDX-License-Identifier: GPL-2.0-only
#
# Copyright (c) 2019 Western Digital Corporation or its affiliates
#


USAGE="cgroup.sh MEMORY_LIMIT_BYTES"

if [ $# -ne 1 ]; then
	echo $USAGE
	exit
fi

MEM_LIMIT=$1

mkdir /sys/fs/cgroup/memory/test
echo ${MEM_LIMIT} | tee /sys/fs/cgroup/memory/test/memory.limit_in_bytes
