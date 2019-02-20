#!/bin/bash
#
# hmmap_print_sections.sh - print out module sections for debugging 
#
# SPDX-License-Identifier: GPL-2.0-only
#
# Copyright (c) 2019 Western Digital Corporation or its affiliates
#

HMMAP_MODS=("hmmap" "hmmap_two_level_cache" "hmmap_mem_backend" "hmmap_block_backend")

for HMMAP_MOD in "${HMMAP_MODS[@]}"
do
	pushd .
	cd /sys/module/${HMMAP_MOD}/sections
	echo "add-symbol-file ${HMMAP_MOD}.ko `cat .text` -s .data `cat .data` -s .bss \
	`cat .bss`"
	popd
done
