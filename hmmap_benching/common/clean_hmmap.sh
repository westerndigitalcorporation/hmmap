#!/bin/bash
#
# clean_hmmap.sh - script to remove hmmap modules
#
# SPDX-License-Identifier: GPL-2.0-only
#
# Copyright (c) 2019 Western Digital Corporation or its affiliates
#

# I could be more intelligent and find the backends and caches currently loaded
BACKENDS=( "hmmap_block_backend" "hmmap_mem_backend hmmap_dax_backend" "hmmap_nvme_mem_backend")
CACHES=( "hmmap_two_level_cache" "hmmap_dimmap_cache" "hmmap_dax_cache" )

rmmod hmmap
for BACKEND in ${BACKENDS[@]}
do
    rmmod ${BACKEND}
done

for CACHE in ${CACHES[@]}
do
    rmmod ${CACHE}
done

rmmod hmmap_list
rmmod hmmap_block_common
rmmod hmmap_common
rm -f /dev/hmmap
