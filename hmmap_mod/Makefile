# SPDX-License-Identifier: GPL-2.0
obj-m := hmmap.o hmmap_list.o hmmap_common.o hmmap_two_level_cache.o \
hmmap_mem_backend.o hmmap_block_backend.o hmmap_pcie_mem_backend.o

# RDMA and DIMMAP are a bit behind
#hmmap_rdma_backend.o
#hmmap_dimmap_cache.o
# Hopefully there is way to not use DAX private headers
#hmmap_dax_backend.o

hmmap-y := hmmap_core.o
hmmap_list-y := list.o
hmmap_common-y := common.o
hmmap_two_level_cache-y := two_level_cache.o
hmmap_mem_backend-y := mem_backend.o
hmmap_block_backend-y := block_backend.o
hmmap_pcie_mem_backend-y := pcie_mem_backend.o
#hmmap_dax_backend-y := dax_backend.o
#hmmap_dimmap_cache-y := dimmap_cache.o
#hmmap_rdma_backend-y := rdma_backend.o

all:
	make -C /lib/modules/$(shell uname -r)/build M=$(PWD) modules
clean:
	make -C /lib/modules/$(shell uname -r)/build M=$(PWD) clean

