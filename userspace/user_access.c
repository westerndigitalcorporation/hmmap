// SPDX-License-Identifier: GPL-2.0-only
/*
 * user_access.c - mmap an array and access it sequentially or randomly
 *
 * Copyright (c) 2019 Western Digital Corporation or its affiliates
 * Copyright (c) 2019 Adam Manzanares <adam.manzanares@wdc.com>
 *
 */

#define _GNU_SOURCE
#include <stdio.h>
#include <string.h>
#include <fcntl.h>
#include <unistd.h>
#include <sys/mman.h>
#include <errno.h>
#include <stdlib.h>

#include "hmmap_uspace_common.h"

char *usage = "user_access filename device_size [0/1 : seq/rand Read] " 
			  "bytes_to_read device_offset num_threads "
				  "rw_iters print_fault\n";

int main (int argc, char **argv)
{
	int configfd;
	char *address = NULL;
	char *endofarg = NULL;
	size_t device_size;
	unsigned long bool_arg;
	bool rand, fault_info;
	unsigned long bytes_to_read, iters, num_threads;

	if (argc != 9) {
		printf("%s",usage);
		return 1;
	}

	device_size = strtol(argv[2],&endofarg, 0);
	if (errno == ERANGE || *endofarg != '\0' || argv[2] == endofarg) {
		printf("Device size parameter error\n");
		return 1;
	}
	
	endofarg = NULL;
	bool_arg = strtoul(argv[3],&endofarg, 0);
	if (errno == ERANGE || *endofarg != '\0' || argv[3] == endofarg
	    || bool_arg < 0 || bool_arg > 1) {
		printf("Seq/Rand must be 0 or 1\n");
		printf("%s",usage);
		return 1;
	}
	
	rand = (bool)bool_arg;
	bytes_to_read = strtoul(argv[4],&endofarg, 0);
	if (errno == ERANGE || *endofarg != '\0' || argv[4] == endofarg ) {
		printf("Bytes to read paramater error\n");
		printf("%s",usage);
		return 1;
	}

	num_threads = strtoul(argv[6],&endofarg, 0);
	if (errno == ERANGE || *endofarg != '\0' || argv[6] == endofarg ) {
		printf("Bytes to read paramater error\n");
		printf("%s",usage);
		return 1;
	}

	iters = strtoul(argv[7], &endofarg, 0);
	if (errno == ERANGE || *endofarg != '\0' || argv[7] == endofarg ) {
		printf("Num iters parameter error\n");
		printf("%s",usage);
		return 1;
	}

	endofarg = NULL;
	bool_arg = strtoul(argv[8], &endofarg, 0);
	if (errno == ERANGE || *endofarg != '\0' || argv[8] == endofarg
	    || bool_arg < 0 || bool_arg > 1) {
		printf("Seq/Rand must be 0 or 1\n");
		printf("%s",usage);
		return 1;
	}

	fault_info = (bool)bool_arg;

	configfd = open(argv[1],O_RDWR);
	if (configfd < 0){
		printf("Open of %s failed\n",argv[1]);
		perror("Open");
		return 1;
	}

	if (device_size % num_threads) {
		printf("Device size must be a multiple of num_threads\n");
		return 1;
	}
	
	if (bytes_to_read % num_threads) {
		printf("bytes to access must be a multiple of num_threads\n");
		return 1;
	}

	address = mmap(NULL,device_size,PROT_READ|PROT_WRITE,MAP_SHARED,
		       configfd,0);
	if (address == MAP_FAILED){
		perror("MMAP failed\n");
		return 1;
	}

	/* Seed the rng */
	random_init();
	
	run_threads(address, device_size, bytes_to_read, rand, num_threads,
		    iters, fault_info);
	
	printf("Closing the file\n");
	close(configfd);
	return 0;
}
