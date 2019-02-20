// SPDX-License-Identifier: GPL-2.0-only
/*
 * baseline.c - allocate an array and access it sequentially or randomly
 *
 * Copyright (c) 2019 Western Digital Corporation or its affiliates
 * Copyright (c) 2019 Adam Manzanares <adam.manzanares@wdc.com>
 *
 */


#include <stdio.h>
#include <string.h>
#include <fcntl.h>
#include <unistd.h>
#include <sys/mman.h>
#include <errno.h>
#include <stdlib.h>

#include "hmmap_uspace_common.h"


char *usage = "baseline array_size [0/1 : seq/rand Read] bytes_to_read "
	       "num_threads rw_iters print_fault\n";


int main (int argc, char **argv)
{
	char *address = NULL;
	char *endofarg = NULL;
	size_t device_size;
	unsigned long bool_arg, bytes_to_read, num_threads, iters;
	bool rand, fault_info;

	if (argc != 7) {
		printf("%s",usage);
		return 1;
	}

	/* Todo remove these if statement with a function */
	device_size = strtol(argv[1],&endofarg, 0);
	if (errno == ERANGE || *endofarg != '\0' || argv[1] == endofarg) {
		printf("Device size parameter error\n");
		printf("%s",usage);
		return 1;
	}

	endofarg = NULL;
	bool_arg = strtoul(argv[2], &endofarg, 0);
	if (errno == ERANGE || *endofarg != '\0' || argv[2] == endofarg 
	    || bool_arg < 0 || bool_arg > 1) {
		printf("Seq/Rand must be 0 or 1\n");
		printf("%s",usage);
		return 1;
	}

	rand = (bool)bool_arg;
	endofarg = NULL;
	bytes_to_read = strtoul(argv[3],&endofarg, 0);
	if (errno == ERANGE || *endofarg != '\0' || argv[3] == endofarg ) {
		printf("Bytes to read paramater error\n");
		printf("%s",usage);
		return 1;
	}

	endofarg = NULL;
	num_threads = strtoul(argv[4],&endofarg, 0);
	if (errno == ERANGE || *endofarg != '\0' || argv[4] == endofarg ) {
		printf("Num threads paramater error\n");
		printf("%s",usage);
		return 1;
	}

	endofarg = NULL;
	iters = strtoul(argv[5], &endofarg, 0);
	if (errno == ERANGE || *endofarg != '\0' || argv[5] == endofarg ) {
		printf("Num iters parameter error\n");
		printf("%s",usage);
		return 1;
	}

	endofarg = NULL;
	bool_arg = strtoul(argv[6], &endofarg, 0);
	if (errno == ERANGE || *endofarg != '\0' || argv[6] == endofarg
	    || bool_arg < 0 || bool_arg > 1) {
		printf("Seq/Rand must be 0 or 1\n");
		printf("%s",usage);
		return 1;
	}

	fault_info = (bool)bool_arg;
	/* Seed the random number generator */
	random_init();
	address = (char *)malloc(device_size);
	if (!address) {
		perror("Malloc failed\n");
		return -1;
	}

	run_threads(address, device_size, bytes_to_read, rand, num_threads,
		    (unsigned int)iters, fault_info);

	printf("Closing the file\n");
	free(address);
	return 0;
}
