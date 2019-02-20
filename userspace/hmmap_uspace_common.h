/* SPDX-License-Identifier: GPL-2.0-only
 *
 * hmmap.h - hmmap
 *
 * Copyright (c) 2019 Western Digital Corporation or its affiliates
 * Copyright (c) 2019 Adam Manzanares <adam.manzanares@wdc.com>
 *
 */

#include <time.h>
#include <stdbool.h>

#define PAGE_SIZE 4096
#define NSINS 1000000000

struct access_thread_info {
	pthread_t tid;
	unsigned int iters;
	char *address;
	size_t device_size;
	unsigned long bytes_to_read;
	bool rand;
	bool fault_info;
	double *rw_times;
};

/* Calculte the time difference between two timespec points */
double calculate_time_diff(struct timespec start, struct timespec end,
			   bool print);

/* Read or write buffer with a given seed value */
double access_buffer(char *address, size_t device_size, int seed_value,
		     bool write);

/* Randomly read bytes_to_read from buffer with a given seed value */
double random_read(char *address, size_t device_size,
		   unsigned long bytes_to_read, int seed_value);

/* Set up the random number generation, uses sodium */
void random_init(void);

/* Run the workload multi-threaded */
void run_threads(char *addr, size_t dev_size, unsigned long bytes_to_read,
		 bool rand, unsigned long num_threads, unsigned int iters,
		 bool fault_info);
