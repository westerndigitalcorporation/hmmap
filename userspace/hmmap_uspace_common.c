// SPDX-License-Identifier: GPL-2.0-only
/*
 * hmmap_uspace_common.c - common routines for hmmap memory benching
 *
 * Copyright (c) 2019 Western Digital Corporation or its affiliates
 * Copyright (c) 2019 Adam Manzanares <adam.manzanares@wdc.com>
 *
 */


#include <stdio.h>
#include <stdlib.h>
#include <limits.h>
#include <sys/types.h>
#include <unistd.h>
#include <math.h>
#include <stdint.h>
#include <pthread.h>

#include "hmmap_uspace_common.h"

static unsigned long xor_shift_seed[2] = {1024,256};


unsigned long xor_random_num(void)
{
	unsigned long x = xor_shift_seed[0];
	unsigned long const y = xor_shift_seed[1];

	xor_shift_seed[0] = y;
    x ^= x << 23; // a
    xor_shift_seed[1] = x ^ y ^ (x >> 17) ^ (y >> 26); // b, c
    return xor_shift_seed[1] + y;	
}

void print_time_double(double time)
{
	printf("Time elapsed   (float): %.15f seconds\n", time);

}
double calculate_time_diff(struct timespec start, struct timespec end, 
			   bool print)
{
	struct timespec diff;
	double elapsed;
	// Adjust if nanoseconds of end is less than nanoseconds of start
	if (end.tv_nsec < start.tv_nsec) {
		diff.tv_sec = end.tv_sec - start.tv_sec -1;
		diff.tv_nsec = end.tv_nsec - start.tv_nsec + NSINS;
	}else {
		diff.tv_sec = end.tv_sec - start.tv_sec -1;
		diff.tv_nsec = end.tv_nsec - start.tv_nsec + NSINS;
	}

	elapsed = diff.tv_sec + (double)diff.tv_nsec/1000000000L;
	if (print)
		print_time_double(elapsed);
	
	return elapsed;
}

/* Should just seed the randomness, but I will also set the pid */
void random_init()
{
	srand(time(NULL));
	xor_shift_seed[0] = rand();
	xor_shift_seed[1] = rand();
}

unsigned long random_ulong(unsigned long range)
{
	return xor_random_num() % range;
}

void output_fault(void)
{
	char ps_command[1024];
	char *args_ptr = ps_command;

	args_ptr += sprintf(args_ptr,"%s","ps -o min_flt,maj_flt ");
	args_ptr += sprintf(args_ptr,"%ld",(long)getpid());

	system((const char*)ps_command);

}

double random_read(char *address, size_t device_size,
		   unsigned long bytes_to_read, int seed)
{

	unsigned long bytes_read = 0;
	unsigned long offset;
	unsigned long num_entries = (device_size / sizeof(unsigned long));
	size_t ulongsz = sizeof(unsigned long);
	struct timespec start,end;
	
	clock_gettime(CLOCK_MONOTONIC, &start);
	while (bytes_read < bytes_to_read) {
		offset = random_ulong(num_entries); 
		volatile unsigned long *cur_long = (unsigned long *)address + offset; 
		xor_shift_seed[0] ^= *cur_long;
		/*if ( *cur_long != offset + (unsigned long)seed) {
			printf("Error accessing offset: %lu, Expected: %lu, \
			       Got %lu, Bytes read %lu\n", 
			       (unsigned long)address + (offset * ulongsz),
			       offset + (unsigned long)seed, 
			       *cur_long,
			       bytes_read);
			exit(1);
		}
		*/
		bytes_read += ulongsz;
	}
	clock_gettime(CLOCK_MONOTONIC, &end);
	return calculate_time_diff(start, end, false);
}

double access_buffer(char *address, size_t device_size, int seed_value,
		     bool write)
{
	char *start_address = address;
	unsigned long curval = (unsigned long)seed_value;
	struct timespec start,end;
	
	clock_gettime(CLOCK_MONOTONIC, &start);
	while( start_address < address + device_size ){
		if (write)
			*((unsigned long*)start_address) = curval;
		else {
			if (*(unsigned long*)start_address != curval) {
				printf("Error accessing offset: %p,\
				       Expected: %lu, Got %lu\n", 
				       start_address,
				       curval, 
				       *((unsigned long*)start_address));
				exit(1);
			}
		}
		
		start_address += sizeof(unsigned long);
		//start_address += 1;
		curval++;
	}

	clock_gettime(CLOCK_MONOTONIC, &end);
	return calculate_time_diff(start,end, false);
}

void *access_thread_work(void *args)
{

	struct access_thread_info *t_args = (struct access_thread_info *)args;
	unsigned int iters = t_args->iters;
	bool rand = t_args->rand;
	bool fault_info = t_args->fault_info;
	char *address = t_args->address;
	size_t device_size = t_args->device_size;
	unsigned long bytes_to_read = t_args->bytes_to_read;
	unsigned int iter_count;
	double *time = t_args->rw_times;

	for (iter_count = 0; iter_count < iters; iter_count++) {
		*(time++) = access_buffer(address,device_size, 0, true);
		if (fault_info)
			output_fault();

		if (rand) {
			*(time++) = random_read(address, device_size,
						bytes_to_read, 0);
		} else {
			*(time++) = access_buffer(address, device_size, 0,
						  false);
		}

		if (fault_info)
			output_fault();

	}

	return NULL;
}

void print_iter_times(double *times, unsigned int iters)
{
	unsigned int cur_iter;
	for(cur_iter = 0; cur_iter < iters; cur_iter++) {
		printf("Write time: %.15f seconds\n", *(times++));
		printf("Read  time  %.15f seconds\n", *(times++));
	}

}

void print_thread_times(struct access_thread_info *tinfo,
			unsigned long num_threads, unsigned int iters)
{
	unsigned long  cur_thread;
	double *times;

	for(cur_thread = 0; cur_thread < num_threads; cur_thread++) {
		printf("Thread:%lu access times\n", cur_thread);
		times = tinfo[cur_thread].rw_times;
		print_iter_times(times, iters);
	}

}

void run_threads(char *addr, size_t dev_size, unsigned long bytes_to_read,
		 bool rand, unsigned long num_threads, unsigned int iters,
		 bool fault_info)
{
	struct access_thread_info *tinfo = NULL;
	unsigned long cur_thread;
	int ret;
	struct timespec start,end;

	clock_gettime(CLOCK_MONOTONIC, &start);
	tinfo = malloc(sizeof(struct access_thread_info) * num_threads);
	if (!tinfo) {
		printf("Error allocating thread info struct\n");
		exit(1);
	}

	for (cur_thread = 0; cur_thread < num_threads; cur_thread++) {
		tinfo[cur_thread].address = addr + ((dev_size / num_threads)
						    * cur_thread);
		tinfo[cur_thread].device_size = dev_size / num_threads;
		tinfo[cur_thread].bytes_to_read = bytes_to_read / num_threads;
		tinfo[cur_thread].rand = rand;
		tinfo[cur_thread].iters = (unsigned int)iters;
		tinfo[cur_thread].fault_info = fault_info;
		tinfo[cur_thread].rw_times = (double *)malloc(sizeof(double) *
							      iters * 2);

		if (!tinfo[cur_thread].rw_times) {
			printf("Error allocating rw time array for thread\n");
			exit(1);
		}
		ret = pthread_create(&tinfo[cur_thread].tid, NULL,
				     &access_thread_work, &tinfo[cur_thread]);
		if (ret != 0) {
			printf("pthread create error bailing\n");
			exit(1);
		}
	}

	for (cur_thread = 0; cur_thread < num_threads; cur_thread++) {
		ret = pthread_join(tinfo[cur_thread].tid, NULL);
		if (ret) {
			printf("Error joining thread bailing\n");
			exit(1);
		}
	}

	print_thread_times(tinfo, num_threads, iters);
	if (tinfo)
		free(tinfo);

	clock_gettime(CLOCK_MONOTONIC, &end);
	printf("All threads run time\n");
	calculate_time_diff(start, end, true);
}
