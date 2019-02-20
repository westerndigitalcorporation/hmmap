#!/usr/bin/python
#
# extractor.py - script to summarize benching output
#
# SPDX-License-Identifier: GPL-2.0-only
#
# Copyright (c) 2019 Western Digital Corporation or its affiliates
#

import argparse
import glob
import numpy as np
import collections
import pandas as pd

def get_args():
	prog_description = 'Extract Summary from Benchmarking\
	                    Output'

	parser = argparse.ArgumentParser(description=prog_description)
	parser.add_argument('output_path', help='Directory containing results')
	#parser.add_argument('--output_prefix', default='',help='Prefix of output files')
	#parser.add_argument('--print_output',type=bool, default=False)
	#parser.add_argument('--plot_output',type=bool, default=False)

	return parser.parse_args()


def extract_file_info(filename):
	read_times = []
	write_times = []
	read_max = 0.0
	write_max = 0.0
	fd = open(filename, "r")
	for line in fd:
		line = line.rstrip()
		elements = line.split()
		if elements[0] == "Write":
			if float(elements[2]) > write_max:
				write_max = float(elements[2])
		elif elements[0] == "Read":
			if float(elements[2]) > read_max:
				read_max = float(elements[2])
		elif elements[0] == "All":
			read_times.append(read_max)
			write_times.append(write_max)
			read_max = 0.0
			write_max = 0.0


	fd.close()
	w_mean = np.mean(write_times)
	w_var = np.var(write_times)
	r_mean = np.mean(read_times)
	r_var = np.var(read_times)

	return w_mean, w_var, r_mean, r_var


if __name__ == "__main__" :

	args = get_args();
	output_dir = args.output_path
	output_files = glob.glob(output_dir + "/*")
	col_names = ['Device', 'Operation', 'Threads', 'W_Mean', 'W_Var', 
	'R_Mean', 'R_Var']
	df = pd.DataFrame(columns = col_names)
	for filename in output_files:
		base = filename.split("/")[-1]
		device = base.split(".")[0]
		threads = base.split(".")[1]
		operation = base.split(".")[2]
		w_mean, w_var, r_mean, r_var = extract_file_info(filename)
		df.loc[-1] = [device, operation, int(threads), w_mean, w_var, r_mean, r_var] 
		df.index = df.index + 1

	df= df.sort_values(['Device', 'Operation', 'Threads'])
	print (df.to_string(index=False))
