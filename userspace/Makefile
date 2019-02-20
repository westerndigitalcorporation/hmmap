# SPDX-License-Identifier: GPL-2.0-only

CC=gcc 
CFLAGS=-g -Wall -fno-omit-frame-pointer
DEPS = hmmap_uspace_common.h
OBJ = hmmap_uspace_common.o
LDFLAGS = -lm -pthread

all: baseline user_access

%.o: %.c $(DEPS)
	$(CC) -c -o $@ $< $(CFLAGS) $(LDFLAGS)

baseline: $(OBJ) baseline.o
	$(CC) -o $@ $^ $(CFLAGS) $(LDFLAGS)  

user_access: $(OBJ) user_access.o
	$(CC) -o $@ $^ $(CFLAGS) $(LDFLAGS)  

clean:
	rm -f *.o
	rm -f user_access
	rm -f baseline

