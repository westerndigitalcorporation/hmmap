/* SPDX-License-Identifier: GPL-2.0-only
 *
 * rdma_backend.h - hmmap rdma backend
 *
 * Copyright (c) 2019 Western Digital Corporation or its affiliates
 * Copyright (c) 2019 Yuanjiang Ni <yuanjiang.ni@wdc.com>
 *
 */


#ifndef RDMA_BACKEND_H
#define RDMA_BACKEND_H

#include <linux/kernel.h>
#include <linux/module.h>
#include <linux/kthread.h>
#include <linux/slab.h>
#include <linux/version.h>
#include <linux/atomic.h>
#include <linux/list.h>

#include <linux/init.h>
#include <linux/err.h>
#include <linux/string.h>
#include <linux/parser.h>
#include <linux/proc_fs.h>
#include <linux/inet.h>
#include <linux/in.h>
#include <linux/pci.h>
#include <linux/time.h>
#include <linux/random.h>
#include <linux/sched.h>


#include <rdma/ib_verbs.h>
#include <rdma/rdma_cm.h>


#define REMOTE_SERVER_IP "192.168.0.12"
#define REMOTE_SERVER_PORT 9400

#define BYTES_PER_GB (1024*1024*1024ul)
#define ONE_GB_MASK 0x3fffffff
#define MAX_MR_SIZE_GB 32

#define uint64_from_ptr(p)    (uint64_t)(uintptr_t)(p)
#define ptr_from_uint64(p)    (void *)(unsigned long)(p)

// from kernel
/*  host to network long long
 *  endian dependent
 *  http://www.bruceblinn.com/linuxinfo/ByteOrder.html
 */
#define ntohll(x) (((uint64_t)(ntohl((int)((x << 32) >> 32))) << 32) | \
		    (unsigned int)ntohl(((int)(x >> 32))))
#define htonll(x) ntohll(x)

#define htonll2(x) cpu_to_be64((x))
#define ntohll2(x) cpu_to_be64((x))

#define TEST_NZ(x)                                                  \
do {                                                                \
	if ((x)) {                                                  \
		UINFO("error: " #x " failed (returned non-null)."); \
		BUG();                                              \
	}                                                           \
} while (0)


#define TEST_Z(x)                                               \
do {                                                            \
	if (!(x)) {                                             \
		UINFO("error: " #x " failed (returned null)."); \
		BUG();                                          \
	}                                                       \
} while (0)

#define USE_POLLING

struct rdma_info {
	uint64_t buf[MAX_MR_SIZE_GB];
	uint32_t rkey[MAX_MR_SIZE_GB];
	int size_gb;
	enum {
		DONE = 1,
		INFO,
		INFO_SINGLE,
		FREE_SIZE,
		EVICT,
		ACTIVITY,
		STOP,
		BIND,
		BIND_SINGLE,
		QUERY
	} type;
};

enum rdma_states {
	IDLE = 1,
	CONNECT_REQUEST,
	ADDR_RESOLVED,
	ROUTE_RESOLVED,
	CONNECTED,
	FREE_MEM_RECV,
	READY,
	BINDING,
	BINDED,
	ERROR
};

// one instance per rdma connection
// the other side is a user-space daemon.
struct rdma_instance {
	enum rdma_states state;
	wait_queue_head_t sem;
	struct ib_cq *cq;
	struct ib_pd *pd;
	struct ib_qp *qp;

	//send/recv. msg buffers
	struct ib_recv_wr rq_wr;
	struct ib_sge recv_sgl;
	struct rdma_info recv_buf;

	struct ib_send_wr sq_wr;    /* send work requrest record */
	struct ib_sge send_sgl;
	struct rdma_info send_buf;/* single send buf */

	//CM
	struct rdma_cm_id *cm_id;

	//mem mgt
	int remote_free_gb;
	//IP
	uint16_t port;          /* dst port in NBO */
	u8 addr[16];            /* dst addr in NBO */
	char *addr_str;         /* dst addr string */
};

struct slab_table_entry {
	uint32_t remote_rkey;
	uint64_t remote_addr;
};

struct rdma_ctx {
#ifndef USE_POLLING
	wait_queue_head_t sem;
#endif
	struct ib_rdma_wr rdma_sq_wr;
	struct ib_sge rdma_sgl;
	unsigned long dev_off;
	bool done;
};

struct rdma_backend_info {
	struct hmmap_dev *dev;
	unsigned long size;
	unsigned int page_size;
	struct rdma_instance *cb; //now only one remote node is supported
	struct slab_table_entry *slab_table[MAX_MR_SIZE_GB];
	struct kmem_cache *ctx_cache;
};



#endif
