// SPDX-License-Identifier: GPL-2.0-only
/*
 * rdma_backend.c - hmmap rdma backend
 *
 * Copyright (c) 2019 Western Digital Corporation or its affiliates
 * Copyright (c) 2019 Yuanjiang Ni <yuanjiang.ni@wdc.com>
 * Copyright (c) 2019 Adam Manzanares <adam.manzanares@wdc.com>
 *
 */


#include <linux/module.h>

#include "rdma_backend.h"
#include "hmmap.h"

struct rdma_backend_info rdma_info = {};

static int rdma_cma_event_handler(struct rdma_cm_id *cma_id,
				   struct rdma_cm_event *event)
{
	int ret;
	struct rdma_instance *cb = cma_id->context;

	UINFO("cma_event type %d cma_id %p\n", event->event, cma_id);

	switch (event->event) {
	case RDMA_CM_EVENT_ADDR_RESOLVED:
		cb->state = ADDR_RESOLVED;
		ret = rdma_resolve_route(cma_id, 2000);
		if (ret) {
			UINFO("rdma_resolve_route error %d\n",
			       ret);
			wake_up_interruptible(&cb->sem);
		}
		break;

	case RDMA_CM_EVENT_ROUTE_RESOLVED:
		cb->state = ROUTE_RESOLVED;
		wake_up_interruptible(&cb->sem);
		break;

	case RDMA_CM_EVENT_ESTABLISHED:
		UINFO("ESTABLISHED\n");
		cb->state = CONNECTED;
		wake_up_interruptible(&cb->sem);
		break;

	case RDMA_CM_EVENT_ADDR_ERROR:
	case RDMA_CM_EVENT_ROUTE_ERROR:
	case RDMA_CM_EVENT_CONNECT_ERROR:
	case RDMA_CM_EVENT_UNREACHABLE:
	case RDMA_CM_EVENT_REJECTED:
		UINFO("cma event %d, error %d\n", event->event,
		       event->status);
		cb->state = ERROR;
		wake_up_interruptible(&cb->sem);
		BUG();
		break;

	case RDMA_CM_EVENT_DISCONNECTED:
		UINFO("DISCONNECT EVENT...\n");

	case RDMA_CM_EVENT_DEVICE_REMOVAL:
		UINFO("cma detected device removal!!!!\n");

	default:
		UINFO("oof bad type or unhandled\n");
		wake_up_interruptible(&cb->sem);
		BUG();
		break;
	}
	return 0;
}


static void fill_sockaddr(struct sockaddr_storage *sin,
			  struct rdma_instance *cb)
{
	struct sockaddr_in *sin4 = NULL;

	memset(sin, 0, sizeof(*sin));
	sin4 = (struct sockaddr_in *)sin;
	sin4->sin_family = AF_INET;
	memcpy((void *)&sin4->sin_addr.s_addr, cb->addr, 4);
	sin4->sin_port = cb->port;
}

static int rdma_bind_client(struct rdma_instance *cb)
{
	struct sockaddr_storage sin;
	int ret;

	fill_sockaddr(&sin, cb);

	ret = rdma_resolve_addr(cb->cm_id, NULL,
				(struct sockaddr *)&sin, 2000);
	if (ret) {
		UINFO("rdma_resolve_addr error %d\n", ret);
		return ret;
	}

	wait_event_interruptible(cb->sem, cb->state >= ROUTE_RESOLVED);
	if (cb->state != ROUTE_RESOLVED) {
		UINFO("addr/route resolution did not resolve: state %d\n",
		       cb->state);
		return -EINTR;
	}
	UDEBUG("rdma_resolve_addr - rdma_resolve_route successful\n");
	return 0;
}

static int _rdma_setup_qp(struct rdma_instance *cb)
{
	struct ib_qp_init_attr init_attr;
	int ret;

	memset(&init_attr, 0, sizeof(init_attr));
	init_attr.cap.max_send_wr = 2048;
	/*FIXME: You may need to tune the maximum work request */
	init_attr.cap.max_recv_wr = 2048;
	init_attr.cap.max_recv_sge = 1;
	init_attr.cap.max_send_sge = 1;
	init_attr.sq_sig_type = IB_SIGNAL_REQ_WR;
	init_attr.qp_type = IB_QPT_RC;
	init_attr.send_cq = cb->cq;
	init_attr.recv_cq = cb->cq;

	ret = rdma_create_qp(cb->cm_id, cb->pd, &init_attr);
	if (!ret)
		cb->qp = cb->cm_id->qp;
	return ret;
}

static int rdma_client_paging_done(struct rdma_instance *cb, struct ib_wc *wc)
{
	struct rdma_ctx *ctx;

	ctx = (struct rdma_ctx *)ptr_from_uint64(wc->wr_id);
	BUG_ON(!ctx);
	UDEBUG("rdma_client_paing_done %ld", ctx->dev_off);
#ifdef USE_POLLING
	WRITE_ONCE(ctx->done, true);
#else
	ctx->done = true;
	wake_up_interruptible(&ctx->sem);
#endif
	return 0;
}

static int rdma_client_send(struct rdma_instance *cb, struct ib_wc *wc)
{
	return 0;
}

void rdma_init_slab_entry(struct rdma_instance *cb)
{
	int i = 0;
	int gb_index = cb->recv_buf.size_gb;

	BUG_ON(rdma_info.slab_table[gb_index] != NULL);

	rdma_info.slab_table[gb_index] =
		kmalloc(sizeof(struct slab_table_entry), GFP_KERNEL);

	TEST_Z(rdma_info.slab_table[gb_index]);

	for (i = 0; i < MAX_MR_SIZE_GB; i++) {
		if (cb->recv_buf.rkey[i]) {
			UDEBUG("Received rkey %x addr %llx from peer\n",
				ntohl(cb->recv_buf.rkey[i]),
				ntohll(cb->recv_buf.buf[i]));
			rdma_info.slab_table[gb_index]->remote_rkey
				= ntohl(cb->recv_buf.rkey[i]);
			rdma_info.slab_table[gb_index]->remote_addr
				= ntohll(cb->recv_buf.buf[i]);
			break;
		}
	}

}

static int rdma_client_recv(struct rdma_instance *cb, struct ib_wc *wc)
{
	if (wc->byte_len != sizeof(cb->recv_buf)) {
		UINFO("Received bogus data, size %d\n",
		       wc->byte_len);
		return -1;
	}
	if (cb->state < CONNECTED) {
		UINFO("cb is not connected\n");
		return -1;
	}
	switch (cb->recv_buf.type) {
	case FREE_SIZE:
		UINFO("free-size received %d\n", cb->recv_buf.size_gb);
		cb->remote_free_gb = cb->recv_buf.size_gb;
		cb->state = FREE_MEM_RECV;
		wake_up_interruptible(&cb->sem);
		break;
	case INFO_SINGLE:
		UINFO("info-single received\n");
		rdma_init_slab_entry(cb);
		cb->state = BINDED;
		wake_up_interruptible(&cb->sem);
		break;
	default:
		UINFO("client receives unknown/supported msg\n");
		UINFO("type %d size %d\n", cb->recv_buf.type,
		      cb->recv_buf.size_gb);
		return -1;
	}
	return 0;
}

static void rdma_cq_event_handler(struct ib_cq *cq, void *ctx)
{
	struct rdma_instance *cb = ctx;
	struct ib_wc wc;
	struct ib_recv_wr *bad_wr;
	int ret;

	BUG_ON(cb->cq != cq);
	if (cb->state == ERROR) {
		UINFO("cq completion in ERROR state\n");
		return;
	}
	ib_req_notify_cq(cb->cq, IB_CQ_NEXT_COMP);

	while ((ret = ib_poll_cq(cb->cq, 1, &wc)) == 1) {
		if (wc.status) {
			if (wc.status == IB_WC_WR_FLUSH_ERR) {
				UINFO("cq flushed\n");
				continue;
			} else {
				UINFO("cq completion failed with "
				       "wr_id %llx status %d opcode %d "
				       "vender_err %x\n",
					wc.wr_id, wc.status, wc.opcode,
					wc.vendor_err);
				goto error;
			}
		}
		switch (wc.opcode) {
		case IB_WC_RECV:
			ret = rdma_client_recv(cb, &wc);
			if (ret) {
				UINFO("recv wc error: %d\n", ret);
				goto error;
			}

			ret = ib_post_recv(cb->qp, &cb->rq_wr, &bad_wr);
			if (ret) {
				UINFO("post recv error: %d\n",
					     ret);
				goto error;
			}
				break;
		case IB_WC_SEND:
			ret = rdma_client_send(cb, &wc);
			if (ret) {
				UINFO("send wc error: %d\n", ret);
				goto error;
			}
			break;
		case IB_WC_RDMA_READ:
			ret = rdma_client_paging_done(cb, &wc);
			if (ret) {
				UINFO("read wc error: %d, cb->state=%d\n",
				      ret, cb->state);
				goto error;
			}
			break;
		case IB_WC_RDMA_WRITE:
			ret = rdma_client_paging_done(cb, &wc);
			if (ret) {
				UINFO("write wc error: %d, cb->state=%d\n",
				      ret, cb->state);
				goto error;
			}
			break;
		default:
			UINFO("%s:%d Unexpected opcode %d, Shutting down\n",
			      __func__, __LINE__, wc.opcode);
			goto error;
		}
	}
	if (ret) {
		UINFO("poll error %d\n", ret);
		goto error;
	}
	return;
error:
	BUG();
	cb->state = ERROR;
}



static int rdma_setup_qp(struct rdma_instance *cb, struct rdma_cm_id *cm_id)
{
	int ret;
	struct ib_cq_init_attr init_attr;

	cb->pd = ib_alloc_pd(cm_id->device, 0);

	if (IS_ERR(cb->pd)) {
		UINFO("ib_alloc_pd failed\n");
		return PTR_ERR(cb->pd);
	}
	UDEBUG("created pd %p\n", cb->pd);

	memset(&init_attr, 0, sizeof(init_attr));
	init_attr.cqe = 4096;
	init_attr.comp_vector = 0;

	cb->cq = ib_create_cq(cm_id->device, rdma_cq_event_handler,
			      NULL, cb, &init_attr);

	if (IS_ERR(cb->cq)) {
		UINFO("ib_create_cq failed\n");
		ret = PTR_ERR(cb->cq);
		goto err1;
	}
	UDEBUG("created cq %p\n", cb->cq);

	ret = ib_req_notify_cq(cb->cq, IB_CQ_NEXT_COMP);
	if (ret) {
		UINFO("ib_create_cq failed\n");
		goto err2;
	}

	ret = _rdma_setup_qp(cb);
	if (ret) {
		UINFO("IS_create_qp failed: %d\n", ret);
		goto err2;
	}
	UDEBUG("created qp %p\n", cb->qp);
	return 0;
err2:
	ib_destroy_cq(cb->cq);
err1:
	ib_dealloc_pd(cb->pd);
	return ret;
}

static int rdma_setup_buffers(struct rdma_instance *cb)
{

	UINFO("IS_setup_buffers called on cb %p\n", cb);

	UINFO("size of IS_rdma_info %lu\n", sizeof(cb->recv_buf));

	cb->recv_sgl.addr = ib_dma_map_single(cb->cm_id->device,
				   &cb->recv_buf, sizeof(cb->recv_buf),
				   DMA_BIDIRECTIONAL);
	if (ib_dma_mapping_error(cb->cm_id->device, cb->recv_sgl.addr)) {
		pr_info("error recv dma mapping");
		return -EIO;
	}

	cb->send_sgl.addr = ib_dma_map_single(cb->cm_id->device,
				   &cb->send_buf, sizeof(cb->send_buf),
				   DMA_BIDIRECTIONAL);

	if (ib_dma_mapping_error(cb->cm_id->device, cb->send_sgl.addr)) {
		pr_info("error recv dma mapping");
		return -EIO;
	}

	cb->recv_sgl.length = sizeof(cb->recv_buf);
	cb->recv_sgl.lkey = cb->pd->local_dma_lkey;
	cb->rq_wr.sg_list = &cb->recv_sgl;
	cb->rq_wr.num_sge = 1;
	cb->rq_wr.next = NULL;

	cb->send_sgl.length = sizeof(cb->send_buf);
	cb->send_sgl.lkey = cb->pd->local_dma_lkey;
	cb->sq_wr.opcode = IB_WR_SEND;
	cb->sq_wr.send_flags = IB_SEND_SIGNALED;
	cb->sq_wr.sg_list = &cb->send_sgl;
	cb->sq_wr.num_sge = 1;
	cb->sq_wr.next = NULL;

	UDEBUG("allocated & registered buffers...\n");
	return 0;
}

static int _rdma_connect_remote(struct rdma_instance *cb)
{
	struct rdma_conn_param conn_param;
	int ret;

	memset(&conn_param, 0, sizeof(conn_param));
	conn_param.responder_resources = 1;
	conn_param.initiator_depth = 1;
	conn_param.retry_count = 10;

	ret = rdma_connect(cb->cm_id, &conn_param);
	if (ret) {
		UINFO("rdma_connect error %d\n", ret);
		return ret;
	}

	wait_event_interruptible(cb->sem, cb->state >= CONNECTED);
	if (cb->state == ERROR) {
		UINFO("wait for CONNECTED state %d\n", cb->state);
		return -1;
	}

	UDEBUG("rdma_connect successful\n");
	return 0;
}

static int rdma_connect_remote(struct rdma_instance *cb)
{
	struct ib_recv_wr *bad_wr;
	int ret;

	ret = ib_post_recv(cb->qp, &cb->rq_wr, &bad_wr);
	if (ret) {
		UINFO("ib_post_recv failed: %d\n", ret);
		return ret;
	}
	UDEBUG("post recv. done\n");

	ret = _rdma_connect_remote(cb);
	if (ret) {
		UINFO("connect error %d\n", ret);
		return ret;
	}
	UDEBUG("post connect sent\n");
	return 0;
}

int rdma_init(unsigned long size, unsigned int page_size, struct hmmap_dev *dev)
{

	rdma_info.size = size;
	rdma_info.page_size = page_size;
	rdma_info.dev = dev;

	memset(&rdma_info.slab_table[0], 0,
			sizeof(struct slab_table_entry *) * MAX_MR_SIZE_GB);

	rdma_info.ctx_cache = KMEM_CACHE(rdma_ctx, 0);
	TEST_Z(rdma_info.ctx_cache);

	rdma_info.cb = kmalloc(sizeof(struct rdma_instance), GFP_KERNEL);
	TEST_Z(rdma_info.cb);


	//Init cb
	rdma_info.cb->port = htons(REMOTE_SERVER_PORT);
	in4_pton(REMOTE_SERVER_IP, -1, rdma_info.cb->addr, -1, NULL);
	rdma_info.cb->state = IDLE;
	init_waitqueue_head(&rdma_info.cb->sem);

	//rdma connection setup
	rdma_info.cb->cm_id = rdma_create_id(&init_net, rdma_cma_event_handler,
			rdma_info.cb, RDMA_PS_TCP, IB_QPT_RC);

	TEST_NZ(IS_ERR(rdma_info.cb->cm_id));

	TEST_NZ(rdma_bind_client(rdma_info.cb));
	TEST_NZ(rdma_setup_qp(rdma_info.cb, rdma_info.cb->cm_id));
	TEST_NZ(rdma_setup_buffers(rdma_info.cb));
	TEST_NZ(rdma_connect_remote(rdma_info.cb));

	wait_event_interruptible(rdma_info.cb->sem,
				 rdma_info.cb->state == FREE_MEM_RECV);
	rdma_info.cb->state = READY;

	return 0;
}

int rdma_remote_paging(struct rdma_instance *cb,
		void *cache_address, unsigned long off, bool in)
{
	int ret = 0;
	int gb_index = off >> 30;
	int offset = off & ONE_GB_MASK;
	struct ib_send_wr *bad_wr;
	struct page *page = vmalloc_to_page(cache_address);
	struct rdma_ctx *ctx;

	ctx = kmem_cache_zalloc(rdma_info.ctx_cache, GFP_KERNEL);
	TEST_Z(ctx);

#ifndef USE_POLLING
	init_waitqueue_head(&ctx->sem);
#endif
	ctx->done = false;
	ctx->dev_off = off;
	ctx->rdma_sgl.addr = ib_dma_map_page(cb->cm_id->device,
				   page, 0, rdma_info.page_size,
				   DMA_BIDIRECTIONAL);

	if (ib_dma_mapping_error(cb->cm_id->device, ctx->rdma_sgl.addr)) {
		pr_info("error ctx dma mapping");
		return -EIO;
	}

	ctx->rdma_sgl.length = rdma_info.page_size;
	ctx->rdma_sgl.lkey = cb->pd->local_dma_lkey;
	ctx->rdma_sq_wr.wr.send_flags = IB_SEND_SIGNALED;
	ctx->rdma_sq_wr.wr.sg_list = &ctx->rdma_sgl;
	ctx->rdma_sq_wr.wr.num_sge = 1;
	ctx->rdma_sq_wr.wr.next = NULL;
	ctx->rdma_sq_wr.wr.wr_id = uint64_from_ptr(ctx);

	ctx->rdma_sq_wr.wr.sg_list->length = rdma_info.page_size;
	ctx->rdma_sq_wr.rkey =
		rdma_info.slab_table[gb_index]->remote_rkey;
	ctx->rdma_sq_wr.remote_addr =
		rdma_info.slab_table[gb_index]->remote_addr + offset;
	ctx->rdma_sq_wr.wr.opcode = (in) ? IB_WR_RDMA_READ : IB_WR_RDMA_WRITE;

	ret = ib_post_send(cb->qp, (struct ib_send_wr *) &ctx->rdma_sq_wr,
			   &bad_wr);

	if (ret) {
		UINFO("client post reade %d, wr=%p\n", ret, &ctx->rdma_sq_wr);
		return ret;
	}

#ifdef USE_POLLING

	for (;;) {
		set_current_state(TASK_UNINTERRUPTIBLE);
		if (READ_ONCE(ctx->done))
			break;
	}
	__set_current_state(TASK_RUNNING);

	ib_dma_unmap_page(cb->cm_id->device,
				   ctx->rdma_sgl.addr, ctx->rdma_sgl.length,
				   DMA_BIDIRECTIONAL);
#else
	wait_event_interruptible(ctx->sem, ctx->done == true);
#endif
	kmem_cache_free(rdma_info.ctx_cache, ctx);

	return 0;
}

int rdma_fill_cache(void *cache_address, unsigned long off)
{
	struct ib_send_wr *bad_wr;
	struct rdma_instance *cb = rdma_info.cb;
	int gb_index = off >> 30;
	int ret = 0;

	UDEBUG("%s\n", __func__);
	if (rdma_info.slab_table[gb_index] == NULL) {
		UDEBUG("ummaped %d\n", gb_index);
		cb->state = BINDING;

		cb->send_buf.type = BIND_SINGLE;
		cb->send_buf.size_gb = gb_index;
		ret = ib_post_send(cb->qp, &cb->sq_wr, &bad_wr);
		if (ret) {
			UINFO("BIND_SINGLE MSG send error %d\n", ret);
			return ret;
		}
		wait_event_interruptible(cb->sem, cb->state == BINDED);
	}

	UDEBUG("maped %d rkey %x addr %llx\n", gb_index,
			rdma_info.slab_table[gb_index]->remote_rkey,
			rdma_info.slab_table[gb_index]->remote_addr);

	UDEBUG("start paging in %d, %ld\n", gb_index, off & ONE_GB_MASK);
	rdma_remote_paging(cb, cache_address, off, true);

	UDEBUG("done paging in %d, %ld\n", gb_index, off & ONE_GB_MASK);
	return 0;
}

int rdma_flush_cache(struct hmmap_flush_info *info, unsigned short num_pages)
{

	struct rdma_instance *cb = rdma_info.cb;
	unsigned short cur_page;
	unsigned long off;
	void *cache_address;
	int gb_index;

	UDEBUG("%s\n", __func__);

	for (cur_page = 0; cur_page < num_pages; cur_page++) {
		off = info[cur_page].offset;
		cache_address = info[cur_page].cache_address;
		gb_index = off >> 30;
		BUG_ON(rdma_info.slab_table[gb_index] == NULL);

		UDEBUG("maped %d rkey %x addr %llx\n", gb_index,
			rdma_info.slab_table[gb_index]->remote_rkey,
			rdma_info.slab_table[gb_index]->remote_addr);

		UDEBUG("start paging out %d, %ld\n",
		       gb_index, off & ONE_GB_MASK);

		rdma_remote_paging(cb, cache_address, off, false);

		UDEBUG("done paging out %d, %ld\n",
		       gb_index, off & ONE_GB_MASK);
	}
	return 0;
}

void rdma_destroy(void)
{
	//TODO: Disconnection with remote node.
}

static struct hmmap_backend rdma_backend = {
	.name = "rdma_backend",
	.init = rdma_init,
	.get_pfn = NULL,
	.fill_cache = rdma_fill_cache,
	.flush_cache = rdma_flush_cache,
	.destroy = rdma_destroy,
};

static int __init hmmap_rdma_backend_init(void)
{
	int ret = hmmap_register_backend(&rdma_backend);

	if (!ret)
		UINFO("RDMA BACKEND REGISTERED\n");
	else
		UINFO("Registering RDMA BACKEND FAILS %d\n", ret);

	return ret;
}

static void __exit hmmap_rdma_backend_exit(void)
{
	hmmap_unregister_backend(&rdma_backend);

}

module_init(hmmap_rdma_backend_init);
module_exit(hmmap_rdma_backend_exit);

MODULE_AUTHOR("Yuanjiang Ni");
MODULE_LICENSE("GPL");
