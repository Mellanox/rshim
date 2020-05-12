/*
 * rshim_net.c - Mellanox RShim network host driver
 *
 * Copyright (c) 2017, Mellanox Technologies. All rights reserved.
 *
 * This program is free software; you can redistribute it and/or
 * modify it under the terms of the GNU General Public License
 * as published by the Free Software Foundation; either version
 * 2 of the License, or (at your option) any later version.
 */

#include <linux/delay.h>
#include <linux/device.h>
#include <linux/io.h>
#include <linux/kernel.h>
#include <linux/math64.h>
#include <linux/module.h>
#include <linux/moduleparam.h>
#include <linux/platform_device.h>
#include <linux/resource.h>
#include <linux/slab.h>
#include <linux/mutex.h>
#include <linux/types.h>
#include <linux/virtio.h>
#include <linux/virtio_config.h>
#include <linux/virtio_ids.h>
#include <linux/virtio_ring.h>
#include <linux/virtio_net.h>
#include <linux/cache.h>
#include <linux/interrupt.h>
#include <linux/version.h>
#include <asm/byteorder.h>

#include "rshim.h"

/* Vring size. */
#define RSH_NET_VRING_SIZE			1024

/*
 * Keepalive time in seconds. If configured, the link is considered down
 * if no Rx activity within the configured time.
 */
static int rshim_net_keepalive;
module_param(rshim_net_keepalive, int, 0644);
MODULE_PARM_DESC(rshim_net_keepalive,
		 "Keepalive time in seconds.");

/* Use a timer for house-keeping. */
static int rshim_net_timer_interval = HZ / 10;

/* Flag to drain the current pending packet. */
static bool rshim_net_draining_mode;

/* Spin lock. */
static DEFINE_SPINLOCK(rshim_net_spin_lock);

/* Work queue. */
static struct workqueue_struct *rshim_net_wq;

/* Virtio ring size. */
static int rshim_net_vring_size = RSH_NET_VRING_SIZE;
module_param(rshim_net_vring_size, int, 0444);
MODULE_PARM_DESC(rshim_net_vring_size, "Size of the vring.");

/* Supported virtio-net features. */
#if LINUX_VERSION_CODE < KERNEL_VERSION(4, 8, 0)
#define RSH_NET_FEATURES		((1 << VIRTIO_NET_F_STATUS) | \
					 (1 << VIRTIO_NET_F_MAC))
#else
#define RSH_NET_FEATURES		((1 << VIRTIO_NET_F_MTU) | \
					 (1 << VIRTIO_NET_F_MAC) | \
					 (1 << VIRTIO_NET_F_STATUS))
#endif

/* Default MAC. */
static u8 rshim_net_default_mac[6] = {0x00, 0x1A, 0xCA, 0xFF, 0xFF, 0x02};
module_param_array(rshim_net_default_mac, byte, NULL, 0);
MODULE_PARM_DESC(rshim_net_default_mac, "default MAC address");

#if LINUX_VERSION_CODE < KERNEL_VERSION(3, 19, 0) && RHEL_RELEASE_CODE < 0x0702

typedef __u16 __bitwise__ __virtio16;
typedef __u32 __bitwise__ __virtio32;
typedef __u64 __bitwise__ __virtio64;

static inline u16 __virtio16_to_cpu(bool little_endian, __virtio16 val)
{
	if (little_endian)
		return le16_to_cpu((__force __le16)val);
	else
		return (__force u16)val;
}

static inline u32 __virtio32_to_cpu(bool little_endian, __virtio32 val)
{
	if (little_endian)
		return le32_to_cpu((__force __le32)val);
	else
		return (__force u32)val;
}

static inline __virtio32 __cpu_to_virtio32(bool little_endian, u32 val)
{
	if (little_endian)
		return (__force __virtio32)cpu_to_le32(val);
	else
		return (__force __virtio32)val;
}

static inline u64 __virtio64_to_cpu(bool little_endian, __virtio64 val)
{
	if (little_endian)
		return le64_to_cpu((__force __le64)val);
	else
		return (__force u64)val;
}

static inline u16 virtio16_to_cpu(struct virtio_device *vdev, __virtio16 val)
{
	return __virtio16_to_cpu(true, val);
}

static inline u32 virtio32_to_cpu(struct virtio_device *vdev, __virtio32 val)
{
	return __virtio32_to_cpu(true, val);
}

static inline __virtio32 cpu_to_virtio32(struct virtio_device *vdev, u32 val)
{
	return __cpu_to_virtio32(true, val);
}

static inline u64 virtio64_to_cpu(struct virtio_device *vdev, __virtio64 val)
{
	return __virtio64_to_cpu(true, val);
}

void virtio_config_changed(struct virtio_device *vdev)
{
	struct virtio_driver *drv;

	drv = container_of(vdev->dev.driver, struct virtio_driver, driver);
	if (drv != NULL && drv->config_changed)
		drv->config_changed(vdev);
}

#define VIRTIO_GET_FEATURES_RETURN_TYPE		u32
#define VIRTIO_FINALIZE_FEATURES_RETURN_TYPE	void
#define VIRTIO_FEATURES_IN_ARRAY

#else

#define VIRTIO_GET_FEATURES_RETURN_TYPE		u64
#define VIRTIO_FINALIZE_FEATURES_RETURN_TYPE	int

#endif

#if LINUX_VERSION_CODE < KERNEL_VERSION(3, 13, 0) && RHEL_RELEASE_CODE < 0x0700
#define VIRTIO_NOTIFY_RETURN_TYPE	void
#define VIRTIO_NOTIFY_RETURN
#else
#define VIRTIO_VRING_NEW_VIRTQUEUE_WITH_BARRIER
#define VIRTIO_NOTIFY_RETURN_TYPE	bool
#define VIRTIO_NOTIFY_RETURN		{ return true; }
#endif

/* MTU setting of the virtio-net interface. */
#define RSH_NET_MTU			1500

struct rshim_net;
static void rshim_net_virtio_rxtx(struct virtqueue *vq, bool is_rx);
static void rshim_net_update_activity(struct rshim_net *net, bool activity);

/* Structure to maintain the ring state. */
struct rshim_net_vring {
	void *va;			/* virtual address */
	struct virtqueue *vq;		/* virtqueue pointer */
	struct vring_desc *desc;	/* current desc */
	struct vring_desc *desc_head;	/* current desc head */
	int cur_len;			/* processed len in current desc */
	int rem_len;			/* remaining length to be processed */
	int size;			/* vring size */
	int align;			/* vring alignment */
	int id;				/* vring id */
	u32 pkt_len;			/* packet total length */
	u16 next_avail;			/* next avail desc id */
	union rshim_tmfifo_msg_hdr hdr;	/* header of the current packet */
	struct rshim_net *net;		/* pointer back to the rshim_net */
#if LINUX_VERSION_CODE < KERNEL_VERSION(4, 6, 0)
	struct vring vr;
#endif
};

/* Event types. */
enum {
	RSH_NET_RX_EVENT,		/* Rx event */
	RSH_NET_TX_EVENT		/* Tx event */
};

/* Ring types (Rx & Tx). */
enum {
	RSH_NET_VRING_RX,		/* Rx ring */
	RSH_NET_VRING_TX,		/* Tx ring */
	RSH_NET_VRING_NUM
};

/* RShim net device structure */
struct rshim_net {
	struct virtio_device vdev;	/* virtual device */
	struct mutex lock;
	struct rshim_backend *bd;		/* backend */
	u8 status;
	u16 virtio_registered : 1;
	u64 features;
	int tx_fifo_size;		/* number of entries of the Tx FIFO */
	int rx_fifo_size;		/* number of entries of the Rx FIFO */
	unsigned long pend_events;	/* pending bits for deferred process */
#if LINUX_VERSION_CODE < KERNEL_VERSION(2, 6, 20)
	struct work_struct work;	/* work struct for deferred process */
#else
	struct delayed_work work;
#endif
	struct timer_list timer;	/* keepalive timer */
	unsigned long rx_jiffies;	/* last Rx jiffies */
	struct rshim_net_vring vrings[RSH_NET_VRING_NUM];
	struct virtio_net_config config;	/* virtio config space */
};

/* Allocate vrings for the net device. */
static int rshim_net_alloc_vrings(struct rshim_net *net)
{
	void *va;
	int i, size;
	struct rshim_net_vring *vring;
	struct virtio_device *vdev = &net->vdev;

	for (i = 0; i < ARRAY_SIZE(net->vrings); i++) {
		vring = &net->vrings[i];
		vring->net = net;
		vring->size = rshim_net_vring_size;
		vring->align = SMP_CACHE_BYTES;
		vring->id = i;

		size = PAGE_ALIGN(vring_size(vring->size, vring->align));
		va = kzalloc(size, GFP_KERNEL);
		if (!va) {
			dev_err(vdev->dev.parent, "vring allocation failed\n");
			return -EINVAL;
		}

		vring->va = va;
	}

	return 0;
}

/* Free vrings of the net device. */
static void rshim_net_free_vrings(struct rshim_net *net)
{
	int i, size;
	struct rshim_net_vring *vring;

	for (i = 0; i < ARRAY_SIZE(net->vrings); i++) {
		vring = &net->vrings[i];
		size = PAGE_ALIGN(vring_size(vring->size, vring->align));
		if (vring->va) {
			kfree(vring->va);
			vring->va = NULL;
			if (vring->vq) {
				vring_del_virtqueue(vring->vq);
				vring->vq = NULL;
			}
		}
	}
}

/* Work handler for Rx, Tx or activity monitoring. */
#if LINUX_VERSION_CODE < KERNEL_VERSION(2, 6, 20)
static void rshim_net_work_handler(void *arg)
{
	struct rshim_net *net = arg;
#else
static void rshim_net_work_handler(struct work_struct *work)
{
	struct rshim_net *net = container_of(work, struct rshim_net, work.work);
#endif
	struct virtqueue *vq;

	/* Tx. */
	if (test_and_clear_bit(RSH_NET_TX_EVENT, &net->pend_events) &&
		       net->virtio_registered) {
		vq = net->vrings[RSH_NET_VRING_TX].vq;
		if (vq)
			rshim_net_virtio_rxtx(vq, false);
	}

	/* Rx. */
	if (test_and_clear_bit(RSH_NET_RX_EVENT, &net->pend_events) &&
		       net->virtio_registered) {
		vq = net->vrings[RSH_NET_VRING_RX].vq;
		if (vq)
			rshim_net_virtio_rxtx(vq, true);
	}

	/* Keepalive check. */
	if (rshim_net_keepalive &&
	    time_after(jiffies, net->rx_jiffies +
		       (unsigned long)rshim_net_keepalive * HZ)) {
		mutex_lock(&net->lock);
		rshim_net_update_activity(net, false);
		mutex_unlock(&net->lock);
	}
}

/* Nothing to do for now. */
static void rshim_net_virtio_dev_release(struct device *dev)
{
}

/* Implement this API for old kernel. */
#if LINUX_VERSION_CODE < KERNEL_VERSION(4, 6, 0)
const struct vring *virtqueue_get_vring(struct virtqueue *vq)
{
	struct rshim_net_vring *vring = (struct rshim_net_vring *)vq->priv;

	return &vring->vr;
}
#endif

/* Get the next packet descriptor from the vring. */
static inline struct vring_desc *
rshim_net_virtio_get_next_desc(struct virtqueue *vq)
{
	unsigned int idx, head;
	struct vring *vr = (struct vring *)virtqueue_get_vring(vq);
	struct rshim_net_vring *vring = (struct rshim_net_vring *)vq->priv;

	if (vring->next_avail == vr->avail->idx)
		return NULL;

	idx = vring->next_avail % vring->size;
	head = vr->avail->ring[idx];
	BUG_ON(head >= vring->size);
	vring->next_avail++;
	return &vr->desc[head];
}

/* Get the total length of a descriptor chain. */
static inline u32 rshim_net_virtio_get_pkt_len(struct virtio_device *vdev,
			struct vring_desc *desc, struct vring *vr)
{
	u32 len = 0, idx;

	while (desc) {
		len += virtio32_to_cpu(vdev, desc->len);
		if (!(virtio16_to_cpu(vdev, desc->flags) & VRING_DESC_F_NEXT))
			break;
		idx = virtio16_to_cpu(vdev, desc->next);
		desc = &vr->desc[idx];
	}

	return len;
}

/* House-keeping timer. */
#if LINUX_VERSION_CODE >= KERNEL_VERSION(4,15,0)
static void rshim_net_timer(struct timer_list *arg)
#else
static void rshim_net_timer(unsigned long arg)
#endif
{
#if LINUX_VERSION_CODE >= KERNEL_VERSION(4,15,0)
	struct rshim_net *net = container_of(arg, struct rshim_net, timer);
#else
	struct rshim_net *net = (struct rshim_net *)arg;
#endif

	/*
	 * Wake up Rx handler in case Rx event is missing or any leftover
	 * bytes are stuck in the backend.
	 */
	test_and_set_bit(RSH_NET_RX_EVENT, &net->pend_events);

	/*
	 * Wake up Tx handler in case virtio has queued too many packets
	 * and are waiting for buffer return.
	 */
	test_and_set_bit(RSH_NET_TX_EVENT, &net->pend_events);

	queue_delayed_work(rshim_net_wq, &net->work, 0);

	mod_timer(&net->timer, jiffies + rshim_net_timer_interval);
}

static void rshim_net_release_cur_desc(struct virtio_device *vdev,
				       struct rshim_net_vring *vring)
{
	int idx;
	unsigned long flags;
	struct vring *vr = (struct vring *)virtqueue_get_vring(vring->vq);

	idx = vr->used->idx % vring->size;
	vr->used->ring[idx].id = vring->desc_head - vr->desc;
	vr->used->ring[idx].len =
		cpu_to_virtio32(vdev, vring->pkt_len);

	/*
	 * Virtio could poll and check the 'idx' to decide
	 * whether the desc is done or not. Add a memory
	 * barrier here to make sure the update above completes
	 * before updating the idx.
	 */
	mb();
	vr->used->idx++;

	vring->desc = NULL;

	/* Notify upper layer. */
	spin_lock_irqsave(&rshim_net_spin_lock, flags);
	vring_interrupt(0, vring->vq);
	spin_unlock_irqrestore(&rshim_net_spin_lock, flags);
}

/* Update the link activity. */
static void rshim_net_update_activity(struct rshim_net *net, bool activity)
{
	if (activity) {
		/* Bring up the link. */
		if (!(net->config.status & VIRTIO_NET_S_LINK_UP)) {
			net->config.status |= VIRTIO_NET_S_LINK_UP;
			virtio_config_changed(&net->vdev);
		}
	} else {
		/* Bring down the link. */
		if (net->config.status & VIRTIO_NET_S_LINK_UP) {
			int i;

			net->config.status &= ~VIRTIO_NET_S_LINK_UP;
			virtio_config_changed(&net->vdev);

			/* Reset the ring state. */
			for (i = 0; i < RSH_NET_VRING_NUM; i++) {
				net->vrings[i].pkt_len =
						sizeof(struct virtio_net_hdr);
				net->vrings[i].cur_len = 0;
				net->vrings[i].rem_len = 0;
			}
		}
	}
}

/* Rx & Tx processing of a virtual queue. */
static void rshim_net_virtio_rxtx(struct virtqueue *vq, bool is_rx)
{
	struct rshim_net_vring *vring = (struct rshim_net_vring *)vq->priv;
	struct rshim_net *net = vring->net;
	struct vring *vr = (struct vring *)virtqueue_get_vring(vq);
	struct virtio_device *vdev = &net->vdev;
	void *addr;
	int len, idx, seg_len;
	struct vring_desc *desc;

	mutex_lock(&net->lock);

	/* Get the current pending descriptor. */
	desc = vring->desc;

	/* Don't continue if booting. */
	if (net->bd->is_boot_open) {
		/* Drop the pending buffer. */
		if (desc != NULL)
			rshim_net_release_cur_desc(vdev, vring);
		mutex_unlock(&net->lock);
		return;
	}

	while (1) {
		if (!desc) {
			/* Don't process new packet in draining mode. */
			if (RSHIM_READ_ONCE(rshim_net_draining_mode))
				break;

			/* Get the head desc of next packet. */
			vring->desc_head = rshim_net_virtio_get_next_desc(vq);
			if (!vring->desc_head) {
				vring->desc = NULL;
				mutex_unlock(&net->lock);
				return;
			}
			desc = vring->desc_head;

			/* Packet length is unknown yet. */
			vring->pkt_len = 0;
			vring->rem_len = sizeof(vring->hdr);
		}

		/* Beginning of a packet. */
		if (vring->pkt_len == 0) {
			if (is_rx) {
				struct virtio_net_hdr *net_hdr;

				/* Read the packet header. */
				len = rshim_fifo_read(net->bd,
					(void *)&vring->hdr +
					sizeof(vring->hdr) - vring->rem_len,
					vring->rem_len, TMFIFO_NET_CHAN, true,
					false);
				if (len > 0) {
					vring->rem_len -= len;
					if (vring->rem_len != 0)
						continue;
				} else
					break;

				/* Update activity. */
				net->rx_jiffies = jiffies;
				rshim_net_update_activity(net, true);

				/* Skip the length 0 packet (keepalive). */
				if (vring->hdr.len == 0) {
					vring->rem_len = sizeof(vring->hdr);
					continue;
				}

				/* Update total length. */
				vring->pkt_len = ntohs(vring->hdr.len) +
					sizeof(struct virtio_net_hdr);

				/* Initialize the packet header. */
				net_hdr = (struct virtio_net_hdr *)
					phys_to_virt(virtio64_to_cpu(
					vdev, desc->addr));
				memset(net_hdr, 0, sizeof(*net_hdr));
			} else {
				/* Write packet header. */
				if (vring->rem_len == sizeof(vring->hdr)) {
					len = rshim_net_virtio_get_pkt_len(
							vdev, desc, vr);
					vring->hdr.data = 0;
					vring->hdr.type = VIRTIO_ID_NET;
					vring->hdr.len = htons(len -
						sizeof(struct virtio_net_hdr));
				}

				len = rshim_fifo_write(net->bd,
					(void *)&vring->hdr +
					sizeof(vring->hdr) - vring->rem_len,
					vring->rem_len, TMFIFO_NET_CHAN,
					true, false);
				if (len > 0) {
					vring->rem_len -= len;
					if (vring->rem_len != 0)
						continue;
				} else
					break;

				/* Update total length. */
				vring->pkt_len = rshim_net_virtio_get_pkt_len(
							vdev, desc, vr);
			}

			vring->cur_len = sizeof(struct virtio_net_hdr);
			vring->rem_len = vring->pkt_len;
		}

		/* Check available space in this desc. */
		len = virtio32_to_cpu(vdev, desc->len);
		if (len > vring->rem_len)
			len = vring->rem_len;

		/* Check whether this desc is full or completed. */
		if (vring->cur_len == len) {
			vring->cur_len = 0;
			vring->rem_len -= len;

			/* Get the next desc on the chain. */
			if (vring->rem_len > 0 &&
			    (virtio16_to_cpu(vdev, desc->flags) &
						VRING_DESC_F_NEXT)) {
				idx = virtio16_to_cpu(vdev, desc->next);
				desc = &vr->desc[idx];
				continue;
			}

			/* Done with this chain. */
			rshim_net_release_cur_desc(vdev, vring);

			/* Clear desc and go back to the loop. */
			desc = NULL;

			continue;
		}

		addr = phys_to_virt(virtio64_to_cpu(vdev, desc->addr));

		if (is_rx) {
			seg_len = rshim_fifo_read(net->bd,
					addr + vring->cur_len,
					len - vring->cur_len,
					TMFIFO_NET_CHAN, true, false);
		} else {
			seg_len = rshim_fifo_write(net->bd,
					addr + vring->cur_len,
					len - vring->cur_len,
					TMFIFO_NET_CHAN, true, false);
		}
		if (seg_len > 0)
			vring->cur_len += seg_len;
		else {
			/* Schedule the worker to speed up Tx. */
			if (!is_rx) {
				if (!test_and_set_bit(RSH_NET_TX_EVENT,
				    &net->pend_events))
					queue_delayed_work(rshim_net_wq,
							   &net->work, 0);
			}
			break;
		}
	}

	/* Save the current desc. */
	vring->desc = desc;

	mutex_unlock(&net->lock);
}

/* The notify function is called when new buffers are posted. */
static VIRTIO_NOTIFY_RETURN_TYPE rshim_net_virtio_notify(struct virtqueue *vq)
{
	struct rshim_net_vring *vring = (struct rshim_net_vring *)vq->priv;
	struct rshim_net *net = vring->net;

	/*
	 * Virtio-net maintains vrings in pairs. Odd number ring for Rx
	 * and even number ring for Tx.
	 */
	if (!(vring->id & 1)) {
		/* Set the RX bit. */
		if (!test_and_set_bit(RSH_NET_RX_EVENT, &net->pend_events))
			queue_delayed_work(rshim_net_wq, &net->work, 0);
	} else {
		/* Set the TX bit. */
		if (!test_and_set_bit(RSH_NET_TX_EVENT, &net->pend_events))
			queue_delayed_work(rshim_net_wq, &net->work, 0);
	}

	VIRTIO_NOTIFY_RETURN;
}

/* Get the array of feature bits for this device. */
static VIRTIO_GET_FEATURES_RETURN_TYPE rshim_net_virtio_get_features(
	struct virtio_device *vdev)
{
	struct rshim_net *net = container_of(vdev, struct rshim_net, vdev);

	return net->features;
}

/* Confirm device features to use. */
static VIRTIO_FINALIZE_FEATURES_RETURN_TYPE rshim_net_virtio_finalize_features(
	struct virtio_device *vdev)
{
	struct rshim_net *net = container_of(vdev, struct rshim_net, vdev);

#ifdef VIRTIO_FEATURES_IN_ARRAY
	net->features = vdev->features[0];
#else
	net->features = vdev->features;
	return 0;
#endif
}

/* Free virtqueues found by find_vqs(). */
static void rshim_net_virtio_del_vqs(struct virtio_device *vdev)
{
	int i;
	struct rshim_net_vring *vring;
	struct virtqueue *vq;
	struct rshim_net *net = container_of(vdev, struct rshim_net, vdev);

	for (i = 0; i < ARRAY_SIZE(net->vrings); i++) {
		vring = &net->vrings[i];

		/* Release the pending packet. */
		if (vring->desc != NULL)
			rshim_net_release_cur_desc(vdev, vring);

		vq = vring->vq;
		if (vq) {
			vring->vq = NULL;
			vring_del_virtqueue(vq);
		}
	}
}

/* Create and initialize the virtual queues. */
static int rshim_net_virtio_find_vqs(struct virtio_device *vdev,
				     unsigned int nvqs,
				     struct virtqueue *vqs[],
				     vq_callback_t *callbacks[],
#if LINUX_VERSION_CODE >= KERNEL_VERSION(4, 12, 0)
				     const char * const names[],
				     const bool *ctx,
				     struct irq_affinity *desc)
#elif LINUX_VERSION_CODE >= KERNEL_VERSION(4, 11, 0)
				     const char * const names[],
				     struct irq_affinity *desc)
#elif LINUX_VERSION_CODE >= KERNEL_VERSION(4, 5, 0) || RHEL_RELEASE_CODE >= 1796
				     const char * const names[])
#else
				     const char *names[])
#endif
{
	int i, ret = -EINVAL, size;
	struct rshim_net_vring *vring;
	struct virtqueue *vq;
	struct rshim_net *net = container_of(vdev, struct rshim_net, vdev);

	if (nvqs > ARRAY_SIZE(net->vrings))
		return -EINVAL;

	for (i = 0; i < nvqs; ++i) {
		if (!names[i])
			goto error;
		vring = &net->vrings[i];

		/* zero vring */
		size = vring_size(vring->size, vring->align);
		memset(vring->va, 0, size);

		vq = vring_new_virtqueue(
#if LINUX_VERSION_CODE >= KERNEL_VERSION(3, 10, 0) || RHEL_RELEASE_CODE >= 1542
					 i,
#endif
					 vring->size, vring->align, vdev,
#if LINUX_VERSION_CODE >= KERNEL_VERSION(3, 3, 0)
					 false,
#endif
#if LINUX_VERSION_CODE >= KERNEL_VERSION(4, 12, 0)
					 false,
#endif
					 vring->va,
					 rshim_net_virtio_notify,
					 callbacks[i], names[i]);
		if (!vq) {
			dev_err(&vdev->dev, "vring_new_virtqueue failed\n");
			ret = -ENOMEM;
			goto error;
		}

#if LINUX_VERSION_CODE < KERNEL_VERSION(4, 6, 0)
		vring_init(&vring->vr, vring->size, vring->va, vring->align);
#endif

		vq->priv = vring;
		/*
		 * Add barrier to make sure vq is ready before assigning to
		 * vring.
		 */
		mb();
		vring->vq = vq;
		vqs[i] = vq;
	}

	return 0;

error:
	rshim_net_virtio_del_vqs(vdev);
	return ret;
}

/* Read the status byte. */
static u8 rshim_net_virtio_get_status(struct virtio_device *vdev)
{
	struct rshim_net *net = container_of(vdev, struct rshim_net, vdev);

	return net->status;
}

/* Write the status byte. */
static void rshim_net_virtio_set_status(struct virtio_device *vdev, u8 status)
{
	struct rshim_net *net = container_of(vdev, struct rshim_net, vdev);

	net->status = status;
}

/* Reset the device. Not much here for now. */
static void rshim_net_virtio_reset(struct virtio_device *vdev)
{
	struct rshim_net *net = container_of(vdev, struct rshim_net, vdev);

	net->status = 0;
}

/* Read the value of a configuration field. */
static void rshim_net_virtio_get(struct virtio_device *vdev,
				 unsigned int offset,
				 void *buf,
				 unsigned int len)
{
	struct rshim_net *net = container_of(vdev, struct rshim_net, vdev);

	if (offset + len > sizeof(net->config) || offset + len < len) {
		dev_err(vdev->dev.parent, "virtio_get access out of bounds\n");
		return;
	}

	memcpy(buf, (u8 *)&net->config + offset, len);
}

/* Write the value of a configuration field. */
static void rshim_net_virtio_set(struct virtio_device *vdev,
				 unsigned int offset,
				 const void *buf,
				 unsigned int len)
{
	struct rshim_net *net = container_of(vdev, struct rshim_net, vdev);

	if (offset + len > sizeof(net->config) || offset + len < len) {
		dev_err(vdev->dev.parent, "virtio_get access out of bounds\n");
		return;
	}

	memcpy((u8 *)&net->config + offset, buf, len);
}

/* Virtio config operations. */
static struct virtio_config_ops rshim_net_virtio_config_ops = {
	.get_features = rshim_net_virtio_get_features,
	.finalize_features = rshim_net_virtio_finalize_features,
	.find_vqs = rshim_net_virtio_find_vqs,
	.del_vqs = rshim_net_virtio_del_vqs,
	.reset = rshim_net_virtio_reset,
	.set_status = rshim_net_virtio_set_status,
	.get_status = rshim_net_virtio_get_status,
	.get = rshim_net_virtio_get,
	.set = rshim_net_virtio_set,
};

/* Remove. */
static int rshim_net_delete_dev(struct rshim_net *net)
{
	if (net) {
		/* Stop the timer. */
		del_timer_sync(&net->timer);

		/* Cancel the pending work. */
		cancel_delayed_work_sync(&net->work);

		/* Unregister virtio. */
		if (net->virtio_registered)
			unregister_virtio_device(&net->vdev);

		/* Free vring. */
		rshim_net_free_vrings(net);

		kfree(net);
	}

	return 0;
}

/* Rx ready. */
void rshim_net_rx_notify(struct rshim_backend *bd)
{
	struct rshim_net *net = (struct rshim_net *)bd->net;

	if (net) {
		test_and_set_bit(RSH_NET_RX_EVENT, &net->pend_events);
		queue_delayed_work(rshim_net_wq, &net->work, 0);
	}
}

/* Remove. */
int rshim_net_delete(struct rshim_backend *bd)
{
	int ret = 0;

	if (bd->net) {
		ret = rshim_net_delete_dev((struct rshim_net *)bd->net);
		bd->net = NULL;
	}

	return ret;
}

/* Init. */
int rshim_net_create(struct rshim_backend *bd)
{
	struct rshim_net *net;
	struct virtio_device *vdev;
	int ret = -ENOMEM;

	if (bd->net)
		return -EEXIST;

	net = kzalloc(sizeof(struct rshim_net), GFP_KERNEL);
	if (!net)
		return ret;

#if LINUX_VERSION_CODE < KERNEL_VERSION(2, 6, 20)
	INIT_WORK(&net->work, rshim_net_work_handler, net);
#else
	INIT_DELAYED_WORK(&net->work, rshim_net_work_handler);
#endif

#if LINUX_VERSION_CODE >= KERNEL_VERSION(4,15,0)
	timer_setup(&net->timer, rshim_net_timer, 0);
#else
	init_timer(&net->timer);
	net->timer.data = (unsigned long)net;
#endif
	net->timer.function = rshim_net_timer;

	net->features = RSH_NET_FEATURES;
#if LINUX_VERSION_CODE >= KERNEL_VERSION(4, 8, 0)
	net->config.mtu = RSH_NET_MTU;
#endif
	memcpy(net->config.mac, rshim_net_default_mac,
	       sizeof(rshim_net_default_mac));
	/* Set MAC address to be unique even number. */
	net->config.mac[5] += bd->dev_index * 2;

	mutex_init(&net->lock);

	vdev = &net->vdev;
	vdev->id.device = VIRTIO_ID_NET;
	vdev->config = &rshim_net_virtio_config_ops;
	vdev->dev.parent = bd->dev;
	vdev->dev.release = rshim_net_virtio_dev_release;
	if (rshim_net_alloc_vrings(net))
		goto err;

	/* Register the virtio device. */
	ret = register_virtio_device(vdev);
	if (ret) {
		dev_err(bd->dev, "register_virtio_device() failed\n");
		goto err;
	}
	net->virtio_registered = 1;

	mod_timer(&net->timer, jiffies + rshim_net_timer_interval);

	net->bd = bd;
	/* Add a barrier to keep the order of the two pointer assignments. */
	mb();
	bd->net = net;

	/* Bring up the interface. */
	mutex_lock(&net->lock);
	rshim_net_update_activity(net, true);
	mutex_unlock(&net->lock);

	return 0;

err:
	rshim_net_delete_dev(net);
	return ret;
}

struct rshim_service rshim_svc = {
	.type = RSH_SVC_NET,
	.create = rshim_net_create,
	.delete = rshim_net_delete,
	.rx_notify = rshim_net_rx_notify
};

static int __init rshim_net_init(void)
{
#if LINUX_VERSION_CODE < KERNEL_VERSION(2, 6, 36)
	rshim_net_wq = create_workqueue("rshim_net");
#else
	rshim_net_wq = alloc_workqueue("rshim_net",
				       WQ_MEM_RECLAIM | WQ_FREEZABLE | WQ_UNBOUND,
				       0);
#endif
	if (!rshim_net_wq)
		return -ENOMEM;

	return rshim_register_service(&rshim_svc);
}

static void __exit rshim_net_exit(void)
{
	/*
	 * Wait 200ms, which should be good enough to drain the current
	 * pending packet.
	 */
	rshim_net_draining_mode = true;
	msleep(200);

	destroy_workqueue(rshim_net_wq);

	return rshim_deregister_service(&rshim_svc);
}

module_init(rshim_net_init);
module_exit(rshim_net_exit);

MODULE_LICENSE("GPL");
MODULE_AUTHOR("Mellanox Technologies");
MODULE_VERSION("0.9");
