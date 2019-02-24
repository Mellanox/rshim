/*
 * Copyright 2017 Mellanox Technologies. All Rights Reserved.
 *
 *   This program is free software; you can redistribute it and/or
 *   modify it under the terms of the GNU General Public License
 *   as published by the Free Software Foundation, version 2.
 *
 *   This program is distributed in the hope that it will be useful, but
 *   WITHOUT ANY WARRANTY; without even the implied warranty of
 *   MERCHANTABILITY OR FITNESS FOR A PARTICULAR PURPOSE, GOOD TITLE or
 *   NON INFRINGEMENT.  See the GNU General Public License for
 *   more details.
 */

#ifndef _RSHIM_H
#define _RSHIM_H

#include <linux/kernel.h>
#include <linux/kref.h>
#include <linux/module.h>
#include <linux/mutex.h>
#include <linux/termios.h>
#include <linux/workqueue.h>
#include <linux/device.h>
#include <linux/cdev.h>

#include "rshim_regs.h"

/* Output macros. */

#define ERROR(fmt, ...) \
	printk(KERN_ERR "rshim: " fmt "\n", ## __VA_ARGS__)

#define INFO(fmt, ...) \
	printk(KERN_INFO "rshim: " fmt "\n", ## __VA_ARGS__)

/* ACCESS_ONCE() wrapper. */
#if LINUX_VERSION_CODE >= KERNEL_VERSION(4, 15, 0)
#define RSHIM_READ_ONCE(x)	READ_ONCE(x)
#else
#define RSHIM_READ_ONCE(x)	ACCESS_ONCE(x)
#endif

/*
 * This forces only one reset to occur at a time.  Once we've gotten
 * more experience with this mode we'll probably remove the #define.
 */
#define RSH_RESET_MUTEX		1

/* Spin flag values. */
#define RSH_SFLG_READING	0x1  /* read is active. */
#define RSH_SFLG_WRITING	0x2  /* write_urb is active. */
#define RSH_SFLG_CONS_OPEN	0x4  /* console stream is open. */

/*
 * Buffer/FIFO sizes.  Note that the FIFO sizes must be powers of 2; also,
 * the read and write buffers must be no larger than the corresponding
 * FIFOs.
 */
#define READ_BUF_SIZE		2048
#define WRITE_BUF_SIZE		2048
#define READ_FIFO_SIZE		(4 * 1024)
#define WRITE_FIFO_SIZE		(4 * 1024)
#define BOOT_BUF_SIZE		(16 * 1024)

/* Sub-device types. */
enum {
	RSH_DEV_TYPE_RSHIM,
	RSH_DEV_TYPE_BOOT,
	RSH_DEV_TYPE_CONSOLE,
	RSH_DEV_TYPE_NET,
	RSH_DEV_TYPE_MISC,
	RSH_DEV_TYPES
};

/* Event types used in rshim_notify(). */
enum {
	RSH_EVENT_FIFO_INPUT,		/* fifo ready for input */
	RSH_EVENT_FIFO_OUTPUT,		/* fifo ready for output */
	RSH_EVENT_FIFO_ERR,		/* fifo error */
	RSH_EVENT_ATTACH,		/* backend attaching */
	RSH_EVENT_DETACH,		/* backend detaching */
};

/* RShim service types. */
enum {
	RSH_SVC_NET,			/* networking service */
	RSH_SVC_MAX
};

/* TMFIFO message header. */
union rshim_tmfifo_msg_hdr {
	struct {
		u8 type;		/* message type */
		__be16 len;		/* payload length */
		u8 unused[5];		/* reserved, set to 0 */
	} __packed;
	u64 data;
};

/* TMFIFO demux channels. */
enum {
	TMFIFO_CONS_CHAN,	/* Console */
	TMFIFO_NET_CHAN,	/* Network */
	TMFIFO_MAX_CHAN		/* Number of channels */
};

/* Various rshim definitions. */
#define RSH_INT_VEC0_RTC__SWINT3_MASK 0x8

#define RSH_BYTE_ACC_READ_TRIGGER 0x50000000
#define RSH_BYTE_ACC_SIZE 0x10000000
#define RSH_BYTE_ACC_PENDING 0x20000000


#define BOOT_CHANNEL        RSH_MMIO_ADDRESS_SPACE__CHANNEL_VAL_BOOT
#define RSHIM_CHANNEL       RSH_MMIO_ADDRESS_SPACE__CHANNEL_VAL_RSHIM
#define UART0_CHANNEL       RSH_MMIO_ADDRESS_SPACE__CHANNEL_VAL_UART0
#define UART1_CHANNEL       RSH_MMIO_ADDRESS_SPACE__CHANNEL_VAL_UART1

#define RSH_BOOT_FIFO_SIZE   512

/* FIFO structure. */
struct rshim_fifo {
	unsigned char *data;
	unsigned int head;
	unsigned int tail;
	wait_queue_head_t operable;
};

/* RShim backend. */
struct rshim_backend {
	/* Device name. */
	char *dev_name;

	/* Backend owner. */
	struct module *owner;

	/* Pointer to the backend device. */
	struct device *dev;

	/* Pointer to the net device. */
	void *net;

	/* House-keeping Timer. */
	struct timer_list timer;

	/* Character device structure for each device. */
	struct cdev cdevs[RSH_DEV_TYPES];

	/*
	 * The reference count for this structure.  This is incremented by
	 * each open, and by the probe routine (thus, one reference for
	 * each of the two interfaces).  It's decremented on each release,
	 * and on each disconnect.
	 */
	struct kref kref;

	/* State flags. */
	u32 is_booting : 1;        /* Waiting for device to come back. */
	u32 is_boot_open : 1;      /* Boot device is open. */
	u32 is_tm_open : 1;        /* TM FIFO device is open. */
	u32 is_cons_open : 1;      /* Console device is open. */
	u32 is_in_boot_write : 1;  /* A thread is in boot_write(). */
	u32 has_cons_work : 1;     /* Console worker thread running. */
	u32 has_debug : 1;         /* Debug enabled for this device. */
	u32 has_tm : 1;            /* TM FIFO found. */
	u32 has_rshim : 1;         /* RSHIM found. */
	u32 has_fifo_work : 1;     /* FIFO output to be done in worker. */
	u32 has_reprobe : 1;       /* Reprobe support after SW reset. */
	u32 drop : 1;              /* Drop the rest of the packet. */
	u32 registered : 1;        /* Backend has been registered. */
	u32 keepalive : 1;         /* A flag to update keepalive. */

	/* Jiffies of last keepalive. */
	u64 last_keepalive;

	/* State flag bits from RSH_SFLG_xxx (see above). */
	int spin_flags;

	/* Total bytes in the read buffer. */
	int read_buf_bytes;
	/* Offset of next unread byte in the read buffer. */
	int read_buf_next;
	/* Bytes left in the current packet, or 0 if no current packet. */
	int read_buf_pkt_rem;
	/* Padded bytes in the read buffer. */
	int read_buf_pkt_padding;

	/* Bytes left in the current packet pending to write. */
	int write_buf_pkt_rem;

	/* Current message header. */
	union rshim_tmfifo_msg_hdr msg_hdr;

	/* Read FIFOs. */
	struct rshim_fifo read_fifo[TMFIFO_MAX_CHAN];

	/* Write FIFOs. */
	struct rshim_fifo write_fifo[TMFIFO_MAX_CHAN];

	/* Read buffer.  This is a DMA'able buffer. */
	unsigned char *read_buf;
	dma_addr_t read_buf_dma;

	/* Write buffer.  This is a DMA'able buffer. */
	unsigned char *write_buf;
	dma_addr_t write_buf_dma;

	/* Current Tx FIFO channel. */
	int tx_chan;

	/* Current Rx FIFO channel. */
	int rx_chan;

	/* First error encountered during read or write. */
	int tmfifo_error;

	/* Buffers used for boot writes.  Allocated at startup. */
	char *boot_buf[2];

	/*
	 * This mutex is used to prevent the interface pointers and the
	 * device pointer from disappearing while a driver entry point
	 * is using them.  It's held throughout a read or write operation
	 * (at least the parts of those operations which depend upon those
	 * pointers) and is also held whenever those pointers are modified.
	 * It also protects state flags, and booting_complete.
	 */
	struct mutex mutex;

	/* We'll signal completion on this when FLG_BOOTING is turned off. */
	struct completion booting_complete;

#ifdef RSH_RESET_MUTEX
	/* Signaled when a device is disconnected. */
	struct completion reset_complete;
#endif

	/*
	 * This wait queue supports fsync; it's woken up whenever an
	 * outstanding USB write URB is done.  This will need to be more
	 * complex if we start doing write double-buffering.
	 */
	wait_queue_head_t write_completed;

	/* State for our outstanding boot write. */
	struct completion boot_write_complete;

	/*
	 * This spinlock is used to protect items which must be updated by
	 * URB completion handlers, since those can't sleep.  This includes
	 * the read and write buffer pointers, as well as spin_flags.
	 */
	spinlock_t spinlock;

	/* Current termios settings for the console. */
#if LINUX_VERSION_CODE < KERNEL_VERSION(2, 6, 20)
	struct termios cons_termios;
#else
	struct ktermios cons_termios;
#endif

	/* Work queue entry. */
#if LINUX_VERSION_CODE < KERNEL_VERSION(2, 6, 20)
	struct work_struct	work;
#else
	struct delayed_work	work;
#endif

	/* Pending boot & fifo request for the worker. */
	u8 *boot_work_buf;
	u32 boot_work_buf_len;
	u32 boot_work_buf_actual_len;
	u8 *fifo_work_buf;
	u32 fifo_work_buf_len;
	int fifo_work_devtype;

	/* Number of open console files. */
	long console_opens;

	/*
	 * Our index in rshim_devs, which is also the high bits of our
	 * minor number.
	 */
	int dev_index;

	/* APIs provided by backend. */

	/* API to write bulk data to RShim via the backend. */
	ssize_t (*write)(struct rshim_backend *bd, int devtype,
			 const char *buf, size_t count);

	/* API to read bulk data from RShim via the backend. */
	ssize_t (*read)(struct rshim_backend *bd, int devtype,
			char *buf, size_t count);

	/* API to cancel a read / write request (optional). */
	void (*cancel)(struct rshim_backend *bd, int devtype, bool is_write);

	/* API to destroy the backend. */
	void (*destroy)(struct kref *kref);

	/* API to read 8 bytes from RShim. */
	int (*read_rshim)(struct rshim_backend *bd, int chan, int addr,
			  u64 *value);

	/* API to write 8 bytes to RShim. */
	int (*write_rshim)(struct rshim_backend *bd, int chan, int addr,
			   u64 value);
};

/* RShim service. */
struct rshim_service {
	/* Service type RSH_SVC_xxx. */
	int type;

	/* Reference number. */
	atomic_t ref;

	/* Create service. */
	int (*create)(struct rshim_backend *bd);

	/* Delete service. */
	int (*delete)(struct rshim_backend *bd);

	/* Notify service Rx is ready. */
	void (*rx_notify)(struct rshim_backend *bd);
};

/* Global variables. */

/* Global array to store RShim devices and names. */
extern struct workqueue_struct *rshim_wq;

/* Common APIs. */

/* Register/unregister backend. */
int rshim_register(struct rshim_backend *bd);
void rshim_deregister(struct rshim_backend *bd);

/* Register / deregister service. */
int rshim_register_service(struct rshim_service *service);
void rshim_deregister_service(struct rshim_service *service);

/* Find backend by name. */
struct rshim_backend *rshim_find(char *dev_name);

/* RShim global lock. */
void rshim_lock(void);
void rshim_unlock(void);

/* Event notification. */
int rshim_notify(struct rshim_backend *bd, int event, int code);

/*
 * FIFO APIs.
 *
 * FIFO is demuxed into two channels, one for network interface
 * (TMFIFO_NET_CHAN), one for console (TMFIFO_CONS_CHAN).
 */

/* Write / read some bytes to / from the FIFO via the backend. */
ssize_t rshim_fifo_read(struct rshim_backend *bd, char *buffer,
		      size_t count, int chan, bool nonblock,
		      bool to_user);
ssize_t rshim_fifo_write(struct rshim_backend *bd, const char *buffer,
		       size_t count, int chan, bool nonblock,
		       bool from_user);

/* Alloc/free the FIFO. */
int rshim_fifo_alloc(struct rshim_backend *bd);
void rshim_fifo_free(struct rshim_backend *bd);

/* Console APIs. */

/* Enable early console. */
int rshim_cons_early_enable(struct rshim_backend *bd);

#endif /* _RSHIM_H */
