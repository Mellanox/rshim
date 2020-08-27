// SPDX-License-Identifier: GPL-2.0-only
/*
 * rshim_usb.c - BlueField SoC RShim USB host driver
 *
 * Copyright (c) 2020 NVIDIA Corporation. All rights reserved.
 */

/*
 * This source code was originally derived from:
 *
 *   USB Skeleton driver - 2.0
 *
 *   Copyright (C) 2001-2004 Greg Kroah-Hartman (greg@kroah.com)
 *
 *	This program is free software; you can redistribute it and/or
 *	modify it under the terms of the GNU General Public License as
 *	published by the Free Software Foundation, version 2.
 *
 * Some code was also lifted from the example drivers in "Linux Device
 * Drivers" by Alessandro Rubini and Jonathan Corbet, published by
 * O'Reilly & Associates.
 */

#include <linux/kernel.h>
#include <linux/fs.h>
#include <linux/cdev.h>
#include <linux/errno.h>
#include <linux/init.h>
#include <linux/kref.h>
#include <linux/module.h>
#include <linux/mutex.h>
#include <linux/poll.h>
#include <linux/seq_file.h>
#include <linux/slab.h>
#include <linux/usb.h>
#include <linux/version.h>
#include <linux/uaccess.h>
#include <linux/ioctl.h>
#include <linux/termios.h>
#include <linux/workqueue.h>
#include <asm/termbits.h>
#include <linux/circ_buf.h>

#include "rshim.h"

/* Disable RSim access. */
static int rshim_disable;
module_param(rshim_disable, int, 0444);
MODULE_PARM_DESC(rshim_disable, "Disable rshim (obsoleted)");

/* Our USB vendor/product IDs. */
#define USB_TILERA_VENDOR_ID	0x22dc	 /* Tilera Corporation */
#define USB_BLUEFIELD_1_PRODUCT_ID	0x0004	 /* Mellanox Bluefield-1 */
#define USB_BLUEFIELD_2_PRODUCT_ID	0x0214	 /* Mellanox Bluefield-2 */

/* Number of retries for the tmfifo read/write path. */
#define READ_RETRIES		5
#define WRITE_RETRIES		5

/* Structure to hold all of our device specific stuff. */
struct rshim_usb {
	/* RShim backend structure. */
	struct rshim_backend bd;

	/*
	 * The USB device for this device.  We bump its reference count
	 * when the first interface is probed, and drop the ref when the
	 * last interface is disconnected.
	 */
	struct usb_device *udev;

	/* The USB interfaces for this device. */
	struct usb_interface *rshim_interface;

	/* State for our outstanding boot write. */
	struct urb *boot_urb;

	/* Control data. */
	u64 ctrl_data;

	/* Interrupt data buffer.  This is a USB DMA'able buffer. */
	u64 *intr_buf;
	dma_addr_t intr_buf_dma;

	/* Read/interrupt urb, retries, and mode. */
	struct urb *read_or_intr_urb;
	int read_or_intr_retries;
	int read_urb_is_intr;

	/* Write urb and retries. */
	struct urb *write_urb;
	int write_retries;

	/* The address of the boot FIFO endpoint. */
	u8 boot_fifo_ep;
	/* The address of the tile-monitor FIFO interrupt endpoint. */
	u8 tm_fifo_int_ep;
	/* The address of the tile-monitor FIFO input endpoint. */
	u8 tm_fifo_in_ep;
	/* The address of the tile-monitor FIFO output endpoint. */
	u8 tm_fifo_out_ep;
};

/* Table of devices that work with this driver */
static struct usb_device_id rshim_usb_table[] = {
	{ USB_DEVICE(USB_TILERA_VENDOR_ID, USB_BLUEFIELD_1_PRODUCT_ID) },
	{ USB_DEVICE(USB_TILERA_VENDOR_ID, USB_BLUEFIELD_2_PRODUCT_ID) },
	{ }					/* Terminating entry */
};
MODULE_DEVICE_TABLE(usb, rshim_usb_table);

/* Random compatibility hacks. */

/* Arguments to an urb completion handler. */
#if LINUX_VERSION_CODE < KERNEL_VERSION(2, 6, 19)
#define URB_COMP_ARGS struct urb *urb, struct pt_regs *regs
#else
#define URB_COMP_ARGS struct urb *urb
#endif

/* Buffer alloc/free routines. */
#if LINUX_VERSION_CODE < KERNEL_VERSION(2, 6, 34)
#define usb_alloc_coherent usb_buffer_alloc
#define usb_free_coherent usb_buffer_free
#endif

/* Completion initialization. */
#if LINUX_VERSION_CODE < KERNEL_VERSION(3, 13, 0)
#define reinit_completion(x) INIT_COMPLETION(*(x))
#endif

static void rshim_usb_delete(struct kref *kref)
{
	struct rshim_backend *bd;
	struct rshim_usb *dev;

	bd = container_of(kref, struct rshim_backend, kref);
	dev = container_of(bd, struct rshim_usb, bd);

	rshim_deregister(bd);
	kfree(dev);
}

/* Rshim read/write routines */

static int rshim_usb_read_rshim(struct rshim_backend *bd, int chan, int addr,
			      u64 *result)
{
	struct rshim_usb *dev = container_of(bd, struct rshim_usb, bd);
	int retval;

	if (!bd->has_rshim)
		return -ENODEV;

	/* Do a blocking control read and endian conversion. */
	retval = usb_control_msg(dev->udev, usb_rcvctrlpipe(dev->udev, 0),
				 0,  /* request */
				 USB_RECIP_ENDPOINT | USB_TYPE_VENDOR |
				 USB_DIR_IN,  /* request type */
				 chan, /* value */
				 addr, /* index */
				 &dev->ctrl_data, 8, 2000);

	/*
	 * The RShim HW puts bytes on the wire in little-endian order
	 * regardless of endianness settings either in the host or the ARM
	 * cores.
	 */
	*result = le64_to_cpu(dev->ctrl_data);
	if (retval == 8)
		return 0;

	/*
	 * These are weird error codes, but we want to use something
	 * the USB stack doesn't use so that we can identify short/long
	 * reads.
	 */
	return retval >= 0 ? (retval > 8 ? -EBADE : -EBADR) : retval;
}

static int rshim_usb_write_rshim(struct rshim_backend *bd, int chan, int addr,
			       u64 value)
{
	struct rshim_usb *dev = container_of(bd, struct rshim_usb, bd);
	int retval;

	if (!bd->has_rshim)
		return -ENODEV;

	/* Convert the word to little endian and do blocking control write. */
	dev->ctrl_data = cpu_to_le64(value);
	retval = usb_control_msg(dev->udev, usb_sndctrlpipe(dev->udev, 0),
				 0,  /* request */
				 USB_RECIP_ENDPOINT | USB_TYPE_VENDOR |
				 USB_DIR_OUT,  /* request type */
				 chan, /* value */
				 addr, /* index */
				 &dev->ctrl_data, 8, 2000);

	if (retval == 8)
		return 0;

	/*
	 * These are weird error codes, but we want to use something
	 * the USB stack doesn't use so that we can identify short/long
	 * writes.
	 */
	return retval >= 0 ? (retval > 8 ? -EBADE : -EBADR) : retval;
}

/* Boot routines */

static void rshim_usb_boot_write_callback(URB_COMP_ARGS)
{
	struct rshim_usb *dev = urb->context;

	if (urb->status == -ENOENT)
		pr_debug("boot tx canceled, actual length %d\n",
			 urb->actual_length);
	else if (urb->status)
		pr_debug("boot tx failed, status %d, actual length %d\n",
			 urb->status, urb->actual_length);

	complete_all(&dev->bd.boot_write_complete);
}

static ssize_t rshim_usb_boot_write(struct rshim_usb *dev, const char *buf,
				  size_t count)
{
	struct rshim_backend *bd = &dev->bd;
	int retval = 0;
	size_t bytes_written = 0;

	/* Create and fill an urb */
	dev->boot_urb = usb_alloc_urb(0, GFP_KERNEL);
	if (unlikely(!dev->boot_urb)) {
		pr_debug("boot_write: couldn't allocate urb\n");
		return -ENOMEM;
	}
	usb_fill_bulk_urb(dev->boot_urb, dev->udev,
			  usb_sndbulkpipe(dev->udev, dev->boot_fifo_ep),
			  (char *)buf, count, rshim_usb_boot_write_callback,
			  dev);

	/* Submit the urb. */
	reinit_completion(&bd->boot_write_complete);
	retval = usb_submit_urb(dev->boot_urb, GFP_KERNEL);
	if (retval)
		goto done;

	/*
	 * Wait until it's done. If anything goes wrong in the USB layer,
	 * the callback function might never get called and cause stuck.
	 * Here we release the mutex so user could use 'ctrl + c' to terminate
	 * the current write. Once the boot file is opened again, the
	 * outstanding urb will be canceled. If not interrupted, it'll timeout
	 * according to the setting of rshim_boot_timeout in seconds.
	 *
	 * Note: when boot stream starts to write, it will either run to
	 * completion, or be interrupted by user. The urb callback function will
	 * be called during this period. There are no other operations to affect
	 * the boot stream. So unlocking the mutex is considered safe.
	 */
	mutex_unlock(&bd->mutex);
	retval = wait_for_completion_interruptible_timeout(
					&bd->boot_write_complete,
					rshim_boot_timeout * HZ);
	if (!retval) {
		/* Abort if timeout. */
		bytes_written = 0;
		retval = -ETIMEDOUT;
	}
	else if (retval > 0)
		retval = 0;

	mutex_lock(&bd->mutex);
	if (retval < 0) {
		usb_kill_urb(dev->boot_urb);
		if (retval != -ETIMEDOUT)
			bytes_written += dev->boot_urb->actual_length;
		goto done;
	}

	if (dev->boot_urb->actual_length !=
		dev->boot_urb->transfer_buffer_length) {
		pr_debug("length mismatch, exp %d act %d stat %d\n",
			 dev->boot_urb->transfer_buffer_length,
			 dev->boot_urb->actual_length,
			 dev->boot_urb->status);
	}

#ifdef RSH_USB_BMC
	/*
	 * The UHCI host controller on the BMC seems to
	 * overestimate the amount of data it's
	 * successfully sent when it sees a babble error.
	 */
	if (dev->boot_urb->status == -EOVERFLOW &&
	    dev->boot_urb->actual_length >= 64) {
		dev->boot_urb->actual_length -= 64;
		pr_debug("saw babble, new length %d\n",
		dev->boot_urb->actual_length);
	}
#endif

	bytes_written = dev->boot_urb->actual_length;

	if (dev->boot_urb->status == -ENOENT &&
	    dev->boot_urb->transfer_buffer_length !=
	    dev->boot_urb->actual_length) {
		pr_debug("boot_write: urb canceled.\n");
	} else {
		if (dev->boot_urb->status) {
			pr_debug("boot_write: urb failed, status %d\n",
				 dev->boot_urb->status);
		}
		if (dev->boot_urb->status != -ENOENT && !retval)
			retval = dev->boot_urb->status;
	}

done:
	usb_free_urb(dev->boot_urb);
	dev->boot_urb = NULL;

	return bytes_written ? bytes_written : retval;
}

/* FIFO routines */

static void rshim_usb_fifo_read_callback(URB_COMP_ARGS)
{
	struct rshim_usb *dev = urb->context;
	struct rshim_backend *bd = &dev->bd;

	spin_lock(&bd->spinlock);

	pr_debug("usb_fifo_read_callback: %s urb completed, status %d, "
		 "actual length %d, intr buf %d\n",
		 dev->read_urb_is_intr ? "interrupt" : "read",
		 urb->status, urb->actual_length, (int) *dev->intr_buf);

	bd->spin_flags &= ~RSH_SFLG_READING;

	if (urb->status == 0) {
		/*
		 * If a read completed, clear the number of bytes available
		 * from the last interrupt, and set up the new buffer for
		 * processing.  (If an interrupt completed, there's nothing
		 * to do, since the number of bytes available was already
		 * set by the I/O itself.)
		 */
		if (!dev->read_urb_is_intr) {
			*dev->intr_buf = 0;
			bd->read_buf_bytes = urb->actual_length;
			bd->read_buf_next = 0;
		}

		/* Process any data we got, and launch another I/O if needed. */
		rshim_notify(bd, RSH_EVENT_FIFO_INPUT, 0);
	} else if (urb->status == -ENOENT) {
		/*
		 * The urb was explicitly cancelled.  The only time we
		 * currently do this is when we close the stream.  If we
		 * mark this as an error, tile-monitor --resume won't work,
		 * so we just want to do nothing.
		 */
	} else if (urb->status == -ECONNRESET ||
		   urb->status == -ESHUTDOWN) {
		/*
		 * The device went away.  We don't want to retry this, and
		 * we expect things to get better, probably after a device
		 * reset, but in the meantime, we should let upper layers
		 * know there was a problem.
		 */
		rshim_notify(bd, RSH_EVENT_FIFO_ERR, urb->status);
	} else if (dev->read_or_intr_retries < READ_RETRIES &&
		   urb->actual_length == 0 &&
		   (urb->status == -EPROTO || urb->status == -EILSEQ ||
		    urb->status == -EOVERFLOW)) {
		/*
		 * We got an error which could benefit from being retried.
		 * Just submit the same urb again.  Note that we don't
		 * handle partial reads; it's hard, and we haven't really
		 * seen them.
		 */
		int retval;

		dev->read_or_intr_retries++;
		retval = usb_submit_urb(urb, GFP_ATOMIC);
		if (retval) {
			pr_debug("fifo_read_callback: resubmitted urb but "
			      "got error %d", retval);
			/*
			 * In this case, we won't try again; signal the
			 * error to upper layers.
			 */
			rshim_notify(bd, RSH_EVENT_FIFO_ERR, retval);
		} else {
			bd->spin_flags |= RSH_SFLG_READING;
		}
	} else {
		/*
		 * We got some error we don't know how to handle, or we got
		 * too many errors.  Either way we don't retry any more,
		 * but we signal the error to upper layers.
		 */
		ERROR("fifo_read_callback: %s urb completed abnormally, "
		      "error %d", dev->read_urb_is_intr ? "interrupt" : "read",
		      urb->status);
		rshim_notify(bd, RSH_EVENT_FIFO_ERR, urb->status);
	}

	spin_unlock(&bd->spinlock);
}

static void rshim_usb_fifo_read(struct rshim_usb *dev, char *buffer,
			      size_t count)
{
	struct rshim_backend *bd = &dev->bd;

	if ((int) *dev->intr_buf || bd->read_buf_bytes) {
		/* We're doing a read. */

		int retval;
		struct urb *urb = dev->read_or_intr_urb;

		usb_fill_bulk_urb(urb, dev->udev,
				  usb_rcvbulkpipe(dev->udev,
						  dev->tm_fifo_in_ep),
				  buffer, count,
				  rshim_usb_fifo_read_callback,
				  dev);
		urb->transfer_dma = dev->bd.read_buf_dma;
		urb->transfer_flags |= URB_NO_TRANSFER_DMA_MAP;

		dev->bd.spin_flags |= RSH_SFLG_READING;
		dev->read_urb_is_intr = 0;
		dev->read_or_intr_retries = 0;

		/* Submit the urb. */
		retval = usb_submit_urb(urb, GFP_ATOMIC);
		if (retval) {
			dev->bd.spin_flags &= ~RSH_SFLG_READING;
			pr_debug("fifo_drain: failed submitting read "
			      "urb, error %d", retval);
		}
		pr_debug("fifo_read_callback: resubmitted read urb\n");
	} else {
		/* We're doing an interrupt. */

		int retval;
		struct urb *urb = dev->read_or_intr_urb;

		usb_fill_int_urb(urb, dev->udev,
				 usb_rcvintpipe(dev->udev, dev->tm_fifo_int_ep),
				 dev->intr_buf, sizeof(*dev->intr_buf),
				 rshim_usb_fifo_read_callback,
				 /*
				  * FIXME: is 6 a good interval value?  That's
				  * polling at 8000/(1 << 6) == 125 Hz.
				  */
				 dev, 6);
		urb->transfer_dma = dev->intr_buf_dma;
		urb->transfer_flags |= URB_NO_TRANSFER_DMA_MAP;

		dev->bd.spin_flags |= RSH_SFLG_READING;
		dev->read_urb_is_intr = 1;
		dev->read_or_intr_retries = 0;

		/* Submit the urb */
		retval = usb_submit_urb(urb, GFP_ATOMIC);
		if (retval) {
			dev->bd.spin_flags &= ~RSH_SFLG_READING;
			pr_debug("fifo_read_callback: failed submitting "
			      "interrupt urb, error %d", retval);
		}
		pr_debug("fifo_read_callback: resubmitted interrupt urb\n");
	}
}

static void rshim_usb_fifo_write_callback(URB_COMP_ARGS)
{
	struct rshim_usb *dev = urb->context;
	struct rshim_backend *bd = &dev->bd;

	spin_lock(&bd->spinlock);

	pr_debug("fifo_write_callback: urb completed, status %d, "
		 "actual length %d, intr buf %d\n",
		 urb->status, urb->actual_length, (int) *dev->intr_buf);

	bd->spin_flags &= ~RSH_SFLG_WRITING;

	if (urb->status == 0) {
		/* A write completed. */
		wake_up_interruptible_all(&bd->write_completed);
		rshim_notify(bd, RSH_EVENT_FIFO_OUTPUT, 0);
	} else if (urb->status == -ENOENT) {
		/*
		 * The urb was explicitly cancelled.  The only time we
		 * currently do this is when we close the stream.  If we
		 * mark this as an error, tile-monitor --resume won't work,
		 * so we just want to do nothing.
		 */
	} else if (urb->status == -ECONNRESET ||
		   urb->status == -ESHUTDOWN) {
		/*
		 * The device went away.  We don't want to retry this, and
		 * we expect things to get better, probably after a device
		 * reset, but in the meantime, we should let upper layers
		 * know there was a problem.
		 */
		rshim_notify(bd, RSH_EVENT_FIFO_ERR, urb->status);
	} else if (dev->write_retries < WRITE_RETRIES &&
		   urb->actual_length == 0 &&
		   (urb->status == -EPROTO || urb->status == -EILSEQ ||
		    urb->status == -EOVERFLOW)) {
		/*
		 * We got an error which could benefit from being retried.
		 * Just submit the same urb again.  Note that we don't
		 * handle partial writes; it's hard, and we haven't really
		 * seen them.
		 */
		int retval;

		dev->write_retries++;
		retval = usb_submit_urb(urb, GFP_ATOMIC);
		if (retval) {
			ERROR("fifo_write_callback: resubmitted urb but "
			      "got error %d", retval);
			/*
			 * In this case, we won't try again; signal the
			 * error to upper layers.
			 */
			rshim_notify(bd, RSH_EVENT_FIFO_ERR, retval);
		} else {
			bd->spin_flags |= RSH_SFLG_WRITING;
		}
	} else {
		/*
		 * We got some error we don't know how to handle, or we got
		 * too many errors.  Either way we don't retry any more,
		 * but we signal the error to upper layers.
		 */
		ERROR("fifo_write_callback: urb completed abnormally, "
		      "error %d", urb->status);
		rshim_notify(bd, RSH_EVENT_FIFO_ERR, urb->status);
	}

	spin_unlock(&bd->spinlock);
}

static int rshim_usb_fifo_write(struct rshim_usb *dev, const char *buffer,
			      size_t count)
{
	struct rshim_backend *bd = &dev->bd;
	int retval;

	WARN_ONCE(count % 8 != 0, "rshim write %d is not multiple of 8 bytes\n",
		  (int)count);

	/* Initialize the urb properly. */
	usb_fill_bulk_urb(dev->write_urb, dev->udev,
			  usb_sndbulkpipe(dev->udev,
					  dev->tm_fifo_out_ep),
			  (char *)buffer,
			  count,
			  rshim_usb_fifo_write_callback,
			  dev);
	dev->write_urb->transfer_dma = bd->write_buf_dma;
	dev->write_urb->transfer_flags |= URB_NO_TRANSFER_DMA_MAP;
	dev->write_retries = 0;

	/* Send the data out the bulk port. */
	retval = usb_submit_urb(dev->write_urb, GFP_ATOMIC);
	if (retval) {
		bd->spin_flags &= ~RSH_SFLG_WRITING;
		ERROR("fifo_write: failed submitting write "
		      "urb, error %d", retval);
		return -1;
	}

	bd->spin_flags |= RSH_SFLG_WRITING;
	return 0;
}

/* Probe routines */

/* These make the endpoint test code in rshim_usb_probe() a lot cleaner. */
#define is_in_ep(ep)   (((ep)->bEndpointAddress & USB_ENDPOINT_DIR_MASK) == \
			USB_DIR_IN)
#define is_bulk_ep(ep) (((ep)->bmAttributes & USB_ENDPOINT_XFERTYPE_MASK) == \
			USB_ENDPOINT_XFER_BULK)
#define is_int_ep(ep)  (((ep)->bmAttributes & USB_ENDPOINT_XFERTYPE_MASK) == \
			USB_ENDPOINT_XFER_INT)
#define max_pkt(ep)    le16_to_cpu(ep->wMaxPacketSize)
#define ep_addr(ep)    (ep->bEndpointAddress)

static ssize_t rshim_usb_backend_read(struct rshim_backend *bd, int devtype,
				    char *buf, size_t count)
{
	struct rshim_usb *dev = container_of(bd, struct rshim_usb, bd);

	switch (devtype) {
	case RSH_DEV_TYPE_NET:
	case RSH_DEV_TYPE_CONSOLE:
		rshim_usb_fifo_read(dev, buf, count);
		return 0;

	default:
		ERROR("bad devtype %d", devtype);
		return -EINVAL;
	}
}

static ssize_t rshim_usb_backend_write(struct rshim_backend *bd, int devtype,
				     const char *buf, size_t count)
{
	struct rshim_usb *dev = container_of(bd, struct rshim_usb, bd);

	switch (devtype) {
	case RSH_DEV_TYPE_NET:
	case RSH_DEV_TYPE_CONSOLE:
		return rshim_usb_fifo_write(dev, buf, count);

	case RSH_DEV_TYPE_BOOT:
		return rshim_usb_boot_write(dev, buf, count);

	default:
		ERROR("bad devtype %d", devtype);
		return -EINVAL;
	}
}

static void rshim_usb_backend_cancel_req(struct rshim_backend *bd, int devtype,
				       bool is_write)
{
	struct rshim_usb *dev = container_of(bd, struct rshim_usb, bd);

	switch (devtype) {
	case RSH_DEV_TYPE_NET:
	case RSH_DEV_TYPE_CONSOLE:
		if (is_write)
			usb_kill_urb(dev->write_urb);
		else
			usb_kill_urb(dev->read_or_intr_urb);
		break;

	case RSH_DEV_TYPE_BOOT:
		usb_kill_urb(dev->boot_urb);
		break;

	default:
		ERROR("bad devtype %d", devtype);
		break;
	}
}

static int rshim_usb_probe(struct usb_interface *interface,
			 const struct usb_device_id *id)
{
	char *usb_dev_name;
	int dev_name_len = 64;
	struct rshim_usb *dev = NULL;
	struct rshim_backend *bd;
	struct usb_host_interface *iface_desc;
	struct usb_endpoint_descriptor *ep;
	int i;
	int allocfail = 0;
	int retval = -ENOMEM;

	/*
	 * Get our device pathname.  The usb_make_path interface uselessly
	 * returns -1 if the output buffer is too small, instead of telling
	 * us how big it needs to be, so we just start with a reasonable
	 * size and double it until the name fits.
	 */
	while (1) {
		usb_dev_name = kmalloc(dev_name_len, GFP_KERNEL);
		if (!usb_dev_name)
			goto error;
		if (usb_make_path(interface_to_usbdev(interface), usb_dev_name,
				  dev_name_len) >= 0)
			break;
		kfree(usb_dev_name);
		dev_name_len *= 2;
	}

	pr_debug("probing %s\n", usb_dev_name);

	/*
	 * Now see if we've previously seen this device.  If so, we use the
	 * same device number, otherwise we pick the first available one.
	 */
	rshim_lock();

	/* Find the backend. */
	bd = rshim_find(usb_dev_name);
	if (bd) {
		pr_debug("found previously allocated rshim_usb structure\n");
		kref_get(&bd->kref);
		dev = container_of(bd, struct rshim_usb, bd);
		kfree(usb_dev_name);
		usb_dev_name = NULL;
	} else {
		pr_debug("creating new rshim_usb structure\n");
		dev = kzalloc(sizeof(*dev), GFP_KERNEL);
		if (dev == NULL) {
			ERROR("couldn't get memory for new device");
			rshim_unlock();
			goto error;
		}

		bd = &dev->bd;
		bd->dev_name = usb_dev_name;
		bd->read = rshim_usb_backend_read;
		bd->write = rshim_usb_backend_write;
		bd->cancel = rshim_usb_backend_cancel_req;
		bd->destroy = rshim_usb_delete;
		bd->read_rshim = rshim_usb_read_rshim;
		bd->write_rshim = rshim_usb_write_rshim;
		bd->has_reprobe = 1;
		bd->owner = THIS_MODULE;
		mutex_init(&bd->mutex);
	}

	/*
	 * This has to be done on the first probe, whether or not we
	 * allocated a new rshim_usb structure, since it's always dropped
	 * on the second disconnect.
	 */
	if (!bd->has_rshim && !bd->has_tm)
		dev->udev = usb_get_dev(interface_to_usbdev(interface));

	/*
	 * It would seem more logical to allocate these above when we create
	 * a new rshim_usb structure, but we don't want to do it until we've
	 * upped the usb device reference count.
	 */
	allocfail |= rshim_fifo_alloc(bd);

	if (!bd->read_buf)
		bd->read_buf = usb_alloc_coherent(dev->udev, READ_BUF_SIZE,
						   GFP_KERNEL,
						   &bd->read_buf_dma);
	allocfail |= bd->read_buf == 0;

	if (!dev->intr_buf) {
		dev->intr_buf = usb_alloc_coherent(dev->udev,
						   sizeof(*dev->intr_buf),
						   GFP_KERNEL,
						   &dev->intr_buf_dma);
		if (dev->intr_buf != NULL)
			*dev->intr_buf = 0;
	}
	allocfail |= dev->intr_buf == 0;

	if (!bd->write_buf) {
		bd->write_buf = usb_alloc_coherent(dev->udev,
						       WRITE_BUF_SIZE,
						       GFP_KERNEL,
						       &bd->write_buf_dma);
	}
	allocfail |= bd->write_buf == 0;

	if (!dev->read_or_intr_urb)
		dev->read_or_intr_urb = usb_alloc_urb(0, GFP_KERNEL);
	allocfail |= dev->read_or_intr_urb == 0;

	if (!dev->write_urb)
		dev->write_urb = usb_alloc_urb(0, GFP_KERNEL);
	allocfail |= dev->write_urb == 0;

	if (allocfail) {
		ERROR("can't allocate buffers or urbs");
		rshim_unlock();
		goto error;
	}

	rshim_unlock();

	iface_desc = interface->cur_altsetting;

	/* Make sure this is a vendor-specific interface class. */
	if (iface_desc->desc.bInterfaceClass != 0xFF)
		goto error;

	/* See which interface this is, then save the correct data. */

	mutex_lock(&bd->mutex);
	if (iface_desc->desc.bInterfaceSubClass == 0) {
		pr_debug("found rshim interface\n");
		/*
		 * We only expect one endpoint here, just make sure its
		 * attributes match.
		 */
		if (iface_desc->desc.bNumEndpoints != 1) {
			ERROR("wrong number of endpoints for rshim interface");
			mutex_unlock(&bd->mutex);
			goto error;
		}
		ep = &iface_desc->endpoint[0].desc;

		/* We expect a bulk out endpoint. */
		if (!is_bulk_ep(ep) || is_in_ep(ep)) {
			mutex_unlock(&bd->mutex);
			goto error;
		}

		bd->has_rshim = 1;
		dev->rshim_interface = interface;
		dev->boot_fifo_ep = ep_addr(ep);

	} else if (iface_desc->desc.bInterfaceSubClass == 1) {
		pr_debug("found tmfifo interface\n");
		/*
		 * We expect 3 endpoints here.  Since they're listed in
		 * random order we have to use their attributes to figure
		 * out which is which.
		 */
		if (iface_desc->desc.bNumEndpoints != 3) {
			ERROR("wrong number of endpoints for tm interface");
			mutex_unlock(&bd->mutex);
			goto error;
		}
		dev->tm_fifo_in_ep = 0;
		dev->tm_fifo_int_ep = 0;
		dev->tm_fifo_out_ep = 0;

		for (i = 0; i < iface_desc->desc.bNumEndpoints; i++) {
			ep = &iface_desc->endpoint[i].desc;

			if (is_in_ep(ep)) {
				if (is_bulk_ep(ep)) {
					/* Bulk in endpoint. */
					dev->tm_fifo_in_ep = ep_addr(ep);
				} else if (is_int_ep(ep)) {
					/* Interrupt in endpoint. */
					dev->tm_fifo_int_ep = ep_addr(ep);
				}
			} else {
				if (is_bulk_ep(ep)) {
					/* Bulk out endpoint. */
					dev->tm_fifo_out_ep = ep_addr(ep);
				}
			}
		}

		if (!dev->tm_fifo_in_ep || !dev->tm_fifo_int_ep ||
		    !dev->tm_fifo_out_ep) {
			ERROR("could not find all required endpoints for "
			      "tm interface");
			mutex_unlock(&bd->mutex);
			goto error;
		}
		bd->has_tm = 1;
	} else {
		mutex_unlock(&bd->mutex);
		goto error;
	}

	/* Save our data pointer in this interface device. */
	usb_set_intfdata(interface, dev);

	if (!bd->dev)
		bd->dev = &dev->udev->dev;

	/*
	 * Register rshim here since it needs to detect whether other backend
	 * has already registered or not, which involves reading/writting rshim
	 * registers and has assumption that the under layer is working.
	 */
	rshim_lock();
	if (!bd->registered) {
		retval = rshim_register(bd);
		if (retval) {
			rshim_unlock();
			goto error;
		}
	}
	rshim_unlock();

	/* Notify that device is attached. */
	retval = rshim_notify(&dev->bd, RSH_EVENT_ATTACH, 0);
	mutex_unlock(&dev->bd.mutex);
	if (retval)
		goto error;

	return 0;

error:
	if (dev) {
		usb_free_urb(dev->read_or_intr_urb);
		dev->read_or_intr_urb = NULL;
		usb_free_urb(dev->write_urb);
		dev->write_urb = NULL;

		usb_free_coherent(dev->udev, READ_BUF_SIZE,
				  dev->bd.read_buf, dev->bd.read_buf_dma);
		dev->bd.read_buf = NULL;

		usb_free_coherent(dev->udev, WRITE_BUF_SIZE,
				  dev->bd.write_buf, dev->bd.write_buf_dma);
		dev->bd.write_buf = NULL;

		rshim_fifo_free(&dev->bd);

		usb_free_coherent(dev->udev, sizeof(*dev->intr_buf),
				  dev->intr_buf, dev->intr_buf_dma);
		dev->intr_buf = NULL;

		rshim_lock();
		kref_put(&dev->bd.kref, rshim_usb_delete);
		rshim_unlock();
	}

	kfree(usb_dev_name);
	return retval;
}

static void rshim_usb_disconnect(struct usb_interface *interface)
{
	struct rshim_usb *dev;
	struct rshim_backend *bd;
	int flush_wq = 0;

	dev = usb_get_intfdata(interface);
	bd = &dev->bd;
	usb_set_intfdata(interface, NULL);

	rshim_notify(bd, RSH_EVENT_DETACH, 0);

	/*
	 * Clear this interface so we don't unregister our devices next
	 * time.
	 */
	mutex_lock(&bd->mutex);

	if (dev->rshim_interface == interface) {
		bd->has_rshim = 0;
		dev->rshim_interface = NULL;
	} else {
		/*
		 * We have to get rid of any USB state, since it may be
		 * tied to the USB device which is going to vanish as soon
		 * as we get both disconnects.  We'll reallocate these
		 * on the next probe.
		 *
		 * Supposedly the code which called us already killed any
		 * outstanding URBs, but it doesn't hurt to be sure.
		 */

		/*
		 * We must make sure the console worker isn't running
		 * before we free all these resources, and particularly
		 * before we decrement our usage count, below.  Most of the
		 * time, if it's even enabled, it'll be scheduled to run at
		 * some point in the future, and we can take care of that
		 * by asking that it be canceled.
		 *
		 * However, it's possible that it's already started
		 * running, but can't make progress because it's waiting
		 * for the device mutex, which we currently have.  We
		 * handle this case by clearing the bit that says it's
		 * enabled.  The worker tests this bit as soon as it gets
		 * the mutex, and if it's clear, it just returns without
		 * rescheduling itself.  Note that if we didn't
		 * successfully cancel it, we flush the work entry below,
		 * after we drop the mutex, to be sure it's done before we
		 * decrement the device usage count.
		 *
		 * XXX This might be racy; what if something else which
		 * would enable the worker runs after we drop the mutex
		 * but before the worker itself runs?
		 */
		flush_wq = !cancel_delayed_work(&bd->work);
		bd->has_cons_work = 0;

		usb_kill_urb(dev->read_or_intr_urb);
		usb_free_urb(dev->read_or_intr_urb);
		dev->read_or_intr_urb = NULL;
		usb_kill_urb(dev->write_urb);
		usb_free_urb(dev->write_urb);
		dev->write_urb = NULL;

		usb_free_coherent(dev->udev, READ_BUF_SIZE,
				  bd->read_buf, bd->read_buf_dma);
		bd->read_buf = NULL;

		usb_free_coherent(dev->udev, sizeof(*dev->intr_buf),
				  dev->intr_buf, dev->intr_buf_dma);
		dev->intr_buf = NULL;

		usb_free_coherent(dev->udev, WRITE_BUF_SIZE,
				  bd->write_buf, bd->write_buf_dma);
		bd->write_buf = NULL;

		rshim_fifo_free(bd);
	}

	if (!bd->has_rshim && !bd->has_tm) {
		usb_put_dev(dev->udev);
		dev->udev = NULL;
		INFO("now disconnected");
	} else {
		pr_debug("partially disconnected\n");
	}

	mutex_unlock(&bd->mutex);

	/* This can't be done while we hold the mutex; see comments above. */
	if (flush_wq)
		flush_workqueue(rshim_wq);

	/* decrement our usage count */
	rshim_lock();
	kref_put(&bd->kref, rshim_usb_delete);
	rshim_unlock();
}

static struct usb_driver rshim_usb_driver = {
	.name = "rshim_usb",
	.probe = rshim_usb_probe,
	.disconnect = rshim_usb_disconnect,
	.id_table = rshim_usb_table,
};

static int __init rshim_usb_init(void)
{
	int result;

	/* Register this driver with the USB subsystem. */
	result = usb_register(&rshim_usb_driver);
	if (result)
		ERROR("usb_register failed, error number %d", result);

	return result;
}

static void __exit rshim_usb_exit(void)
{
	/* Deregister this driver with the USB subsystem. */
	usb_deregister(&rshim_usb_driver);
}

module_init(rshim_usb_init);
module_exit(rshim_usb_exit);

MODULE_LICENSE("GPL");
MODULE_AUTHOR("Mellanox Technologies");
MODULE_VERSION("0.10");
