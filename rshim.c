/*
 * rshim_common.c - Mellanox host-side driver for RShim
 *
 * Copyright 2017 Mellanox Technologies. All Rights Reserved.
 *
 *   This program is free software; you can redistribute it and/or
 *   modify it under the terms of the GNU General Public License
 *   as published by the Free Software Foundation, version 2.
 *
 *   This program is distributed in the hope that it will be useful, but
 *   WITHOUT ANY WARRANTY; without even the implied warranty of
 *   MERCHANTABILITY OR FITNESS FOR A PARTICULAR PURPOSE, GOOD TITLE or
 *   NON INFRINGEMENT.	See the GNU General Public License for more details.
 */

#include <linux/kernel.h>
#include <linux/fs.h>
#include <linux/errno.h>
#include <linux/init.h>
#include <linux/kref.h>
#include <linux/module.h>
#include <linux/mutex.h>
#include <linux/poll.h>
#include <linux/seq_file.h>
#include <linux/slab.h>
#include <linux/version.h>
#include <linux/uaccess.h>
#include <linux/ioctl.h>
#include <linux/termios.h>
#include <linux/workqueue.h>
#include <linux/sched.h>
#include <asm/termbits.h>
#include <linux/circ_buf.h>
#include <linux/delay.h>
#include <linux/virtio_ids.h>
#if LINUX_VERSION_CODE >= KERNEL_VERSION(4, 11, 0)
#include <linux/sched/signal.h>
#endif

#include "rshim.h"

/* Maximum number of devices controlled by this driver. */
int rshim_nr_devs = 64;
module_param(rshim_nr_devs, int, 0444);
MODULE_PARM_DESC(rshim_nr_devs, "Maximum number of supported devices");

static char *backend_driver = "";
module_param(backend_driver, charp, 0444);
MODULE_PARM_DESC(backend_driver, "Rshim backend driver to use");

static int rshim_keepalive_period = 300;
module_param(rshim_keepalive_period, int, 0644);
MODULE_PARM_DESC(rshim_keepalive_period, "Keepalive period in milliseconds");

static int rshim_sw_reset_skip;
module_param(rshim_sw_reset_skip, int, 0644);
MODULE_PARM_DESC(rshim_sw_reset_skip, "Skip SW_RESET during booting");

int rshim_boot_timeout = 300;
module_param(rshim_boot_timeout, int, 0644);
MODULE_PARM_DESC(rshim_boot_timeout, "Boot timeout in seconds");
EXPORT_SYMBOL(rshim_boot_timeout);

#define RSH_KEEPALIVE_MAGIC_NUM 0x5089836482ULL

/* Circular buffer macros. */

#define read_empty(bd, chan) \
	(CIRC_CNT((bd)->read_fifo[chan].head, \
		  (bd)->read_fifo[chan].tail, READ_FIFO_SIZE) == 0)
#define read_full(bd, chan) \
	(CIRC_SPACE((bd)->read_fifo[chan].head, \
		    (bd)->read_fifo[chan].tail, READ_FIFO_SIZE) == 0)
#define read_space(bd, chan) \
	CIRC_SPACE((bd)->read_fifo[chan].head, \
		   (bd)->read_fifo[chan].tail, READ_FIFO_SIZE)
#define read_cnt(bd, chan) \
	CIRC_CNT((bd)->read_fifo[chan].head, \
		 (bd)->read_fifo[chan].tail, READ_FIFO_SIZE)
#define read_cnt_to_end(bd, chan) \
	CIRC_CNT_TO_END((bd)->read_fifo[chan].head, \
			(bd)->read_fifo[chan].tail, READ_FIFO_SIZE)
#define read_data_ptr(bd, chan) \
	((bd)->read_fifo[chan].data + \
	 ((bd)->read_fifo[chan].tail & (READ_FIFO_SIZE - 1)))
#define read_consume_bytes(bd, chan, nbytes) \
	((bd)->read_fifo[chan].tail = \
		((bd)->read_fifo[chan].tail + (nbytes)) & \
		 (READ_FIFO_SIZE - 1))
#define read_space_to_end(bd, chan) \
	CIRC_SPACE_TO_END((bd)->read_fifo[chan].head, \
			  (bd)->read_fifo[chan].tail, READ_FIFO_SIZE)
#define read_space_offset(bd, chan) \
	((bd)->read_fifo[chan].head & (READ_FIFO_SIZE - 1))
#define read_space_ptr(bd, chan) \
	((bd)->read_fifo[chan].data + read_space_offset(bd, (chan)))
#define read_add_bytes(bd, chan, nbytes) \
	((bd)->read_fifo[chan].head = \
		((bd)->read_fifo[chan].head + (nbytes)) & \
		 (READ_FIFO_SIZE - 1))
#define read_reset(bd, chan) \
	((bd)->read_fifo[chan].head = (bd)->read_fifo[chan].tail = 0)

#define write_empty(bd, chan) \
	(CIRC_CNT((bd)->write_fifo[chan].head, \
		  (bd)->write_fifo[chan].tail, WRITE_FIFO_SIZE) == 0)
#define write_full(bd, chan) \
	(CIRC_SPACE((bd)->write_fifo[chan].head, \
		    (bd)->write_fifo[chan].tail, WRITE_FIFO_SIZE) == 0)
#define write_space(bd, chan) \
	CIRC_SPACE((bd)->write_fifo[chan].head, \
		   (bd)->write_fifo[chan].tail, WRITE_FIFO_SIZE)
#define write_cnt(bd, chan) \
	CIRC_CNT((bd)->write_fifo[chan].head, \
		 (bd)->write_fifo[chan].tail, WRITE_FIFO_SIZE)
#define write_cnt_to_end(bd, chan) \
	CIRC_CNT_TO_END((bd)->write_fifo[chan].head, \
			(bd)->write_fifo[chan].tail, WRITE_FIFO_SIZE)
#define write_data_offset(bd, chan) \
	((bd)->write_fifo[chan].tail & (WRITE_FIFO_SIZE - 1))
#define write_data_ptr(bd, chan) \
	((bd)->write_fifo[chan].data + write_data_offset(bd, (chan)))
#define write_consume_bytes(bd, chan, nbytes) \
	((bd)->write_fifo[chan].tail = \
		 ((bd)->write_fifo[chan].tail + (nbytes)) & \
		  (WRITE_FIFO_SIZE - 1))
#define write_space_to_end(bd, chan) \
	CIRC_SPACE_TO_END((bd)->write_fifo[chan].head, \
			  (bd)->write_fifo[chan].tail, WRITE_FIFO_SIZE)
#define write_space_ptr(bd, chan) \
	((bd)->write_fifo[chan].data + \
	 ((bd)->write_fifo[chan].head & (WRITE_FIFO_SIZE - 1)))
#define write_add_bytes(bd, chan, nbytes) \
	((bd)->write_fifo[chan].head = \
	 ((bd)->write_fifo[chan].head + (nbytes)) & \
	  (WRITE_FIFO_SIZE - 1))
#define write_reset(bd, chan) \
	((bd)->write_fifo[chan].head = (bd)->write_fifo[chan].tail = 0)

/* Arguments to an fsync entry point. */
#if LINUX_VERSION_CODE < KERNEL_VERSION(2, 6, 35)
#define FSYNC_ARGS struct file *file, struct dentry *dentry, int datasync
#define FSYNC_CALL file, dentry, datasync
#elif LINUX_VERSION_CODE < KERNEL_VERSION(3, 1, 0)
#define FSYNC_ARGS struct file *file, int datasync
#define FSYNC_CALL file, datasync
#else
#define FSYNC_ARGS struct file *file, loff_t start, loff_t end, int datasync
#define FSYNC_CALL file, start, end, datasync
#endif

/*
 * Tile-to-host bits (UART 0 scratchpad).
 */
/*
 * Output write pointer mask.  Note that this is the maximum size; the
 * write pointer may be smaller if requested by the host.
 */
#define CONS_RSHIM_T2H_OUT_WPTR_MASK     0x3FF

/* Tile is done mask. */
#define CONS_RSHIM_T2H_DONE_MASK         0x400

/*
 * Input read pointer mask.  Note that this is the maximum size; the read
 * pointer may be smaller if requested by the host.
 */
#define CONS_RSHIM_T2H_IN_RPTR_MASK      0x1FF800

/* Input read pointer shift. */
#define CONS_RSHIM_T2H_IN_RPTR_SHIFT     11

/* Tile is done mask. */
#define CONS_RSHIM_T2H_DONE_MASK         0x400

/* Number of words to send as sync-data (calculated by packet MTU). */
#define TMFIFO_MAX_SYNC_WORDS            (1536 / 8)

/* Terminal characteristics for newly created consoles. */
#if LINUX_VERSION_CODE < KERNEL_VERSION(2, 6, 20)
static struct termios init_console_termios = {
#else
static struct ktermios init_console_termios = {
#endif
	.c_iflag = INLCR | ICRNL,
	.c_oflag = OPOST | ONLCR,
	.c_cflag = B115200 | HUPCL | CLOCAL | CREAD | CS8,
	.c_lflag = ISIG | ICANON | ECHOE | ECHOK | ECHOCTL | ECHOKE | IEXTEN,
	.c_line = 0,
	.c_cc = INIT_C_CC,
};

/* Completion initialization. */
#if LINUX_VERSION_CODE < KERNEL_VERSION(3, 13, 0)
#define reinit_completion(x) INIT_COMPLETION(*(x))
#endif

static DEFINE_MUTEX(rshim_mutex);

/*
 * Array of all of the rshim devices.  The high bits of our minor number
 * index into this table to find the relevant device.
 */
struct rshim_backend **rshim_devs;

/*
 * Work queue. Right now we have one for the whole driver; we might
 * eventually decide that we need one per device, but we'll see.
 */
struct workqueue_struct *rshim_wq;
EXPORT_SYMBOL(rshim_wq);

/*
 * Array of pointers to kmalloc'ed strings, holding the path name for
 * all of the devices we've seen.  If rshim_devs[i] is non-NULL, then
 * rshim_dev_names[i] is its path name.  If rshim_devs[i] is NULL, then
 * rshim_dev_names[i] is the name that was last used for that device.
 * When we see a new device, we look it up in this table; this allows us to
 * use the same device index we did last time we saw the device.  The
 * strings within the array persist until the driver is unloaded.
 */
char **rshim_dev_names;

/* Name of the sub-device types. */
char *rshim_dev_minor_names[RSH_DEV_TYPES] = {
	[RSH_DEV_TYPE_RSHIM] = "rshim",
	[RSH_DEV_TYPE_BOOT] = "boot",
	[RSH_DEV_TYPE_CONSOLE] = "console",
	[RSH_DEV_TYPE_NET] = "net",
	[RSH_DEV_TYPE_MISC] = "misc",
};

/* dev_t base index. */
static dev_t rshim_dev_base;

/* Class structure for our device class. */
static struct class *rshim_class;

/* Registered services. */
static struct rshim_service *rshim_svc[RSH_SVC_MAX];

/* FIFO reset. */
static void rshim_fifo_reset(struct rshim_backend *bd);

/* Display level of the misc device file. */
static int rshim_misc_level;

/* Global lock / unlock. */

void rshim_lock(void)
{
	mutex_lock(&rshim_mutex);
}
EXPORT_SYMBOL(rshim_lock);

void rshim_unlock(void)
{
	mutex_unlock(&rshim_mutex);
}
EXPORT_SYMBOL(rshim_unlock);

/*
 * Read some bytes from RShim.
 *
 * The provided buffer size should be multiple of 8 bytes. If not, the
 * leftover bytes (which presumably were sent as NUL bytes by the sender)
 * will be discarded.
 */
static ssize_t rshim_read_default(struct rshim_backend *bd, int devtype,
				char *buf, size_t count)
{
	int retval, total = 0, avail = 0;
	u64 word;

	/* Read is only supported for RShim TMFIFO. */
	if (devtype != RSH_DEV_TYPE_NET && devtype != RSH_DEV_TYPE_CONSOLE) {
		ERROR("bad devtype %d", devtype);
		return -EINVAL;
	}
	if (bd->is_boot_open)
		return 0;

	while (total < count) {
		if (avail == 0) {
			retval = bd->read_rshim(bd, RSHIM_CHANNEL,
						RSH_TM_TILE_TO_HOST_STS, &word);
			if (retval < 0)
				break;
			avail = word & RSH_TM_TILE_TO_HOST_STS__COUNT_MASK;
			if (avail == 0)
				break;
		}
		retval = bd->read_rshim(bd, RSHIM_CHANNEL,
					RSH_TM_TILE_TO_HOST_DATA, &word);
		if (retval < 0)
			break;
		/*
		 * Convert it to little endian before sending to RShim. The
		 * other side should decode it as little endian as well which
		 * is usually the default case.
		 */
		word = le64_to_cpu(word);
		if (total + sizeof(word) <= count) {
			*(u64 *)buf = word;
			buf += sizeof(word);
			total += sizeof(word);
		} else {
			/* Copy the rest data which is less than 8 bytes. */
			memcpy(buf, &word, count - total);
			total = count;
			break;
		}
		avail--;
	}

	return total;
}

/*
 * Write some bytes to the RShim backend.
 *
 * If count is not multiple of 8-bytes, the data will be padded to 8-byte
 * aligned which is required by RShim HW.
 */
static ssize_t rshim_write_delayed(struct rshim_backend *bd, int devtype,
				   const char *buf, size_t count)
{
	u64 word;
	char pad_buf[sizeof(u64)] = { 0 };
	int size_addr, size_mask, data_addr, max_size;
	int retval, avail = 0, byte_cnt = 0;
	unsigned long timeout, cur_time;

	switch (devtype) {
	case RSH_DEV_TYPE_NET:
	case RSH_DEV_TYPE_CONSOLE:
		if (bd->is_boot_open)
			return count;
		size_addr = RSH_TM_HOST_TO_TILE_STS;
		size_mask = RSH_TM_HOST_TO_TILE_STS__COUNT_MASK;
		data_addr = RSH_TM_HOST_TO_TILE_DATA;
		retval = bd->read_rshim(bd, RSHIM_CHANNEL,
					RSH_TM_HOST_TO_TILE_CTL, &word);
		if (retval < 0) {
			ERROR("read_rshim error %d", retval);
			return retval;
		}
		max_size = (word >> RSH_TM_HOST_TO_TILE_CTL__MAX_ENTRIES_SHIFT)
			   & RSH_TM_HOST_TO_TILE_CTL__MAX_ENTRIES_RMASK;
		break;

	case RSH_DEV_TYPE_BOOT:
		size_addr = RSH_BOOT_FIFO_COUNT;
		size_mask = RSH_BOOT_FIFO_COUNT__BOOT_FIFO_COUNT_MASK;
		data_addr = RSH_BOOT_FIFO_DATA;
		max_size = RSH_BOOT_FIFO_SIZE;
		break;

	default:
		ERROR("bad devtype %d", devtype);
		return -EINVAL;
	}

	timeout = msecs_to_jiffies(rshim_boot_timeout * 1000);

	while (byte_cnt < count) {
		/* Check the boot cancel condition. */
		if (devtype == RSH_DEV_TYPE_BOOT && !bd->boot_work_buf)
			break;

		/* Add padding if less than 8 bytes left. */
		if (byte_cnt + sizeof(u64) > count) {
			memcpy(pad_buf, buf, count - byte_cnt);
			buf = (const char *)pad_buf;
		}

		cur_time = jiffies + timeout;
		while (avail <= 0) {
			/* Calculate available space in words. */
			retval = bd->read_rshim(bd, RSHIM_CHANNEL, size_addr,
						&word);
			if (retval < 0) {
				ERROR("read_rshim error %d", retval);
				break;
			}
			avail = max_size - (int)(word & size_mask) - 8;
			if (avail > 0)
				break;

			/* Return failure if the peer is not responding. */
			if (time_after(jiffies, cur_time))
				return -ETIMEDOUT;
			mutex_unlock(&bd->mutex);
			msleep_interruptible(1);
			mutex_lock(&bd->mutex);
			if (signal_pending(current))
				return -ERESTARTSYS;
		}

		word = *(u64 *)buf;
		/*
		 * Convert to little endian before sending to RShim. The
		 * receiving side should call le64_to_cpu() to convert
		 * it back.
		 */
		word = cpu_to_le64(word);
		retval = bd->write_rshim(bd, RSHIM_CHANNEL, data_addr, word);
		if (retval < 0) {
			ERROR("write_rshim error %d", retval);
			break;
		}
		buf += sizeof(word);
		byte_cnt += sizeof(word);
		avail--;
	}

	/* Return number shouldn't count the padded bytes. */
	return (byte_cnt > count) ? count : byte_cnt;
}

static ssize_t rshim_write_default(struct rshim_backend *bd, int devtype,
				   const char *buf, size_t count)
{
	int retval;

	switch (devtype) {
	case RSH_DEV_TYPE_NET:
	case RSH_DEV_TYPE_CONSOLE:
		if (bd->is_boot_open)
			return count;

		/* Set the flag so there is only one outstanding request. */
		bd->spin_flags |= RSH_SFLG_WRITING;

		/* Wake up the worker. */
		bd->fifo_work_buf = (char *)buf;
		bd->fifo_work_buf_len = count;
		bd->fifo_work_devtype = devtype;
		wmb();
		bd->has_fifo_work = 1;
		queue_delayed_work(rshim_wq, &bd->work, 0);
		return 0;

	case RSH_DEV_TYPE_BOOT:
		reinit_completion(&bd->boot_write_complete);
		bd->boot_work_buf_len = count;
		bd->boot_work_buf_actual_len = 0;
		wmb();
		bd->boot_work_buf = (char *)buf;
		queue_delayed_work(rshim_wq, &bd->work, 0);

		mutex_unlock(&bd->mutex);
		retval = wait_for_completion_interruptible(
					&bd->boot_write_complete);
		/* Cancel the request if interrupted. */
		if (retval)
			bd->boot_work_buf = NULL;

		mutex_lock(&bd->mutex);
		return bd->boot_work_buf_actual_len;

	default:
		ERROR("bad devtype %d", devtype);
		return -EINVAL;
	}
}

/*
 * Write to the RShim reset control register.
 */
static int rshim_write_reset_control(struct rshim_backend *bd)
{
	int ret;
	u64 word;
	u32 val;
	u8  shift;

	ret = bd->read_rshim(bd, RSHIM_CHANNEL, RSH_RESET_CONTROL, &word);
	if (ret < 0) {
		ERROR("failed to read rshim reset control error %d", ret);
		return ret;
	}

	val = RSH_RESET_CONTROL__RESET_CHIP_VAL_KEY;
	shift = RSH_RESET_CONTROL__RESET_CHIP_SHIFT;
	word &= ~((u64) RSH_RESET_CONTROL__RESET_CHIP_MASK);
	word |= (val << shift);

	/*
	 * The reset of the ARM can be blocked when the DISABLED bit
	 * is set. The big assumption is that the DISABLED bit would
	 * be hold high for a short period and only the platform code
	 * can reset that bit. Thus the ARM reset can be delayed and
	 * in theory this should not impact the behavior of the RShim
	 * driver.
	 */
	ret = bd->write_rshim(bd, RSHIM_CHANNEL, RSH_RESET_CONTROL, word);
	if (ret < 0) {
		ERROR("failed to write rshim reset control error %d", ret);
		return ret;
	}

	return 0;
}

/* Boot file operations routines */

/*
 * Wait for boot to complete, if necessary.  Return 0 if the boot is done
 * and it's safe to continue, an error code if something went wrong.  Note
 * that this routine must be called with the device mutex held.  If it
 * returns successfully, the mutex will still be held (although it may have
 * been dropped and reacquired); if it returns unsuccessfully the mutex
 * will have been dropped.
 */
static int wait_for_boot_done(struct rshim_backend *bd)
{
	int retval;

	if (!bd->has_reprobe || rshim_sw_reset_skip)
		return 0;

	if (!bd->has_rshim || bd->is_booting) {
		while (bd->is_booting) {
			pr_info("boot write, waiting for re-probe\n");
			/* We're booting, and the backend isn't ready yet. */
			mutex_unlock(&bd->mutex);
			/*
			 * FIXME: might we want a timeout here, too?  If
			 * the reprobe takes a very long time, something's
			 * probably wrong.  Maybe a couple of minutes?
			 */
			retval = wait_for_completion_interruptible(
				&bd->booting_complete);
			if (retval)
				return retval;
			mutex_lock(&bd->mutex);
		}
		if (!bd->has_rshim) {
			mutex_unlock(&bd->mutex);
			return -ENODEV;
		}
	}

	return 0;
}

static ssize_t rshim_boot_write(struct file *file, const char *user_buffer,
			      size_t count, loff_t *ppos)
{
	struct rshim_backend *bd = file->private_data;
	int retval = 0, whichbuf = 0, len;
	size_t bytes_written = 0;

	mutex_lock(&bd->mutex);
	if (bd->is_in_boot_write) {
		mutex_unlock(&bd->mutex);
		return -EBUSY;
	}

	retval = wait_for_boot_done(bd);
	if (retval) {
		pr_err("boot_write: wait for boot failed, err %d\n", retval);
		/* wait_for_boot_done already dropped mutex */
		return retval;
	}

	/*
	 * We're going to drop the mutex while we wait for any outstanding
	 * write to complete; this keeps another thread from getting in here
	 * while we do that.
	 */
	bd->is_in_boot_write = 1;

	/* Loop as long as there is 8 bytes (minimum size for rshim write). */
	while (count + bd->boot_rem_cnt >= sizeof(u64)) {
		size_t buf_bytes = min((size_t)BOOT_BUF_SIZE,
				(count + bd->boot_rem_cnt) & (-((size_t)8)));
		char *buf = bd->boot_buf[whichbuf];

		whichbuf ^= 1;

		/* Copy the previous remaining data first. */
		if (bd->boot_rem_cnt)
			memcpy(buf, &bd->boot_rem_data, bd->boot_rem_cnt);

		if (copy_from_user(buf + bd->boot_rem_cnt, user_buffer,
				   buf_bytes - bd->boot_rem_cnt)) {
			retval = -EFAULT;
			pr_err("boot_write: copy from user failed\n");
			break;
		}

		retval = bd->write(bd, RSH_DEV_TYPE_BOOT, buf, buf_bytes);
		if (retval > bd->boot_rem_cnt) {
			len = retval - bd->boot_rem_cnt;
			count -= len;
			user_buffer += len;
			bytes_written += len;
			bd->boot_rem_cnt = 0;
		} else if (retval == 0) {
			/* Wait for some time instead of busy polling. */
			msleep_interruptible(1);
			if (signal_pending(current)) {
				retval = -ERESTARTSYS;
				break;
			}
			continue;
		}
		if (retval != buf_bytes)
			break;
	}

	/* Buffer the remaining data. */
	if (count + bd->boot_rem_cnt < sizeof(bd->boot_rem_data)) {
		if (copy_from_user((u8*)&bd->boot_rem_data + bd->boot_rem_cnt,
				   user_buffer, count))
			return -EFAULT;
		bd->boot_rem_cnt += count;
		bytes_written += count;
	}

	bd->is_in_boot_write = 0;
	mutex_unlock(&bd->mutex);

	return bytes_written ? bytes_written : retval;
}

static int rshim_boot_release(struct inode *inode, struct file *file)
{
	struct rshim_backend *bd = file->private_data;
	struct module *owner;
	int retval;

	/* Restore the boot mode register. */
	retval = bd->write_rshim(bd, RSHIM_CHANNEL,
				 RSH_BOOT_CONTROL,
				 RSH_BOOT_CONTROL__BOOT_MODE_VAL_EMMC);
	if (retval)
		ERROR("couldn't set boot_control, err %d", retval);

	mutex_lock(&bd->mutex);
	/* Flush the leftover data with zeros padded. */
	if (bd->boot_rem_cnt) {
		memset((u8*)&bd->boot_rem_data + bd->boot_rem_cnt, 0,
		       sizeof(u64) - bd->boot_rem_cnt);
		bd->write_rshim(bd, RSHIM_CHANNEL, RSH_BOOT_FIFO_DATA,
				bd->boot_rem_data);
	}
	bd->is_boot_open = 0;
	queue_delayed_work(rshim_wq, &bd->work, HZ);
	mutex_unlock(&bd->mutex);

	rshim_lock();
	owner = RSHIM_READ_ONCE(bd->owner);
	kref_put(&bd->kref, bd->destroy);
	module_put(owner);
	rshim_unlock();

	return 0;
}

static const struct file_operations rshim_boot_fops = {
	.owner = THIS_MODULE,
	.write = rshim_boot_write,
	.release = rshim_boot_release,
};

int rshim_boot_open(struct file *file)
{
	int retval;
	int i;
	struct rshim_backend *bd = file->private_data;
#if RSH_RESET_MUTEX
	unsigned long devs_locked = 0;
#endif

	file->f_op = &rshim_boot_fops;

#if RSH_RESET_MUTEX
	/*
	 * We're going to prevent resets and operations from running in
	 * parallel with other resets.  Our method for this is to grab
	 * every device's mutex before doing the reset, and then holding
	 * onto them until the device we reset is reprobed, or a timeout
	 * expires; the latter is mostly paranoia.  Anyway, in order to
	 * find all of the other devices, we're going to need to walk the
	 * device table, so we need to grab its mutex.  We have to do it
	 * before we get our own device's mutex for lock ordering reasons.
	 */
	rshim_lock();
#endif

	mutex_lock(&bd->mutex);

	if (bd->is_boot_open) {
		INFO("can't boot, boot file already open");
		mutex_unlock(&bd->mutex);
#if RSH_RESET_MUTEX
		rshim_unlock();
#endif
		return -EBUSY;
	}

	if (!bd->has_rshim) {
		mutex_unlock(&bd->mutex);
#if RSH_RESET_MUTEX
		rshim_unlock();
#endif
		return -ENODEV;
	}

	pr_info("begin booting\n");
	reinit_completion(&bd->booting_complete);
	bd->is_booting = 1;
	bd->boot_rem_cnt = 0;

	/*
	 * Before we reset the chip, make sure we don't have any
	 * outstanding writes, and flush the write and read FIFOs. (Note
	 * that we can't have any outstanding reads, since we kill those
	 * upon release of the TM FIFO file.)
	 */
	if (bd->cancel)
		bd->cancel(bd, RSH_DEV_TYPE_NET, true);
	bd->read_buf_bytes = 0;
	bd->read_buf_pkt_rem = 0;
	bd->read_buf_pkt_padding = 0;
	spin_lock_irq(&bd->spinlock);
	/* FIXME: should we be waiting for WRITING to go off, instead? */
	bd->spin_flags &= ~RSH_SFLG_WRITING;
	for (i = 0; i < TMFIFO_MAX_CHAN; i++) {
		read_reset(bd, i);
		write_reset(bd, i);
	}
	spin_unlock_irq(&bd->spinlock);

	/* Set RShim (external) boot mode. */
	retval = bd->write_rshim(bd, RSHIM_CHANNEL, RSH_BOOT_CONTROL,
				 RSH_BOOT_CONTROL__BOOT_MODE_VAL_NONE);
	if (retval) {
		ERROR("boot_open: error %d writing boot control", retval);
		bd->is_booting = 0;
		mutex_unlock(&bd->mutex);
#if RSH_RESET_MUTEX
		rshim_unlock();
#endif
		return retval;
	}

	if (rshim_sw_reset_skip) {
		bd->is_boot_open = 1;
		mutex_unlock(&bd->mutex);
#if RSH_RESET_MUTEX
		rshim_unlock();
#endif
		return 0;
	}

#if RSH_RESET_MUTEX
	/*
	 * Acquire all of the other devices' mutexes, to keep them from
	 * doing anything while we're performing the reset.  Also kill
	 * any outstanding boot urbs; that way we'll restart them, after
	 * the reset is done, and not report errors to the writers.
	 */
	for (i = 0; i < rshim_nr_devs; i++) {
		if (rshim_devs[i] && rshim_devs[i] != bd) {
			mutex_lock(&rshim_devs[i]->mutex);
			devs_locked |= 1UL << i;
			if (rshim_devs[i]->cancel) {
				rshim_devs[i]->cancel(rshim_devs[i],
						    RSH_DEV_TYPE_BOOT, true);
			}
		}
	}
	reinit_completion(&bd->reset_complete);
#endif

	bd->is_boot_open = 1;

	/*
	 * Disable the watchdog. The channel and offset are the same on all
	 * the BlueField SoC so far.
	 */
	bd->write_rshim(bd, RSH_MMIO_ADDRESS_SPACE__CHANNEL_VAL_WDOG1,
			RSH_ARM_WDG_CONTROL_WCS, 0);

	/* SW reset. */
	retval = rshim_write_reset_control(bd);

	/* Reset the TmFifo. */
	rshim_fifo_reset(bd);

	/*
	 * Note that occasionally, we get various errors on writing to
	 * the reset register.  This appears to be caused by the chip
	 * actually resetting before the response goes out, or perhaps by
	 * our noticing the device unplug before we've seen the response.
	 * Either way, the chip _does_ actually reset, so we just ignore
	 * the error.  Should we ever start getting these errors without
	 * the chip being reset, we'll have to figure out how to handle
	 * this more intelligently.  (One potential option is to not reset
	 * directly, but to set up a down counter to do the reset, but that
	 * seems kind of kludgy, especially since Tile software might also
	 * be trying to use the down counter.)
	 */
	if (retval && retval != -EPROTO && retval != -ESHUTDOWN &&
#ifdef RSH_USB_BMC
	    /*
	     * The host driver on the BMC sometimes produces EOVERFLOW on
	     * reset.  It also seems to have seems to have some sort of bug
	     * which makes it return more bytes than we actually wrote!  In
	     * that case we're returning EBADE.
	     */
	    retval != -EOVERFLOW && retval != -EBADE &&
#endif
	    retval != -ETIMEDOUT && retval != -EPIPE) {
		ERROR("boot_open: error %d writing reset control", retval);
		mutex_unlock(&bd->mutex);
#if RSH_RESET_MUTEX
		while (devs_locked) {
			int i = __builtin_ctzl(devs_locked);

			mutex_unlock(&rshim_devs[i]->mutex);
			devs_locked &= ~(1UL << i);
		}
		rshim_unlock();
#endif
		bd->is_boot_open = 0;

		return retval;
	}

	if (retval)
		pr_err("boot_open: got error %d on reset write\n", retval);

	mutex_unlock(&bd->mutex);

#if RSH_RESET_MUTEX
	rshim_unlock();
	/*
	 * We wait for reset_complete (signaled by probe), or for an
	 * interrupt, or a timeout (set to 5s because of no re-probe
	 * in the PCIe case). Note that we dropped dev->mutex above
	 * so that probe can run; the BOOT_OPEN flag should keep our device
	 * from trying to do anything before the device is reprobed.
	 */
	retval = wait_for_completion_interruptible_timeout(&bd->reset_complete,
							   5 * HZ);
	if (retval == 0 && bd->has_reprobe)
		ERROR("timed out waiting for device reprobe after reset");

	while (devs_locked) {
		int i = __builtin_ctz(devs_locked);

		mutex_unlock(&rshim_devs[i]->mutex);
		devs_locked &= ~(1UL << i);
	}
#endif

	return 0;
}

/* FIFO common routines */

/*
 * Signal an error on the FIFO, and wake up anyone who might need to know
 * about it.
 */
static void rshim_fifo_err(struct rshim_backend *bd, int err)
{
	int i;

	bd->tmfifo_error = err;
	wake_up_interruptible_all(&bd->write_completed);
	for (i = 0; i < TMFIFO_MAX_CHAN; i++) {
		wake_up_interruptible_all(&bd->read_fifo[i].operable);
		wake_up_interruptible_all(&bd->write_fifo[i].operable);
	}
}

static int rshim_fifo_tx_avail(struct rshim_backend *bd)
{
	u64 word;
	int ret, max_size, avail;

	/* Get FIFO max size. */
	ret = bd->read_rshim(bd, RSHIM_CHANNEL,
				RSH_TM_HOST_TO_TILE_CTL, &word);
	if (ret < 0) {
		ERROR("read_rshim error %d", ret);
		return ret;
	}
	max_size = (word >> RSH_TM_HOST_TO_TILE_CTL__MAX_ENTRIES_SHIFT)
		   & RSH_TM_HOST_TO_TILE_CTL__MAX_ENTRIES_RMASK;

	/* Calculate available size. */
	ret = bd->read_rshim(bd, RSHIM_CHANNEL, RSH_TM_HOST_TO_TILE_STS, &word);
	if (ret < 0) {
		ERROR("read_rshim error %d", ret);
		return ret;
	}
	avail = max_size - (int)(word & RSH_TM_HOST_TO_TILE_STS__COUNT_MASK)
		- 1;

	return avail;
}

static int rshim_fifo_sync(struct rshim_backend *bd)
{
	int i, avail, ret;
	union rshim_tmfifo_msg_hdr hdr;

	avail = rshim_fifo_tx_avail(bd);
	if (avail < 0)
		return avail;

	hdr.data = 0;
	hdr.type = VIRTIO_ID_NET;

	for (i = 0; i < avail; i++) {
		ret = bd->write_rshim(bd, RSHIM_CHANNEL,
				      RSH_TM_HOST_TO_TILE_DATA, hdr.data);
		if (ret < 0)
			return ret;
	}

	return 0;
}

/* Just adds up all the bytes of the header. */
static u8 rshim_fifo_ctrl_checksum(union rshim_tmfifo_msg_hdr *hdr)
{
	u8 checksum = 0;
	int i;

	for (i = 0; i < sizeof(*hdr); i++)
		checksum += ((u8 *)hdr)[i];

	return checksum;
}

static void rshim_fifo_ctrl_update_checksum(union rshim_tmfifo_msg_hdr *hdr)
{
	u8 checksum;

	hdr->checksum = 0;
	checksum = rshim_fifo_ctrl_checksum(hdr);
	hdr->checksum = ~checksum + 1;
}

static bool rshim_fifo_ctrl_verify_checksum(union rshim_tmfifo_msg_hdr *hdr)
{
	u8 checksum = rshim_fifo_ctrl_checksum(hdr);

	return checksum ? false : true;
}

static void rshim_fifo_ctrl_rx(struct rshim_backend *bd,
			       union rshim_tmfifo_msg_hdr *hdr)
{
	if (!rshim_fifo_ctrl_verify_checksum(hdr))
		return;

	switch (hdr->type) {
	case TMFIFO_MSG_MAC_1:
		memcpy(bd->peer_mac, hdr->mac, 3);
		break;
	case TMFIFO_MSG_MAC_2:
		memcpy(bd->peer_mac + 3, hdr->mac, 3);
		break;
	case TMFIFO_MSG_VLAN_ID:
		bd->vlan[0] = ntohs(hdr->vlan[0]);
		bd->vlan[1] = ntohs(hdr->vlan[1]);
		break;
	case TMFIFO_MSG_PXE_ID:
		bd->pxe_client_id = ntohl(hdr->pxe_id);
		/* Last info to receive, set the flag. */
		bd->peer_ctrl_resp = 1;
		wake_up_interruptible_all(&bd->ctrl_wait);
		break;
	default:
		return;
	}
}

static int rshim_fifo_ctrl_tx(struct rshim_backend *bd)
{
	union rshim_tmfifo_msg_hdr hdr;
	int len = 0;

	if (bd->peer_mac_set) {
		bd->peer_mac_set = 0;
		hdr.data = 0;
		hdr.type = TMFIFO_MSG_MAC_1;
		memcpy(hdr.mac, bd->peer_mac, 3);
		rshim_fifo_ctrl_update_checksum(&hdr);
		memcpy(bd->write_buf, &hdr.data, sizeof(hdr.data));
		hdr.type = TMFIFO_MSG_MAC_2;
		memcpy(hdr.mac, bd->peer_mac + 3, 3);
		rshim_fifo_ctrl_update_checksum(&hdr);
		memcpy(bd->write_buf + sizeof(hdr.data), &hdr.data,
		       sizeof(hdr.data));
		len = sizeof(hdr.data) * 2;
	} else if (bd->peer_pxe_id_set) {
		bd->peer_pxe_id_set = 0;
		hdr.data = 0;
		hdr.type = TMFIFO_MSG_PXE_ID;
		hdr.pxe_id = htonl(bd->pxe_client_id);
		rshim_fifo_ctrl_update_checksum(&hdr);
		memcpy(bd->write_buf, &hdr.data, sizeof(hdr.data));
		len = sizeof(hdr.data);
	} else if (bd->peer_vlan_set) {
		bd->peer_vlan_set = 0;
		hdr.data = 0;
		hdr.type = TMFIFO_MSG_VLAN_ID;
		hdr.vlan[0] = htons(bd->vlan[0]);
		hdr.vlan[1] = htons(bd->vlan[1]);
		rshim_fifo_ctrl_update_checksum(&hdr);
		memcpy(bd->write_buf, &hdr.data, sizeof(hdr.data));
		len = sizeof(hdr.data);
	} else if (bd->peer_ctrl_req) {
		bd->peer_ctrl_req = 0;
		hdr.data = 0;
		hdr.type = TMFIFO_MSG_CTRL_REQ;
		rshim_fifo_ctrl_update_checksum(&hdr);
		memcpy(bd->write_buf, &hdr.data, sizeof(hdr.data));
		len = sizeof(hdr.data);
	}

	return len;
}

/* Drain the read buffer, and start another read/interrupt if needed. */
static void rshim_fifo_input(struct rshim_backend *bd)
{
	union rshim_tmfifo_msg_hdr *hdr;
	bool rx_avail = false;

	if (bd->is_boot_open)
		return;

again:
	while (bd->read_buf_next < bd->read_buf_bytes) {
		int copysize;

		/*
		 * If we're at the start of a packet, then extract the
		 * header, and update our count of bytes remaining in the
		 * packet.
		 */
		if (bd->read_buf_pkt_rem == 0) {
			/* Make sure header is received. */
			if (bd->read_buf_next + sizeof(*hdr) >
				bd->read_buf_bytes)
				break;

			pr_debug("next hdr %d\n", bd->read_buf_next);

			hdr = (union rshim_tmfifo_msg_hdr *)
				&bd->read_buf[bd->read_buf_next];

			bd->read_buf_pkt_rem = ntohs(hdr->len) + sizeof(*hdr);
			bd->read_buf_pkt_padding =
				(8 - (bd->read_buf_pkt_rem & 7)) & 7;
			if (hdr->type == VIRTIO_ID_NET)
				bd->rx_chan = TMFIFO_NET_CHAN;
			else if (hdr->type == VIRTIO_ID_CONSOLE) {
				bd->rx_chan = TMFIFO_CONS_CHAN;
				/* Strip off the message header for console. */
				bd->read_buf_next += sizeof(*hdr);
				bd->read_buf_pkt_rem -= sizeof(*hdr);
				if (bd->read_buf_pkt_rem == 0)
					continue;
			} else {
				bd->read_buf_pkt_rem = 0;
				bd->read_buf_pkt_padding = 0;
				if (hdr->len == 0) {
					bd->read_buf_next += sizeof(*hdr);
					rshim_fifo_ctrl_rx(bd, hdr);
					continue;
				}
				else {
					pr_debug("bad type %d, drop it",
						 hdr->type);
					bd->read_buf_next = bd->read_buf_bytes;
					break;
				}
			}

			pr_debug("drain: hdr, nxt %d rem %d chn %d\n",
			      bd->read_buf_next, bd->read_buf_pkt_rem,
			      bd->rx_chan);
			bd->drop = 0;
		}

		if (bd->rx_chan == TMFIFO_CONS_CHAN &&
		    !(bd->spin_flags & RSH_SFLG_CONS_OPEN)) {
			/*
			 * If data is coming in for a closed console
			 * channel, we want to just throw it away.
			 * Resetting the channel every time through this
			 * loop is a relatively cheap way to do that.  Note
			 * that this works because the read buffer is no
			 * larger than the read FIFO; thus, we know that if
			 * we reset it here, we will always be able to
			 * drain the read buffer of any console data, and
			 * will then launch another read.
			 */
			read_reset(bd, TMFIFO_CONS_CHAN);
			bd->drop = 1;
		} else if (bd->rx_chan == TMFIFO_NET_CHAN && bd->net == NULL) {
			/* Drop if networking is not enabled. */
			read_reset(bd, TMFIFO_NET_CHAN);
			bd->drop = 1;
		}

		copysize = min(bd->read_buf_pkt_rem,
			       bd->read_buf_bytes - bd->read_buf_next);
		copysize = min(copysize,
			       read_space_to_end(bd, bd->rx_chan));

		pr_debug("drain: copysize %d, head %d, tail %d, "
			 "remaining %d\n", copysize,
			 bd->read_fifo[bd->rx_chan].head,
			 bd->read_fifo[bd->rx_chan].tail,
			 bd->read_buf_pkt_rem);

		if (copysize == 0) {
			/*
			 * We have data, but no space to put it in, so
			 * we're done.
			 */
			pr_debug("drain: no more space in channel %d\n",
				 bd->rx_chan);
			break;
		}

		if (!bd->drop) {
			memcpy(read_space_ptr(bd, bd->rx_chan),
			       &bd->read_buf[bd->read_buf_next],
			       copysize);
			read_add_bytes(bd, bd->rx_chan, copysize);
		}

		bd->read_buf_next += copysize;
		bd->read_buf_pkt_rem -= copysize;

		wake_up_interruptible_all(&bd->read_fifo[
				      bd->rx_chan].operable);
		pr_debug("woke up readable chan %d\n", bd->rx_chan);

		if (bd->read_buf_pkt_rem <= 0) {
			bd->read_buf_next = bd->read_buf_next +
				bd->read_buf_pkt_padding;
			rx_avail = true;
		}
	}

	/*
	 * We've processed all of the data we can, so now we decide if we
	 * need to launch another I/O.  If there's still data in the read
	 * buffer, or if we're already reading, don't launch any new
	 * operations.  If an interrupt just completed, and said there was
	 * data, or the last time we did a read we got some data, then do
	 * another read.  Otherwise, do an interrupt.
	 */
	if (bd->read_buf_next < bd->read_buf_bytes ||
	    (bd->spin_flags & RSH_SFLG_READING)) {
		/* We're doing nothing. */
		pr_debug("fifo_input: no new read: %s\n",
			 (bd->read_buf_next < bd->read_buf_bytes) ?
			 "have data" : "already reading");
	} else {
		int len;

		/* Process it if more data is received. */
		len = bd->read(bd, RSH_DEV_TYPE_NET, (char *)bd->read_buf,
			      READ_BUF_SIZE);
		if (len > 0) {
			bd->read_buf_bytes = len;
			bd->read_buf_next = 0;
			goto again;
		}
	}

	if (rx_avail) {
		if (bd->rx_chan == TMFIFO_NET_CHAN) {
			struct rshim_service *svc;

			/*
			 * Protect rshim_svc with RCU lock. See comments in
			 * rshim_register_service() / rshim_register_service()
			 */
			rcu_read_lock();
			svc = rcu_dereference(rshim_svc[RSH_SVC_NET]);
			if (svc != NULL)
				(*svc->rx_notify)(bd);
			rcu_read_unlock();
		}
	}
}

ssize_t rshim_fifo_read(struct rshim_backend *bd, char *buffer,
		      size_t count, int chan, bool nonblock,
		      bool to_user)
{
	size_t rd_cnt = 0;

	mutex_lock(&bd->mutex);

	while (count) {
		size_t readsize;
		int pass1;
		int pass2;

		pr_debug("fifo_read, top of loop, remaining count %zd\n",
			 count);

		/*
		 * We check this each time through the loop since the
		 * device could get disconnected while we're waiting for
		 * more data in the read FIFO.
		 */
		if (!bd->has_tm) {
			mutex_unlock(&bd->mutex);
			pr_debug("fifo_read: returning %zd/ENODEV\n", rd_cnt);
			return rd_cnt ? rd_cnt : -ENODEV;
		}

		if (bd->tmfifo_error) {
			mutex_unlock(&bd->mutex);
			pr_debug("fifo_read: returning %zd/%d\n", rd_cnt,
			      bd->tmfifo_error);
			return rd_cnt ? rd_cnt : bd->tmfifo_error;
		}

		if (read_empty(bd, chan)) {
			pr_debug("fifo_read: fifo empty\n");
			if (rd_cnt || nonblock) {
				if (rd_cnt == 0) {
					spin_lock_irq(&bd->spinlock);
					rshim_fifo_input(bd);
					spin_unlock_irq(&bd->spinlock);
				}
				mutex_unlock(&bd->mutex);
				pr_debug("fifo_read: returning %zd/EAGAIN\n",
				      rd_cnt);
				return rd_cnt ? rd_cnt : -EAGAIN;
			}

			mutex_unlock(&bd->mutex);

			pr_debug("fifo_read: waiting for readable chan %d\n",
				 chan);
			if (wait_event_interruptible(
					bd->read_fifo[chan].operable,
					    !read_empty(bd, chan))) {
				pr_debug("fifo_read: returning ERESTARTSYS\n");
				return to_user ? -EINTR : -ERESTARTSYS;
			}

			mutex_lock(&bd->mutex);

			/*
			 * Since we dropped the mutex, we must make
			 * sure our interface is still there before
			 * we do anything else.
			 */
			continue;
		}

		/*
		 * Figure out how many bytes we will transfer on this pass.
		 */
		spin_lock_irq(&bd->spinlock);

		readsize = min(count, (size_t)read_cnt(bd, chan));

		pass1 = min(readsize, (size_t)read_cnt_to_end(bd, chan));
		pass2 = readsize - pass1;

		spin_unlock_irq(&bd->spinlock);

		pr_debug("fifo_read: readsize %zd, head %d, tail %d\n",
			 readsize, bd->read_fifo[chan].head,
			 bd->read_fifo[chan].tail);

		if (!to_user) {
			memcpy(buffer, read_data_ptr(bd, chan), pass1);
			if (pass2) {
				memcpy(buffer + pass1,
				       bd->read_fifo[chan].data, pass2);
			}
		} else {
			if (copy_to_user(buffer, read_data_ptr(bd, chan),
				pass1) || (pass2 && copy_to_user(buffer + pass1,
				bd->read_fifo[chan].data, pass2))) {
				mutex_unlock(&bd->mutex);
				pr_debug("fifo_read: returns %zd/EFAULT\n",
					 rd_cnt);
				return rd_cnt ? rd_cnt : -EFAULT;
			}
		}

		spin_lock_irq(&bd->spinlock);

		read_consume_bytes(bd, chan, readsize);

		/*
		 * We consumed some bytes, so let's see if we can process
		 * any more incoming data.
		 */
		rshim_fifo_input(bd);

		spin_unlock_irq(&bd->spinlock);

		count -= readsize;
		buffer += readsize;
		rd_cnt += readsize;
		pr_debug("fifo_read: transferred %zd bytes\n", readsize);
	}

	mutex_unlock(&bd->mutex);

	pr_debug("fifo_read: returning %zd\n", rd_cnt);
	return rd_cnt;
}
EXPORT_SYMBOL(rshim_fifo_read);

static void rshim_fifo_output(struct rshim_backend *bd)
{
	int writesize, write_buf_next = 0;
	int write_avail = WRITE_BUF_SIZE - write_buf_next;
	int numchan = TMFIFO_MAX_CHAN;
	int chan, chan_offset;

	/* If we're already writing, we have nowhere to put data. */
	if (bd->spin_flags & RSH_SFLG_WRITING)
		return;

	if (!bd->write_buf_pkt_rem) {
		/* Send control messages. */
		writesize = rshim_fifo_ctrl_tx(bd);
		if (writesize > 0) {
			write_avail -= writesize;
			write_buf_next += writesize;
		}
	}

	/* Walk through all the channels, sending as much data as possible. */
	for (chan_offset = 0; chan_offset < numchan; chan_offset++) {
		/*
		 * Pick the current channel if not done, otherwise round-robin
		 * to the next channel.
		 */
		if (bd->write_buf_pkt_rem > 0)
			chan = bd->tx_chan;
		else {
			u16 cur_len;
			union rshim_tmfifo_msg_hdr *hdr = &bd->msg_hdr;

			chan = bd->tx_chan = (bd->tx_chan + 1) % numchan;
			cur_len = write_cnt(bd, chan);

			/*
			 * Set up message header for console data which is byte
			 * stream. Network packets already have the message
			 * header included.
			 */
			if (chan == TMFIFO_CONS_CHAN) {
				if (cur_len == 0)
					continue;
				hdr->data = 0;
				hdr->type = VIRTIO_ID_CONSOLE;
				hdr->len = htons(cur_len);
			} else {
				int pass1;

				if (cur_len <
					sizeof(union rshim_tmfifo_msg_hdr))
					continue;

				pass1 = write_cnt_to_end(bd, chan);
				if (pass1 >= sizeof(*hdr)) {
					hdr = (union rshim_tmfifo_msg_hdr *)
						write_data_ptr(bd, chan);
				} else {
					memcpy(hdr, write_data_ptr(bd, chan),
					       pass1);
					memcpy((u8 *)hdr + pass1,
					       bd->write_fifo[chan].data,
					       sizeof(*hdr) - pass1);
				}
			}

			bd->write_buf_pkt_rem = ntohs(hdr->len) + sizeof(*hdr);
		}

		/* Send out the packet header for the console data. */
		if (chan == TMFIFO_CONS_CHAN &&
		    bd->write_buf_pkt_rem > ntohs(bd->msg_hdr.len)) {
			union rshim_tmfifo_msg_hdr *hdr = &bd->msg_hdr;
			int left = bd->write_buf_pkt_rem - ntohs(hdr->len);
			u8 *pos = (u8 *)hdr + sizeof(*hdr) - left;

			writesize = min(write_avail, left);
			memcpy(&bd->write_buf[write_buf_next], pos, writesize);
			write_buf_next += writesize;
			bd->write_buf_pkt_rem -= writesize;
			write_avail -= writesize;

			/*
			 * Don't continue if no more space for the header.
			 * It'll be picked up next time.
			 */
			if (left != writesize)
				break;
		}

		writesize = min(write_avail, (int)write_cnt(bd, chan));
		writesize = min(writesize, bd->write_buf_pkt_rem);

		/*
		 * The write size should be aligned to 8 bytes unless for the
		 * last block, which will be padded at the end.
		 */
		if (bd->write_buf_pkt_rem != writesize)
			writesize &= -8;

		if (writesize > 0) {
			int pass1;
			int pass2;

			pass1 = min(writesize,
				    (int)write_cnt_to_end(bd, chan));
			pass2 = writesize - pass1;

			pr_debug("fifo_outproc: chan %d, writesize %d, next %d,"
				 " head %d, tail %d\n",
				 chan, writesize, write_buf_next,
				 bd->write_fifo[chan].head,
				 bd->write_fifo[chan].tail);

			memcpy(&bd->write_buf[write_buf_next],
			       write_data_ptr(bd, chan), pass1);
			memcpy(&bd->write_buf[write_buf_next + pass1],
			       bd->write_fifo[chan].data, pass2);

			write_consume_bytes(bd, chan, writesize);
			write_buf_next += writesize;
			bd->write_buf_pkt_rem -= writesize;
			/* Add padding at the end. */
			if (bd->write_buf_pkt_rem == 0)
				write_buf_next = (write_buf_next + 7) & -8;
			write_avail = WRITE_BUF_SIZE - write_buf_next;

			wake_up_interruptible_all(
				&bd->write_fifo[chan].operable);
			pr_debug("woke up writable chan %d\n", chan);
		}
	}

	/* Drop the data if it is still booting. */
	if (bd->is_boot_open)
		return;

	/* If we actually put anything in the buffer, send it. */
	if (write_buf_next) {
		bd->write(bd, RSH_DEV_TYPE_NET, (char *)bd->write_buf,
			  write_buf_next);
	}
}

int rshim_fifo_alloc(struct rshim_backend *bd)
{
	int i, allocfail = 0;

	for (i = 0; i < TMFIFO_MAX_CHAN; i++) {
		if (!bd->read_fifo[i].data)
			bd->read_fifo[i].data =
				kmalloc(READ_FIFO_SIZE, GFP_KERNEL);
		allocfail |= bd->read_fifo[i].data == 0;

		if (!bd->write_fifo[i].data)
			bd->write_fifo[i].data =
				kmalloc(WRITE_FIFO_SIZE, GFP_KERNEL);
		allocfail |= bd->write_fifo[i].data == 0;
	}

	return allocfail;
}
EXPORT_SYMBOL(rshim_fifo_alloc);

static void rshim_fifo_reset(struct rshim_backend *bd)
{
	int i;

	bd->read_buf_bytes = 0;
	bd->read_buf_pkt_rem = 0;
	bd->read_buf_next = 0;
	bd->read_buf_pkt_padding = 0;
	bd->write_buf_pkt_rem = 0;
	bd->rx_chan = bd->tx_chan = 0;

	spin_lock_irq(&bd->spinlock);
	bd->spin_flags &= ~(RSH_SFLG_WRITING |
			    RSH_SFLG_READING);
	for (i = 0; i < TMFIFO_MAX_CHAN; i++) {
		read_reset(bd, i);
		write_reset(bd, i);
	}
	spin_unlock_irq(&bd->spinlock);
}

void rshim_fifo_free(struct rshim_backend *bd)
{
	int i;

	for (i = 0; i < TMFIFO_MAX_CHAN; i++) {
		kfree(bd->read_fifo[i].data);
		bd->read_fifo[i].data = NULL;
		kfree(bd->write_fifo[i].data);
		bd->write_fifo[i].data = NULL;
	}

	rshim_fifo_reset(bd);

	bd->has_tm = 0;
}
EXPORT_SYMBOL(rshim_fifo_free);

ssize_t rshim_fifo_write(struct rshim_backend *bd, const char *buffer,
		       size_t count, int chan, bool nonblock,
		       bool from_user)
{
	size_t wr_cnt = 0;

	mutex_lock(&bd->mutex);

	while (count) {
		size_t writesize;
		int pass1;
		int pass2;

		pr_debug("fifo_write, top of loop, remaining count %zd\n",
			 count);

		/*
		 * We check this each time through the loop since the
		 * device could get disconnected while we're waiting for
		 * more space in the write buffer.
		 */
		if (!bd->has_tm) {
			mutex_unlock(&bd->mutex);
			pr_debug("fifo_write: returning %zd/ENODEV\n", wr_cnt);
			return wr_cnt ? wr_cnt : -ENODEV;
		}

		if (bd->tmfifo_error) {
			mutex_unlock(&bd->mutex);
			pr_debug("fifo_write: returning %zd/%d\n", wr_cnt,
				 bd->tmfifo_error);
			return wr_cnt ? wr_cnt : bd->tmfifo_error;
		}

		if (write_full(bd, chan)) {
			pr_debug("fifo_write: fifo full\n");
			if (nonblock) {
				mutex_unlock(&bd->mutex);
				pr_debug("fifo_write: returning %zd/EAGAIN\n",
					 wr_cnt);
				return wr_cnt ? wr_cnt : -EAGAIN;
			}

			mutex_unlock(&bd->mutex);
			pr_debug("fifo_write: waiting for writable chan %d\n",
				 chan);
			if (wait_event_interruptible(
				     bd->write_fifo[chan].operable,
					     !write_full(bd, chan))) {
				pr_debug("fifo_write: returning "
					 "%zd/ERESTARTSYS\n", wr_cnt);
				return wr_cnt ? wr_cnt : -ERESTARTSYS;
			}
			mutex_lock(&bd->mutex);
			/*
			 * Since we dropped the mutex, we must make
			 * sure our interface is still there before
			 * we do anything else.
			 */
			continue;
		}

		spin_lock_irq(&bd->spinlock);

		writesize = min(count, (size_t)write_space(bd, chan));
		pass1 = min(writesize, (size_t)write_space_to_end(bd, chan));
		pass2 = writesize - pass1;

		spin_unlock_irq(&bd->spinlock);

		pr_debug("fifo_write: writesize %zd, head %d, tail %d\n",
			 writesize, bd->write_fifo[chan].head,
			 bd->write_fifo[chan].tail);

		if (!from_user) {
			memcpy(write_space_ptr(bd, chan), buffer, pass1);
			if (pass2) {
				memcpy(bd->write_fifo[chan].data,
				       buffer + pass1, pass2);
			}
		} else {
			if (copy_from_user(write_space_ptr(bd, chan), buffer,
				pass1) || (pass2 &&
				copy_from_user(bd->write_fifo[chan].data,
						buffer + pass1, pass2))) {
				mutex_unlock(&bd->mutex);
				pr_debug("fifo_write: returns %zd/EFAULT\n",
					 wr_cnt);
				return wr_cnt ? wr_cnt : -EFAULT;
			}
		}

		spin_lock_irq(&bd->spinlock);

		write_add_bytes(bd, chan, writesize);

		/* We have some new bytes, let's see if we can write any. */
		rshim_fifo_output(bd);

		spin_unlock_irq(&bd->spinlock);

		count -= writesize;
		buffer += writesize;
		wr_cnt += writesize;
		pr_debug("fifo_write: transferred %zd bytes this pass\n",
			 writesize);
	}

	mutex_unlock(&bd->mutex);

	pr_debug("fifo_write: returning %zd\n", wr_cnt);
	return wr_cnt;
}
EXPORT_SYMBOL(rshim_fifo_write);

static int rshim_fifo_fsync(FSYNC_ARGS, int chan)
{
	struct rshim_backend *bd = file->private_data;

	mutex_lock(&bd->mutex);

	/*
	 * To ensure that all of our data has actually made it to the
	 * device, we first wait until the channel is empty, then we wait
	 * until there is no outstanding write urb.
	 */
	while (!write_empty(bd, chan))
		if (wait_event_interruptible(bd->write_fifo[chan].operable,
					     write_empty(bd, chan))) {
			mutex_unlock(&bd->mutex);
			return -ERESTARTSYS;
		}

	while (bd->spin_flags & RSH_SFLG_WRITING)
		if (wait_event_interruptible(bd->write_completed,
					     !(bd->spin_flags &
					       RSH_SFLG_WRITING))) {
			mutex_unlock(&bd->mutex);
			return -ERESTARTSYS;
		}

	mutex_unlock(&bd->mutex);

	return 0;
}

static unsigned int rshim_fifo_poll(struct file *file, poll_table *wait,
				  int chan)
{
	struct rshim_backend *bd = file->private_data;
	unsigned int retval = 0;

	mutex_lock(&bd->mutex);

	poll_wait(file, &bd->read_fifo[chan].operable, wait);
	poll_wait(file, &bd->write_fifo[chan].operable, wait);

	spin_lock_irq(&bd->spinlock);

	if (!read_empty(bd, chan))
		retval |= POLLIN | POLLRDNORM;
	if (!write_full(bd, chan))
		retval |= POLLOUT | POLLWRNORM;
	/*
	 * We don't report POLLERR on the console so that it doesn't get
	 * automatically disconnected when it fails, and so that you can
	 * connect to it in the error state before rebooting the target.
	 * This is inconsistent, but being consistent turns out to be very
	 * annoying.  If someone tries to actually type on it, they'll
	 * get an error.
	 */
	if (bd->tmfifo_error && chan != TMFIFO_CONS_CHAN)
		retval |= POLLERR;
	spin_unlock_irq(&bd->spinlock);

	mutex_unlock(&bd->mutex);

	pr_debug("poll chan %d file %p returns 0x%x\n", chan, file, retval);

	return retval;
}


static int rshim_fifo_release(struct inode *inode, struct file *file,
			      int chan)
{
	struct rshim_backend *bd = file->private_data;
	struct module *owner;

	mutex_lock(&bd->mutex);

	if (chan == TMFIFO_CONS_CHAN) {
		/*
		 * If we aren't the last console file, nothing to do but
		 * fix the reference count.
		 */
		bd->console_opens--;
		if (bd->console_opens) {
			mutex_unlock(&bd->mutex);
			return 0;
		}

		/*
		 * We've told the host to stop using the TM FIFO console,
		 * but there may be a lag before it does.  Unless we
		 * continue to read data from the console stream, the host
		 * may spin forever waiting for the console to be drained
		 * and not realize that it's time to stop using it.
		 * Clearing the CONS_OPEN spin flag will discard any future
		 * incoming console data, but if our input buffers are full
		 * now, we might not be even reading from the hardware
		 * FIFO.  To avoid problems, clear the buffers and call the
		 * drainer so that it knows there's space.
		 */
		spin_lock_irq(&bd->spinlock);

		bd->spin_flags &= ~RSH_SFLG_CONS_OPEN;

		read_reset(bd, TMFIFO_CONS_CHAN);
		write_reset(bd, TMFIFO_CONS_CHAN);

		if (bd->has_tm)
			rshim_fifo_input(bd);

		spin_unlock_irq(&bd->spinlock);
	}

	if (chan == TMFIFO_CONS_CHAN)
		bd->is_cons_open = 0;
	else
		bd->is_tm_open = 0;

	if (!bd->is_tm_open && !bd->is_cons_open) {
		if (bd->cancel)
			bd->cancel(bd, RSH_DEV_TYPE_NET, false);

		spin_lock_irq(&bd->spinlock);
		bd->spin_flags &= ~RSH_SFLG_READING;
		spin_unlock_irq(&bd->spinlock);
	}

	mutex_unlock(&bd->mutex);

	rshim_lock();
	owner = RSHIM_READ_ONCE(bd->owner);
	kref_put(&bd->kref, bd->destroy);
	module_put(owner);
	rshim_unlock();

	return 0;
}

/* TMFIFO file operations routines */

static ssize_t rshim_tmfifo_read(struct file *file, char *user_buffer,
				   size_t count, loff_t *ppos)
{
	struct rshim_backend *bd = file->private_data;

	return rshim_fifo_read(bd, user_buffer, count, TMFIFO_NET_CHAN,
			     file->f_flags & O_NONBLOCK, true);
}

static ssize_t rshim_tmfifo_write(struct file *file, const char *user_buffer,
				size_t count, loff_t *ppos)
{
	struct rshim_backend *bd = file->private_data;

	return rshim_fifo_write(bd, user_buffer, count, TMFIFO_NET_CHAN,
			      file->f_flags & O_NONBLOCK, true);
}

static int rshim_tmfifo_fsync(FSYNC_ARGS)
{
	return rshim_fifo_fsync(FSYNC_CALL, TMFIFO_NET_CHAN);
}

static unsigned int rshim_tmfifo_poll(struct file *file, poll_table *wait)
{
	return rshim_fifo_poll(file, wait, TMFIFO_NET_CHAN);
}

static int rshim_tmfifo_release(struct inode *inode, struct file *file)
{
	return rshim_fifo_release(inode, file, TMFIFO_NET_CHAN);
}

static const struct file_operations rshim_tmfifo_fops = {
	.owner = THIS_MODULE,
	.read = rshim_tmfifo_read,
	.write = rshim_tmfifo_write,
	.fsync = rshim_tmfifo_fsync,
	.poll = rshim_tmfifo_poll,
	.release = rshim_tmfifo_release,
};

static int rshim_tmfifo_open(struct file *file)
{
	struct rshim_backend *bd = file->private_data;

	file->f_op = &rshim_tmfifo_fops;

	mutex_lock(&bd->mutex);

	if (bd->is_tm_open) {
		pr_debug("tmfifo_open: file already open\n");
		mutex_unlock(&bd->mutex);
		return -EBUSY;
	}

	bd->is_tm_open = 1;

	spin_lock_irq(&bd->spinlock);

	/* Call the drainer to do an initial read, if needed. */
	rshim_fifo_input(bd);

	spin_unlock_irq(&bd->spinlock);

	mutex_unlock(&bd->mutex);

	return 0;
}

/* Console file operations routines */

#if LINUX_VERSION_CODE < KERNEL_VERSION(2, 6, 20)
static void rshim_work_handler(void *arg)
{
	struct rshim_backend *bd = arg;
#else
static void rshim_work_handler(struct work_struct *work)
{
	struct rshim_backend *bd = container_of((struct delayed_work *) work,
					      struct rshim_backend, work);
#endif
	mutex_lock(&bd->mutex);

	if (bd->keepalive && bd->has_rshim) {
		bd->write_rshim(bd, RSHIM_CHANNEL, RSH_SCRATCHPAD1,
				RSH_KEEPALIVE_MAGIC_NUM);
		bd->keepalive = 0;
	}

	if (bd->boot_work_buf != NULL) {
		bd->boot_work_buf_actual_len = rshim_write_delayed(bd,
							RSH_DEV_TYPE_BOOT,
							bd->boot_work_buf,
							bd->boot_work_buf_len);
		bd->boot_work_buf = NULL;
		complete_all(&bd->boot_write_complete);
	}

	if (bd->is_boot_open) {
		mutex_unlock(&bd->mutex);
		return;
	}

	if (bd->has_fifo_work) {
		int len;

		len = rshim_write_delayed(bd, bd->fifo_work_devtype,
					  bd->fifo_work_buf,
					  bd->fifo_work_buf_len);
		bd->has_fifo_work = 0;

		spin_lock(&bd->spinlock);
		bd->spin_flags &= ~RSH_SFLG_WRITING;
		if (len == bd->fifo_work_buf_len) {
			wake_up_interruptible_all(&bd->write_completed);
			rshim_notify(bd, RSH_EVENT_FIFO_OUTPUT, 0);
		} else {
			ERROR("fifo_write: completed abnormally (%d).", len);
		}
		spin_unlock(&bd->spinlock);
	}

	if (bd->has_cons_work) {
		spin_lock_irq(&bd->spinlock);

		/* FIFO output. */
		rshim_fifo_output(bd);

		/* FIFO input. */
		rshim_fifo_input(bd);

		spin_unlock_irq(&bd->spinlock);

		bd->has_cons_work = 0;
	}

	if (!bd->has_reprobe && bd->is_cons_open) {
		bd->has_cons_work = 1;
		mod_timer(&bd->timer, jiffies + HZ / 10);
	}

	mutex_unlock(&bd->mutex);
}

static ssize_t rshim_console_read(struct file *file, char *user_buffer,
				    size_t count, loff_t *ppos)
{
	struct rshim_backend *bd = file->private_data;

	return rshim_fifo_read(bd, user_buffer, count, TMFIFO_CONS_CHAN,
			     file->f_flags & O_NONBLOCK, true);
}

static ssize_t rshim_console_write(struct file *file, const char *user_buffer,
				 size_t count, loff_t *ppos)
{
	struct rshim_backend *bd = file->private_data;

	return rshim_fifo_write(bd, user_buffer, count, TMFIFO_CONS_CHAN,
			      file->f_flags & O_NONBLOCK, true);
}

static int rshim_console_fsync(FSYNC_ARGS)
{
	return rshim_fifo_fsync(FSYNC_CALL, TMFIFO_CONS_CHAN);
}

#if LINUX_VERSION_CODE < KERNEL_VERSION(2, 6, 19)
static int rshim_console_ioctl(struct inode *inode, struct file *file,
				 unsigned int cmd, unsigned long arg)
#else
static long rshim_console_unlocked_ioctl(struct file *file, unsigned int
				       cmd, unsigned long arg)
#endif
{
	struct rshim_backend *bd = file->private_data;
	int retval = 0;

	mutex_lock(&bd->mutex);

	switch (cmd) {
	case TCGETS: {
#ifdef TCGETS2
		if (kernel_termios_to_user_termios_1(
			(struct termios __user *)arg, &bd->cons_termios))
#else
		if (kernel_termios_to_user_termios(
			(struct termios __user *)arg, &bd->cons_termios))
#endif
			retval = -EFAULT;
		break;
	}

	case TCSETS:
	case TCSETSW:
	case TCSETSF: {
#ifdef TCGETS2
		if (user_termios_to_kernel_termios_1(
			&bd->cons_termios, (struct termios __user *)arg))
#else
		if (user_termios_to_kernel_termios(
			&bd->cons_termios, (struct termios __user *)arg))
#endif
			retval = -EFAULT;
		break;
	}

	default:
		retval = -EINVAL;
		break;
	}

	mutex_unlock(&bd->mutex);

	return retval;
}

static unsigned int rshim_console_poll(struct file *file, poll_table *wait)
{
	return rshim_fifo_poll(file, wait, TMFIFO_CONS_CHAN);
}

static int rshim_console_release(struct inode *inode, struct file *file)
{
	return rshim_fifo_release(inode, file, TMFIFO_CONS_CHAN);
}

static const struct file_operations rshim_console_fops = {
	.owner = THIS_MODULE,
	.read = rshim_console_read,
	.write = rshim_console_write,
	.fsync = rshim_console_fsync,
#if LINUX_VERSION_CODE < KERNEL_VERSION(2, 6, 19)
	.ioctl = rshim_console_ioctl,
#else
	.unlocked_ioctl = rshim_console_unlocked_ioctl,
#endif
	.poll = rshim_console_poll,
	.release = rshim_console_release,
};

static int rshim_console_open(struct file *file)
{
	struct rshim_backend *bd = file->private_data;

	file->f_op = &rshim_console_fops;

	mutex_lock(&bd->mutex);

	if (bd->is_cons_open) {
		mutex_unlock(&bd->mutex);
		return -EBUSY;
	}

	bd->is_cons_open = 1;

	spin_lock_irq(&bd->spinlock);

	bd->spin_flags |= RSH_SFLG_CONS_OPEN;

	spin_unlock_irq(&bd->spinlock);

	if (!bd->has_cons_work) {
		bd->has_cons_work = 1;
		queue_delayed_work(rshim_wq, &bd->work, HZ / 10);
	}

	bd->console_opens++;
	mutex_unlock(&bd->mutex);

	return 0;
}

static int rshim_boot_done(struct rshim_backend *bd)
{
	if (bd->has_rshim && bd->has_tm) {
		/* Clear any previous errors. */
		bd->tmfifo_error = 0;

		/*
		 * If someone might be waiting for the device to come up,
		 * tell them it's ready.
		 */
		if (bd->is_booting) {
			bd->is_booting = 0;

			pr_debug("signaling booting complete\n");
			complete_all(&bd->booting_complete);
#if RSH_RESET_MUTEX
			complete_all(&bd->reset_complete);
#endif
		};

		/* If the console device is open, start the worker. */
		if (bd->is_cons_open && !bd->has_cons_work) {
			bd->has_cons_work = 1;
			pr_debug("probe: console_work submitted\n");
			queue_delayed_work(rshim_wq, &bd->work, 0);
		}

		/* Tell the user this device is now attached. */
		INFO("%s now attached", rshim_dev_names[bd->dev_index]);
	}

	return 0;
}

/* Rshim file operations routines */

static ssize_t rshim_rshim_read(struct file *file, char *user_buffer,
			      size_t count, loff_t *ppos)
{
	struct rshim_backend *bd;
	int retval = 0;
	u64 buf;

	/* rshim registers are all 8-byte aligned. */
	if (count != 8 || (*ppos & 7) != 0)
		return -EINVAL;

	bd = file->private_data;

	mutex_lock(&bd->mutex);
	retval = bd->read_rshim(bd,
				(*ppos >> 16) & 0xF, /* channel # */
				*ppos & 0xFFFF,	 /* addr */
				&buf);
	mutex_unlock(&bd->mutex);

	/* If the read was successful, copy the data to userspace */
	if (!retval && copy_to_user(user_buffer, &buf, count))
		return -EFAULT;

	return retval ? retval : count;
}

static ssize_t rshim_rshim_write(struct file *file, const char *user_buffer,
			       size_t count, loff_t *ppos)
{
	struct rshim_backend *bd;
	int retval = 0;
	u64 buf;

	/* rshim registers are all 8-byte aligned. */
	if (count != 8 || (*ppos & 7) != 0)
		return -EINVAL;

	/* Copy the data from userspace */
	if (copy_from_user(&buf, user_buffer, count))
		return -EFAULT;

	bd = file->private_data;

	mutex_lock(&bd->mutex);
	retval = bd->write_rshim(bd,
				 (*ppos >> 16) & 0xF, /* channel # */
				 *ppos & 0xFFFF, /* addr */
				 buf);
	mutex_unlock(&bd->mutex);

	return retval ? retval : count;
}

static int rshim_rshim_release(struct inode *inode, struct file *file)
{
	struct rshim_backend *bd = file->private_data;
	struct module *owner;

	rshim_lock();
	owner = RSHIM_READ_ONCE(bd->owner);
	kref_put(&bd->kref, bd->destroy);
	module_put(owner);
	rshim_unlock();

	return 0;
}

static const struct file_operations rshim_rshim_fops = {
	.owner = THIS_MODULE,
	.read = rshim_rshim_read,
	.write = rshim_rshim_write,
	.release = rshim_rshim_release,
	.llseek = default_llseek,
};

static int rshim_rshim_open(struct file *file)
{
	file->f_op = &rshim_rshim_fops;

	return 0;
}

/* Misc file operations routines */

/*
 * Logging over rshim misc file.
 */
/* Log module */
const char * const rshim_log_mod[] = {
	"others", "BL1", "BL2", "BL2R", "BL31", "UEFI"
};

/* Log level */
const char * const rshim_log_level[] = { "INFO", "WARN", "ERR", "ASSERT" };

/* Log type. */
#define BF_RSH_LOG_TYPE_UNKNOWN         0x00ULL
#define BF_RSH_LOG_TYPE_PANIC           0x01ULL
#define BF_RSH_LOG_TYPE_EXCEPTION       0x02ULL
#define BF_RSH_LOG_TYPE_UNUSED          0x03ULL
#define BF_RSH_LOG_TYPE_MSG             0x04ULL

/* Utility macro. */
#define BF_RSH_LOG_MOD_MASK             0x0FULL
#define BF_RSH_LOG_MOD_SHIFT            60
#define BF_RSH_LOG_TYPE_MASK            0x0FULL
#define BF_RSH_LOG_TYPE_SHIFT           56
#define BF_RSH_LOG_LEN_MASK             0x7FULL
#define BF_RSH_LOG_LEN_SHIFT            48
#define BF_RSH_LOG_ARG_MASK             0xFFFFFFFFULL
#define BF_RSH_LOG_ARG_SHIFT            16
#define BF_RSH_LOG_HAS_ARG_MASK         0xFFULL
#define BF_RSH_LOG_HAS_ARG_SHIFT        8
#define BF_RSH_LOG_LEVEL_MASK           0xFFULL
#define BF_RSH_LOG_LEVEL_SHIFT          0
#define BF_RSH_LOG_PC_MASK              0xFFFFFFFFULL
#define BF_RSH_LOG_PC_SHIFT             0
#define BF_RSH_LOG_SYNDROME_MASK        0xFFFFFFFFULL
#define BF_RSH_LOG_SYNDROME_SHIFT       0

#define BF_RSH_LOG_HEADER_GET(f, h) \
	(((h) >> BF_RSH_LOG_##f##_SHIFT) & BF_RSH_LOG_##f##_MASK)

#define AARCH64_MRS_REG_SHIFT	5
#define AARCH64_MRS_REG_MASK	0xffff

struct rshim_log_reg {
	char *name;
	u32 opcode;
};

static struct rshim_log_reg rshim_log_regs[] = {
	{"actlr_el1",		0b1100000010000001},
	{"actlr_el2",		0b1110000010000001},
	{"actlr_el3",		0b1111000010000001},
	{"afsr0_el1",		0b1100001010001000},
	{"afsr0_el2",		0b1110001010001000},
	{"afsr0_el3",		0b1111001010001000},
	{"afsr1_el1",		0b1100001010001001},
	{"afsr1_el2",		0b1110001010001001},
	{"afsr1_el3",		0b1111001010001001},
	{"amair_el1",		0b1100010100011000},
	{"amair_el2",		0b1110010100011000},
	{"amair_el3",		0b1111010100011000},
	{"ccsidr_el1",		0b1100100000000000},
	{"clidr_el1",		0b1100100000000001},
	{"cntkctl_el1",		0b1100011100001000},
	{"cntp_ctl_el0",	0b1101111100010001},
	{"cntp_cval_el0",	0b1101111100010010},
	{"cntv_ctl_el0",	0b1101111100011001},
	{"cntv_cval_el0",	0b1101111100011010},
	{"contextidr_el1",	0b1100011010000001},
	{"cpacr_el1",		0b1100000010000010},
	{"cptr_el2",		0b1110000010001010},
	{"cptr_el3",		0b1111000010001010},
	{"vtcr_el2",		0b1110000100001010},
	{"ctr_el0",		0b1101100000000001},
	{"currentel",		0b1100001000010010},
	{"dacr32_el2",		0b1110000110000000},
	{"daif",		0b1101101000010001},
	{"dczid_el0",		0b1101100000000111},
	{"dlr_el0",		0b1101101000101001},
	{"dspsr_el0",		0b1101101000101000},
	{"elr_el1",		0b1100001000000001},
	{"elr_el2",		0b1110001000000001},
	{"elr_el3",		0b1111001000000001},
	{"esr_el1",		0b1100001010010000},
	{"esr_el2",		0b1110001010010000},
	{"esr_el3",		0b1111001010010000},
	{"esselr_el1",		0b1101000000000000},
	{"far_el1",		0b1100001100000000},
	{"far_el2",		0b1110001100000000},
	{"far_el3",		0b1111001100000000},
	{"fpcr",		0b1101101000100000},
	{"fpexc32_el2",		0b1110001010011000},
	{"fpsr",		0b1101101000100001},
	{"hacr_el2",		0b1110000010001111},
	{"har_el2",		0b1110000010001000},
	{"hpfar_el2",		0b1110001100000100},
	{"hstr_el2",		0b1110000010001011},
	{"far_el1",		0b1100001100000000},
	{"far_el2",		0b1110001100000000},
	{"far_el3",		0b1111001100000000},
	{"hcr_el2",		0b1110000010001000},
	{"hpfar_el2",		0b1110001100000100},
	{"id_aa64afr0_el1",	0b1100000000101100},
	{"id_aa64afr1_el1",	0b1100000000101101},
	{"id_aa64dfr0_el1",	0b1100000000101100},
	{"id_aa64isar0_el1",	0b1100000000110000},
	{"id_aa64isar1_el1",	0b1100000000110001},
	{"id_aa64mmfr0_el1",	0b1100000000111000},
	{"id_aa64mmfr1_el1",	0b1100000000111001},
	{"id_aa64pfr0_el1",	0b1100000000100000},
	{"id_aa64pfr1_el1",	0b1100000000100001},
	{"ifsr32_el2",		0b1110001010000001},
	{"isr_el1",		0b1100011000001000},
	{"mair_el1",		0b1100010100010000},
	{"mair_el2",		0b1110010100010000},
	{"mair_el3",		0b1111010100010000},
	{"midr_el1",		0b1100000000000000},
	{"mpidr_el1",		0b1100000000000101},
	{"nzcv",		0b1101101000010000},
	{"revidr_el1",		0b1100000000000110},
	{"rmr_el3",		0b1111011000000010},
	{"par_el1",		0b1100001110100000},
	{"rvbar_el3",		0b1111011000000001},
	{"scr_el3",		0b1111000010001000},
	{"sctlr_el1",		0b1100000010000000},
	{"sctlr_el2",		0b1110000010000000},
	{"sctlr_el3",		0b1111000010000000},
	{"sp_el0",		0b1100001000001000},
	{"sp_el1",		0b1110001000001000},
	{"spsel",		0b1100001000010000},
	{"spsr_abt",		0b1110001000011001},
	{"spsr_el1",		0b1100001000000000},
	{"spsr_el2",		0b1110001000000000},
	{"spsr_el3",		0b1111001000000000},
	{"spsr_fiq",		0b1110001000011011},
	{"spsr_irq",		0b1110001000011000},
	{"spsr_und",		0b1110001000011010},
	{"tcr_el1",		0b1100000100000010},
	{"tcr_el2",		0b1110000100000010},
	{"tcr_el3",		0b1111000100000010},
	{"tpidr_el0",		0b1101111010000010},
	{"tpidr_el1",		0b1100011010000100},
	{"tpidr_el2",		0b1110011010000010},
	{"tpidr_el3",		0b1111011010000010},
	{"tpidpro_el0",		0b1101111010000011},
	{"vbar_el1",		0b1100011000000000},
	{"vbar_el2",		0b1110011000000000},
	{"vbar_el3",		0b1111011000000000},
	{"vmpidr_el2",		0b1110000000000101},
	{"vpidr_el2",		0b1110000000000000},
	{"ttbr0_el1",		0b1100000100000000},
	{"ttbr0_el2",		0b1110000100000000},
	{"ttbr0_el3",		0b1111000100000000},
	{"ttbr1_el1",		0b1100000100000001},
	{"vtcr_el2",		0b1110000100001010},
	{"vttbr_el2",		0b1110000100001000},
	{NULL,			0b0000000000000000},
};

static char * rshim_log_get_reg_name(u64 opcode)
{
	struct rshim_log_reg *reg = rshim_log_regs;

	while (reg->name) {
		if (reg->opcode == opcode)
			return reg->name;
		reg++;
	}

	return "unknown";
}

static int rshim_misc_show_crash(struct rshim_backend *bd, u64 hdr,
				 struct seq_file *s)
{
	int retval = 0, i, module, type, len;
	u64 opcode, data;
	u32 pc, syndrome, ec;

	module = BF_RSH_LOG_HEADER_GET(MOD, hdr);
	if (module >= ARRAY_SIZE(rshim_log_mod))
		module = 0;
	type = BF_RSH_LOG_HEADER_GET(TYPE, hdr);
	len = BF_RSH_LOG_HEADER_GET(LEN, hdr);

	if (type == BF_RSH_LOG_TYPE_EXCEPTION) {
		syndrome = BF_RSH_LOG_HEADER_GET(SYNDROME, hdr);
		ec = syndrome >> 26;
		seq_printf(s, " Exception(%s): syndrome = 0x%x%s\n",
			   rshim_log_mod[module], syndrome,
			   (ec == 0x24 || ec == 0x25) ? "(Data Abort)" :
			   (ec == 0x2f) ? "(SError)" : "");
	}
	else if (type == BF_RSH_LOG_TYPE_PANIC) {
		pc = BF_RSH_LOG_HEADER_GET(PC, hdr);
		seq_printf(s, " PANIC(%s): PC = 0x%x\n", rshim_log_mod[module],
			   pc);
	}

	for (i = 0; i < len/2; i++) {
		retval = bd->read_rshim(bd, RSHIM_CHANNEL, RSH_SCRATCH_BUF_DAT,
					&opcode);
		if (retval)
			break;

		retval = bd->read_rshim(bd, RSHIM_CHANNEL, RSH_SCRATCH_BUF_DAT,
					&data);
		if (retval)
			break;

		opcode = (le64_to_cpu(opcode) >> AARCH64_MRS_REG_SHIFT) &
			 AARCH64_MRS_REG_MASK;
		seq_printf(s, "   %-16s0x%llx\n", rshim_log_get_reg_name(opcode),
			   data);
	}

	return retval;
}

static int rshim_misc_show_msg(struct rshim_backend *bd, u64 hdr,
			       struct seq_file *s)
{
	int retval;
	int module = BF_RSH_LOG_HEADER_GET(MOD, hdr);
	int len = BF_RSH_LOG_HEADER_GET(LEN, hdr);
	int level = BF_RSH_LOG_HEADER_GET(LEVEL, hdr);
	int has_arg = BF_RSH_LOG_HEADER_GET(HAS_ARG, hdr);
	u32 arg = BF_RSH_LOG_HEADER_GET(ARG, hdr);
	u64 data;
	char *buf, *p;

	if (len <= 0)
		return -EINVAL;

	if (module >= ARRAY_SIZE(rshim_log_mod))
		module = 0;
	if (level >= ARRAY_SIZE(rshim_log_level))
		level = 0;

	buf = kmalloc(len * sizeof(uint64_t) + 1, GFP_KERNEL);
	if (!buf)
		return -ENOMEM;
	p = buf;

	while (len--) {
		retval = bd->read_rshim(bd, RSHIM_CHANNEL, RSH_SCRATCH_BUF_DAT,
					&data);
		if (retval)
			return retval;
		memcpy(p, &data, sizeof(data));
		p += sizeof(data);
	}
	*p = '\0';
	if (!has_arg) {
		seq_printf(s, " %s[%s]: %s\n", rshim_log_level[level],
			   rshim_log_mod[module], buf);
	} else {
		seq_printf(s, " %s[%s]: ", rshim_log_level[level],
			   rshim_log_mod[module]);
		seq_printf(s, buf, arg);
		seq_printf(s, "\n");
	}

	kfree(buf);
	return 0;
}

static int rshim_misc_show_log(struct rshim_backend *bd, struct seq_file *s)
{
	int i, retval, type, len;
	u64 data, idx, hdr;

	seq_printf(s, "---------------------------------------\n");
	seq_printf(s, "             Log Messages\n");
	seq_printf(s, "---------------------------------------\n");

	/* Take the semaphore. */
	while (true) {
		mutex_lock(&bd->mutex);
		retval = bd->read_rshim(bd, RSHIM_CHANNEL, RSH_SEMAPHORE0, &data);
		mutex_unlock(&bd->mutex);
		if (retval) {
			ERROR("couldn't read RSH_SEMAPHORE0");
			return retval;
		}

		if (!data)
			break;

		if (msleep_interruptible(10))
			return -EINTR;
	}

	mutex_lock(&bd->mutex);

	/* Read the current index. */
	retval = bd->read_rshim(bd, RSHIM_CHANNEL, RSH_SCRATCH_BUF_CTL, &idx);
	if (retval) {
		ERROR("couldn't read RSH_SCRATCH_BUF_CTL");
		goto done;
	}
	idx = (idx >> RSH_SCRATCH_BUF_CTL__IDX_SHIFT) &
		RSH_SCRATCH_BUF_CTL__IDX_MASK;
	if (idx <= 1)
		goto done;

	/* Reset the index to 0. */
	retval = bd->write_rshim(bd, RSHIM_CHANNEL, RSH_SCRATCH_BUF_CTL, 0);
	if (retval) {
		ERROR("couldn't write RSH_SCRATCH_BUF_CTL");
		goto done;
	}

	i = 0;
	while (i < idx) {
		retval = bd->read_rshim(bd, RSHIM_CHANNEL, RSH_SCRATCH_BUF_DAT,
					&hdr);
		if (retval) {
			ERROR("couldn't read RSH_SCRATCH_BUF_DAT");
			goto done;
		}
		hdr = le64_to_cpu(hdr);
		type = BF_RSH_LOG_HEADER_GET(TYPE, hdr);
		len = BF_RSH_LOG_HEADER_GET(LEN, hdr);
		i += 1 + len;
		/* Ignore if wraparounded. */
		if (i > idx)
			break;

		switch (type) {
		case BF_RSH_LOG_TYPE_PANIC:
		case BF_RSH_LOG_TYPE_EXCEPTION:
			rshim_misc_show_crash(bd, hdr, s);
			break;
		case BF_RSH_LOG_TYPE_MSG:
			rshim_misc_show_msg(bd, hdr, s);
			break;
		default:
			/* Drain this message. */
			while (len--)
				bd->read_rshim(bd, RSHIM_CHANNEL,
					       RSH_SCRATCH_BUF_DAT, &data);
			break;
		}
	}

	/* Restore the idx value. */
	bd->write_rshim(bd, RSHIM_CHANNEL, RSH_SCRATCH_BUF_CTL, idx);

done:
	/* Release the semaphore. */
	bd->write_rshim(bd, RSHIM_CHANNEL, RSH_SEMAPHORE0, 0);
	mutex_unlock(&bd->mutex);

	return retval;
}

static int
rshim_misc_seq_show(struct seq_file *s, void *token)
{
	struct rshim_backend *bd = s->private;
	u8 *mac = bd->peer_mac;
	int retval;
	u64 value;

	/* Boot mode. */
	mutex_lock(&bd->mutex);
	retval = bd->read_rshim(bd, RSHIM_CHANNEL, RSH_BOOT_CONTROL, &value);
	mutex_unlock(&bd->mutex);
	if (retval) {
		ERROR("couldn't read rshim register");
		return retval;
	}

	/* Display level. */
	seq_printf(s, "%-16s%d (0:basic, 1:advanced, 2:log)\n",
		   "DISPLAY_LEVEL", rshim_misc_level);

	seq_printf(s, "%-16s%lld (0:rshim, 1:emmc, 2:emmc-boot-swap)\n",
		   "BOOT_MODE", value & RSH_BOOT_CONTROL__BOOT_MODE_MASK);

	seq_printf(s, "%-16s%d (seconds)\n", "BOOT_TIMEOUT",
		   rshim_boot_timeout);

	/* SW reset flag is always 0. */
	seq_printf(s, "%-16s%d (1: reset)\n", "SW_RESET", 0);

	/* Display the driver name. */
	seq_printf(s, "%-16s%s (ro)\n", "DEV_NAME", bd->dev_name);

	if (rshim_misc_level == 1) {
		/*
		 * Display the target-side information. Send a request and wait
		 * for some time for the response.
		 */
		mutex_lock(&bd->mutex);
		bd->peer_ctrl_req = 1;
		bd->peer_ctrl_resp = 0;
		memset(mac, 0, 6);
		bd->has_cons_work = 1;
		mutex_unlock(&bd->mutex);
		queue_delayed_work(rshim_wq, &bd->work, 0);
		wait_event_interruptible_timeout(bd->ctrl_wait,
						 bd->peer_ctrl_resp, HZ);
		seq_printf(s, "%-16s%02x:%02x:%02x:%02x:%02x:%02x (rw)\n",
			   "PEER_MAC",
			   mac[0], mac[1], mac[2], mac[3], mac[4], mac[5]);
		seq_printf(s, "%-16s0x%08x (rw)\n", "PXE_ID",
			   htonl(bd->pxe_client_id));
		seq_printf(s, "%-16s%d %d (rw)\n", "VLAN_ID", bd->vlan[0],
			   bd->vlan[1]);
	} else if (rshim_misc_level == 2) {
		rshim_misc_show_log(bd, s);
	}

	return 0;
}

static ssize_t rshim_misc_write(struct file *file, const char *user_buffer,
				size_t count, loff_t *ppos)
{
	struct rshim_backend *bd;
	int i, retval = 0, value, mac[6], vlan[2] = { 0 };
	char buf[64], key[32], *p = buf;

	if (*ppos != 0 || count >= sizeof(buf))
		return -EINVAL;

	/* Copy the data from userspace */
	if (copy_from_user(buf, user_buffer, count))
		return -EFAULT;
	buf[sizeof(buf) - 1] = '\0';

	if (sscanf(p, "%s", key) != 1)
		return -EINVAL;
        p += strlen(key);

	bd = ((struct seq_file *)file->private_data)->private;

	if (strcmp(key, "DISPLAY_LEVEL") == 0) {
		if (sscanf(p, "%d", &value) != 1)
			return -EINVAL;
		rshim_misc_level = value;
	} else if (strcmp(key, "BOOT_TIMEOUT") == 0) {
		if (sscanf(p, "%d", &value) != 1)
			return -EINVAL;
		rshim_boot_timeout = value;
	} else if (strcmp(key, "BOOT_MODE") == 0) {
		if (sscanf(p, "%x", &value) != 1)
			return -EINVAL;
		retval = bd->write_rshim(bd, RSHIM_CHANNEL, RSH_BOOT_CONTROL,
				 value & RSH_BOOT_CONTROL__BOOT_MODE_MASK);
	} else if (strcmp(key, "SW_RESET") == 0) {
		if (sscanf(p, "%x", &value) != 1)
			return -EINVAL;
		if (value) {
			if (!bd->has_reprobe) {
				/* Detach, which shouldn't hold bd->mutex. */
				rshim_notify(bd, RSH_EVENT_DETACH, 0);

				mutex_lock(&bd->mutex);
				/* Reset the TmFifo. */
				rshim_fifo_reset(bd);
				mutex_unlock(&bd->mutex);
			}

			/* SW reset. */
			retval = rshim_write_reset_control(bd);

			if (!bd->has_reprobe) {
				/* Attach. */
				msleep_interruptible(1000);
				mutex_lock(&bd->mutex);
				rshim_notify(bd, RSH_EVENT_ATTACH, 0);
				mutex_unlock(&bd->mutex);
			}
		}
	} else if (strcmp(key, "PEER_MAC") == 0) {
		if (sscanf(p, "%x:%x:%x:%x:%x:%x",
		    &mac[0], &mac[1], &mac[2], &mac[3], &mac[4], &mac[5]) != 6)
			return -EINVAL;
		mutex_lock(&bd->mutex);
		for (i = 0; i < 6; i++)
			bd->peer_mac[i] = mac[i];
		bd->peer_mac_set = 1;
		bd->has_cons_work = 1;
		queue_delayed_work(rshim_wq, &bd->work, 0);
		mutex_unlock(&bd->mutex);
	} else if (strcmp(key, "PXE_ID") == 0) {
		if (sscanf(p, "%x", &value) != 1)
			return -EINVAL;
		mutex_lock(&bd->mutex);
		bd->pxe_client_id = ntohl(value);
		bd->peer_pxe_id_set = 1;
		bd->has_cons_work = 1;
		queue_delayed_work(rshim_wq, &bd->work, 0);
		mutex_unlock(&bd->mutex);
	} else if (strcmp(key, "VLAN_ID") == 0) {
		if (sscanf(p, "%d %d", &vlan[0], &vlan[1]) > 2)
			return -EINVAL;
		mutex_lock(&bd->mutex);
		bd->vlan[0] = vlan[0];
		bd->vlan[1] = vlan[1];
		bd->peer_vlan_set = 1;
		bd->has_cons_work = 1;
		queue_delayed_work(rshim_wq, &bd->work, 0);
		mutex_unlock(&bd->mutex);
	} else {
		return -EINVAL;
	}

	return retval? retval : count;
}

static int rshim_misc_release(struct inode *inode, struct file *file)
{
	struct rshim_backend *bd;
	struct module *owner;
	int retval;

	/*
	 * Note that since this got turned into a seq file by
	 * rshim_misc_open(), our device pointer isn't in the usual spot
	 * (the file's private data); that's used by the seq file
	 * subsystem.
	 */
	bd = ((struct seq_file *)file->private_data)->private;

	retval = single_release(inode, file);
	if (retval)
		return retval;

	rshim_lock();
	owner = RSHIM_READ_ONCE(bd->owner);
	kref_put(&bd->kref, bd->destroy);
	module_put(owner);
	rshim_unlock();

	return 0;
}

static const struct file_operations rshim_misc_fops = {
	.owner = THIS_MODULE,
	.read = seq_read,
	.llseek = seq_lseek,
	.write = rshim_misc_write,
	.release = rshim_misc_release,
};

static int rshim_misc_open(struct file *file)
{
	struct rshim_backend *bd = file->private_data;
	int retval;

	/*
	 * If file->private_data is non-NULL, seq_open (called by
	 * single_open) thinks it's already a seq_file struct, and
	 * scribbles over it!  Very bad.
	 */
	file->private_data = NULL;

	file->f_op = &rshim_misc_fops;
	retval = single_open(file, rshim_misc_seq_show, bd);

	return retval;
}

/* Common file operations routines */

static int rshim_open(struct inode *inode, struct file *file)
{
	struct rshim_backend *bd;
	int subminor = iminor(inode);
	int retval;

	rshim_lock();

	bd = rshim_devs[subminor / RSH_DEV_TYPES];
	if (!bd) {
		rshim_unlock();
		return -ENODEV;
	}

	/* Add a reference to the owner. */
	if (!try_module_get(bd->owner)) {
		rshim_unlock();
		return -ENODEV;
	}

	/* Increment our usage count for the device. */
	kref_get(&bd->kref);

	rshim_unlock();

	file->private_data = bd;

	switch (subminor % RSH_DEV_TYPES) {
	case RSH_DEV_TYPE_BOOT:
		retval = rshim_boot_open(file);
		break;

	case RSH_DEV_TYPE_RSHIM:
		retval = rshim_rshim_open(file);
		break;

	case RSH_DEV_TYPE_CONSOLE:
		retval = rshim_console_open(file);
		break;

	case RSH_DEV_TYPE_NET:
		retval = rshim_tmfifo_open(file);
		break;

	case RSH_DEV_TYPE_MISC:
		retval = rshim_misc_open(file);
		break;

	default:
		retval = -ENODEV;
		break;
	}

	/* If the minor open failed, drop the usage count. */
	if (retval < 0) {
		struct module *owner;

		rshim_lock();
		owner = RSHIM_READ_ONCE(bd->owner);
		kref_put(&bd->kref, bd->destroy);
		module_put(owner);
		rshim_unlock();
	}

	return retval;
}

static const struct file_operations rshim_fops = {
	.owner = THIS_MODULE,
	.open =	rshim_open,
};

int rshim_notify(struct rshim_backend *bd, int event, int code)
{
	int i, rc = 0;
	struct rshim_service *svc;

	switch (event) {
	case RSH_EVENT_FIFO_INPUT:
		rshim_fifo_input(bd);
		break;

	case RSH_EVENT_FIFO_OUTPUT:
		rshim_fifo_output(bd);
		break;

	case RSH_EVENT_FIFO_ERR:
		rshim_fifo_err(bd, code);
		break;

	case RSH_EVENT_ATTACH:
		rshim_boot_done(bd);

		/* Sync-up the tmfifo if reprobe is not supported. */
		if (!bd->has_reprobe && bd->has_rshim)
			rshim_fifo_sync(bd);

		rcu_read_lock();
		for (i = 0; i < RSH_SVC_MAX; i++) {
			svc = rcu_dereference(rshim_svc[i]);
			if (svc != NULL && svc->create != NULL) {
				rc = (*svc->create)(bd);
				if (rc == -EEXIST)
					rc = 0;
				else if (rc) {
					pr_err("Failed to attach svc %d\n", i);
					break;
				}
			}
		}
		rcu_read_unlock();

		spin_lock_irq(&bd->spinlock);
		rshim_fifo_input(bd);
		spin_unlock_irq(&bd->spinlock);
		break;

	case RSH_EVENT_DETACH:
		for (i = 0; i < RSH_SVC_MAX; i++) {
			/*
			 * The svc->delete() could call into Linux kernel and
			 * potentially trigger synchronize_rcu(). So it should
			 * be outside of the rcu_read_lock(). Instead, a ref
			 * counter is used here to avoid race condition between
			 * svc deletion such as caused by kernel module unload.
			 */
			rcu_read_lock();
			svc = rcu_dereference(rshim_svc[i]);
			if (svc != NULL)
				atomic_inc(&svc->ref);
			rcu_read_unlock();

			if (svc != NULL) {
				(*svc->delete)(bd);
				atomic_dec(&svc->ref);
			}
		}
		bd->dev = NULL;
		break;
	}

	return rc;
}
EXPORT_SYMBOL(rshim_notify);

static int rshim_find_index(char *dev_name)
{
	int i, dev_index = -1;

	/* First look for a match with a previous device name. */
	for (i = 0; i < rshim_nr_devs; i++)
		if (rshim_dev_names[i] &&
		    !strcmp(dev_name, rshim_dev_names[i])) {
			pr_debug("found match with previous at index %d\n", i);
			dev_index = i;
			break;
		}

	/* Then look for a never-used slot. */
	if (dev_index < 0) {
		for (i = 0; i < rshim_nr_devs; i++)
			if (!rshim_dev_names[i]) {
				pr_debug("found never-used slot %d\n", i);
				dev_index = i;
				break;
			}
	}

	/* Finally look for a currently-unused slot. */
	if (dev_index < 0) {
		for (i = 0; i < rshim_nr_devs; i++)
			if (!rshim_devs[i]) {
				pr_debug("found unused slot %d\n", i);
				dev_index = i;
				break;
			}
	}

	return dev_index;
}

struct rshim_backend *rshim_find(char *dev_name)
{
	int dev_index = rshim_find_index(dev_name);

	/* If none of that worked, we fail. */
	if (dev_index < 0) {
		ERROR("couldn't find slot for new device %s", dev_name);
		return NULL;
	}

	return rshim_devs[dev_index];
}
EXPORT_SYMBOL(rshim_find);

/* House-keeping timer. */
#if LINUX_VERSION_CODE >= KERNEL_VERSION(4,15,0)
static void rshim_timer_func(struct timer_list *arg)
#else
static void rshim_timer_func(unsigned long arg)
#endif
{
#if LINUX_VERSION_CODE >= KERNEL_VERSION(4,15,0)
	struct rshim_backend *bd = container_of(arg, struct rshim_backend, timer);
#else
	struct rshim_backend *bd = (struct rshim_backend *)arg;
#endif
	u32 period = msecs_to_jiffies(rshim_keepalive_period);

	if (bd->has_cons_work)
		queue_delayed_work(rshim_wq, &bd->work, 0);

	/* Request keepalive update and restart the ~300ms timer. */
	if (time_after(jiffies, (unsigned long)bd->last_keepalive + period)) {
		bd->keepalive = 1;
		bd->last_keepalive = jiffies;
		queue_delayed_work(rshim_wq, &bd->work, 0);
	}
	mod_timer(&bd->timer, jiffies + period);
}

#if LINUX_VERSION_CODE < KERNEL_VERSION(2, 6, 26)

static ssize_t show_rshim_path(struct class_device *cdev, char *buf)
{
	struct rshim_backend *bd = class_get_devdata(cdev);

	if (bd == NULL)
		return -ENODEV;
	return snprintf(buf, PAGE_SIZE, "%s\n",
			rshim_dev_names[bd->dev_index]);
}

static CLASS_DEVICE_ATTR(rshim_path, 0444, show_rshim_path, NULL);

#else

static ssize_t show_rshim_path(struct device *cdev,
			       struct device_attribute *attr, char *buf)
{
	struct rshim_backend *bd = dev_get_drvdata(cdev);

	if (bd == NULL)
		return -ENODEV;
	return snprintf(buf, PAGE_SIZE, "%s\n",
			rshim_dev_names[bd->dev_index]);
}

static DEVICE_ATTR(rshim_path, 0444, show_rshim_path, NULL);

#endif

static void
rshim_load_modules(struct work_struct *work)
{
	request_module("rshim_net");
}

static DECLARE_DELAYED_WORK(rshim_load_modules_work, rshim_load_modules);

/*
 * For some SmartNIC cards with UART connected to the same RSim host, the
 * BOO_MODE comes up with 0 after power-cycle thus not able to boot from eMMC.
 * This function provides a workaround to detect such case and reset the card
 * with the correct boot mode.
 */
static void rshim_boot_workaround_check(struct rshim_backend *bd)
{
	int retval;
	u64 value, uptime_sw, uptime_hw;

	/* Check boot mode 0, which supposes to be set externally. */
	retval = bd->read_rshim(bd, RSHIM_CHANNEL, RSH_BOOT_CONTROL, &value);
	if (retval || value != RSH_BOOT_CONTROL__BOOT_MODE_VAL_NONE)
		return;

	/*
	 * The logic below detects whether it's a hard reset. Register
	 * RSH_UPTIME_POR has the value of cycles since hw reset, register
	 * RSH_UPTIME has value of the most recent reset (sw or hard reset).
	 * If the gap between these two values is less than 1G, we treat it
	 * as hard reset.
	 *
	 * If boot mode is 0 after hard-reset, we update the boot mode and
	 * initiate sw reset so the chip could boot up.
	 */
	retval = bd->read_rshim(bd, RSHIM_CHANNEL, RSH_UPTIME_POR, &uptime_hw);
	if (retval)
		return;

	retval = bd->read_rshim(bd, RSHIM_CHANNEL, RSH_UPTIME, &uptime_sw);
	if (retval)
		return;

	if (uptime_sw - uptime_hw < 1000000000ULL) {
		retval = bd->write_rshim(bd, RSHIM_CHANNEL,
					 RSH_BOOT_CONTROL,
					 RSH_BOOT_CONTROL__BOOT_MODE_VAL_EMMC);
		if (!retval) {
			/* SW reset. */
			retval = rshim_write_reset_control(bd);
			msleep(100);
		}
	}
}

/* Check whether backend is allowed to register or not. */
static int rshim_access_check(struct rshim_backend *bd)
{
	int i, retval;
	u64 value;

	/*
	 * Add a check and delay to make sure rshim is ready.
	 * It's mainly used in BlueField2+ where the rshim (like USB) access is
	 * enabled in boot ROM which might happen after external host detects
	 * the rshim device.
	 */
	for (i = 0; i < 10; i++) {
		retval = bd->read_rshim(bd, RSHIM_CHANNEL,
					RSH_TM_HOST_TO_TILE_CTL, &value);
		if (!retval && value)
			break;
		msleep(100);
	}

	rshim_boot_workaround_check(bd);

	/* Write value 0 to RSH_SCRATCHPAD1. */
	retval = bd->write_rshim(bd, RSHIM_CHANNEL, RSH_SCRATCHPAD1, 0);
	if (retval < 0)
		return -ENODEV;

	/*
	 * Poll RSH_SCRATCHPAD1 up to one second to check whether it's reset to
	 * the keepalive magic value, which indicates another backend driver has
	 * already attached to this target.
	 */
	for (i = 0; i < 10; i++) {
		retval = bd->read_rshim(bd, RSHIM_CHANNEL, RSH_SCRATCHPAD1,
					&value);
		if (retval < 0)
			return -ENODEV;

		if (value == RSH_KEEPALIVE_MAGIC_NUM) {
			INFO("another backend already attached.");
			return -EEXIST;
		}

		msleep(100);
	}

	return 0;
}

int rshim_register(struct rshim_backend *bd)
{
	int i, retval, dev_index;

	if (bd->registered)
		return 0;

	if (backend_driver[0] && strcmp(backend_driver, bd->owner->name))
		return -EACCES;

	dev_index = rshim_find_index(bd->dev_name);
	if (dev_index < 0)
		return -ENODEV;

	if (!bd->read_rshim || !bd->write_rshim) {
		pr_err("read_rshim/write_rshim missing\n");
		return -EINVAL;
	}

	retval = rshim_access_check(bd);
	if (retval)
		return retval;

	if (!bd->write)
		bd->write = rshim_write_default;
	if (!bd->read)
		bd->read = rshim_read_default;

	kref_init(&bd->kref);
	spin_lock_init(&bd->spinlock);
#if RSH_RESET_MUTEX
	init_completion(&bd->reset_complete);
#endif
	for (i = 0; i < TMFIFO_MAX_CHAN; i++) {
		init_waitqueue_head(&bd->read_fifo[i].operable);
		init_waitqueue_head(&bd->write_fifo[i].operable);
	}

	init_waitqueue_head(&bd->write_completed);
	init_waitqueue_head(&bd->ctrl_wait);
	init_completion(&bd->booting_complete);
	init_completion(&bd->boot_write_complete);
	memcpy(&bd->cons_termios, &init_console_termios,
	       sizeof(init_console_termios));
#if LINUX_VERSION_CODE < KERNEL_VERSION(2, 6, 20)
	INIT_WORK(&bd->work, rshim_work_handler, bd);
#else
	INIT_DELAYED_WORK(&bd->work, rshim_work_handler);
#endif

	bd->dev_index = dev_index;
	if (rshim_dev_names[dev_index] != bd->dev_name) {
		kfree(rshim_dev_names[dev_index]);
		rshim_dev_names[dev_index] = bd->dev_name;
	}
	rshim_devs[dev_index] = bd;

	for (i = 0; i < RSH_DEV_TYPES; i++) {
#if LINUX_VERSION_CODE < KERNEL_VERSION(2, 6, 26)
		struct class_device *cl_dev;
#else
		struct device *cl_dev;
#endif
		int err;
		char devbuf[32];

		cdev_init(&bd->cdevs[i], &rshim_fops);
		bd->cdevs[i].owner = THIS_MODULE;
		/*
		 * FIXME: is this addition really legal, or should
		 * we be using MKDEV?
		 */
		err = cdev_add(&bd->cdevs[i],
			       rshim_dev_base +
			       bd->dev_index * RSH_DEV_TYPES + i,
			       1);
		/*
		 * We complain if this fails, but we don't return
		 * an error; it really shouldn't happen, and it's
		 * hard to go un-do the rest of the adds.
		 */
		if (err)
			pr_err("rsh%d: couldn't add minor %d\n", dev_index, i);

#if LINUX_VERSION_CODE < KERNEL_VERSION(2, 6, 26)
		cl_dev = class_device_create(
#elif LINUX_VERSION_CODE < KERNEL_VERSION(2, 6, 27)
		cl_dev = device_create_drvdata(
#else
		cl_dev = device_create(
#endif
				       rshim_class, NULL, rshim_dev_base +
				       bd->dev_index * RSH_DEV_TYPES + i, NULL,
#if LINUX_VERSION_CODE < KERNEL_VERSION(2, 6, 31)
				       "rshim%d-%s",
#else
				       "rshim%d!%s",
#endif
				       bd->dev_index, rshim_dev_minor_names[i]);
		if (IS_ERR(cl_dev)) {
			pr_err("rsh%d: couldn't add dev %s, err %ld\n",
			       dev_index,
			       format_dev_t(devbuf, rshim_dev_base + dev_index *
					    RSH_DEV_TYPES + i),
			       PTR_ERR(cl_dev));
		} else {
			pr_debug("added class dev %s\n",
				 format_dev_t(devbuf, rshim_dev_base +
					      bd->dev_index *
					      RSH_DEV_TYPES + i));
		}

#if LINUX_VERSION_CODE < KERNEL_VERSION(2, 6, 26)
		class_set_devdata(cl_dev, bd);
		if (class_device_create_file(cl_dev,
				     &class_device_attr_rshim_path))
#else
		dev_set_drvdata(cl_dev, bd);
		if (device_create_file(cl_dev, &dev_attr_rshim_path))
#endif
			ERROR("could not create rshim_path file in sysfs");
	}

	for (i = 0; i < 2; i++) {
		bd->boot_buf[i] = kmalloc(BOOT_BUF_SIZE, GFP_KERNEL);
		if (!bd->boot_buf[i]) {
			if (i == 1) {
				kfree(bd->boot_buf[0]);
				bd->boot_buf[0] = NULL;
			}
		}
	}

#if LINUX_VERSION_CODE >= KERNEL_VERSION(4,15,0)
	timer_setup(&bd->timer, rshim_timer_func, 0);
#else
	init_timer(&bd->timer);
	bd->timer.data = (unsigned long)bd;
	bd->timer.function = rshim_timer_func;
#endif

	bd->registered = 1;

	/* Start the keepalive timer. */
	bd->last_keepalive = jiffies;
	mod_timer(&bd->timer, jiffies + 1);

	schedule_delayed_work(&rshim_load_modules_work, 10 * HZ);

	return 0;
}
EXPORT_SYMBOL(rshim_register);

void rshim_deregister(struct rshim_backend *bd)
{
	int i;

	if (!bd->registered)
		return;

	/* Stop the timer. */
	del_timer_sync(&bd->timer);

	for (i = 0; i < 2; i++)
		kfree(bd->boot_buf[i]);

	for (i = 0; i < RSH_DEV_TYPES; i++) {
		cdev_del(&bd->cdevs[i]);
#if LINUX_VERSION_CODE < KERNEL_VERSION(2, 6, 26)
		class_device_destroy(
#else
		device_destroy(
#endif
			       rshim_class,
			       rshim_dev_base + bd->dev_index *
			       RSH_DEV_TYPES + i);
	}

	rshim_devs[bd->dev_index] = NULL;
	bd->registered = 0;
}
EXPORT_SYMBOL(rshim_deregister);

int rshim_register_service(struct rshim_service *service)
{
	int i, retval = 0;
	struct rshim_service *svc;

	rshim_lock();

	atomic_set(&service->ref, 0);

	BUG_ON(service->type >= RSH_SVC_MAX);

	if (!rshim_svc[service->type]) {
		svc = kmalloc(sizeof(*svc), GFP_KERNEL);
		if (svc) {
			memcpy(svc, service, sizeof(*svc));
			/*
			 * Add memory barrir to make sure 'svc' is ready
			 * before switching the pointer.
			 */
			smp_mb();

			/*
			 * rshim_svc[] is protected by RCU. References to it
			 * should have rcu_read_lock() / rcu_dereference() /
			 * rcu_read_lock().
			 */
			rcu_assign_pointer(rshim_svc[service->type], svc);

			/* Attach the service to all backends. */
			for (i = 0; i < rshim_nr_devs; i++) {
				if (rshim_devs[i] != NULL) {
					retval = svc->create(rshim_devs[i]);
					if (retval && retval != -EEXIST)
						break;
				}
			}
		} else
			retval = -ENOMEM;
	} else
		retval = -EEXIST;

	rshim_unlock();

	/* Deregister / cleanup the service in case of failures. */
	if (retval && retval != -EEXIST)
		rshim_deregister_service(service);

	return retval;
}
EXPORT_SYMBOL(rshim_register_service);

void rshim_deregister_service(struct rshim_service *service)
{
	int i;
	struct rshim_service *svc = NULL;

	BUG_ON(service->type >= RSH_SVC_MAX);

	/*
	 * Use synchronize_rcu() to make sure no more outstanding
	 * references to the 'svc' pointer before releasing it.
	 *
	 * The reason to use RCU is that the rshim_svc pointer will be
	 * accessed in rshim_notify() which could be called in interrupt
	 * context and not suitable for mutex lock.
	 */
	rshim_lock();
	if (rshim_svc[service->type]) {
		svc = rshim_svc[service->type];

		/* Delete the service from all backends. */
		for (i = 0; i < rshim_nr_devs; i++)
			if (rshim_devs[i] != NULL)
				svc->delete(rshim_devs[i]);

		rcu_assign_pointer(rshim_svc[service->type], NULL);
	}
	rshim_unlock();
	if (svc != NULL) {
		synchronize_rcu();

		/* Make sure no more references to the svc pointer. */
		while (atomic_read(&svc->ref) != 0)
			msleep(100);
		kfree(svc);
	}
}
EXPORT_SYMBOL(rshim_deregister_service);

static int __init rshim_init(void)
{
	int result, class_registered = 0;

	/* Register our device class. */
	rshim_class = class_create(THIS_MODULE, "rsh");
	if (IS_ERR(rshim_class)) {
		result = PTR_ERR(rshim_class);
		goto error;
	}
	class_registered = 1;

	/* Allocate major/minor numbers. */
	result = alloc_chrdev_region(&rshim_dev_base, 0,
				     rshim_nr_devs * RSH_DEV_TYPES,
				     "rsh");
	if (result < 0) {
		ERROR("can't get rshim major");
		goto error;
	}

	rshim_dev_names = kzalloc(rshim_nr_devs *
				    sizeof(rshim_dev_names[0]), GFP_KERNEL);
	rshim_devs = kcalloc(rshim_nr_devs, sizeof(rshim_devs[0]),
			       GFP_KERNEL);

	if (!rshim_dev_names || !rshim_devs) {
		result = -ENOMEM;
		goto error;
	}

#if LINUX_VERSION_CODE < KERNEL_VERSION(2, 6, 36)
	rshim_wq = create_workqueue("rshim");
#else
	rshim_wq = alloc_workqueue("rshim",
				   WQ_MEM_RECLAIM | WQ_FREEZABLE | WQ_UNBOUND,
				   0);
#endif
	if (!rshim_wq) {
		result = -ENOMEM;
		goto error;
	}

	return 0;

error:
	if (rshim_dev_base)
		unregister_chrdev_region(rshim_dev_base,
				 rshim_nr_devs * RSH_DEV_TYPES);
	if (class_registered)
		class_destroy(rshim_class);
	kfree(rshim_dev_names);
	kfree(rshim_devs);

	return result;
}

static void __exit rshim_exit(void)
{
	int i;

	flush_delayed_work(&rshim_load_modules_work);

	/* Free the major/minor numbers. */
	unregister_chrdev_region(rshim_dev_base,
				 rshim_nr_devs * RSH_DEV_TYPES);

	/* Destroy our device class. */
	class_destroy(rshim_class);

	/* Destroy our work queue. */
	destroy_workqueue(rshim_wq);

	for (i = 0; i < RSH_SVC_MAX; i++)
		kfree(rshim_svc[i]);

	for (i = 0; i < rshim_nr_devs; i++)
		kfree(rshim_dev_names[i]);

	kfree(rshim_dev_names);
	kfree(rshim_devs);
}

module_init(rshim_init);
module_exit(rshim_exit);

MODULE_LICENSE("GPL");
MODULE_AUTHOR("Mellanox Technologies");
MODULE_VERSION("0.25");
