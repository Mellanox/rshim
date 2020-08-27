// SPDX-License-Identifier: BSD-3-Clause OR GPL-2.0-only
/*
 * rshim_pcie_lf.c - BlueField SoC RShim PCIe host driver for Livefish mode
 *
 * Copyright (c) 2020 NVIDIA Corporation. All rights reserved.
 */

#include <linux/pci.h>
#include <linux/version.h>
#include <linux/sched.h>
#if LINUX_VERSION_CODE >= KERNEL_VERSION(4, 11, 0)
#include <linux/sched/signal.h>
#endif

#include "rshim.h"

/* Disable RSim access. */
static int rshim_disable;
module_param(rshim_disable, int, 0444);
MODULE_PARM_DESC(rshim_disable, "Disable rshim (obsoleted)");

/** Our Vendor/Device IDs. */
#define TILERA_VENDOR_ID					0x15b3
#define BLUEFIELD1_DEVICE_ID					0x0211
#define BLUEFIELD2_DEVICE_ID					0x0214

/* Mellanox Address & Data Capabilities */
#define MELLANOX_ADDR						0x58
#define MELLANOX_DATA						0x5c
#define MELLANOX_CAP_READ					0x1

/* TRIO_CR_GATEWAY registers */
#define TRIO_CR_GW_LOCK						0xe38a0
#define TRIO_CR_GW_LOCK_CPY					0xe38a4
#define TRIO_CR_GW_DATA_UPPER					0xe38ac
#define TRIO_CR_GW_DATA_LOWER					0xe38b0
#define TRIO_CR_GW_CTL						0xe38b4
#define TRIO_CR_GW_ADDR_UPPER					0xe38b8
#define TRIO_CR_GW_ADDR_LOWER					0xe38bc
#define TRIO_CR_GW_LOCK_ACQUIRED				0x80000000
#define TRIO_CR_GW_LOCK_RELEASE					0x0
#define TRIO_CR_GW_BUSY						0x60000000
#define TRIO_CR_GW_TRIGGER					0xe0000000
#define TRIO_CR_GW_READ_4BYTE					0x6
#define TRIO_CR_GW_WRITE_4BYTE					0x2

#define CRSPACE_RSH_CHANNEL1_BASE				0x310000

struct rshim_pcie {
	/* RShim backend structure. */
	struct rshim_backend	bd;

	struct pci_dev *pci_dev;

	/* Keep track of number of 8-byte word writes */
	u8 write_count;
};

/* Mechanism to access the CR space using hidden PCI capabilities */
static int pci_cap_read(struct pci_dev *pci_dev, int offset,
				u32 *result)
{
	int retval;

	/*
	 * Write target offset to MELLANOX_ADDR.
	 * Set LSB to indicate a read operation.
	 */
	retval = pci_write_config_dword(pci_dev, MELLANOX_ADDR,
				offset | MELLANOX_CAP_READ);
	if (retval)
		return retval;

	/* Read result from MELLANOX_DATA */
	retval = pci_read_config_dword(pci_dev, MELLANOX_DATA,
				result);
	if (retval)
		return retval;

	return 0;
}

static int pci_cap_write(struct pci_dev *pci_dev, int offset,
				u32 value)
{
	int retval;

	/* Write data to MELLANOX_DATA */
	retval = pci_write_config_dword(pci_dev, MELLANOX_DATA,
				value);
	if (retval)
		return retval;

	/*
	 * Write target offset to MELLANOX_ADDR.
	 * Leave LSB clear to indicate a write operation.
	 */
	retval = pci_write_config_dword(pci_dev, MELLANOX_ADDR,
				offset);
	if (retval)
		return retval;

	return 0;
}

/* Acquire and release the TRIO_CR_GW_LOCK. */
static int trio_cr_gw_lock_acquire(struct pci_dev *pci_dev)
{
	int retval, retry = 0;
	u32 read_value;

	/* Wait until TRIO_CR_GW_LOCK is free */
	do {
		retval = pci_cap_read(pci_dev, TRIO_CR_GW_LOCK,
				&read_value);
		if (retval)
			return retval;

		if (signal_pending(current))
			return -EINTR;

		if (++retry > LOCK_RETRY_CNT)
			return -ETIMEDOUT;
	} while (read_value & TRIO_CR_GW_LOCK_ACQUIRED);

	/* Acquire TRIO_CR_GW_LOCK */
	retval = pci_cap_write(pci_dev, TRIO_CR_GW_LOCK,
				TRIO_CR_GW_LOCK_ACQUIRED);
	if (retval)
		return retval;

	return 0;
}

static int trio_cr_gw_lock_release(struct pci_dev *pci_dev)
{
	int retval;

	/* Release TRIO_CR_GW_LOCK */
	retval = pci_cap_write(pci_dev, TRIO_CR_GW_LOCK,
				TRIO_CR_GW_LOCK_RELEASE);

	return retval;
}

/*
 * Mechanism to access the RShim from the CR space using the
 * TRIO_CR_GATEWAY.
 */
static int crspace_rsh_gw_read(struct pci_dev *pci_dev, int addr,
				u32 *result)
{
	int retval;

	if (pci_dev->device == BLUEFIELD2_DEVICE_ID) {
		addr = (addr & 0xffff) + CRSPACE_RSH_CHANNEL1_BASE;
		retval = pci_cap_read(pci_dev, addr, result);

		return retval;
	}

	addr += RSH_CHANNEL_BASE(RSHIM_CHANNEL);

	/* Acquire TRIO_CR_GW_LOCK */
	retval = trio_cr_gw_lock_acquire(pci_dev);
	if (retval)
		return retval;

	/* Write addr to TRIO_CR_GW_ADDR_LOWER */
	retval = pci_cap_write(pci_dev, TRIO_CR_GW_ADDR_LOWER,
				addr);
	if (retval)
		return retval;

	/* Set TRIO_CR_GW_READ_4BYTE */
	retval = pci_cap_write(pci_dev, TRIO_CR_GW_CTL,
				TRIO_CR_GW_READ_4BYTE);
	if (retval)
		return retval;

	/* Trigger TRIO_CR_GW to read from addr */
	retval = pci_cap_write(pci_dev, TRIO_CR_GW_LOCK,
				TRIO_CR_GW_TRIGGER);
	if (retval)
		return retval;

	/* Read 32-bit data from TRIO_CR_GW_DATA_LOWER */
	retval = pci_cap_read(pci_dev, TRIO_CR_GW_DATA_LOWER,
				result);
	if (retval)
		return retval;

	*result = be32_to_cpu(*result);

	/* Release TRIO_CR_GW_LOCK */
	retval = trio_cr_gw_lock_release(pci_dev);
	if (retval)
		return retval;

	return 0;
}

static int crspace_rsh_gw_write(struct pci_dev *pci_dev, int addr,
				u32 value)
{
	int retval;

	if (pci_dev->device == BLUEFIELD2_DEVICE_ID) {
		addr = (addr & 0xffff) + CRSPACE_RSH_CHANNEL1_BASE;
		retval = pci_cap_write(pci_dev, addr,
					value);
		return retval;
	}

	/*
	 * All Rshim accesses except writes to the BOOT_FIFO_DATA go through
	 * the Byte Access Widget and hence need to use the RSHIM_CHANNEL.
	 */
	if ((addr & 0xffff) != RSH_BOOT_FIFO_DATA)
		addr += RSH_CHANNEL_BASE(RSHIM_CHANNEL);

	/* Acquire TRIO_CR_GW_LOCK */
	retval = trio_cr_gw_lock_acquire(pci_dev);
	if (retval)
		return retval;

	/* Write 32-bit data to TRIO_CR_GW_DATA_LOWER */
	retval = pci_cap_write(pci_dev, TRIO_CR_GW_DATA_LOWER,
				cpu_to_be32(value));
	if (retval)
		return retval;

	/* Write addr to TRIO_CR_GW_ADDR_LOWER */
	retval = pci_cap_write(pci_dev, TRIO_CR_GW_ADDR_LOWER,
				addr);
	if (retval)
		return retval;

	/* Set TRIO_CR_GW_WRITE_4BYTE */
	retval = pci_cap_write(pci_dev, TRIO_CR_GW_CTL,
				TRIO_CR_GW_WRITE_4BYTE);
	if (retval)
		return retval;

	/* Trigger CR gateway to write to RShim */
	retval = pci_cap_write(pci_dev, TRIO_CR_GW_LOCK,
				TRIO_CR_GW_TRIGGER);
	if (retval)
		return retval;

	/* Release TRIO_CR_GW_LOCK */
	retval = trio_cr_gw_lock_release(pci_dev);
	if (retval)
		return retval;

	return 0;
}

/* Wait until the RSH_BYTE_ACC_CTL pending bit is cleared */
static int rshim_byte_acc_pending_wait(struct pci_dev *pci_dev)
{
	int retval, retry = 0;
	u32 read_value;

	do {
		retval = crspace_rsh_gw_read(pci_dev, RSH_BYTE_ACC_CTL,
				&read_value);
		if (retval)
			return retval;

		if (signal_pending(current))
			return -EINTR;

		if (++retry > LOCK_RETRY_CNT)
			return -ETIMEDOUT;
	} while (read_value & RSH_BYTE_ACC_PENDING);

	return 0;
}

/* Acquire BAW Interlock */
static int rshim_byte_acc_lock_acquire(struct pci_dev *pci_dev)
{
	int retval, retry = 0;
	u32 read_value;

	do {
		if (signal_pending(current))
			return -EINTR;

		if (++retry > LOCK_RETRY_CNT)
			return -ETIMEDOUT;

		retval = crspace_rsh_gw_read(pci_dev, RSH_BYTE_ACC_INTERLOCK,
			&read_value);
		if (retval)
			return retval;
	} while (!(read_value & 0x1));

	return 0;
}

/* Release BAW Interlock */
static int rshim_byte_acc_lock_release(struct pci_dev *pci_dev)
{
	return crspace_rsh_gw_write(pci_dev,
				RSH_BYTE_ACC_INTERLOCK, 0);
}

/*
 * Mechanism to do an 8-byte access to the Rshim using
 * two 4-byte accesses through the Rshim Byte Access Widget.
 */
static int rshim_byte_acc_read(struct pci_dev *pci_dev, int addr,
				u64 *result)
{
	int retval;
	u32 read_value;
	u64 read_result;

	/* Wait for RSH_BYTE_ACC_CTL pending bit to be cleared */
	retval = rshim_byte_acc_pending_wait(pci_dev);
	if (retval)
		return retval;

	/* Acquire RSH_BYTE_ACC_INTERLOCK */
	if (pci_dev->device == BLUEFIELD2_DEVICE_ID) {
		retval = rshim_byte_acc_lock_acquire(pci_dev);
		if (retval)
			return retval;
	}

	/* Write target address to RSH_BYTE_ACC_ADDR */
	retval = crspace_rsh_gw_write(pci_dev, RSH_BYTE_ACC_ADDR,
				addr);
	if (retval)
		goto exit_read;

	/* Write control and trigger bits to perform read */
	retval = crspace_rsh_gw_write(pci_dev, RSH_BYTE_ACC_CTL,
			RSH_BYTE_ACC_READ_TRIGGER | RSH_BYTE_ACC_SIZE_4BYTE);
	if (retval)
		goto exit_read;

	/* Wait for RSH_BYTE_ACC_CTL pending bit to be cleared */
	retval = rshim_byte_acc_pending_wait(pci_dev);
	if (retval)
		goto exit_read;

	/* Read RSH_BYTE_ACC_RDAT to read lower 32-bits of data */
	retval = crspace_rsh_gw_read(pci_dev, RSH_BYTE_ACC_RDAT,
				&read_value);
	if (retval)
		goto exit_read;

	read_result = (u64)read_value;

	/* Wait for RSH_BYTE_ACC_CTL pending bit to be cleared */
	retval = rshim_byte_acc_pending_wait(pci_dev);
	if (retval)
		goto exit_read;

	/* Read RSH_BYTE_ACC_RDAT to read upper 32-bits of data */
	retval = crspace_rsh_gw_read(pci_dev, RSH_BYTE_ACC_RDAT,
				&read_value);
	if (retval)
		goto exit_read;

	read_result |= ((u64)read_value << 32);
	*result = read_result;

exit_read:
	/* Release RSH_BYTE_ACC_INTERLOCK */
	if (pci_dev->device == BLUEFIELD2_DEVICE_ID)
		retval = rshim_byte_acc_lock_release(pci_dev);

	return retval;
}

static int rshim_byte_acc_write(struct pci_dev *pci_dev, int addr,
				u64 value)
{
	int retval;

	/* Wait for RSH_BYTE_ACC_CTL pending bit to be cleared */
	retval = rshim_byte_acc_pending_wait(pci_dev);
	if (retval)
		return retval;

	/* Acquire RSH_BYTE_ACC_INTERLOCK */
	if (pci_dev->device == BLUEFIELD2_DEVICE_ID) {
		retval = rshim_byte_acc_lock_acquire(pci_dev);
		if (retval)
			return retval;
	}

	/* Write target address to RSH_BYTE_ACC_ADDR */
	retval = crspace_rsh_gw_write(pci_dev, RSH_BYTE_ACC_ADDR,
				addr);
	if (retval)
		goto exit_write;

	/* Write control bits to RSH_BYTE_ACC_CTL */
	retval = crspace_rsh_gw_write(pci_dev, RSH_BYTE_ACC_CTL,
				RSH_BYTE_ACC_SIZE_4BYTE);
	if (retval)
		goto exit_write;

	/* Write lower 32 bits of data to TRIO_CR_GW_DATA */
	retval = crspace_rsh_gw_write(pci_dev, RSH_BYTE_ACC_WDAT,
				(u32)(value));
	if (retval)
		goto exit_write;

	/* Wait for RSH_BYTE_ACC_CTL pending bit to be cleared */
	retval = rshim_byte_acc_pending_wait(pci_dev);
	if (retval)
		goto exit_write;

	/* Write upper 32 bits of data to TRIO_CR_GW_DATA */
	retval = crspace_rsh_gw_write(pci_dev, RSH_BYTE_ACC_WDAT,
				(u32)(value >> 32));
	if (retval)
		goto exit_write;

exit_write:
	/* Release RSH_BYTE_ACC_INTERLOCK */
	if (pci_dev->device == BLUEFIELD2_DEVICE_ID)
		retval = rshim_byte_acc_lock_release(pci_dev);

	return retval;
}

/*
 * The RShim Boot FIFO has a holding register which can couple
 * two consecutive 4-byte writes into a single 8-byte write
 * before pushing the data into the FIFO.
 * Hence the RShim Byte Access Widget is not necessary to write
 * to the BOOT FIFO using 4-byte writes.
 */
static int rshim_boot_fifo_write(struct pci_dev *pci_dev, int addr,
				u64 value)
{
	int retval;

	/* Write lower 32 bits of data to RSH_BOOT_FIFO_DATA */
	retval = crspace_rsh_gw_write(pci_dev, addr, (u32)(value));
	if (retval)
		return retval;

	/* Write upper 32 bits of data to RSH_BOOT_FIFO_DATA */
	retval = crspace_rsh_gw_write(pci_dev, addr, (u32)(value >> 32));
	if (retval)
		return retval;

	return 0;
}

/* RShim read/write routines */
static int rshim_pcie_read(struct rshim_backend *bd, int chan, int addr,
				u64 *result)
{
	struct rshim_pcie *dev = container_of(bd, struct rshim_pcie, bd);
	struct pci_dev *pci_dev = dev->pci_dev;
	int retval;

	if (!bd->has_rshim || !dev->pci_dev)
		return -ENODEV;

	dev->write_count = 0;

	retval = rshim_byte_acc_read(pci_dev, RSH_CHANNEL_BASE(chan) + addr,
					result);

	return retval;
}

static int rshim_pcie_write(struct rshim_backend *bd, int chan, int addr,
				u64 value)
{
	struct rshim_pcie *dev = container_of(bd, struct rshim_pcie, bd);
	struct pci_dev *pci_dev = dev->pci_dev;
	int retval;
	u64 result;
	bool is_boot_stream = (addr == RSH_BOOT_FIFO_DATA);

	if (!bd->has_rshim || !dev->pci_dev)
		return -ENODEV;

	/*
	 * Limitation in BlueField-1
	 * We cannot stream large numbers of PCIe writes to the RShim.
	 * Instead, we must write no more than 15 words before
	 * doing a read from another register within the RShim,
	 * which forces previous writes to drain.
	 * Note that we allow a max write_count of 7 since each 8-byte
	 * write is done using 2 4-byte writes in the boot fifo case.
	 */
	if (pci_dev->device == BLUEFIELD1_DEVICE_ID) {
		if (dev->write_count == 7) {
			mb();
			rshim_pcie_read(bd, RSHIM_CHANNEL, RSH_SCRATCHPAD,
					&result);
		}
		dev->write_count++;
	}

	if (is_boot_stream)
		retval = rshim_boot_fifo_write(pci_dev,
						RSH_CHANNEL_BASE(chan) + addr,
						value);
	else
		retval = rshim_byte_acc_write(pci_dev,
						RSH_CHANNEL_BASE(chan) + addr,
						value);

	return retval;
}

static void rshim_pcie_delete(struct kref *kref)
{
	struct rshim_backend *bd;
	struct rshim_pcie *dev;

	bd = container_of(kref, struct rshim_backend, kref);
	dev = container_of(bd, struct rshim_pcie, bd);

	rshim_deregister(bd);
	if (dev->pci_dev)
		dev_set_drvdata(&dev->pci_dev->dev, NULL);
	kfree(dev);
}

/* Probe routine */
static int rshim_pcie_probe(struct pci_dev *pci_dev,
				const struct pci_device_id *id)
{
	struct rshim_pcie *dev = NULL;
	struct rshim_backend *bd = NULL;
	char *pcie_dev_name;
	int retval, err = 0, allocfail = 0, max_name_len = 64;

	pcie_dev_name = kzalloc(max_name_len, GFP_KERNEL);
	if (!pcie_dev_name)
		return -ENOMEM;
	retval = snprintf(pcie_dev_name, max_name_len,
			  "pcie-lf-%04x:%02x:%02x.%x",
			  pci_domain_nr(pci_dev->bus),
			  pci_dev->bus->number, PCI_SLOT(pci_dev->devfn),
			  PCI_FUNC(pci_dev->devfn));
	if (WARN_ON_ONCE(retval >= max_name_len)) {
		err = -EINVAL;
		goto error;
	}

	pr_debug("Probing %s\n", pcie_dev_name);

	rshim_lock();

	/* Find the backend. */
	bd = rshim_find(pcie_dev_name);
	if (bd) {
		kref_get(&bd->kref);
		dev = container_of(bd, struct rshim_pcie, bd);
	} else {
		/* Get some memory for this device's driver state. */
		dev = kzalloc(sizeof(*dev), GFP_KERNEL);
		if (dev == NULL) {
			err = -ENOMEM;
			rshim_unlock();
			goto error;
		}

		bd = &dev->bd;
		bd->owner = THIS_MODULE;
		bd->dev_name = pcie_dev_name;
		bd->destroy = rshim_pcie_delete;
		bd->read_rshim = rshim_pcie_read;
		bd->write_rshim = rshim_pcie_write;
		dev->write_count = 0;
		mutex_init(&bd->mutex);
	}

	retval = rshim_fifo_alloc(bd);
	if (retval) {
		rshim_unlock();
		ERROR("Failed to allocate fifo\n");
		err = -ENOMEM;
		goto enable_failed;
	}

	allocfail |= rshim_fifo_alloc(bd);

	if (!bd->read_buf) {
		bd->read_buf = kzalloc(READ_BUF_SIZE,
					   GFP_KERNEL);
	}
	allocfail |= bd->read_buf == 0;

	if (!bd->write_buf) {
		bd->write_buf = kzalloc(WRITE_BUF_SIZE,
					    GFP_KERNEL);
	}
	allocfail |= bd->write_buf == 0;

	if (allocfail) {
		rshim_unlock();
		ERROR("can't allocate buffers");
		goto enable_failed;
	}

	rshim_unlock();

	/* Enable the device. */
	err = pci_enable_device(pci_dev);
	if (err != 0) {
		ERROR("Device enable failed with error %d", err);
		goto enable_failed;
	}

	/* Initialize object */
	dev->pci_dev = pci_dev;
	dev_set_drvdata(&pci_dev->dev, dev);

	/* Enable PCI bus mastering. */
	pci_set_master(pci_dev);

	/*
	 * Register rshim here since it needs to detect whether other backend
	 * has already registered or not, which involves reading/writting rshim
	 * registers and has assumption that the under layer is working.
	 */
	rshim_lock();
	bd->has_rshim = 1;
	bd->has_tm = 1;
	if (!bd->registered) {
		retval = rshim_register(bd);
		if (retval) {
			ERROR("Backend register failed with error %d", retval);
			rshim_unlock();
			goto register_failed;
		}
	}
	rshim_unlock();

	/* Notify that the device is attached */
	mutex_lock(&bd->mutex);
	retval = rshim_notify(bd, RSH_EVENT_ATTACH, 0);
	mutex_unlock(&bd->mutex);
	if (retval)
		goto register_failed;

	return 0;

register_failed:
	pci_disable_device(pci_dev);

enable_failed:
	rshim_lock();
	kref_put(&dev->bd.kref, rshim_pcie_delete);
	rshim_unlock();
error:
	kfree(pcie_dev_name);

	return err;
}

/* Called via pci_unregister_driver() when the module is removed. */
static void rshim_pcie_remove(struct pci_dev *pci_dev)
{
	struct rshim_pcie *dev = dev_get_drvdata(&pci_dev->dev);
	int retval, flush_wq;

	mutex_lock(&dev->bd.mutex);
	/*
	 * Reset TRIO_PCIE_INTFC_RX_BAR0_ADDR_MASK and TRIO_MAP_RSH_BASE.
	 * Otherwise, upon host reboot, the two registers will retain previous
	 * values that don't match the new BAR0 address that is assigned to
	 * the PCIe ports, causing host MMIO access to RShim to fail.
	 */
	retval = rshim_pcie_write(&dev->bd, RSHIM_CHANNEL,
			RSH_SWINT & 0xFFFF, RSH_INT_VEC0_RTC__SWINT3_MASK);
	if (retval)
		ERROR("RShim write failed");

	/* Clear the flags before deleting the backend. */
	dev->bd.has_rshim = 0;
	dev->bd.has_tm = 0;
	mutex_unlock(&dev->bd.mutex);

	rshim_notify(&dev->bd, RSH_EVENT_DETACH, 0);

	mutex_lock(&dev->bd.mutex);
	flush_wq = !cancel_delayed_work(&dev->bd.work);
	if (flush_wq)
		flush_workqueue(rshim_wq);
	dev->bd.has_cons_work = 0;
	kfree(dev->bd.read_buf);
	kfree(dev->bd.write_buf);
	rshim_fifo_free(&dev->bd);
	dev->pci_dev = NULL;
	mutex_unlock(&dev->bd.mutex);

	rshim_lock();
	kref_put(&dev->bd.kref, rshim_pcie_delete);
	rshim_unlock();

	pci_disable_device(pci_dev);
	dev_set_drvdata(&pci_dev->dev, NULL);
}

static struct pci_device_id rshim_pcie_table[] = {
	{ PCI_DEVICE(TILERA_VENDOR_ID, BLUEFIELD1_DEVICE_ID), },
	{ PCI_DEVICE(TILERA_VENDOR_ID, BLUEFIELD2_DEVICE_ID), },
	{ 0, }
};
MODULE_DEVICE_TABLE(pci, rshim_pcie_table);

static struct pci_driver rshim_pcie_driver = {
	.name = "rshim_pcie_lf",
	.probe = rshim_pcie_probe,
	.remove = rshim_pcie_remove,
	.id_table = rshim_pcie_table,
};

static int __init rshim_pcie_init(void)
{
	int result;

	/* Register the driver */
	result = pci_register_driver(&rshim_pcie_driver);
	if (result)
		ERROR("pci_register failed, error number %d", result);

	return result;
}

static void __exit rshim_pcie_exit(void)
{
	/* Unregister the driver. */
	pci_unregister_driver(&rshim_pcie_driver);
}

module_init(rshim_pcie_init);
module_exit(rshim_pcie_exit);

MODULE_LICENSE("Dual BSD/GPL");
MODULE_AUTHOR("Mellanox Technologies");
MODULE_VERSION("0.8");
