/*
 * rshim_pcie.c - Mellanox RShim PCIe host driver
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
 *   NON INFRINGEMENT.  See the GNU General Public License for
 *   more details.
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
#define BLUEFIELD_DEVICE_ID					0xc2d2

/** The offset in BAR2 of the RShim region. */
#define PCI_RSHIM_WINDOW_OFFSET					0x0

/** The size the RShim region. */
#define PCI_RSHIM_WINDOW_SIZE					0x100000

/* Maximum number of devices this driver can handle */
#define MAX_DEV_COUNT						16

struct rshim_pcie {
	/* RShim backend structure. */
	struct rshim_backend	bd;

	struct pci_dev *pci_dev;

	/* RShim BAR size. */
	uint64_t bar0_size;

	/* Address of the RShim registers. */
	u8 __iomem *rshim_regs;

	/* Keep track of number of 8-byte word writes */
	u8 write_count;
};

static struct rshim_pcie *instances[MAX_DEV_COUNT];

#ifndef CONFIG_64BIT
/* Wait until the RSH_BYTE_ACC_CTL pending bit is cleared */
static int rshim_byte_acc_pending_wait(struct rshim_pcie *dev, int chan)
{
	u32 read_value;

	do {
		read_value = readl(dev->rshim_regs +
			(RSH_BYTE_ACC_CTL | (chan << 16)));

		if (signal_pending(current))
			return -EINTR;

	} while (read_value & RSH_BYTE_ACC_PENDING);

	return 0;
}

/*
 * RShim read/write methods for 32-bit systems
 * Mechanism to do an 8-byte access to the Rshim using
 * two 4-byte accesses through the Rshim Byte Access Widget.
 */
static int rshim_byte_acc_read(struct rshim_pcie *dev, int chan, int addr,
				u64 *result)
{
	int retval;
	u32 read_value;
	u64 read_result;

	/* Wait for RSH_BYTE_ACC_CTL pending bit to be cleared */
	retval = rshim_byte_acc_pending_wait(dev, chan);
	if (retval)
		return retval;

	/* Write control bits to RSH_BYTE_ACC_CTL */
	writel(RSH_BYTE_ACC_SIZE, dev->rshim_regs +
		(RSH_BYTE_ACC_CTL | (chan << 16)));

	/* Write target address to RSH_BYTE_ACC_ADDR */
	writel(addr, dev->rshim_regs + (RSH_BYTE_ACC_ADDR | (chan << 16)));

	/* Write trigger bits to perform read */
	writel(RSH_BYTE_ACC_READ_TRIGGER, dev->rshim_regs +
		(RSH_BYTE_ACC_CTL | (chan << 16)));

	/* Wait for RSH_BYTE_ACC_CTL pending bit to be cleared */
	retval = rshim_byte_acc_pending_wait(dev, chan);
	if (retval)
		return retval;

	/* Read RSH_BYTE_ACC_RDAT to read lower 32-bits of data */
	read_value = readl(dev->rshim_regs +
		(RSH_BYTE_ACC_RDAT | (chan << 16)));

	read_result = (u64)read_value << 32;

	/* Wait for RSH_BYTE_ACC_CTL pending bit to be cleared */
	retval = rshim_byte_acc_pending_wait(dev, chan);
	if (retval)
		return retval;

	/* Read RSH_BYTE_ACC_RDAT to read upper 32-bits of data */
	read_value = readl(dev->rshim_regs +
		(RSH_BYTE_ACC_RDAT | (chan << 16)));

	read_result |= (u64)read_value;
	*result = be64_to_cpu(read_result);

	return 0;
}

static int rshim_byte_acc_write(struct rshim_pcie *dev, int chan, int addr,
				u64 value)
{
	int retval;

	/* Wait for RSH_BYTE_ACC_CTL pending bit to be cleared */
	retval = rshim_byte_acc_pending_wait(dev, chan);
	if (retval)
		return retval;

	/* Write control bits to RSH_BYTE_ACC_CTL */
	writel(RSH_BYTE_ACC_SIZE, dev->rshim_regs +
		(RSH_BYTE_ACC_CTL | (chan << 16)));

	/* Write target address to RSH_BYTE_ACC_ADDR */
	writel(addr, dev->rshim_regs + (RSH_BYTE_ACC_ADDR | (chan << 16)));

	/* Write control bits to RSH_BYTE_ACC_CTL */
	writel(RSH_BYTE_ACC_SIZE, dev->rshim_regs +
		(RSH_BYTE_ACC_CTL | (chan << 16)));

	/* Write lower 32 bits of data to TRIO_CR_GW_DATA */
	writel((u32)(value >> 32), dev->rshim_regs +
		(RSH_BYTE_ACC_WDAT | (chan << 16)));

	/* Wait for RSH_BYTE_ACC_CTL pending bit to be cleared */
	retval = rshim_byte_acc_pending_wait(dev, chan);
	if (retval)
		return retval;

	/* Write upper 32 bits of data to TRIO_CR_GW_DATA */
	writel((u32)(value), dev->rshim_regs +
		(RSH_BYTE_ACC_WDAT | (chan << 16)));

	return 0;
}
#endif /* CONFIG_64BIT */

/* RShim read/write routines */
static int rshim_pcie_read(struct rshim_backend *bd, int chan, int addr,
				u64 *result)
{
	struct rshim_pcie *dev = container_of(bd, struct rshim_pcie, bd);
	int retval = 0;

	if (!bd->has_rshim)
		return -ENODEV;

	dev->write_count = 0;

#ifndef CONFIG_64BIT
	retval = rshim_byte_acc_read(dev, chan, addr, result);
#else
	*result = readq(dev->rshim_regs + (addr | (chan << 16)));
#endif
	return retval;
}

static int rshim_pcie_write(struct rshim_backend *bd, int chan, int addr,
				u64 value)
{
	struct rshim_pcie *dev = container_of(bd, struct rshim_pcie, bd);
	u64 result;
	int retval = 0;

	if (!bd->has_rshim)
		return -ENODEV;

	/*
	 * We cannot stream large numbers of PCIe writes to the RShim's BAR.
	 * Instead, we must write no more than 15 8-byte words before
	 * doing a read from another register within the BAR,
	 * which forces previous writes to drain.
	 */
	if (dev->write_count == 15) {
		mb();
		rshim_pcie_read(bd, chan, RSH_SCRATCHPAD, &result);
	}
	dev->write_count++;
#ifndef CONFIG_64BIT
	retval = rshim_byte_acc_write(dev, chan, addr, value);
#else
	writeq(value, dev->rshim_regs + (addr | (chan << 16)));
#endif

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
	struct rshim_pcie *dev;
	struct rshim_backend *bd;
	char *pcie_dev_name;
	int index, ret, allocfail = 0;
	const int max_name_len = 20;

	for (index = 0; index < MAX_DEV_COUNT; index++)
		if (instances[index] == NULL)
			break;
	if (index == MAX_DEV_COUNT) {
		dev_err(&pci_dev->dev, "Driver cannot handle any more devices.");
		return -ENODEV;
	}

	pcie_dev_name = kzalloc(max_name_len, GFP_KERNEL);
	if (!pcie_dev_name)
		return -ENOMEM;
	ret = snprintf(pcie_dev_name, max_name_len, "rshim_pcie%d", index);
	if (WARN_ON_ONCE(ret >= max_name_len)) {
		ret = -EINVAL;
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
			ret = -ENOMEM;
			rshim_unlock();
			goto error;
		}

		instances[index] = dev;
		bd = &dev->bd;
		bd->has_rshim = 1;
		bd->has_tm = 1;
		bd->dev_name = pcie_dev_name;
		bd->read_rshim = rshim_pcie_read;
		bd->write_rshim = rshim_pcie_write;
		bd->destroy = rshim_pcie_delete;
		bd->owner = THIS_MODULE;
		dev->write_count = 0;
		mutex_init(&bd->mutex);
	}

	ret = rshim_fifo_alloc(bd);
	if (ret) {
		rshim_unlock();
		dev_err(&pci_dev->dev, "Failed to allocate fifo\n");
		ret = -ENOMEM;
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
		dev_err(&pci_dev->dev, "can't allocate buffers");
		ret = -ENOMEM;
		goto enable_failed;
	}

	rshim_unlock();

	/* Enable the device. */
	ret = pci_enable_device(pci_dev);
	if (ret) {
		dev_err(&pci_dev->dev, "Device enable failed with error %d",
			ret);
		goto enable_failed;
	}

	/* Initialize object */
	dev->pci_dev = pci_dev;
	dev_set_drvdata(&pci_dev->dev, dev);

	dev->bar0_size = pci_resource_len(pci_dev, 0);

	/* Fail if the BAR is unassigned. */
	if (!dev->bar0_size) {
		dev_err(&pci_dev->dev, "BAR unassigned, run 'lspci -v'.");
		ret = -ENOMEM;
		goto rshim_map_failed;
	}

	/* Map in the RShim registers. */
	dev->rshim_regs = ioremap(pci_resource_start(pci_dev, 0) +
				  PCI_RSHIM_WINDOW_OFFSET,
				  PCI_RSHIM_WINDOW_SIZE);
	if (dev->rshim_regs == NULL) {
		dev_err(&pci_dev->dev, "Failed to map RShim registers\n");
		ret = -ENOMEM;
		goto rshim_map_failed;
	}

	/* Enable PCI bus mastering. */
	pci_set_master(pci_dev);

	/*
	 * Register rshim here since it needs to detect whether other backend
	 * has already registered or not, which involves reading/writting rshim
	 * registers and has assumption that the under layer is working.
	 */
	rshim_lock();
	if (!bd->registered) {
		ret = rshim_register(bd);
		if (ret) {
			rshim_unlock();
			goto rshim_map_failed;
		} else
			pcie_dev_name = NULL;
	}
	rshim_unlock();

	/* Notify that the device is attached */
	mutex_lock(&bd->mutex);
	ret = rshim_notify(bd, RSH_EVENT_ATTACH, 0);
	mutex_unlock(&bd->mutex);
	if (ret)
		goto rshim_map_failed;

	return 0;

 rshim_map_failed:
	pci_disable_device(pci_dev);
 enable_failed:
	rshim_lock();
	kref_put(&bd->kref, rshim_pcie_delete);
	rshim_unlock();
 error:
	kfree(pcie_dev_name);
	return ret;
}

/* Called via pci_unregister_driver() when the module is removed. */
static void rshim_pcie_remove(struct pci_dev *pci_dev)
{
	struct rshim_pcie *dev = dev_get_drvdata(&pci_dev->dev);
	int flush_wq;

	if (!dev)
		return;

	/*
	 * Reset TRIO_PCIE_INTFC_RX_BAR0_ADDR_MASK and TRIO_MAP_RSH_BASE.
	 * Otherwise, upon host reboot, the two registers will retain previous
	 * values that don't match the new BAR0 address that is assigned to
	 * the PCIe ports, causing host MMIO access to RShim to fail.
	 */
	rshim_pcie_write(&dev->bd, (RSH_SWINT >> 16) & 0xF,
		RSH_SWINT & 0xFFFF, RSH_INT_VEC0_RTC__SWINT3_MASK);

	/* Clear the flags before unmapping rshim registers to avoid race. */
	dev->bd.has_rshim = 0;
	dev->bd.has_tm = 0;
	mb();

	if (dev->rshim_regs)
		iounmap(dev->rshim_regs);

	rshim_notify(&dev->bd, RSH_EVENT_DETACH, 0);
	mutex_lock(&dev->bd.mutex);
	flush_wq = !cancel_delayed_work(&dev->bd.work);
	if (flush_wq)
		flush_workqueue(rshim_wq);
	dev->bd.has_cons_work = 0;
	kfree(dev->bd.read_buf);
	kfree(dev->bd.write_buf);
	rshim_fifo_free(&dev->bd);
	mutex_unlock(&dev->bd.mutex);

	rshim_lock();
	kref_put(&dev->bd.kref, rshim_pcie_delete);
	rshim_unlock();

	pci_disable_device(pci_dev);
	dev_set_drvdata(&pci_dev->dev, NULL);
}

static struct pci_device_id rshim_pcie_table[] = {
	{ PCI_DEVICE(TILERA_VENDOR_ID, BLUEFIELD_DEVICE_ID), },
	{ 0, }
};
MODULE_DEVICE_TABLE(pci, rshim_pcie_table);

static struct pci_driver rshim_pcie_driver = {
	.name = "rshim_pcie",
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

MODULE_LICENSE("GPL");
MODULE_AUTHOR("Mellanox Technologies");
MODULE_VERSION("0.6");
