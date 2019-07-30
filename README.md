                  BlueField Rshim Host Driver

The rshim driver provides a way to access the rshim resources on
the BlueField target from external host machine. The current version
implements virtual console and virtual network interface over rshim.
It also provides rshim register access and some tools to manage the
target, such as doing soft-reset, etc.

*) Source Code

The source code can be found under <BF_INSTALL>/src/drivers/rshim,
where BF_INSTALL is the installation location of the BlueField
release tarball.

*) Build & Install

  # Need to be root to install the driver
  cd <BF_INSTALL>/src/drivers/rshim/
  make -C /lib/modules/`uname -r`/build M=$PWD
  make -C /lib/modules/`uname -r`/build M=$PWD INSTALL_MOD_DIR=extra/rshim modules_install

  The following kernel modules will be installed:

  Common modules:
    rshim.ko           rshim common code including console support
    rshim_net.ko       rshim network driver

  Different Backends:
    rshim_usb.ko       rshim USB backend
    rshim_pcie.ko      rshim PCIe backend with firmware burnt
    rshim_pcie_lf.ko   rshim PCIe backend in livefish mode

*) Device Files

  Each rshim backend will create a directory /dev/rshim<N>/ with the
  following files. '<N>' is the device id, which could be 0, 1, etc.

  - /dev/rshim<N>/boot
  Boot device file used to send boot stream to the ARM side, for example,
    cat install.bfb > /dev/rshim<N>/boot

  - /dev/rshim<N>/console
  Console device, which can be used by console tools to connect to the ARM side,
  such as "screen /dev/rshim<N>/console".

  - /dev/rshim<N>/rshim
  Device file used to access rshim register space. When reading / writing to
  this file, encode the offset as "((rshim_channel << 16) | register_offset)".

  - /dev/rshim<N>/misc:
  Key/Value pairs used to read/write misc information. For example,
    # Dump the content.
    cat /dev/rshim<N>/misc
      BOOT_MODE 1                   # eMMC boot mode (0:USB/PCIe, 1: eMMC)
      SW_RESET  0                   # Set to 1 to initiate SW RESET
      DRV_NAME  rshim_usb           # Backend driver name (display-only)

    # Turn on the 'rshim_adv_cfg' flag could display more information like
    # below.
    echo 1 > /sys/module/rshim/parameters/rshim_adv_cfg
    cat /dev/rshim<N>/misc
      ...
      PEER_MAC  00:1a:ca:ff:ff:01   # Target-side MAC address
      PXE_ID    0x01020304          # PXE DHCP-client-identifier

    # Initiate a SW reset.
    # It'll depend on the 'BOOT_MODE' to boot from USB/PCIe or eMMC.
    echo "SW_RESET 1" > /dev/rshim<N>/misc

    The 'PEER_MAC' attribute can be used to display/set the target-side MAC
    address of the rshim network interface. It works when the target-side is in
    UEFI BootManager or in Linux where the tmfifo has been loaded. The new MAC
    address will take effect in next boot.

*) What if both USB and PCIe access are enabled

  When both USB and PCIe are enabled, the related kernel modules rshim_usb.ko
  and rshim_pcie.ko will be loaded automatically. By default, the driver will
  pick one to access rshim depending on which one is detected first.

  /etc/modprobe.d/rshim.conf can be used to specify which rshim driver to use,
  which will disable the 'auto-select' behavior.

     # /etc/modprobe.d/rshim.conf
     #
     # Uncomment the 'options' line below to specify a driver to use (rshim_usb,
     # rshim_pcie, or rshim_pcie_lf). If not specified, the first available one
     # will be selected by default.
     #
     # options rshim backend_driver=rshim_usb

*) Multiple Boards Support

  Multiple boards could connect to the same host machine. Each of them has its
  own device directory /dev/rshim<N>. Below are some guidelines how to set up
  rshim networking properly in such case.

  - Each target should load only one backend (usb, pcie or pcie_lf).

  - The host rshim network interface should have different MAC address and IP
    address, which can be configured with ifconfig like below or save it in
    configuration.
      ifconfig tmfifo_net0 192.168.100.2/24 hw ether 02:02:02:02:02:02

  - The ARM side tmfifo interface should have unique MAC and IP as well, which
    can be done in the console.

*) How to change the MAC address of the ARM side interface permanently

  # Below is an example to change the MAC address from 00:1a:ca:ff:ff:01 to
  # 00:1a:ca:ff:ff:10.

  echo 1 > /sys/module/rshim/parameters/rshim_adv_cfg
  cat /dev/rshim<N>/misc
    ...
    PEER_MAC  00:1a:ca:ff:ff:01   # This is the current configured MAC address
    ...
  echo "PEER_MAC 00:1a:ca:ff:ff:10" > /dev/rshim<N>/misc
