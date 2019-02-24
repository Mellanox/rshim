#
# Build:
#   make -C /lib/modules/`uname -r`/build M=$PWD [clean]
#
# Install (as root):
#   make -C /lib/modules/`uname -r`/build M=$PWD INSTALL_MOD_DIR=extra/rshim modules_install
#

obj-m := rshim.o rshim_net.o rshim_usb.o rshim_pcie.o rshim_pcie_lf.o
