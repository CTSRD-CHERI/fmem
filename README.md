# fmem

Tool to access FPGA memory on Stratix10.

This is needed to access FPGA memory from EL1 (kernel) as we are unable to access it from EL0 (userspace) properly.

You will need [this](https://github.com/CTSRD-CHERI/freebsd-morello/blob/stratix10/sys/arm64/intel/fmem.c) device-driver.

Example usage:

    root@stratix10:/home/br/fmem # ./fmem /dev/fmem0 0xe0 w 0x20457000
    (readw)  0xe0 == 0x20050807
    (writew) 0xe0 == 0x20457000
