
# Azure Integrated HSM Linux Driver

---

## Overview

This directory contains the Linux kernel driver source code for the **Azure Integrated HSM** Device.

---

## Build Instructions

### Prerequisites

- Linux kernel headers
- GCC, Make, and build essentials

### Build Clean Option
``` 
cd src
make clean
```

### Build Steps
```bash
cd src
export KERNEL_SRC= "Path To Kernel Headers Directory"
make

#### Example Buliding For 6.5.0-1023-azure
    cd src
    export KERNEL_SRC=/usr/src/linux-headers-6.5.0-1023-azure
    make
    ==>> This will generate a AziHsm.ko file.
```

---

## License

This driver is licensed under **GPLv2-or-later**. See `LICENSE.md` for details.

---

## Contributing

All contributors must comply with Microsoft’s Open Source Release Policy.

---

## Trademarks 
This project may contain trademarks or logos for projects, products, or services. Authorized use of Microsoft trademarks or logos is subject to and must follow Microsoft’s Trademark & Brand Guidelines. Use of Microsoft trademarks or logos in modified versions of this project must not cause confusion or imply Microsoft sponsorship. Any use of third-party trademarks or logos are subject to those third-party’s policies.
