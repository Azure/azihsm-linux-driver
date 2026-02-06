
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

This project welcomes contributions and suggestions.  Most contributions require you to agree to a
Contributor License Agreement (CLA) declaring that you have the right to, and actually do, grant us
the rights to use your contribution. For details, visit https://cla.opensource.microsoft.com.

When you submit a pull request, a CLA bot will automatically determine whether you need to provide
a CLA and decorate the PR appropriately (e.g., status check, comment). Simply follow the instructions
provided by the bot. You will only need to do this once across all repos using our CLA.

This project has adopted the [Microsoft Open Source Code of Conduct](https://opensource.microsoft.com/codeofconduct/).
For more information see the [Code of Conduct FAQ](https://opensource.microsoft.com/codeofconduct/faq/) or
contact [opencode@microsoft.com](mailto:opencode@microsoft.com) with any additional questions or comments.

## Trademarks

This project may contain trademarks or logos for projects, products, or services. Authorized use of Microsoft
trademarks or logos is subject to and must follow
[Microsoft's Trademark & Brand Guidelines](https://www.microsoft.com/en-us/legal/intellectualproperty/trademarks/usage/general).
Use of Microsoft trademarks or logos in modified versions of this project must not cause confusion or imply Microsoft sponsorship.
Any use of third-party trademarks or logos are subject to those third-party's policies.
