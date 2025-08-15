/* SPDX-License-Identifier: GPL-2.0 */

#ifndef _LINUX_AZIHSM_H
#define _LINUX_AZIHSM_H

#include <linux/kernel.h>
#include <linux/pci.h>
#include "azihsm_ctrl.h"
#include "azihsm_mgmt.h"
#include "azihsm_mgmt_if_dev.h"
#include "azihsm_log.h"
#include "azihsm_abort.h"

#define AZIHSM_DRIVER_VERSION "2.1.0"

struct azihsm_dev {
	struct pci_dev *pdev;
	void __iomem *bar0;
	void __iomem *bar2;
	void __iomem *bar4;
	size_t irq_cnt;
	struct azihsm_ctrl ctrl;
	struct azihsm_mgmt mgmt;
};

int __init azihsm_ctrl_dev_mod_init(void);
void __exit azihsm_ctrl_dev_mod_exit(void);

int __init azihsm_hsm_dev_mod_init(void);
void __exit azihsm_hsm_dev_mod_exit(void);

int __init azihsm_aes_dev_mod_init(void);

int __init azihsm_mgmt_if_dev_mod_init(void);
void __exit azihsm_mgmt_if_dev_mod_exit(void);

#endif // _LINUX_AZIHSM_H
