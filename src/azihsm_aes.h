/* SPDX-License-Identifier: GPL-2.0 */
#ifndef _LINUX_AZIHSM_AES_H
#define _LINUX_AZIHSM_AES_H

#include <linux/kernel.h>
#include <linux/xarray.h>
#include <linux/cdev.h>
#include <linux/interrupt.h>
#include <linux/kobject.h>
#include <linux/pci.h>

#include "azihsm_ioq_pool.h"

struct azihsm_ctrl;
#define AZIHSM_AES_DEV_NAME "azihsm-aes"

#define AES_MIN_ID 256
extern int azihsm_num_aes_slots;
#define AES_IOQ_SZ (azihsm_num_aes_slots)
/* For now we are hardcoding the MSIx start to 1
 * assuming that we will always get 32 MSIx. This
 * will change if we need to be able to work with
 * less than 32 MSIx vectors.
 */

#define AEX_MSIX_START 16
struct azihsm_aes_cfg {
	struct azihsm_ctrl *ctrl;
	u16 ioq_id_start;
	u16 ioq_size;
	void *ioq_db;
	u16 msix_start;
	u16 msix_max_cnt;
};

struct azihsm_aes {
	struct azihsm_ctrl *ctrl;
	struct pci_dev *pdev;
	struct azihsm_ioq_pool ioq_pool;
	struct mutex aes_lock;
	/*
	 * @dev_kobj: Pointer to kobject
	 * that we get after creating kobject
	 * and sysfs file
	 * This is specific to aes perf counters
	 */
	struct kobject *dev_kobj;
};

int azihsm_aes_init(struct azihsm_aes *aes, struct azihsm_aes_cfg *aes_cfg,
		    const bool abort);

void azihsm_aes_deinit(struct azihsm_aes *aes, const bool abort);

#endif // _LINUX_AZIHSM_AES_H
