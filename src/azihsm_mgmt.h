/* SPDX-License-Identifier: GPL-2.0 */

#ifndef _LINUX_AZIHSM_MGMT_H
#define _LINUX_AZIHSM_MGMT_H

#include <linux/kernel.h>
#include <linux/pci.h>
#include <linux/dmapool.h>
#include <linux/fs.h>
#include <linux/cdev.h>

#define AZIHSM_MGMT_IF_DEV_NAME "azihsm-mgmt"
#define AZIHSM_MGMT_IF_DEV_COUNT (16 * 65)

/*
 * Per vf context
 * ctrl_id
 *   Controller id of the VF
 * Resource count is set and queried
 * directly from HW
 */
struct azihsm_per_vf_context {
	u32 ctrl_id;
};

struct azihsm_mgmt {
	struct pci_dev *pdev;
	struct cdev cdev;
	unsigned int major;
	unsigned int minor;
	struct device *cdev_dev;

	bool is_pf;

	/*
	 * sriov_pcie_cfg_space_pos
	 * offset in the pcie configuration space
	 */
	int sriov_pcie_cfg_space_pos;
	/*
	 * Value of the control register in the
	 * SRIOV caps
	 */
	u16 pf_sriov_ctrl_reg;
	/* total_vf register */
	u16 pf_sriov_total_vf_reg;
	/* num vf register*/
	u16 pf_sriov_num_vf_reg;

	/* vf context. Length of this array is equal to number of
	 *  vfs configured (num vfs in SRIOV caps)
	 */
	struct azihsm_per_vf_context *vf_context;
};

int azihsm_mgmt_if_init(struct azihsm_mgmt *mgmt);

void azihsm_mgmt_if_deinit(struct azihsm_mgmt *mgmt);

#endif // _LINUX_AZIHSM_MGMT_H
