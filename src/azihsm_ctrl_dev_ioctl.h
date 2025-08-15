/* SPDX-License-Identifier: GPL-2.0 */

#ifndef _LINUX_AZIHSM_CTRL_DEV_IOCTL_H
#define _LINUX_AZIHSM_CTRL_DEV_IOCTL_H

#include <linux/ioctl.h>
#include <linux/types.h>

#define AZIHSM_CTRL_DEV_INFO_PI_LEN (32 + 1)
#define AZIHSM_CTRL_DEV_INFO_SN_LEN (32 + 1)
#define AZIHSM_CTRL_DEV_INFO_MN_LEN (4 + 1)
#define AZIHSM_CTRL_DEV_INFO_FR_LEN (32 + 1)
#define AZIHSM_CTRL_DEV_INFO_DR_LEN (32 + 1)

#define AZIHSM_CTRL_DEV_INFO_ENTROPY_LENGTH 32

struct azihsm_ctrl_dev_info {
	__u32 argsz;
	__u16 id;
	char pci_info[AZIHSM_CTRL_DEV_INFO_PI_LEN];
	char serial_num[AZIHSM_CTRL_DEV_INFO_SN_LEN];
	char model_num[AZIHSM_CTRL_DEV_INFO_MN_LEN];
	char firmware_rev[AZIHSM_CTRL_DEV_INFO_FR_LEN];
	char driver_rev[AZIHSM_CTRL_DEV_INFO_DR_LEN];
	char device_entropy[AZIHSM_CTRL_DEV_INFO_ENTROPY_LENGTH];
};

struct azihsm_ctrl;
int azihsm_ctrl_dev_get_dev_info(struct azihsm_ctrl *ctrl,
				 struct azihsm_ctrl_dev_info *dev_info);

#endif //_LINUX_AZIHSM_CTRL_DEV_IOCTL_H
