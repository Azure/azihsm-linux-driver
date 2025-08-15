/* SPDX-License-Identifier: GPL-2.0 */
#ifndef _LINUX_AZIHSM_MGMT_DEV_IOCTL_H
#define _LINUX_AZIHSM_MGMT_DEV_IOCTL_H

#include <linux/ioctl.h>
#include <linux/types.h>
#include "azihsm_ctrl_dev_ioctl.h"

#define AZIHSM_MGMT_STATUS_SUCCESS 0
#define AZIHSM_MGMT_STATUS_NOT_PF 1
#define AZIHSM_MGMT_STATUS_INVALID_VF_IDX 2
#define AZIHSM_MGMT_STATUS_RES_CNT_ALREADY_SET 3
#define AZIHSM_MGMT_STATUS_SET_RES_CNT_FAILED 4
#define AZIHSM_MGMT_STATUS_RES_CNT_NOT_SET 5
#define AZIHSM_IOCTL_MGMT_STATUS_DEVICE_INFO_INVALID_BUF_SIZE 6
#define AZIHSM_IOCTL_MGMT_STATUS_GET_RES_CNT_FAILED 7

struct azihsm_mgmt_if_res_cnt {
	__u32 argsz;
	__u16 vf_idx;
	__u16 res_cnt;
	__u32 status;
};

/*
 * IOCTL AZIHSM_CTRL_DEV_IOCTL_SET_RES_CNT to set resource count
 *  for a given VF
 *  This ioctl is only available for management plane applications
 * This ioctl is only valid for a PF
 */

#define AZIHSM_MGMT_IF_DEV_IOCTL_SET_RES_CNT \
	_IOWR('A', 0x2, struct azihsm_mgmt_if_res_cnt)

/*
 * IOCTL AZIHSM_MGMT_IF_DEV_IOCTL_GET_RES_CNT
 * returns the resource count allocated for a VF
 * Only PF (for now) can issue this call.
 * Only available on the management interface
 */
#define AZIHSM_MGMT_IF_DEV_IOCTL_GET_RES_CNT \
	_IOWR('A', 0x3, struct azihsm_mgmt_if_res_cnt)

struct azihsm_mgmt_if_get_vf_count {
	__u32 argsz;
	__u16 vf_count;
};

/*
 * AZIHSM_MGMT_IF_DEV_IOCTL_GET_VF_COUNT
 * Returns the number of VFs configured in the PF
 * Only available on the management interface
 * Only PF driver can issue this ioctl
 */
#define AZIHSM_MGMT_IF_DEV_IOCTL_GET_VF_COUNT \
	_IOWR('A', 0x4, struct azihsm_mgmt_if_get_vf_count)

/*
 * AZIHSM_MGMT_IF_DEV_IOCTL_GET_DEV_INFO
 * Available on the management interface
 * Only PF can issue this call.
 *
 * Note that there is a similar ioctl available
 * on the general interface that a VF driver can
 * call
 */
#define AZIHSM_MGMT_IF_DEV_IOCTL_GET_DEV_INFO \
	_IOWR('A', 0x5, struct azihsm_ctrl_dev_info)
#endif //_LINUX_AZIHSM_MGMT_DEV_IOCTL_H
