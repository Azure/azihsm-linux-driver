/* SPDX-License-Identifier: GPL-2.0 */

#ifndef _LINUX_AZIHSM_MGMT_IF_DEV_H
#define _LINUX_AZIHSM_MGMT_IF_DEV_H

#include <linux/idr.h>
#include <linux/uaccess.h>
#include <linux/version.h>

struct azihsm_mgt;

int azihsm_mgmt_if_dev_init(struct azihsm_mgmt *mgmt, const bool abort);

void azihsm_mgmt_if_dev_deinit(struct azihsm_mgmt *mgmt, const bool abort);

#endif //_LINUX_AZIHSM_CTRL_DEV_H
