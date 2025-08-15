/* SPDX-License-Identifier: GPL-2.0 */
#ifndef _LINUX_AZIHSM_HSM_DEV_H
#define _LINUX_AZIHSM_HSM_DEV_H

#include <linux/idr.h>
#include <linux/uaccess.h>
#include <linux/version.h>

struct azihsm_hsm;

int azihsm_hsm_dev_init(struct azihsm_hsm *hsm, const bool abort);
int azihsm_hsm_dev_alloc_minor(struct azihsm_hsm *hsm);
int azihsm_hsm_dev_dealloc_minor(struct azihsm_hsm *hsm);

void azihsm_hsm_dev_deinit(struct azihsm_hsm *hsm, const bool abort);

#endif //_LINUX_AZIHSM_HSM_DEV_H
