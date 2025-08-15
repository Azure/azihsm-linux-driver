/* SPDX-License-Identifier: GPL-2.0 */

#ifndef _LINUX_AZIHSM_IOQ_POOL_H
#define _LINUX_AZIHSM_IOQ_POOL_H

#include <linux/kernel.h>
#include <linux/xarray.h>
#include <linux/cdev.h>
#include <linux/interrupt.h>
#include <linux/pci.h>
#include <linux/kobject.h>
#include <linux/sysfs.h>

#include "azihsm_ioq.h"

struct azihsm_ctrl;
struct azihsm_ioq_pool;

struct azihsm_ioq_pool_irq_ctx {
	struct azihsm_ioq_pool *pool;
	int irq;
	struct tasklet_struct tasklet;
	struct xarray ioqs;
};

struct azihsm_ioq_pool_cfg {
	struct azihsm_ctrl *ctrl;
	struct pci_dev *pdev;
	const char *name;
	enum azihsm_ioq_type ioq_type;
	u16 ioq_id_start;
	u16 ioq_size;
	void *ioq_db;
	struct azihsm_ioq_ops *ioq_ops;
	u16 msix_start;
	u16 msix_max_cnt;
};

struct azihsm_ioq_pool {
	struct azihsm_ctrl *ctrl;
	struct pci_dev *pdev;
	const char *name;
	enum azihsm_ioq_type ioq_type;
	/*
	 * ioq_select_id is used to
	 * select the next SQ to send
	 * the command out on
	 */
	u16 ioq_select_id;
	u16 ioq_start_idx;
	u16 ioq_size;
	void *ioq_db;
	struct azihsm_ioq_ops *ioq_ops;
	u16 ioq_max_cnt;
	u16 ioq_cnt;
	u16 msix_start;
	u16 msix_max_cnt;
	u16 msix_cnt;
	struct xarray irqs;
	struct xarray ioqs;

	struct kobject *parent_kobj;
};

int azihsm_ioq_pool_init(struct azihsm_ioq_pool *ioq_pool,
			 struct azihsm_ioq_pool_cfg *cfg);

void azihsm_ioq_pool_deinit(struct azihsm_ioq_pool *ioq_pool, const bool abort);

u16 azihsm_ioq_pool_queue_cnt(struct azihsm_ioq_pool *ioq_pool);

int azihsm_ioq_pool_submit_cmd(struct azihsm_ioq_pool *ioq_pool, u16 id,
			       void *cmd);
int azihsm_ioq_pool_create_queue_pair(struct azihsm_ctrl *ctrl,
				      struct azihsm_ioq *ioq);
void azihsm_ioq_pool_delete_queue_pair(struct azihsm_ctrl *ctrl,
				       struct azihsm_ioq *ioq,
				       const bool abort);

bool azihsm_sq_is_full(struct azihsm_ioq_sq *sq);

#endif // _LINUX_AZIHSM_IOQ_POOL_H
