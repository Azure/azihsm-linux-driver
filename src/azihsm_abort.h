/* SPDX-License-Identifier: GPL-2.0 */

#ifndef _LINUX_AZIHSM_ABORT_H
#define _LINUX_AZIHSM_ABORT_H

#include <linux/kernel.h>
#include <linux/sbitmap.h>
#include <linux/xarray.h>
#include <linux/device.h>
#include <linux/mutex.h>
#include <linux/sysfs.h>
#include <linux/kobject.h>
#include <linux/ktime.h>
#include "azihsm_ioq.h"
#include "azihsm_ctrl.h"
#include "azihsm_hsm_dev_ioctl.h"

// Internal Status For Handling Command Aborts
enum IOQ_CMD_INTERNAL_STS {
	AZIHSM_IOQ_CMD_STS_SUCCESS = 0,
	AZIHSM_IOQ_CMD_STS_ABORTED = 1,
	AZIHSM_IOQ_CMD_STS_ABORT_IN_PROGRESS = 2,
	AZIHSM_IOQ_CMD_STS_QSELECT_FAILED = 3,
	AZIHSM_IOQ_CMD_STS_QDISABLED = 4,
	AZIHSM_IOQ_CMD_STS_UNDEFINED = 5,
	AZIHSM_CTRL_NOT_READY = 6, // Controller is Not in ready state
};

#define ABORT_TYPE_TIMEOUT ABORT_TYPE_RESERVED
#define PERFORM_L1_ABORT(_abort_type) (_abort_type == ABORT_TYPE_TIMEOUT)

/*
 * The timer resolution of the health monitor timer
 */
#define AZIHSM_HEALTH_MON_TIME msecs_to_jiffies(6000)

/* abort status codes*/
#define AZIHSM_IOQ_LEVEL_ONE_ABORT_SUCCESS 0
#define AZIHSM_IOQ_ABORT_IN_PROGRESS 1
#define AZIHSM_IOQ_ABORT_LEVEL_ONE_FAILED 2
#define AZIHSM_ABORT_LEVEL_TWO_FAILED 3

int azihsm_abort(struct azihsm_ctrl *ctrl, struct azihsm_ioq *ioq,
		 struct completion *completion_object, bool crash,
		 u32 abort_type);

/**
 * azihsm_ctrl_cmd_delete_sq(). Delete a SQ
 * @ctrl : Ctrl interface
 * @id : Id of the queue
 */
int azihsm_ctrl_cmd_delete_sq(struct azihsm_ctrl *ctrl, u16 id);

void *azihsm_ioq_store_ctx(struct azihsm_ioq_store *store, u16 tag);

void azihsm_ioq_store_free_ctx(struct azihsm_ioq_store *store, u16 tag);

void azihsm_disable_cp_queues(struct azihsm_ctrl *ctrl);
void azihsm_disable_fp_queues(struct azihsm_ctrl *ctrl);

void azihsm_ctrl_flush_cmds_from_cp_queues(struct azihsm_ctrl *ctrl);
void azihsm_ctrl_flush_cmds_from_fp_queues(struct azihsm_ctrl *ctrl);
void azihsm_disable_all_queues_in_pool(struct device *dev,
				       struct azihsm_ioq_pool *pool);
void azihsm_flush_all_commands_on_ioq(struct azihsm_ctrl *ctrl,
				      struct azihsm_ioq *ioq,
				      const int completion_status);
void azihsm_ctrl_flush_cmds_from_ioqs(struct azihsm_ctrl *ctrl,
				      struct azihsm_ioq_pool *pool);
/*
 * Check whether ioq is disabled or not
 * Caller must be holding the ioq->submit_lock
 * before calling this function
 */
bool azihsm_is_ioq_disabled(struct azihsm_ioq *ioq);

void azihsm_health_monitor(struct work_struct *work);

#endif // _LINUX_AZIHSM_IOQ_H
