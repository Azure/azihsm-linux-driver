/* SPDX-License-Identifier: GPL-2.0 */

#ifndef _LINUX_AZIHSM_IOQ_PERF_H
#define _LINUX_AZIHSM_IOQ_PERF_H

#include "azihsm_hsm.h"
#include "azihsm_hsm_cmd.h"
#include "azihsm_hsm_dev_ioctl.h"
#include "azihsm_abort.h"
#include <linux/dmapool.h>
#include "azihsm_ioq_util.h"

void azihsm_ioq_perf_update_cntrs_before_submission(struct azihsm_hsm *hsm,
						    struct azihsm_ioq *ioq);

void azihsm_ioq_perf_update_cntrs_after_submission(struct azihsm_hsm *hsm,
						   struct azihsm_ioq *ioq,
						   ktime_t *submission_time,
						   ktime_t *completion_time);

#endif // _LINUX_AZIHSM_IOQ_PERF_H
