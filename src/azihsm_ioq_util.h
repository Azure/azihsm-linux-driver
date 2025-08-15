/* SPDX-License-Identifier: GPL-2.0 */
#ifndef _LINUX_AZIHSM_IOQ_UTIL_H_
#define _LINUX_AZIHSM_IOQ_UTIL_H_

#include <linux/kernel.h>
#include <linux/completion.h>
#include "azihsm_ioq_pool.h"

struct azihsm_ioq *azihsm_ioq_find_queue_for_submission(
	struct azihsm_ioq_pool *ioq_pool, const int ioq_pool_start_id,
	struct device *dev, struct mutex *pool_lock);

#endif
