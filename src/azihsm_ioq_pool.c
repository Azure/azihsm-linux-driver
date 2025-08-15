// SPDX-License-Identifier: GPL-2.0

#include "azihsm_ioq_pool.h"
#include "azihsm_ctrl_cmd.h"
#include "azihsm_log.h"

#define AZIHSM_IOQ_POOL_MAX_QUEUE_CNT 128

static int azihsm_ioq_pool_get_ioq_cnt(struct azihsm_ioq_pool *pool,
				       u16 *queue_cnt)
{
	int err;
	u16 cnt = AZIHSM_IOQ_POOL_MAX_QUEUE_CNT;

	switch (pool->ioq_type) {
	case AZIHSM_IOQ_TYPE_CTRL:
		*queue_cnt = 1;
		break;

	case AZIHSM_IOQ_TYPE_HSM:
		err = azihsm_ctrl_cmd_set_hsm_queue_cnt(pool->ctrl, &cnt);
		if (err)
			goto err;
		*queue_cnt = cnt;
		break;

	case AZIHSM_IOQ_TYPE_AES:
		err = azihsm_ctrl_cmd_set_aes_queue_cnt(pool->ctrl, &cnt);
		if (err)
			goto err;
		*queue_cnt = cnt;
		break;

	default:
		err = -EINVAL;
		goto err;
	}

	return 0;
err:
	return err;
}

static irqreturn_t azihsm_ioq_pool_irq(int irq, void *data)
{
	struct azihsm_ioq_pool_irq_ctx *irq_ctx = data;

	tasklet_schedule(&irq_ctx->tasklet);
	return IRQ_HANDLED;
}

static void azihsm_ioq_pool_soft_irq(unsigned long data)
{
	struct azihsm_ioq_pool_irq_ctx *irq_ctx =
		(struct azihsm_ioq_pool_irq_ctx *)data;
	unsigned long index;
	struct azihsm_ioq *ioq;

	xa_for_each(&irq_ctx->ioqs, index, ioq) {
		azihsm_ioq_complete_cmds(ioq);
	}
}

static void azihsm_ioq_pool_free_irq(struct azihsm_ioq_pool *pool, int vec)
{
	struct azihsm_ioq_pool_irq_ctx *irq_ctx = xa_load(&pool->irqs, vec);

	AZIHSM_LOG_ENTRY("%s pool:%p freeing irq:%d\n", __func__, pool, vec);

	if (irq_ctx == NULL) {
		AZIHSM_LOG_ERROR(
			"[ERROR] %s pool:%p irq context not found for vec:%d\n",
			__func__, pool, vec);
		return;
	}

	xa_erase(&pool->irqs, vec);
	pci_free_irq(pool->pdev, vec, irq_ctx);
	xa_destroy(&irq_ctx->ioqs);
	kfree(irq_ctx);
	AZIHSM_LOG_EXIT("%s pool:%p freeing irq:%d\n", __func__, pool, vec);
}

static int azihsm_ioq_pool_alloc_irq(struct azihsm_ioq_pool *pool, int vec)
{
	int err;
	struct azihsm_ioq_pool_irq_ctx *irq_ctx;
	const struct device *dev = &pool->pdev->dev;

	AZIHSM_DEV_LOG_ENTRY(dev, "%s pool:%p vec:%d\n", __func__, pool, vec);

	irq_ctx = kzalloc(sizeof(*irq_ctx), GFP_KERNEL);
	if (!irq_ctx) {
		err = -ENOMEM;
		goto alloc_fail;
	}

	tasklet_init(&irq_ctx->tasklet, azihsm_ioq_pool_soft_irq,
		     (unsigned long)irq_ctx);

	xa_init(&irq_ctx->ioqs);

	err = pci_request_irq(pool->pdev, vec, azihsm_ioq_pool_irq, NULL,
			      irq_ctx, "%s-%d", pool->name, vec);
	if (err) {
		AZIHSM_DEV_LOG_ERROR(
			dev, "pool:%p request irq failed for %s msix=%d", pool,
			pool->name, vec);
		goto request_irq_fail;
	}

	err = xa_insert(&pool->irqs, vec, irq_ctx, GFP_KERNEL);
	if (err) {
		AZIHSM_DEV_LOG_ERROR(
			dev, "pool:%p storing irq ctx failed for %s msix=%d",
			pool, pool->name, vec);
		goto ctx_insert_fail;
	}

	AZIHSM_DEV_LOG_EXIT(dev, "%s pool:%p vec:%d\n", __func__, pool, vec);

	return 0;

ctx_insert_fail:
	pci_free_irq(pool->pdev, vec, irq_ctx);
request_irq_fail:
	kfree(irq_ctx);
alloc_fail:
	return err;
}

static void azihsm_ioq_pool_free_irqs(struct azihsm_ioq_pool *pool)
{
	int id = 0;
	const int msix_cnt = pool->msix_cnt;

	AZIHSM_LOG_ENTRY("%s pool:%p msix_cnt:%d\n", __func__, pool, msix_cnt);
	for (; id < msix_cnt; id++) {
		int vec = id + pool->msix_start;

		azihsm_ioq_pool_free_irq(pool, vec);
		pool->msix_cnt -= 1;
	}
	AZIHSM_LOG_EXIT("%s pool:%p msix_cnt:%d\n", __func__, pool, msix_cnt);
}

static int azihsm_ioq_pool_alloc_irqs(struct azihsm_ioq_pool *pool)
{
	int err;
	int vec_cnt = MCR_MIN(pool->msix_max_cnt, pool->ioq_max_cnt);
	int id = 0;
	const struct device *dev = &pool->pdev->dev;

	pool->msix_cnt = 0;

	AZIHSM_DEV_LOG_ENTRY(dev, "%s pool:%p vector count:%d\n", __func__,
			     pool, vec_cnt);

	for (; id < vec_cnt; id++) {
		int vec = id + pool->msix_start;

		AZIHSM_DEV_LOG_INFO(dev, "creating irq %d for %s", vec,
				    pool->name);
		err = azihsm_ioq_pool_alloc_irq(pool, vec);
		if (err)
			goto alloc_irq_fail;
		pool->msix_cnt += 1;
	}

	AZIHSM_DEV_LOG_EXIT(dev, "%s pool:%p\n", __func__, pool);

	return 0;

alloc_irq_fail:
	azihsm_ioq_pool_free_irqs(pool);
	return err;
}

int azihsm_ioq_pool_create_queue_pair(struct azihsm_ctrl *ctrl,
				      struct azihsm_ioq *ioq)
{
	int err;
	dma_addr_t cq_addr = azihsm_ioq_cq_dma_addr(ioq);
	dma_addr_t sq_addr = azihsm_ioq_sq_dma_addr(ioq);

	AZIHSM_LOG_ENTRY("[ENTRY] %s ioq:%p\n", __func__, ioq);

	err = azihsm_ctrl_cmd_create_cq(ctrl, cq_addr, ioq->id, ioq->size,
					ioq->vec);
	if (err) {
		AZIHSM_LOG_ERROR("%s ioq:%p create_cq id:%d size:%d failed\n",
				 __func__, ioq, ioq->id, ioq->size);
		goto create_cq_fail;
	}

	err = azihsm_ctrl_cmd_create_sq(ctrl, sq_addr, ioq->id, ioq->id,
					ioq->size, ioq->pri);
	if (err) {
		AZIHSM_LOG_ERROR(
			"%s ioq:%p create_sq id:%d cq id:%d size:%d pri:%d failed\n",
			__func__, ioq, ioq->id, ioq->id, ioq->size, ioq->pri);
		goto create_sq_fail;
	}

	AZIHSM_LOG_EXIT("[EXIT] %s ioq:%p\n", __func__, ioq);
	return 0;

create_sq_fail:
	azihsm_ctrl_cmd_delete_cq(ctrl, ioq->id);
create_cq_fail:
	return err;
}

void azihsm_ioq_pool_delete_queue_pair(struct azihsm_ctrl *ctrl,
				       struct azihsm_ioq *ioq, const bool abort)
{
	AZIHSM_LOG_ENTRY("%s ioq:%p id:%d abort:%d\n", __func__, ioq, ioq->id,
			 abort);

	/* delete the sysfs entries for the sq */
	if (ioq->sq.sq_sysfs_kobj) {
		sysfs_remove_group(ioq->sq.sq_sysfs_kobj,
				   &ioq->sq.sq_attribute_group);
		kobject_put(ioq->sq.sq_sysfs_kobj);
		ioq->sq.sq_sysfs_kobj = NULL;
	}

	if (!abort) {
		//
		// We are not in the abort path, delete the Queue from Hardware First
		// When we come from level-2 abort here, we will never fire this command
		// becuase the Level-2 abort will disable the controller. Which will
		// delete all these queues.
		//
		azihsm_ctrl_cmd_delete_sq(ctrl, ioq->id);
		azihsm_ctrl_cmd_delete_cq(ctrl, ioq->id);

	} else {
		AZIHSM_LOG_INFO(
			"[%s] ioq:%p id:%d abort:%d Skipping Firing IOQ Del To H/w\n",
			__func__, ioq, ioq->id, abort);
	}

	// Then cleanup the resources allocated for the Queue
	azihsm_ioq_deinit(ioq);

	AZIHSM_LOG_EXIT("%s ioq:%p id:%d\n", __func__, ioq, ioq->id);
}

static int azihsm_ioq_pool_create_ioq(struct azihsm_ioq_pool *pool, u16 ioq_id,
				      u16 vec,
				      enum azihsm_ioq_pri azihsm_priority)
{
	int err;
	struct azihsm_ioq *ioq;
	struct azihsm_ioq_cfg ioq_cfg = { 0 };
	struct azihsm_ioq_pool_irq_ctx *irq_ctx;
	const struct device *dev = &pool->pdev->dev;

	AZIHSM_DEV_LOG_ENTRY(dev, "%s pool:%p ioq_id:%d vec:%d\n", __func__,
			     pool, ioq_id, vec);

	ioq = kzalloc(sizeof(*ioq), GFP_KERNEL);
	if (!ioq)
		return -ENOMEM;

	ioq_cfg.id = ioq_id;
	ioq_cfg.size = pool->ioq_size;
	ioq_cfg.vec = vec;
	// TODO: This needs to be converted to QOS policy as AES queues have
	// 1 high priority and 1 low priority per resource group
	ioq_cfg.pri = azihsm_priority;
	ioq_cfg.dev = &pool->pdev->dev;
	ioq_cfg.db = pool->ioq_db;
	ioq_cfg.ops = pool->ioq_ops;
	ioq_cfg.ioq_type = pool->ioq_type;
	ioq_cfg.parent_sysfs_kobj = pool->parent_kobj;

	err = azihsm_ioq_init(ioq, &ioq_cfg);
	if (err) {
		AZIHSM_DEV_LOG_ERROR(
			dev,
			"[ERROR] %s pool:%p azihsm_ioq_init failed err:%d\n",
			__func__, pool, err);
		goto ioq_init_fail;
	}

	err = azihsm_ioq_pool_create_queue_pair(pool->ctrl, ioq);
	if (err) {
		AZIHSM_DEV_LOG_ERROR(
			dev,
			"[ERROR] %s pool:%p azihsm_ioq_pool_create_queue_pair failed err:%d\n",
			__func__, pool, err);
		goto create_queue_pair_fail;
	}

	err = xa_insert(&pool->ioqs, ioq_id, ioq, GFP_KERNEL);
	if (err) {
		AZIHSM_DEV_LOG_ERROR(dev, "storing ioq failed for %s id=%d",
				     pool->name, ioq_id);
		goto ioq_insert_fail;
	}

	irq_ctx = xa_load(&pool->irqs, vec);
	if (!irq_ctx) {
		AZIHSM_DEV_LOG_ERROR(
			dev, "[ERROR] %s pool:%p xa_load failed vec:%d\n",
			__func__, pool, vec);
		err = -ENOENT;
		goto irq_ctx_fail;
	}

	err = xa_insert(&irq_ctx->ioqs, ioq_id, ioq, GFP_KERNEL);
	if (err) {
		AZIHSM_DEV_LOG_ERROR(
			dev, "storing ioq in irq_ctx failed for %s id=%d",
			pool->name, ioq_id);
		goto ioq_irq_insert_fail;
	}

	AZIHSM_DEV_LOG_EXIT(dev, "%s pool:%p\n", __func__, pool);

	return 0;

ioq_irq_insert_fail:
irq_ctx_fail:
	xa_erase(&pool->irqs, ioq_id);
ioq_insert_fail:
	//
	// This is a failure condition local to this function,
	// We will always pass abort as false here, becuase we
	// want to do the whole cleanup.
	//
	azihsm_ioq_pool_delete_queue_pair(pool->ctrl, ioq, false);

create_queue_pair_fail:
	if (ioq->sq.sq_sysfs_kobj) {
		sysfs_remove_group(ioq->sq.sq_sysfs_kobj,
				   &ioq->sq.sq_attribute_group);
		kobject_put(ioq->sq.sq_sysfs_kobj);
		ioq->sq.sq_sysfs_kobj = NULL;
	}
	kfree(ioq);
ioq_init_fail:
	return err;
}

static void azihsm_ioq_pool_delete_ioq(struct azihsm_ioq_pool *pool, u16 ioq_id,
				       const bool abort)
{
	struct azihsm_ioq *ioq;
	struct azihsm_ioq_pool_irq_ctx *irq_ctx;

	AZIHSM_LOG_ENTRY("%s pool:%p ioq_id:%d\n", __func__, pool, ioq_id);

	ioq = xa_load(&pool->ioqs, ioq_id);
	if (ioq == NULL) {
		AZIHSM_LOG_ERROR("%s pool:%p ioq_id:%d xa_load() failed\n",
				 __func__, pool, ioq_id);
		return;
	}

	irq_ctx = xa_load(&pool->irqs, ioq->vec);
	if (irq_ctx == NULL) {
		AZIHSM_LOG_ERROR("%s pool:%p xa_load() on vec:%d failed\n",
				 __func__, pool, ioq->vec);
		return;
	}

	xa_erase(&irq_ctx->ioqs, ioq_id);
	xa_erase(&pool->ioqs, ioq_id);
	azihsm_ioq_pool_delete_queue_pair(pool->ctrl, ioq, abort);
	kfree(ioq);
	AZIHSM_LOG_EXIT("%s pool:%p ioq_id:%d\n", __func__, pool, ioq_id);
}

static void azihsm_ioq_pool_delete_ioqs(struct azihsm_ioq_pool *pool,
					const bool abort)
{
	u16 id = 0;
	const u16 queue_cnt = pool->ioq_cnt;
	int ioq_id;

	AZIHSM_LOG_ENTRY("%s pool:%p queue_cnt:%d abort:%d\n", __func__, pool,
			 queue_cnt, abort);

	for (; id < queue_cnt; id++) {
		ioq_id = id + pool->ioq_start_idx;
		azihsm_ioq_pool_delete_ioq(pool, ioq_id, abort);
	}
	pool->ioq_cnt = 0;
	AZIHSM_LOG_EXIT("%s pool:%p queue_cnt:%d\n", __func__, pool, queue_cnt);
}

static int azihsm_ioq_pool_create_ioqs(struct azihsm_ioq_pool *pool)
{
	int err;
	u16 id = 0;
	enum azihsm_ioq_pri pri;

	const struct device *dev = &pool->pdev->dev;

	AZIHSM_DEV_LOG_ENTRY(dev, "%s pool:%p\n", __func__, pool);

	pool->ioq_cnt = 0;

	for (; id < pool->ioq_max_cnt; id++) {
		int ioq_id = id + pool->ioq_select_id;
		int vec = (id % pool->msix_cnt) + pool->msix_start;

		//
		//Keep flipping the priority between low and high
		//
		pri = (!(ioq_id % 2)) ? AZIHSM_IOQ_PRI_LOW :
					AZIHSM_IOQ_PRI_HIGH;

		AZIHSM_DEV_LOG_INFO(
			dev,
			"creating queue id %d priority %d with irq %d for %s",
			ioq_id, pri, vec, pool->name);

		err = azihsm_ioq_pool_create_ioq(pool, ioq_id, vec, pri);
		if (err) {
			AZIHSM_DEV_LOG_ERROR(
				dev,
				"[ERROR] %s pool:%p azihsm_ioq_pool_create_ioq failed err:%d\n",
				__func__, pool, err);
			goto create_ioq_fail;
		}
		pool->ioq_cnt += 1;
	}
	AZIHSM_DEV_LOG_EXIT(dev, "%s pool:%p\n", __func__, pool);
	return 0;

create_ioq_fail:
	return err;
}

int azihsm_ioq_pool_init(struct azihsm_ioq_pool *pool,
			 struct azihsm_ioq_pool_cfg *cfg)
{
	int err;
	u16 ioq_cnt;

	pool->ctrl = cfg->ctrl;
	pool->pdev = cfg->pdev;
	pool->name = cfg->name;
	pool->ioq_type = cfg->ioq_type;
	pool->ioq_select_id = cfg->ioq_id_start;
	pool->ioq_start_idx = pool->ioq_select_id;
	pool->ioq_size = cfg->ioq_size;
	pool->ioq_db = cfg->ioq_db;
	pool->ioq_ops = cfg->ioq_ops;
	pool->msix_start = cfg->msix_start;
	pool->msix_max_cnt = cfg->msix_max_cnt;

	AZIHSM_LOG_ENTRY(
		"%s pool:%p type:%d start_id:%d size:%d msix_start:%d msix_max_cnt:%d\n",
		__func__, pool, cfg->ioq_type, cfg->ioq_id_start, cfg->ioq_size,
		cfg->msix_start, cfg->msix_max_cnt);

	err = azihsm_ioq_pool_get_ioq_cnt(pool, &ioq_cnt);
	if (err) {
		AZIHSM_LOG_ERROR(
			"%s pool:%p azihsm_ioq_pool_get_ioq_cnt failed err:%d\n",
			__func__, pool, err);
		goto queue_cnt_fail;
	}

	pool->ioq_max_cnt = ioq_cnt;

	if (ioq_cnt == 0)
		return 0;

	xa_init(&pool->irqs);
	xa_init(&pool->ioqs);

	err = azihsm_ioq_pool_alloc_irqs(pool);
	if (err) {
		AZIHSM_LOG_ERROR(
			"%s pool:%p azihsm_ioq_pool_alloc_irqs failed err:%d\n",
			__func__, pool, err);
		goto alloc_irqs_fail;
	}

	err = azihsm_ioq_pool_create_ioqs(pool);
	if (err) {
		AZIHSM_LOG_ERROR(
			"%s pool:%p azihsm_ioq_pool_create_ioqs failed err:%d\n",
			__func__, pool, err);
		goto create_ioqs_fail;
	}

	AZIHSM_LOG_EXIT("%s pool:%p\n", __func__, pool);

	return 0;

create_ioqs_fail:
	azihsm_ioq_pool_free_irqs(pool);
alloc_irqs_fail:
queue_cnt_fail:
	return err;
}

void azihsm_ioq_pool_deinit(struct azihsm_ioq_pool *pool, const bool abort)
{
	AZIHSM_LOG_ENTRY("%s pool:%p abort_path:%d\n", __func__, pool, abort);
	azihsm_ioq_pool_delete_ioqs(pool, abort);
	azihsm_ioq_pool_free_irqs(pool);
	if (pool->ioq_max_cnt) {
		xa_destroy(&pool->ioqs);
		xa_destroy(&pool->irqs);
	}
	AZIHSM_LOG_EXIT("%s pool:%p\n", __func__, pool);
}

static unsigned int azihsm_ioq_sq_get_head(struct azihsm_ioq_sq *sq)
{
	return atomic_read(&sq->sq_head_ptr_on_compl);
}

bool azihsm_sq_is_full(struct azihsm_ioq_sq *sq)
{
	unsigned int sq_head = azihsm_ioq_sq_get_head(sq);

	if (sq->size == 0) {
		AZIHSM_LOG_ERROR("SQ id[%d] size is zero. ERROR\n", sq->id);
		BUG();
	}

	if (sq_head == ((sq->tail + 1) % sq->size)) {
		AZIHSM_LOG_ENTRY(
			"SQ Full [Sq-Id:%d] [sq-head:%d] [sq-tail:%d] [sq-size:%d] [CalcValue:%d]",
			sq->id, sq_head, sq->tail, sq->size,
			((sq->tail + 1) % sq->size));

		return true;
	} else
		return false;
}
