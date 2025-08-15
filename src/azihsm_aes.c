// SPDX-License-Identifier: GPL-2.0

#include "azihsm_aes.h"
#include "azihsm_aes_cmd.h"
#include "azihsm_aes_dev.h"
#include "azihsm_ctrl.h"
#include "azihsm_log.h"

#define AZIHSM_AES_DMA_PAGE_SIZE SZ_4K

/*
 * Functions Local to This File
 */
static size_t azihsm_aes_ioq_ops_page_size(void)
{
	return AZIHSM_AES_DMA_PAGE_SIZE;
}

static void azihsm_aes_ioq_ops_set_io_data(void *cmd, unsigned int data)
{
	struct azihsm_aes_cmd *aes_cmd = cmd;

	aes_cmd->io_data = data;
}

static unsigned int azihsm_aes_ioq_ops_get_io_data(void *cmd)
{
	struct azihsm_aes_cmd *aes_cmd = cmd;

	return aes_cmd->io_data;
}

static u16 azihsm_aes_ioq_ops_cqe_size(void)
{
	return AZIHSM_AES_CQE_SZ;
}

static void *azihsm_aes_ioq_ops_cqe(void *cmd)
{
	struct azihsm_aes_cmd *aes_cmd = cmd;

	return &aes_cmd->cqe;
}

static u16 azihsm_aes_ioq_ops_cqe_get_cid(void *cqe)
{
	struct azihsm_aes_cqe *aes_cqe = cqe;

	return aes_cqe->cmd_id;
}

static u16 azihsm_aes_ioq_ops_cqe_get_phase(void *cqe)
{
	struct azihsm_aes_cqe *aes_cqe = cqe;

	return aes_cqe->ph_sts.ph_sts_bits.phase;
}

static u16 azihsm_aes_ioq_ops_cqe_get_sq_head(void *cqe)
{
	struct azihsm_aes_cqe *aes_cqe = cqe;

	return aes_cqe->sq_head;
}

static u16 azihsm_aes_ioq_ops_sqe_size(void)
{
	return AZIHSM_AES_SQE_SZ;
}

static void *azihsm_aes_ioq_ops_sqe(void *cmd)
{
	struct azihsm_aes_cmd *aes_cmd = cmd;

	return &aes_cmd->sqe;
}

static void azihsm_aes_ioq_ops_sqe_set_cid(void *sqe, u16 cid)
{
	struct azihsm_aes_sqe *aes_sqe = sqe;

	aes_sqe->cmd_id = cid;
}

static int azihsm_aes_ioq_ops_complete_cmd(void *cmd,
					   const int completion_status)
{
	struct azihsm_aes_cmd *aes_cmd = cmd;

	aes_cmd->completion_status = completion_status;
	complete(&aes_cmd->cmpl);
	return 0;
}

static int azihsm_aes_ioq_ops_get_cmd_tag(void *cmd)
{
	struct azihsm_aes_cmd *aes_cmd = cmd;

	return aes_cmd->tag;
}

static void azihsm_aes_ioq_ops_set_cmd_tag(void *cmd, const int tag)
{
	struct azihsm_aes_cmd *aes_cmd = cmd;

	aes_cmd->tag = tag;
}

/*
 * Functions Exposed From This File
 */

static struct azihsm_ioq_ops azihsm_aes_ioq_ops = {
	.page_size = azihsm_aes_ioq_ops_page_size,
	.set_io_data = azihsm_aes_ioq_ops_set_io_data,
	.get_io_data = azihsm_aes_ioq_ops_get_io_data,
	.cqe_size = azihsm_aes_ioq_ops_cqe_size,
	.cqe = azihsm_aes_ioq_ops_cqe,
	.cqe_get_cid = azihsm_aes_ioq_ops_cqe_get_cid,
	.cqe_get_phase = azihsm_aes_ioq_ops_cqe_get_phase,
	.cqe_get_sq_head = azihsm_aes_ioq_ops_cqe_get_sq_head,
	.sqe_size = azihsm_aes_ioq_ops_sqe_size,
	.sqe = azihsm_aes_ioq_ops_sqe,
	.sqe_set_cid = azihsm_aes_ioq_ops_sqe_set_cid,
	.complete_cmd = azihsm_aes_ioq_ops_complete_cmd,
	.get_tag = azihsm_aes_ioq_ops_get_cmd_tag,
	.set_tag = azihsm_aes_ioq_ops_set_cmd_tag,
};

int azihsm_aes_init(struct azihsm_aes *aes, struct azihsm_aes_cfg *aes_cfg,
		    const bool abort)
{
	int err;
	struct azihsm_ioq_pool_cfg ioq_pool_cfg = { 0 };

	aes->pdev = aes_cfg->ctrl->pdev;

	ioq_pool_cfg.name = AZIHSM_AES_DEV_NAME;
	ioq_pool_cfg.ctrl = aes_cfg->ctrl;
	ioq_pool_cfg.pdev = aes_cfg->ctrl->pdev;
	ioq_pool_cfg.ioq_db = aes_cfg->ioq_db;
	ioq_pool_cfg.ioq_id_start = aes_cfg->ioq_id_start;
	ioq_pool_cfg.ioq_size = aes_cfg->ioq_size;
	ioq_pool_cfg.ioq_type = AZIHSM_IOQ_TYPE_AES;
	ioq_pool_cfg.ioq_ops = &azihsm_aes_ioq_ops;
	ioq_pool_cfg.msix_start = aes_cfg->msix_start;
	ioq_pool_cfg.msix_max_cnt = aes_cfg->msix_max_cnt;

	AZIHSM_DEV_LOG_ENTRY(
		&aes_cfg->ctrl->pdev->dev,
		"[ENTRY] %s aes:%p ioq_id_start:%d ioq_size:%d MSI-X start:%d MSI-X max:%d\n",
		__func__, aes, aes_cfg->ioq_id_start, aes_cfg->ioq_size,
		aes_cfg->msix_start, aes_cfg->msix_max_cnt);

	if (false == abort)
		mutex_init(&aes->aes_lock);

	aes->ioq_pool.parent_kobj = aes->dev_kobj;

	err = azihsm_ioq_pool_init(&aes->ioq_pool, &ioq_pool_cfg);
	if (err) {
		AZIHSM_DEV_LOG_ERROR(&aes_cfg->ctrl->pdev->dev,
				     "Failed To Create IOQ Pool");
		return err;
	}

	/* do not create soft device if the number of queues is 0*/
	if (aes->ioq_pool.ioq_max_cnt == 0) {
		AZIHSM_DEV_LOG_ERROR(
			&aes->pdev->dev,
			"Device has 0 AES queues. Not creating AES device link\n");
		return 0;
	}

	atomic_add(
		aes->ioq_pool.ioq_max_cnt,
		&aes->ctrl->hsm
			 .hsm_admin_attribute_array
				 [AZIHSM_HSM_ADMIN_ATTRIBUTE_NUM_FPQS_CREATED]
			 .counter);

	AZIHSM_DEV_LOG_EXIT(&aes_cfg->ctrl->pdev->dev, "[EXIT] %s aes:%p\n",
			    __func__, aes);

	return 0;
}

void azihsm_aes_deinit(struct azihsm_aes *aes, const bool abort)
{
	AZIHSM_LOG_ENTRY("%s aes:%p\n", __func__, aes);
	azihsm_ioq_pool_deinit(&aes->ioq_pool, abort);
	AZIHSM_LOG_EXIT("%s aes:%p\n", __func__, aes);
}
