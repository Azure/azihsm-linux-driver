// SPDX-License-Identifier: GPL-2.0

#include "azihsm_ctrl.h"
#include "azihsm.h"
#include "azihsm_ctrl_cmd.h"
#include "azihsm_abort.h"
#include "azihsm_ctrl_dev_ioctl.h"
#include <linux/module.h>
#include <linux/idr.h>
#include <linux/uaccess.h>
#include <linux/version.h>
#include <linux/workqueue.h>
#include <linux/timer.h>

#define AZIHSM_CTRL_DMA_PAGE_SIZE SZ_4K
#define AZIHSM_CTRL_IOQ_ID 0
#define AZIHSM_CTRL_IOQ_SIZE 16
#define AZIHSM_CTRL_IRQ_NUM 0
#define AZIHSM_CTRL_MAX_RES_CNT ((u8)64)

static u8 azihsm_ctrl_pf_res_cnt = 1;

module_param_named(pf_res_cnt, azihsm_ctrl_pf_res_cnt, byte, 0444);
MODULE_PARM_DESC(pf_res_cnt,
		 "Physical function resource count. Default: 1 Max: 64");

static size_t azihsm_ctrl_ioq_ops_page_size(void)
{
	return AZIHSM_CTRL_DMA_PAGE_SIZE;
}

static void azihsm_ctrl_ioq_ops_set_io_data(void *cmd, unsigned int data)
{
	struct azihsm_ctrl_cmd *ctrl_cmd = cmd;

	ctrl_cmd->io_data = data;
}

static unsigned int azihsm_ctrl_ioq_ops_get_io_data(void *cmd)
{
	struct azihsm_ctrl_cmd *ctrl_cmd = cmd;

	return ctrl_cmd->io_data;
}

static u16 azihsm_ctrl_ioq_ops_cqe_size(void)
{
	return AZIHSM_CTRL_CMD_CQE_SIZE;
}

static void *azihsm_ctrl_ioq_ops_cqe(void *cmd)
{
	struct azihsm_ctrl_cmd *ctrl_cmd = cmd;

	return &ctrl_cmd->cqe;
}

static u16 azihsm_ctrl_ioq_ops_cqe_get_cid(void *cqe)
{
	struct azihsm_ctrl_cmd_cqe *ctrl_cqe = cqe;

	return ctrl_cqe->cid;
}

static u16 azihsm_ctrl_ioq_ops_cqe_get_phase(void *cqe)
{
	struct azihsm_ctrl_cmd_cqe *ctrl_cqe = cqe;

	return ctrl_cqe->psf.fld.p;
}

static u16 azihsm_ctrl_ioq_ops_cqe_get_sq_head(void *cqe)
{
	struct azihsm_ctrl_cmd_cqe *ctrl_cqe = cqe;

	return ctrl_cqe->sqhd;
}

static u16 azihsm_ctrl_ioq_ops_sqe_size(void)
{
	return AZIHSM_CTRL_CMD_SQE_SIZE;
}

static void *azihsm_ctrl_ioq_ops_sqe(void *cmd)
{
	struct azihsm_ctrl_cmd *ctrl_cmd = cmd;

	return &ctrl_cmd->sqe;
}

static void azihsm_ctrl_ioq_ops_sqe_set_cid(void *sqe, u16 cid)
{
	union azihsm_ctrl_cmd_sqe *ctrl_sqe = sqe;

	ctrl_sqe->any.hdr.cid = cid;
}

static int azihsm_ctrl_ioq_ops_complete_cmd(void *cmd,
					    const int completion_status)
{
	struct azihsm_ctrl_cmd *ctrl_cmd = cmd;

	ctrl_cmd->completion_status = completion_status;

	complete(&ctrl_cmd->cmpl);

	return 0;
}

static struct azihsm_ioq_ops azihsm_ctrl_ioq_ops = {
	.page_size = azihsm_ctrl_ioq_ops_page_size,
	.set_io_data = azihsm_ctrl_ioq_ops_set_io_data,
	.get_io_data = azihsm_ctrl_ioq_ops_get_io_data,
	.cqe_size = azihsm_ctrl_ioq_ops_cqe_size,
	.cqe = azihsm_ctrl_ioq_ops_cqe,
	.cqe_get_cid = azihsm_ctrl_ioq_ops_cqe_get_cid,
	.cqe_get_phase = azihsm_ctrl_ioq_ops_cqe_get_phase,
	.cqe_get_sq_head = azihsm_ctrl_ioq_ops_cqe_get_sq_head,
	.sqe_size = azihsm_ctrl_ioq_ops_sqe_size,
	.sqe = azihsm_ctrl_ioq_ops_sqe,
	.sqe_set_cid = azihsm_ctrl_ioq_ops_sqe_set_cid,
	.complete_cmd = azihsm_ctrl_ioq_ops_complete_cmd,
	.get_tag = NULL,
	.set_tag = NULL,
};

static int azihsm_ctrl_page_pool_create(struct azihsm_ctrl *ctrl,
					const bool abort)
{
	int err;

	if (true == abort)
		return 0;

	ctrl->page_pool = dma_pool_create(AZIHSM_CTRL_DEV_NAME,
					  &ctrl->pdev->dev,
					  AZIHSM_CTRL_DMA_PAGE_SIZE,
					  AZIHSM_CTRL_DMA_PAGE_SIZE, 0);
	if (!ctrl->page_pool) {
		err = -ENOMEM;
		AZIHSM_DEV_LOG_ERROR(
			&ctrl->pdev->dev,
			"[%s]:Controller page pool creation failure", __func__);
		goto dma_pool_fail;
	}

	return 0;

dma_pool_fail:
	return err;
}

static void azihsm_ctrl_page_pool_destroy(struct azihsm_ctrl *ctrl,
					  const bool abort)
{
	if (true == abort)
		return;
	/* normal shutdown */
	if (!ctrl->page_pool)
		return;

	dma_pool_destroy(ctrl->page_pool);
	ctrl->page_pool = NULL;
}

/*
 * This function can be called from level-2 abort
 * to perform the crash recovery. In that case the
 * CFS bit could be set and the firmware would be
 * In crash recovery stages. The driver should give
 * enough time to the firmware to recover the
 * controller. We will only check for the CFS bit
 * when the controller has completed the requested
 * operation.
 *
 */
static int azihsm_ctrl_hw_wait_ready(struct azihsm_ctrl *ctrl, bool enable)
{
	int err;
	union azihsm_ctrl_reg_cap cap;
	union azihsm_ctrl_reg_csts csts;
	unsigned long timeout;
	int ready = enable ? 1 : 0;
	const struct device *dev = &ctrl->pdev->dev;

	cap.val = readq(&ctrl->reg->cap);
	timeout = ((cap.fld.to + 1) * HZ / 2) + jiffies;

	AZIHSM_DEV_LOG_ENTRY(dev, "%s controller\n",
			     enable ? "enabling" : "disabling");
	for (;;) {
		csts.val = readl(&ctrl->reg->csts);
		if (csts.val == ~0) {
			AZIHSM_DEV_LOG_ERROR(dev, "device has gone\n");
			err = -ENODEV;
			goto err;
		}

		if (csts.fld.rdy == ready) {
			AZIHSM_DEV_LOG_INFO(dev, "controller %s\n",
					    enable ? "enabled" : "disabled");

			if (csts.fld.cfs) {
				AZIHSM_DEV_LOG_ERROR(
					dev,
					"controller has faulted [CSTS:0x%x]\n",
					csts.val);

				err = -EFAULT;
				goto err;
			}

			break;
		}

		if (time_after(jiffies, timeout)) {
			AZIHSM_DEV_LOG_ERROR(dev, "controller has timedout\n");
			err = -ETIMEDOUT;
			goto err;
		}
	}

	return 0;

err:
	return err;
}

/**
 * azihsm_ctrl_disable_enabled_controller
 * @ctrl :- Controller instance
 *
 * If controller is enabled, disables the
 * controller.
 *
 * Returns: 0 on success.
 */
static int azihsm_ctrl_disable_enabled_controller(struct azihsm_ctrl *ctrl)
{
	union azihsm_ctrl_reg_cc cc;
	union azihsm_ctrl_reg_csts csts;
	int ret = 0;

	AZIHSM_DEV_LOG_ENTRY(&ctrl->pdev->dev, "[ENTRY] %s azihsm_ctrl:%p\n",
			     __func__, ctrl);

	csts.val = readl(&ctrl->reg->csts);
	cc.val = readl(&ctrl->reg->cc);
	AZIHSM_DEV_LOG_INFO(
		&ctrl->pdev->dev,
		"[INFO: %s ctrl:%p CSTS REGISTER VALUE:0x%x CC REGISTER VALUE:0x%x\n",
		__func__, ctrl, csts.val, cc.val);
	if (csts.fld.rdy || cc.fld.en) {
		/*
		 * Controller is enabled.
		 */
		AZIHSM_DEV_LOG_INFO(
			&ctrl->pdev->dev,
			"[INFO: controller enabled. Disabling] %s azihsm_ctrl:%p\n",
			__func__, ctrl);

		ret = azihsm_ctrl_hw_disable(ctrl);
		if (ret) {
			AZIHSM_DEV_LOG_ERROR(
				&ctrl->pdev->dev,
				"[ERROR] %s disabling controller:%p during startup failed. ret:%d\n",
				__func__, ctrl, ret);
		}
	} else {
		AZIHSM_DEV_LOG_INFO(
			&ctrl->pdev->dev,
			"[INFO: controller not enabled. Nothing to do] %s azihsm_ctrl:%p\n",
			__func__, ctrl);

		ret = 0;
	}

	AZIHSM_DEV_LOG_EXIT(&ctrl->pdev->dev,
			    "[EXIT] %s azihsm_ctrl:%p return value:%d\n",
			    __func__, ctrl, ret);
	return ret;
}

int azihsm_ctrl_hw_enable(struct azihsm_ctrl *ctrl)
{
	int err;
	u64 asq_dma_addr, acq_dma_addr;
	union azihsm_ctrl_reg_aqa aqa;
	union azihsm_ctrl_reg_cc cc;
	union azihsm_ctrl_reg_vs vs;

	AZIHSM_DEV_LOG_ENTRY(&ctrl->pdev->dev, "%s azihsm_ctrl:%p\n", __func__,
			     ctrl);

	/*
	 * Before enabling the controller, check to see
	 * if the controller is already enabled and if it is
	 * enabled, disable the controller
	 * This is needed for the case where the machine is
	 * powered off in an abnormal manner (VM power off)
	 * but the controller is left in an enabled state
	 * The following can fail and if it does fail,
	 * return error
	 */
	err = azihsm_ctrl_disable_enabled_controller(ctrl);
	if (err)
		return err;

	/*
	 * Update the admin queue attributes with submission and completion
	 * queue size.
	 * Note: The queue sizes are zero based
	 * The following operations assume that the controller is disabled
	 */
	aqa.val = readl(&ctrl->reg->aqa);
	aqa.fld.asqs = AZIHSM_CTRL_IOQ_SIZE - 1;
	aqa.fld.acqs = AZIHSM_CTRL_IOQ_SIZE - 1;
	writel(aqa.val, &ctrl->reg->aqa);

	// Update the submission queue dma address
	asq_dma_addr = azihsm_ioq_sq_dma_addr(&ctrl->ioq);
	writeq(asq_dma_addr, &ctrl->reg->asq);

	// Update the completion queue dma address
	acq_dma_addr = azihsm_ioq_cq_dma_addr(&ctrl->ioq);
	writeq(acq_dma_addr, &ctrl->reg->acq);

	// Set the controller enable bit
	cc.val = readl(&ctrl->reg->cc);
	cc.fld.en = 1;
	writel(cc.val, &ctrl->reg->cc);

	err = azihsm_ctrl_hw_wait_ready(ctrl, true);
	if (err) {
		AZIHSM_DEV_LOG_ERROR(
			&ctrl->pdev->dev,
			"[ERROR] %s azihsm_ctrl:%p azihsm_ctrl_hw_wait_ready failed err:%d\n",
			__func__, ctrl, err);
		goto hw_ready_err;
	}

	vs.val = readl(&ctrl->reg->vs);
	AZIHSM_DEV_LOG_EXIT(&ctrl->pdev->dev, "controller version %u.%u.%u\n",
			    vs.fld.mjr, vs.fld.mnr, vs.fld.ter);

	return 0;

hw_ready_err:
	return err;
}

int azihsm_ctrl_hw_nssr(struct azihsm_ctrl *ctrl)
{
	AZIHSM_DEV_LOG_ENTRY(&ctrl->pdev->dev, "%s mcr_ctrl:%p\n", __func__,
			     ctrl);
	writel(NVME_SS_RESET_SIGNATURE, &ctrl->reg->ssr);

	//
	// Firmware is ignoring the NSSR bit right now.
	// We will revisit if we need to wait for the
	// controller disable to happen, like when the
	// enable bit is reset. For now just return success.
	//
	return 0;
}

int azihsm_ctrl_hw_disable(struct azihsm_ctrl *ctrl)
{
	int err;
	union azihsm_ctrl_reg_cc cc;

	AZIHSM_DEV_LOG_ENTRY(&ctrl->pdev->dev, "%s azihsm_ctrl:%p\n", __func__,
			     ctrl);

	// Clear the controller enable bit
	cc.val = readl(&ctrl->reg->cc);
	cc.fld.en = 0;
	writel(cc.val, &ctrl->reg->cc);

	err = azihsm_ctrl_hw_wait_ready(ctrl, false);
	if (err) {
		AZIHSM_DEV_LOG_ERROR(
			&ctrl->pdev->dev,
			"[ERROR] %s azihsm_ctrl:%p azihsm_ctrl_hw_wait_ready failed err:%d\n",
			__func__, ctrl, err);
		goto hw_ready_err;
	}

	AZIHSM_DEV_LOG_EXIT(&ctrl->pdev->dev, "%s azihsm_ctrl:%p\n", __func__,
			    ctrl);
	return 0;

hw_ready_err:
	return err;
}

static irqreturn_t azihsm_ctrl_irq(int irq, void *data)
{
	struct azihsm_ctrl *ctrl = data;

	if (!ctrl) {
		AZIHSM_LOG_ERROR("[%s] Called With Null Pointer", __func__);

		// Interrrupt was not from this device/we are not handling it
		return IRQ_NONE;
	}

	tasklet_schedule(&ctrl->tasklet);
	return IRQ_HANDLED;
}

static void azihsm_ctrl_soft_irq(unsigned long data)
{
	struct azihsm_ctrl *ctrl = (struct azihsm_ctrl *)data;

	if (!ctrl) {
		AZIHSM_LOG_ERROR("[%s] Called With Null Pointer", __func__);
		return;
	}

	azihsm_ioq_complete_cmds(&ctrl->ioq);
}

/*
 * Function :- azihsm_log_ctrl_ident
 * Log the serial number, model number
 * and firmware revision to kernel log
 * Note these are not NULL terminated
 */
static void azihsm_log_ctrl_ident(struct device *dev, struct azihsm_ctrl *ctrl)
{
	int i;

	AZIHSM_DEV_LOG_ENTRY(dev, "controller id %d\n", ctrl->ident->ctrl_id);
	/* log the serial number model number and firmware version */
	{
		char buf[AZIHSM_CTRL_IDENT_SN_LEN + 1];

		for (i = 0; i < AZIHSM_CTRL_IDENT_SN_LEN; i++)
			buf[i] = ctrl->ident->sn[i];

		buf[i] = 0;
		AZIHSM_DEV_LOG_INFO(dev, "Controller serial number:%s\n", buf);
	}

	{
		char buf[AZIHSM_CTRL_IDENT_FR_LEN + 1];
		{
			for (i = 0; i < AZIHSM_CTRL_IDENT_FR_LEN; i++)
				buf[i] = ctrl->ident->fr[i];

			buf[i] = 0;
		}

		AZIHSM_DEV_LOG_INFO(dev, "Controller firmware revision:%s\n",
				    buf);
	}
}

static int azihsm_ctrl_ident_init(struct azihsm_ctrl *ctrl)
{
	int err;
	void *pg;
	dma_addr_t pg_dma_addr;
	struct device *dev = &ctrl->pdev->dev;

	AZIHSM_DEV_LOG_ENTRY(&ctrl->pdev->dev, "%s azihsm_ctrl:%p\n", __func__,
			     ctrl);

	pg = dma_pool_alloc(ctrl->page_pool, GFP_KERNEL, &pg_dma_addr);
	if (!pg) {
		err = -ENOMEM;
		AZIHSM_DEV_LOG_ERROR(
			dev, "[%s: azihsm_ctrl:%p] Ident page alloc failure",
			__func__, ctrl);
		goto page_alloc_fail;
	}

	err = azihsm_ctrl_cmd_ident(ctrl, pg_dma_addr);
	if (err) {
		AZIHSM_DEV_LOG_ERROR(
			dev,
			"[%s: azihsm_ctrl:%p] azihsm_ctrl_cmd_ident failed",
			__func__, ctrl);
		goto cmd_fail;
	}

	ctrl->ident = pg;
	ctrl->ident_dma_addr = pg_dma_addr;

	azihsm_log_ctrl_ident(dev, ctrl);

	/*
	 * Basic validation of the sizes of the FP and HSM queues (to be
	 * consistent with Windows driver)
	 */
	if ((ctrl->ident->cp_sqes.fld.max != CP_SQE_SZ_POWOFTWO) ||
	    (ctrl->ident->cp_cqes.fld.max != CP_CQE_SZ_POWOFTWO) ||
	    (ctrl->ident->fp_sqes.fld.max != FP_SQE_SZ_POWOFTWO) ||
	    (ctrl->ident->fp_cqes.fld.max != FP_CQE_SZ_POWOFTWO)) {
		AZIHSM_DEV_LOG_ERROR(
			dev,
			"Identify data reported by controller mismatched between CQE and SQE Reported: [CPSQES: %d, CPCQES: %d, FPSQES: %d, FPCQES: %d] Expected: [CPSQES: %d, CPCQES: %d, FPSQES: %d, FPCQES: %d]\n",
			ctrl->ident->cp_sqes.fld.max,
			ctrl->ident->cp_cqes.fld.max,
			ctrl->ident->fp_sqes.fld.max,
			ctrl->ident->fp_cqes.fld.max, CP_SQE_SZ, CP_CQE_SZ,
			FP_SQE_SZ, FP_CQE_SZ);

		err = -EINVAL;
		goto cmd_fail;
	}

	AZIHSM_DEV_LOG_EXIT(&ctrl->pdev->dev, "%s azihsm_ctrl:%p\n", __func__,
			    ctrl);
	return 0;

cmd_fail:
	dma_pool_free(ctrl->page_pool, pg, pg_dma_addr);
page_alloc_fail:
	return err;
}

static void azihsm_ctrl_ident_deinit(struct azihsm_ctrl *ctrl)
{
	AZIHSM_DEV_LOG_ENTRY(&ctrl->pdev->dev, "%s azihsm_ctrl:%p\n", __func__,
			     ctrl);
	if (!ctrl->ident)
		return;

	dma_pool_free(ctrl->page_pool, ctrl->ident, ctrl->ident_dma_addr);
	ctrl->ident = NULL;
	ctrl->ident_dma_addr = 0;
	AZIHSM_DEV_LOG_EXIT(&ctrl->pdev->dev, "%s azihsm_ctrl:%p\n", __func__,
			    ctrl);
}

static int azihsm_ctrl_hsm_init(struct azihsm_ctrl *ctrl, const bool abort)
{
	int err;
	struct azihsm_hsm_cfg cfg;
	const struct device *dev = &ctrl->pdev->dev;

	cfg.ctrl = ctrl;
	cfg.ioq_db = ctrl->db_reg;
	cfg.ioq_id_start = HSM_MIN_ID;
	cfg.ioq_size = HSM_IOQ_SZ;
	cfg.msix_max_cnt = (ctrl->irq_cnt - 1) / 2;
	cfg.msix_start = 1;

	AZIHSM_DEV_LOG_ENTRY(
		dev, "%s azihsm_ctrl:%p ioq_size:%d max_msix_count:%d\n",
		__func__, ctrl, HSM_IOQ_SZ, cfg.msix_max_cnt);

	err = azihsm_hsm_init(&ctrl->hsm, &cfg, abort);
	if (err) {
		AZIHSM_DEV_LOG_ERROR(dev, "hsm init failed. err=%d", err);
		goto init_fail;
	}

	AZIHSM_DEV_LOG_EXIT(dev, "%s azihsm_ctrl:%p\n", __func__, ctrl);
	/* set up back pointers */
	ctrl->hsm.ctrl = ctrl;

	return 0;

init_fail:
	return err;
}

static void azihsm_ctrl_hsm_deinit(struct azihsm_ctrl *ctrl, const bool abort)
{
	AZIHSM_DEV_LOG_ENTRY(&ctrl->pdev->dev, "%s azihsm_ctrl:%p\n", __func__,
			     ctrl);
	azihsm_hsm_deinit(&ctrl->hsm, abort);
	AZIHSM_DEV_LOG_EXIT(&ctrl->pdev->dev, "%s azihsm_ctrl:%p\n", __func__,
			    ctrl);
}

static void azihsm_ctrl_aes_deinit(struct azihsm_ctrl *ctrl, const bool abort)
{
	AZIHSM_DEV_LOG_ENTRY(&ctrl->pdev->dev, "%s azihsm_ctrl:%p\n", __func__,
			     ctrl);
	azihsm_aes_deinit(&ctrl->aes, abort);
	AZIHSM_DEV_LOG_EXIT(&ctrl->pdev->dev, "%s azihsm_ctrl:%p\n", __func__,
			    ctrl);
}

static int azihsm_ctrl_aes_init(struct azihsm_ctrl *ctrl, const bool abort)
{
	int err;
	struct azihsm_aes_cfg cfg;
	const struct device *dev = &ctrl->pdev->dev;

	cfg.ctrl = ctrl;
	cfg.ioq_db = ctrl->db_reg;
	cfg.ioq_id_start = AES_MIN_ID;
	cfg.ioq_size = AES_IOQ_SZ;
	cfg.msix_max_cnt = ctrl->irq_cnt / 2;
	cfg.msix_start = 16;

	AZIHSM_DEV_LOG_ENTRY(
		dev,
		"%s azihsm_ctrl:%p id_start:%d ioq_size:%d irq_cnt:%d msix_start:%d\n",
		__func__, ctrl, cfg.ioq_id_start, cfg.ioq_size,
		cfg.msix_max_cnt, cfg.msix_start);

	ctrl->aes.ctrl = ctrl; /* set up the back pointers */
	err = azihsm_aes_init(&ctrl->aes, &cfg, abort);
	if (err) {
		AZIHSM_DEV_LOG_ERROR(dev, "aes init failed. err=%d", err);
		goto init_fail;
	}

	AZIHSM_DEV_LOG_EXIT(dev, "%s azihsm_ctrl:%p\n", __func__, ctrl);
	return 0;

init_fail:
	return err;
}

int azihsm_ctrl_sw_enable(struct azihsm_ctrl *ctrl, const bool abort)
{
	int err;
	const struct device *dev = &ctrl->pdev->dev;
	union azihsm_ctrl_reg_cc cc;
	u8 res_cnt = MCR_MIN(AZIHSM_CTRL_MAX_RES_CNT, azihsm_ctrl_pf_res_cnt);

	AZIHSM_DEV_LOG_ENTRY(dev, "%s azihsm_ctrl:%p\n", __func__, ctrl);

	tasklet_init(&ctrl->tasklet, azihsm_ctrl_soft_irq, (unsigned long)ctrl);

	err = pci_request_irq(ctrl->pdev, AZIHSM_CTRL_IRQ_NUM, azihsm_ctrl_irq,
			      NULL, ctrl, "azihsm_ctrl-%d",
			      AZIHSM_CTRL_IRQ_NUM);
	if (err) {
		AZIHSM_DEV_LOG_ERROR(
			dev, "request irq failed for controller, vector=%d",
			AZIHSM_CTRL_IRQ_NUM);
		goto request_irq_fail;
	}

	err = azihsm_ctrl_page_pool_create(ctrl, abort);
	if (err) {
		AZIHSM_DEV_LOG_ERROR(
			dev,
			"%s azihsm_ctrl:%p azihsm_ctrl_page_pool_create failed err:%d\n",
			__func__, ctrl, err);
		goto dma_pool_fail;
	}

	err = azihsm_ctrl_ident_init(ctrl);
	if (err) {
		AZIHSM_DEV_LOG_ERROR(
			dev,
			"%s azihsm_ctrl:%p azihsm_ctrl_ident_init failed err:%d\n",
			__func__, ctrl, err);
		goto ident_init_fail;
	}

	// Set IO Queue entry sizes
	cc.val = readl(&ctrl->reg->cc);
	cc.fld.cp_iocqes = ctrl->ident->cp_cqes.fld.max;
	cc.fld.cp_iosqes = ctrl->ident->cp_sqes.fld.max;
	cc.fld.fp_iocqes = ctrl->ident->fp_cqes.fld.max;
	cc.fld.fp_iosqes = ctrl->ident->fp_sqes.fld.max;
	writel(cc.val, &ctrl->reg->cc);

	if (ctrl->is_pf && res_cnt > 0) {
		err = azihsm_ctrl_cmd_set_res_cnt(ctrl, ctrl->ident->ctrl_id,
						  res_cnt);
		if (err) {
			AZIHSM_DEV_LOG_ERROR(
				dev,
				"%s azihsm_ctrl:%p failed to set resource count err:%d\n",
				__func__, ctrl, err);
		} else {
			AZIHSM_DEV_LOG_INFO(
				dev,
				"%s azihsm_ctrl:%p set resource count to %d",
				__func__, ctrl, res_cnt);
		}
	}

	err = azihsm_ctrl_hsm_init(ctrl, abort);
	if (err) {
		AZIHSM_DEV_LOG_ERROR(
			dev,
			"%s azihsm_ctrl:%p azihsm_ctrl_hsm_init failed err:%d\n",
			__func__, ctrl, err);

		goto dev_init_fail;
	}

	ctrl->aes.dev_kobj = ctrl->hsm.dev_kobj;
	err = azihsm_ctrl_aes_init(ctrl, abort);
	if (err) {
		AZIHSM_DEV_LOG_ERROR(
			dev,
			"%s azihsm_ctrl:%p azihsm_ctrl_aes_init failed err:%d\n",
			__func__, ctrl, err);
		goto aes_init_fail;
	}

	// We will start firing the commands to the controller here.
	// Mark the controller as ready to accept interrupts
	AZIHSM_CTRL_ST_READY(ctrl);
	ctrl->ctrl_irq_allocated = true;
	return 0;

aes_init_fail:
	azihsm_ctrl_hsm_deinit(ctrl, abort);
dev_init_fail:
	azihsm_ctrl_ident_deinit(ctrl);
ident_init_fail:
	azihsm_ctrl_page_pool_destroy(ctrl, abort);
dma_pool_fail:
	pci_free_irq(ctrl->pdev, AZIHSM_CTRL_IRQ_NUM, ctrl);
	ctrl->ctrl_irq_allocated = false;
request_irq_fail:
	return err;
}

void azihsm_ctrl_sw_disable(struct azihsm_ctrl *ctrl, const bool abort)
{
	AZIHSM_LOG_ENTRY("%s azihsm_ctrl:%p\n", __func__, ctrl);
	azihsm_ctrl_aes_deinit(ctrl, abort);
	azihsm_ctrl_hsm_deinit(ctrl, abort);
	azihsm_ctrl_ident_deinit(ctrl);
	azihsm_ctrl_page_pool_destroy(ctrl, abort);
	if (true == ctrl->ctrl_irq_allocated) {
		pci_free_irq(ctrl->pdev, AZIHSM_CTRL_IRQ_NUM, ctrl);
		ctrl->ctrl_irq_allocated = false;
	}
	AZIHSM_LOG_EXIT("%s azihsm_ctrl:%p\n", __func__, ctrl);
}

static void azihsm_setup_hmon(struct azihsm_ctrl *ctrl)
{
	if (!ctrl->hmon.init_done) {
		AZIHSM_LOG_INFO("%s: Setting Up Health Mon Timer [%p]\n",
				__func__, ctrl);

		ctrl->hmon.init_done = true;
		ctrl->hmon.ctrl = ctrl;
		INIT_DELAYED_WORK(&ctrl->hmon.hmon_work, azihsm_health_monitor);

		schedule_delayed_work(&ctrl->hmon.hmon_work,
				      AZIHSM_HEALTH_MON_TIME);
	}
}

static void azihsm_cleanup_hmon(struct azihsm_ctrl *ctrl)
{
	AZIHSM_LOG_ENTRY("%s:Cleaning Up Health Moniter Timer [%p]\n", __func__,
			 ctrl);

	cancel_delayed_work_sync(&ctrl->hmon.hmon_work);
	ctrl->hmon.init_done = false;
	ctrl->hmon.ctrl = NULL;
}

int azihsm_ctrl_init(struct azihsm_ctrl *ctrl,
		     const struct azihsm_ctrl_cfg *cfg, const bool abort)
{
	int err;
	struct azihsm_ioq_cfg ioq_cfg = { 0 };

	AZIHSM_CTRL_ST_RESET(ctrl);
	AZIHSM_CTRL_SET_ABORT_STATE(ctrl, AZIHSM_CONTROLLER_IS_NOT_IN_ABORT);

	ctrl->pdev = cfg->pdev;
	ctrl->reg = cfg->ctrl_reg;
	ctrl->db_reg = cfg->db_reg;
	ctrl->irq_cnt = cfg->irq_cnt;
	ctrl->is_pf = cfg->is_pf;
	ctrl->ctrl_irq_allocated = false;
	snprintf(ctrl->drv_rev, sizeof(ctrl->drv_rev), "%s",
		 AZIHSM_DRIVER_VERSION);

	ioq_cfg.id = AZIHSM_CTRL_IOQ_ID;
	ioq_cfg.size = AZIHSM_CTRL_IOQ_SIZE;
	ioq_cfg.db = ctrl->db_reg;
	ioq_cfg.ops = &azihsm_ctrl_ioq_ops;
	ioq_cfg.dev = &ctrl->pdev->dev;
	AZIHSM_LOG_ENTRY("%s azihsm_ctrl:%p\n", __func__, ctrl);

	AZIHSM_CTRL_ST_IN_PROGRESS(ctrl);

	if (!abort)
		mutex_init(&ctrl->abort_mutex);

	err = azihsm_ioq_init(&ctrl->ioq, &ioq_cfg);
	if (err) {
		AZIHSM_LOG_ERROR(
			"[ERROR] %s azihsm_ctrl:%p azihsm_ioq_init failed err:%d\n",
			__func__, ctrl, err);
		goto ioq_fail;
	}

	err = azihsm_ctrl_hw_enable(ctrl);
	if (err) {
		AZIHSM_LOG_ERROR(
			"%s azihsm_ctrl:%p azihsm_ctrl_hw_enable failed err:%d\n",
			__func__, ctrl, err);
		goto hw_enable_fail;
	}

	err = azihsm_ctrl_sw_enable(ctrl, abort);
	if (err) {
		AZIHSM_LOG_ERROR(
			"%s azihsm_ctrl:%p azihsm_ctrl_sw_enable failed err:%d\n",
			__func__, ctrl, err);
		goto sw_enable_fail;
	}

	ctrl->level_one_abort_count = 0;
	ctrl->level_two_abort_count = 0;
	ctrl->proc_not_own_fd_cnt = 0;
	ctrl->session_flush_cnt = 0;
	ctrl->close_by_not_own_proc_cnt = 0;

	if (!abort)
		// Everything is good, setup the health Monitor
		azihsm_setup_hmon(ctrl);

	get_random_bytes(&ctrl->entropy_data,
			 AZIHSM_CTRL_DEV_INFO_ENTROPY_LENGTH);

	AZIHSM_LOG_EXIT("%s azihsm_ctrl:%p\n", __func__, ctrl);
	return 0;

sw_enable_fail:
	azihsm_ctrl_hw_disable(ctrl);
hw_enable_fail:
	azihsm_ioq_deinit(&ctrl->ioq);
ioq_fail:
	AZIHSM_CTRL_ST_RESET(ctrl);
	return err;
}

void azihsm_ctrl_deinit(struct azihsm_ctrl *ctrl, const bool abort,
			u32 abort_type)
{
	AZIHSM_LOG_ENTRY("%s azihsm_ctrl:%p\n", __func__, ctrl);

	if (abort) {
		//
		// First disable the hardware if it was abort
		// And then disable the soft states. We will
		// Not be firing any commands to hardware in this path
		// We cannot remove the memory, till the controller is
		// disabled.
		//
		if (abort_type == ABORT_TYPE_APP_L2_CTRL_NSSR)
			azihsm_ctrl_hw_nssr(ctrl);
		else
			azihsm_ctrl_hw_disable(ctrl);

		azihsm_ctrl_sw_disable(ctrl, abort);
	} else {
		//
		// We are shutting down, disable the
		// health monitor.
		//
		azihsm_cleanup_hmon(ctrl);

		//
		// In normal run, first disable the software
		// and then disable the hardware, You will be
		// firing the delete queue commands here which need
		// to respond, and then freeing the queue's memory out.
		//
		azihsm_ctrl_sw_disable(ctrl, abort);
		azihsm_ctrl_hw_disable(ctrl);
	}

	azihsm_ioq_deinit(&ctrl->ioq);
	ctrl->reg = NULL;
	ctrl->db_reg = NULL;
	ctrl->irq_cnt = 0;

	AZIHSM_CTRL_ST_RESET(ctrl);

	AZIHSM_LOG_EXIT("%s azihsm_ctrl:%p\n", __func__, ctrl);
}

/*
 * Function :- azihsm_ctrl_dev_get_dev_info
 * Accessor function to get the information for the device
 * Returns PCI bus device function, name
 *  and information from the FW
 *
 * The data that is returned is copied from the
 * CONTROLLER identify information
 *
 * Do not assume that our identify structures are NULL
 * terminated. There is no need to NULL terminate user
 * buffers
 *
 * Always returns 0
 *
 * This function can be called in any context
 */
int azihsm_ctrl_dev_get_dev_info(struct azihsm_ctrl *ctrl,
				 struct azihsm_ctrl_dev_info *dev_info)
{
	size_t entropy_size =
		(sizeof(dev_info->device_entropy) < sizeof(ctrl->entropy_data) ?
			 sizeof(dev_info->device_entropy) :
			 sizeof(ctrl->entropy_data));
	const char *azihsm_pci_name = pci_name(ctrl->pdev);

	dev_info->id = ctrl->ident->ctrl_id;
	strscpy(dev_info->pci_info, azihsm_pci_name,
		sizeof(dev_info->pci_info));

	memset(dev_info->serial_num, 0, sizeof(dev_info->serial_num));
	memcpy(dev_info->serial_num, ctrl->ident->sn, sizeof(ctrl->ident->sn));

	memset(dev_info->model_num, 0, sizeof(dev_info->model_num));

	memset(dev_info->firmware_rev, 0, sizeof(dev_info->firmware_rev));
	memcpy(dev_info->firmware_rev, ctrl->ident->fr,
	       sizeof(ctrl->ident->fr));

	memset(dev_info->driver_rev, 0, sizeof(dev_info->driver_rev));
	memcpy(dev_info->driver_rev, ctrl->drv_rev, sizeof(ctrl->drv_rev));

	memcpy(dev_info->device_entropy, ctrl->entropy_data, entropy_size);
	return 0;
}
