// SPDX-License-Identifier: GPL-2.0
#include <linux/kernel.h>
#include <linux/completion.h>
#include "azihsm_aes.h"
#include "azihsm_aes_cmd.h"
#include "azihsm_abort.h"
#include "azihsm_ioq_util.h"
#include "azihsm_ioq_perf.h"
#include "azihsm_log.h"

/*
 * azihsm_abort_timeout_in_jiffies
 * time in jiffies to wait before
 * timing out and starting abort
 */

extern int azihsm_abort_timeout_in_jiffies;

void azihsm_aes_cmd_init(struct azihsm_aes_cmd *cmd, const u8 opc,
			 const u8 psdt, const u8 cmd_type, const u8 frame_type,
			 const u8 cipher)
{
	struct azihsm_aes_sqe clean_sqe = { 0 };

	if (!cmd)
		return;

	init_completion(&cmd->cmpl);

	cmd->sqe = clean_sqe;
	cmd->sqe.attr.cmd_opc = opc;
	cmd->sqe.attr.psdt = psdt;
	cmd->sqe.attr.cmd_type = cmd_type;
	cmd->sqe.frame_type = frame_type;
	cmd->sqe.attr.cipher = cipher;
}

/*
 *	azihsm_aes_cmd_process
 *	Main entry point to submit a command
 *	to the device on the fast path
 *
 *	Parameters
 *		aes	=>	AES context for the device
 *		cmd	=>	command to submit to the device
 *
 *	Find a SQ to use
 *	Unless an abort is in progress,	a queue will
 *	be available to submit the command
 *
 *	This thread submits the command and waits for
 *	a completion to arrive or timeout to happen.
 *	If timeout happens, abort kicks in
 *
 *	Once a queue is chosen, the command is submitted
 *	This procedure waits for a slot to be available
 *	on the SQ.
 *
 *	return values
 *		EAGAIN :- Abort is in progress
 *		or a queue cannot be found
 *		or this command is aborted
 */

int azihsm_aes_cmd_process(struct azihsm_aes *aes, struct azihsm_aes_cmd *cmd)
{
	int err = 0;
	u16 tag = 0;
	struct device *dev = &aes->pdev->dev;
	unsigned long timeout = azihsm_abort_timeout_in_jiffies;
	struct azihsm_ioq *ioq = NULL;
	struct azihsm_hsm *hsm = &aes->ctrl->hsm;
	ktime_t start_time, end_time;
	/* count is the total # of queues in the pool */

	if (aes->ioq_pool.ioq_select_id < AES_MIN_ID) {
		AZIHSM_DEV_LOG_ERROR(
			dev,
			"[ERROR:%s] AES controller. Current IOQ id:%d is invalid. Must be >= %d\n",
			__func__, aes->ioq_pool.ioq_select_id, AES_MIN_ID);

		/* do not error it but reset it*/
		aes->ioq_pool.ioq_select_id = AES_MIN_ID;
	}

	if (AZIHSM_CTRL_IS_ABORT_IN_PROGRESS(aes->ctrl)) {
		AZIHSM_DEV_LOG_ERROR(
			dev,
			"MCR controller abort is in progress. Retry command\n");

		cmd->completion_status = AZIHSM_IOQ_CMD_STS_ABORT_IN_PROGRESS;
		return -EAGAIN;
	}

	ioq = azihsm_ioq_find_queue_for_submission(&aes->ioq_pool, AES_MIN_ID,
						   dev, &aes->aes_lock);

	if (ioq == NULL) {
		AZIHSM_DEV_LOG_ERROR(
			dev,
			"[ERROR:%s] AES controller. Unable to find queue to submit\n",
			__func__);
		cmd->completion_status = AZIHSM_IOQ_CMD_STS_QSELECT_FAILED;
		return -EAGAIN;
	}

	/* Acquire the lock on the SQ */
	mutex_lock(&ioq->submit_lock);

	if (azihsm_is_ioq_disabled(ioq) == true) {
		AZIHSM_DEV_LOG_ERROR(
			dev,
			"AES ioq. SQ is disabled. Abort in progress. Retry command\n");
		mutex_unlock(&ioq->submit_lock);
		cmd->completion_status = AZIHSM_IOQ_CMD_STS_QDISABLED;
		return -EAGAIN;
	}

	AZIHSM_DEV_LOG_INFO(dev,
			    "%s: aes:%p cmd:%p ioq:%p pri:%d id:%d vec:%d\n",
			    __func__, aes, cmd, ioq, ioq->pri, ioq->id,
			    ioq->vec);

	azihsm_ioq_perf_update_cntrs_before_submission(hsm, ioq);
	start_time = ktime_get();

	err = azihsm_ioq_submit_cmd(ioq, cmd, &tag);

	mutex_unlock(&ioq->submit_lock);

	if (err) {
		AZIHSM_DEV_LOG_ERROR(
			dev, "%s: failure op=%d cipher:%d cmd_type:%d err:%d\n",
			__func__, cmd->sqe.attr.cmd_opc, cmd->sqe.attr.cipher,
			cmd->sqe.attr.cmd_type, err);

		goto submit_fail;
	}

	/*
	 * NOTE Using The Interruptable versions of functions.
	 * At this point we are waiting for the command to be completed
	 * by the hardware. If we use the interruptable versions the wait
	 * will be interrupted and we will release the hardware buffers.
	 * The two contending parts of the code are the freeing of the dma
	 * buffers and the copy_to_user.
	 * Consider the following points:-
	 *
	 * 1. The freeing of dma buffers can only happen after the hardware
	 *	is done with dma and the copy to user is completed. copy_to_user
	 *	cannot be done in the bottom half and needs to be done in the
	 *	context of the user thread.
	 * 2. If the wait is interrupted in between, we will still need to keep
	 *	the buffers around as the hardware is touching the buffers. We can
	 *	keep the buffers around, and use a lazy free scheme to free those
	 *	but we still cannot return from this function because the
	 *	command information [azihsm_hsm_generic_cmd] is allocated on the stack.
	 *	The completion is the part of this cmd structure.
	 * 3. Theinterruptable versions of these functions are usually used
	 *	  for hardware where the commands can be aborted deterministically.
	 *	  When the wait is interrupted, the commands will be aborted and then the
	 *	ioctl will be completed.
	 * /linux-source-5.15.0/drivers/spi/spi-tegra20-slink.c
	 *
	 */
	err = wait_for_completion_timeout(&cmd->cmpl, timeout);
	end_time = ktime_get();
	if (err == 0) {
		err = -ETIMEDOUT;

		AZIHSM_DEV_LOG_ERROR(
			dev,
			"%s: Command timeout. op=%d cipher:%d type=%d cid:%d err=%d\n",
			__func__, cmd->sqe.attr.cmd_opc, cmd->sqe.attr.cipher,
			cmd->sqe.attr.cmd_type, tag, err);

		atomic_inc(&ioq->sq.hsm_ioq_attribute_array
				    [SQ_ATTRIBUTE_INDEX_NUM_IOS_TIMEDOUT]
					    .counter);

		goto wait_fail;
	}

	if (cmd->completion_status == AZIHSM_IOQ_CMD_STS_ABORTED) {
		/*
		 * This command was aborted on this SQ
		 * so return it back to caller
		 */
		AZIHSM_DEV_LOG_ERROR(
			dev,
			"AES Command submitted on IOQ:%d aborted. tag:%d\n",
			ioq->id, tag);

		return -EAGAIN;
	} /* Else command completed successfully */

	azihsm_ioq_perf_update_cntrs_after_submission(hsm, ioq, &start_time,
						      &end_time);

	if (cmd->cqe.ph_sts.ph_sts_bits.sts != 0) {
		atomic_inc(&ioq->sq.hsm_ioq_attribute_array
				    [SQ_ATTRIBUTE_INDEX_TOTAL_IOS_IN_ERROR]
					    .counter);

		atomic_inc(
			&hsm->hsm_global_attribute_array
				 [AZIHSM_HSM_GLOBAL_ATTRIBUTE_TOTAL_ERROR_COMPLETIONS]
					 .counter);
		//
		// This command is fired and the firmware failed the command
		// for some reason. The command status needs to be propogated
		// to the application with a IOCTL status of success.
		// If we fail the ioctl, the appilcation will never look at
		// the command status and take corrective action. Just log
		// the error and pass the status up to application
		//
		AZIHSM_DEV_LOG_ERROR(
			dev,
			"%s: F/w Cmd failure. op=%d cipher:%d cmd_type:%d cid=%d status=%d\n",
			__func__, cmd->sqe.attr.cmd_opc, cmd->sqe.attr.cipher,
			cmd->sqe.attr.cmd_type, tag,
			cmd->cqe.ph_sts.ph_sts_bits.sts);
	}
	return 0;

wait_fail:
	// Start abort
	// if an abort is already in progress, this thread
	// needs to make sure the command is removed from the
	// context store so the command is not completed in
	// another context
	// Note azihsm_abort can also fail if an existing thread
	// performing level 2 abort failed and marked the device
	// as non-operable.
	err = azihsm_abort(aes->ctrl, ioq, &cmd->cmpl, false,
			   ABORT_TYPE_TIMEOUT);
	if (err)
		/*
		 * if abort is in progress, we need to make sure
		 *  we free up this tag from our context store
		 */
		azihsm_ioq_cancel_cmd(ioq, tag);
	err = -EAGAIN;
submit_fail:
	return err;
}
