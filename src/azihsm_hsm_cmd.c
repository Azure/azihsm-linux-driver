// SPDX-License-Identifier: GPL-2.0

#include "azihsm_hsm.h"
#include "azihsm_hsm_cmd.h"
#include "azihsm_hsm_dev_ioctl.h"
#include "azihsm_abort.h"
#include <linux/dmapool.h>
#include "azihsm_ioq_util.h"
#include "azihsm_ioq_perf.h"
#include "azihsm_log.h"

/*
 * azihsm_abort_timeout_in_jiffies
 * time in jiffies to wait before
 * timing out and starting abort
 */
extern int azihsm_abort_timeout_in_jiffies;

/*
 *	azihsm_hsm_generic_cmd_process
 *	Main entry point to submit a command
 *	to the device on the control path
 *
 *	Parameters
 *		hsm	=>	HSM context for the device
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
 *		-EAGAIN :- Abort is in progress
 *			or a queue cannot be found
 *			or this command is aborted
 */

int azihsm_hsm_generic_cmd_process(struct azihsm_hsm *hsm,
				   struct azihsm_hsm_generic_cmd *cmd)
{
	int err = -EAGAIN;

	u16 tag;
	struct device *dev = &hsm->pdev->dev;
	unsigned long timeout = azihsm_abort_timeout_in_jiffies;
	struct azihsm_ioq *ioq = NULL;
	ktime_t start_time, end_time;

	if (hsm->ioq_pool.ioq_select_id < HSM_MIN_ID) {
		AZIHSM_DEV_LOG_INFO(
			dev,
			"[INFO:%s] HSM controller. Current IOQ id:%d is invalid. Must be >= %d\n",
			__func__, hsm->ioq_pool.ioq_select_id, HSM_MIN_ID);
		hsm->ioq_pool.ioq_select_id = HSM_MIN_ID;
	}

	if (AZIHSM_CTRL_IS_ABORT_IN_PROGRESS(hsm->ctrl)) {
		AZIHSM_DEV_LOG_ERROR(
			dev,
			"MCR controller abort is in progress. Retry command\n");

		cmd->completion_status = AZIHSM_IOQ_CMD_STS_ABORT_IN_PROGRESS;
		return -EAGAIN;
	}

	if (!AZIHSM_CTRL_ST_ISRDY(hsm->ctrl)) {
		AZIHSM_DEV_LOG_ERROR(
			dev,
			"[%s] Controller Is Not Ready, This Could Happen If The Level-2 Abort Failed\n",
			__func__);

		cmd->completion_status = AZIHSM_CTRL_NOT_READY;
		return -EAGAIN;
	}

	ioq = azihsm_ioq_find_queue_for_submission(&hsm->ioq_pool, HSM_MIN_ID,
						   dev, &hsm->hsm_lock);

	if (ioq == NULL) {
		AZIHSM_DEV_LOG_ERROR(
			dev,
			"[ERROR:%s] HSM controller. Unable to find queue to submit\n",
			__func__);

		cmd->completion_status = AZIHSM_IOQ_CMD_STS_QSELECT_FAILED;
		return -EAGAIN;
	}

	/* Acquire the lock on the SQ */
	mutex_lock(&ioq->submit_lock);

	if (azihsm_is_ioq_disabled(ioq) == true) {
		AZIHSM_DEV_LOG_ERROR(
			dev,
			"HSM ioq. SQ[%d] is disabled. Abort in progress. Retry command\n",
			ioq->id);
		mutex_unlock(&ioq->submit_lock);

		cmd->completion_status = AZIHSM_IOQ_CMD_STS_QDISABLED;
		return -EAGAIN;
	}

	azihsm_ioq_perf_update_cntrs_before_submission(hsm, ioq);
	start_time = ktime_get();

	err = azihsm_ioq_submit_cmd(ioq, cmd, &tag);

	mutex_unlock(&ioq->submit_lock);
	if (err) {
		AZIHSM_DEV_LOG_ERROR(
			dev,
			"HSM ioq. ioq_submit_cmd failed. command submission failed\n");
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
	 * 3. The interruptable versions of these functions are usually used
	 *  for hardware where the commands can be aborted deterministically.
	 *  When the wait is interrupted, the commands will be aborted and then the
	 *	ioctl will be completed.
	 * /linux-source-5.15.0/drivers/spi/spi-tegra20-slink.c
	 *
	 */
	err = wait_for_completion_timeout(&cmd->cmpl, timeout);
	end_time = ktime_get();
	if (err == 0) {
		/*
		 * Error code = 0 Means that the wait timed out.
		 * The hardware could still be processing the command.
		 * This is the place where the Abort logic will kick in.
		 */
		err = -ETIMEDOUT;

		atomic_inc(&ioq->sq.hsm_ioq_attribute_array
				    [SQ_ATTRIBUTE_INDEX_NUM_IOS_TIMEDOUT]
					    .counter);

		AZIHSM_DEV_LOG_ERROR(dev, "Command timed out. Timeout[%lu]\n",
				     timeout);

		goto wait_fail;
	}

	if (cmd->completion_status == AZIHSM_IOQ_CMD_STS_ABORTED) {
		/* This command was aborted so return it back to caller */
		AZIHSM_DEV_LOG_ERROR(
			dev, "HSM Command submitted on SQ:%d aborted. tag:%d\n",
			ioq->id, tag);
		return -EAGAIN;
	} /* Else command completed successfully */

	azihsm_ioq_perf_update_cntrs_after_submission(hsm, ioq, &start_time,
						      &end_time);

	if (cmd->cqe.psf.fld.sc != 0) {
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
			"Command unsuccessful. op=%d cmdset:%d cid=%d status=%d\n",
			cmd->sqe.opc, cmd->sqe.set, tag, cmd->cqe.psf.fld.sc);
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
	err = azihsm_abort(hsm->ctrl, ioq, &cmd->cmpl, false,
			   ABORT_TYPE_TIMEOUT);
	if (err) {
		/* if abort is in progress or abort has failed
		 *  clean up our context from context store
		 */
		azihsm_ioq_cancel_cmd(ioq, tag);
	}
	/* indicate status code to applications to retry this command again*/
	err = -EAGAIN;
submit_fail:
	return err;
}
