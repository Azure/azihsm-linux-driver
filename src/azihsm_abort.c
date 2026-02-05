// SPDX-License-Identifier: GPL-2.0

#include "azihsm_ioq.h"
#include "azihsm_abort.h"
#include "azihsm_aes.h"
#include "azihsm_aes_cmd.h"
#include "azihsm_aes_dev.h"
#include "azihsm_ctrl.h"
#include "azihsm_log.h"
#include "azihsm_ctrl_cmd.h"

extern bool azihsm_pf_lvl2_abort_enabled;

/*
 * azihsm_is_ioq_disabled
 *  Returns true if IOQ is disabled else false
 * caller must be holding the submit_lock on the
 *  ioq
 */
bool azihsm_is_ioq_disabled(struct azihsm_ioq *ioq)
{
	if (!ioq)
		return true;

	if (ioq->ioq_disabled == true)
		return true;
	else
		return false;
}

/*
 * azihsm_ioq_disable
 * Mark the IOQ as disabled
 *
 * Caller must hold the submit_lock on the IOQ
 * marking a IOQ as disabled. This enables this
 * IOQ to be not eligible for posting commands.
 *
 * To ensure that we are not racing with completion
 * context, caller must acquire the
 * compl_lock on the ioq
 *
 * returns void
 */

static void azihsm_ioq_disable(struct device *dev, struct azihsm_ioq *ioq)
{
	AZIHSM_DEV_LOG_ENTRY(dev, "Disabling IOQ:%d\n", ioq->id);
	ioq->ioq_disabled = true;
	AZIHSM_DEV_LOG_EXIT(dev, "Disabled IOQ:%d\n", ioq->id);
}

/*
 * Function :- azihsm_ioq_enable
 * Enable the ioq
 *
 */
static void azihsm_ioq_enable(struct device *dev, struct azihsm_ioq *ioq)
{
	AZIHSM_DEV_LOG_ENTRY(dev, "Enabling IOQ:%d\n", ioq->id);
	ioq->ioq_disabled = false;
	AZIHSM_DEV_LOG_EXIT(dev, "Enabled IOQ:%d\n", ioq->id);
}

void azihsm_disable_all_queues_in_pool(struct device *dev,
				       struct azihsm_ioq_pool *pool)
{
	int id = 0;
	struct azihsm_ioq *ioq = NULL;
	const u16 queue_cnt = pool->ioq_cnt;
	int ioq_id;
	const u16 start_idx = pool->ioq_start_idx;

	AZIHSM_DEV_LOG_ENTRY(
		dev, "Disabling Queues in Pool. QueueCnt:%d StartIdx:%d\n",
		queue_cnt, start_idx);
	for (; id < queue_cnt; id++) {
		ioq_id = id + start_idx;
		ioq = xa_load(&pool->ioqs, ioq_id);
		if (ioq) {
			mutex_lock(&ioq->submit_lock);
			spin_lock_bh(&ioq->cmpl_lock);
			azihsm_ioq_disable(dev, ioq);
			spin_unlock_bh(&ioq->cmpl_lock);
			mutex_unlock(&ioq->submit_lock);
		}
	}
	AZIHSM_DEV_LOG_EXIT(
		dev, "Done.Disabling Queues in Pool. QueueCnt:%d StartIdx:%d\n",
		queue_cnt, start_idx);
}

/*
 * Function : azihsm_flush_all_commands_on_ioq
 * Flush all commands on a IOQ
 *
 * Caller must be holding the compl_lock on the ioq
 * This ensures we do not race with the completion handler
 * or other threads accessing the context store of this ioq
 */
void azihsm_flush_all_commands_on_ioq(struct azihsm_ctrl *ctrl,
				      struct azihsm_ioq *ioq,
				      const int completion_status)
{
	unsigned long index;
	void *cmd;
	const u16 size = ioq->size;
	struct device *dev = &ctrl->pdev->dev;
	u16 tag;

	AZIHSM_DEV_LOG_ENTRY(
		dev, "Flushing all commands from Queue id:%d queue size:%d\n",
		ioq->id, size);

	xa_for_each(&ioq->store.ctx_store, index, cmd) {
		if (cmd) {
			if (!ioq->ops->get_tag)
				continue;
			tag = ioq->ops->get_tag(cmd);
			if (tag != -1) {
				AZIHSM_DEV_LOG_INFO(
					dev,
					"flushing index:%d on ioq:%d tag:%d\n",
					(int)index, ioq->id, tag);
				azihsm_ioq_store_free_ctx(&ioq->store, tag);
				if (completion_status ==
				    AZIHSM_IOQ_CMD_STS_ABORTED)
					atomic_inc(
						&ctrl->hsm
							 .hsm_global_attribute_array
								 [AZIHSM_HSM_GLOBAL_ATTRIBUTE_TOTAL_CMDS_ABORTED]
							 .counter);
				ioq->ops->complete_cmd(cmd, completion_status);
				AZIHSM_DEV_LOG_INFO(
					dev,
					"Done flushing index:%d on ioq:%d tag:%d\n",
					(int)index, ioq->id, tag);
			}
		}
	}
}

void azihsm_ctrl_flush_cmds_from_ioqs(struct azihsm_ctrl *ctrl,
				      struct azihsm_ioq_pool *pool)
{
	const u16 queue_cnt = pool->ioq_cnt;
	struct device *dev = &ctrl->pdev->dev;
	const u16 start_idx = pool->ioq_start_idx;
	struct azihsm_ioq *ioq;
	u16 id = 0;
	u16 ioq_id;

	AZIHSM_DEV_LOG_ENTRY(
		dev,
		"Flushing all commands from Queues start idx:%d queue cnt:%d\n",
		start_idx, queue_cnt);

	for (; id < queue_cnt; id++) {
		ioq_id = id + start_idx;
		ioq = xa_load(&pool->ioqs, ioq_id);
		if (ioq) {
			spin_lock_bh(&ioq->cmpl_lock);
			azihsm_flush_all_commands_on_ioq(
				ctrl, ioq, AZIHSM_IOQ_CMD_STS_ABORTED);
			spin_unlock_bh(&ioq->cmpl_lock);
		}
	}

	AZIHSM_DEV_LOG_EXIT(
		dev,
		"Done Flushing all commands from Queues start idx:%d queue cnt:%d\n",
		start_idx, queue_cnt);
}

/*
 * azihsm_level_one_abort
 * This function performs level one abort on a given IOQ
 * When this function is called, new commands may be dispatched
 *  to the SQ (by other threads)
 *
 *  Acquire the completion lock on the IOQ
 *	Mark the IOQ as disabled
 *  Release the completion lock on the IOQ
 *
 *  With the above steps, bottom half will not process any completions
 *   on the IOQ. New commands will not be submitted to the IOQ
 *
 *  Delete the SQ and flush all commands on the IOQ (This ensures
 *  existing threads that have commands pending on the IOQ will be completed
 *  ) with status code indicating that the command has been aborted
 *
 *  delete a SQ may fail (controller may have gone south and not responding to
 *  admin commands. In this case, force level 2 abort

 *
 *  This function can return any of the following values
 *  AZIHSM_IOQ_LEVEL_ONE_ABORT_SUCCESS :- level one abort is success
 *  AZIHSM_IOQ_ABORT_IN_PROGRESS :- Level one abort is in progress
 *		this status code is communicated to threads that start
 *		abort on SQs which already have abort in progress
 *  AZIHSM_IOQ_ABORT_LEVEL_ONE_FAILED :- level one abort failed
 *		This status code is returned when deleting sq or creating sq
 *		fails
 */
static int azihsm_level_one_abort(struct azihsm_ctrl *ctrl,
				  struct azihsm_ioq *ioq, bool crash)
{
	int rc;
	struct device *dev = &ctrl->pdev->dev;
	union azihsm_ctrl_reg_csts csts;
	bool ctrl_crashed = false;

	csts.val = readl(&ctrl->reg->csts);
	ctrl_crashed = crash || csts.fld.cfs;

	if (ctrl_crashed) {
		AZIHSM_DEV_LOG_ERROR(
			dev,
			"%s: Ctrl Crash Detected In Lvl-1 Abort [Crash:%d, Csts:%d] -Skipping Lvl-1 Abort-",
			__func__, crash, csts.fld.cfs);

		return AZIHSM_IOQ_ABORT_LEVEL_ONE_FAILED;
	}

	if (!ioq) {
		AZIHSM_DEV_LOG_ERROR(
			dev,
			"%s: IOQ Is NULL Skipping Lvl-1 Abort [Crash:%d, Csts:%d] ",
			__func__, crash, csts.fld.cfs);
		return AZIHSM_IOQ_ABORT_LEVEL_ONE_FAILED;
	}

	AZIHSM_DEV_LOG_INFO(
		dev, "Level one abort started on [SQ:%d] [Cnt:%d] [Crash:%d]",
		ioq->id, ctrl->level_one_abort_count, crash);

	ctrl->level_one_abort_count += 1;

	atomic_inc(
		&ctrl->hsm
			 .hsm_global_attribute_array
				 [AZIHSM_HSM_GLOBAL_ATTRIBUTE_TOTAL_LVL_1_ABORTS]
			 .counter);

	atomic_inc(&ioq->sq.hsm_ioq_attribute_array
			    [SQ_ATTRIBUTE_INDEX_NUM_LEVEL1_ABORT]
				    .counter);

	mutex_lock(&ioq->submit_lock);
	spin_lock_bh(&ioq->cmpl_lock);
	azihsm_ioq_disable(dev, ioq);
	spin_unlock_bh(&ioq->cmpl_lock);
	mutex_unlock(&ioq->submit_lock);

	/*
	 * send a command to delete the SQ
	 * Do not touch the CQ. Other SQs may be bound to the CQ
	 * Note about the following code to delete the SQ
	 *  When the response for the delete_sq comes back, the completion
	 *  handler will try to acquire the completion lock for the admin queue
	 *  and therefore there will be no deadlock
	 *
	 *  Because the SQ is marked disabled any completions that occur with CQEs
	 *  pointing to this SQ will not be processed.
	 */
	AZIHSM_DEV_LOG_INFO(dev, "[Level one abort] Deleting SQ:%d size:%d\n",
			    ioq->id, ioq->size);
	rc = azihsm_ctrl_cmd_delete_sq(ctrl, ioq->id);
	AZIHSM_DEV_LOG_INFO(dev,
			    "[Level one abort] Done Deleting SQ:%d ret:%d\n",
			    ioq->id, rc);

	if (rc) {
		AZIHSM_DEV_LOG_ERROR(
			dev,
			"[Level one abort] Deleting SQ:%d failed. Forcing level 2 abort\n",
			ioq->id);
		return AZIHSM_IOQ_ABORT_LEVEL_ONE_FAILED;
	}
	atomic_inc(
		&ctrl->hsm
			 .hsm_admin_attribute_array
				 [AZIHSM_HSM_ADMIN_ATTRIBUTE_NUM_Q_DELETE_CMDS]
			 .counter);

	/*
	 * Walk through each command in the command store
	 *  and complete it. Free up the slot associated with
	 *  the command
	 *
	 * The only commands left in the store will be the commands
	 * issued by other threads on the same IOQ and that are waiting
	 * for completion
	 * Complete each of these and mark them as aborted
	 */
	AZIHSM_DEV_LOG_INFO(
		dev, "[Level one abort] Flushing all commands on SQ:%d\n",
		ioq->id);

	spin_lock_bh(&ioq->cmpl_lock);
	azihsm_flush_all_commands_on_ioq(ctrl, ioq, AZIHSM_IOQ_CMD_STS_ABORTED);
	spin_unlock_bh(&ioq->cmpl_lock);

	azihsm_ioq_sq_restart(ioq);
	/*
	 * Recreate the SQ with the device. None of the other attributes
	 *  are being modified (DMA buffers for the SQ)
	 */
	AZIHSM_DEV_LOG_INFO(dev, "[Level one abort] Creating SQ:%d\n", ioq->id);
	rc = azihsm_ctrl_cmd_create_sq(ctrl, azihsm_ioq_sq_dma_addr(ioq),
				       ioq->id, ioq->id, ioq->size, ioq->pri);

	if (rc) {
		AZIHSM_DEV_LOG_ERROR(
			dev,
			"[Level one Abort]. Recreating SQ:%d failed. err:%d\n",
			ioq->id, rc);

		rc = AZIHSM_IOQ_ABORT_LEVEL_ONE_FAILED;
	} else {
		/*
		 *abort has succeeded. Existing commands have been completed
		 *  Allow new commands to be posted to the queue again
		 */
		AZIHSM_DEV_LOG_INFO(
			dev, "[Level one abort] Creating SQ:%d success\n",
			ioq->id);

		rc = AZIHSM_IOQ_LEVEL_ONE_ABORT_SUCCESS;
	}

	/*
	 * if creating the SQ failed at the device, leave the SQ disabled so no commands can be
	 *  submitted on it
	 */
	if (rc == AZIHSM_IOQ_LEVEL_ONE_ABORT_SUCCESS) {
		mutex_lock(&ioq->submit_lock);
		azihsm_ioq_enable(dev, ioq);
		mutex_unlock(&ioq->submit_lock);
	}

	return rc;
}

/*
 * Main function for MCR level 2 abort
 *  Level 2 abort is started when aborting a IOQ fails for
 *  any reason or when the level one abort has been tried
 *  for a set number of times
 *
 *  Disable all HSM and AES queues
 *   This ensures that no commands are submitted on these queues
 *   Any thread that attempts to post a command will fail and will
 *   have to retry
 *
 *  Disable the controller
 *  Flush all commands on all HSM and AES queues
 *  De initialize the controller
 *  Initialize the controller again with saved controller
 *	configuration
 *
 *  Note :-
 *	Level 2 abort can fail. This might happen for example
 *	if initializing the controller or recreating queues
 *	fails.
 *	if this happens, fallback method is to clean up all
 *	resources and shut down.
 */
static int azihsm_level_two_abort(struct azihsm_ctrl *ctrl, u32 abort_type)
{
	int rc;
	struct device *dev = &ctrl->pdev->dev;

	/* Disable all CP and FP queues */
	AZIHSM_DEV_LOG_ENTRY(dev, "[ENTRY] Level two abort [Cnt:%d]\n",
			     ctrl->level_two_abort_count);

	ctrl->level_two_abort_count += 1;

	atomic_inc(
		&ctrl->hsm
			 .hsm_global_attribute_array
				 [AZIHSM_HSM_GLOBAL_ATTRIBUTE_TOTAL_LVL_2_ABORTS]
			 .counter);

	AZIHSM_DEV_LOG_ERROR(
		dev, "Level two abort. Disabling all queues in HSM pool\n");
	azihsm_disable_all_queues_in_pool(&ctrl->pdev->dev,
					  &ctrl->hsm.ioq_pool);

	AZIHSM_DEV_LOG_ERROR(
		dev, "Level two abort. Disabling all queues in AES pool\n");
	azihsm_disable_all_queues_in_pool(&ctrl->pdev->dev,
					  &ctrl->aes.ioq_pool);

	/*
	 * Disabled all queues above.
	 * Any completions (due to DPC and bottom half) for these queues
	 * will not be completed. Instead they are flushed
	 */

	AZIHSM_DEV_LOG_ERROR(
		dev, "Level two abort. Flushing all commands in HSM pool\n");
	azihsm_ctrl_flush_cmds_from_ioqs(ctrl, &ctrl->hsm.ioq_pool);

	AZIHSM_DEV_LOG_ERROR(
		dev, "Level two abort. Flushing all commands in AES pool\n");
	azihsm_ctrl_flush_cmds_from_ioqs(ctrl, &ctrl->aes.ioq_pool);

	AZIHSM_DEV_LOG_ERROR(dev, "Level two abort. Deiniting the controller\n");
	azihsm_ctrl_deinit(ctrl, true, abort_type);

	/*
	 * At this point any commands submitted by applications
	 * will be failed because the controller is marked as
	 * not initialized
	 */

	AZIHSM_DEV_LOG_ERROR(dev,
			    "Level two abort. Reinitializing the controller\n");
	rc = azihsm_ctrl_init(ctrl, &ctrl->saved_cfg, true);

	if (rc) {
		AZIHSM_DEV_LOG_ERROR(
			dev, "[ERROR] Level two abort failed rc=%d\n", rc);
	} else {
		AZIHSM_DEV_LOG_ERROR(
			dev,
			"Level two abort success. Controller is ready for use\n");
	}
	return rc;
}

/**
 *Function :- azihsm_ioq_abort
 * Main entry point for SQ abort
 * Abort on a SQ is initiated when a command
 * posted on a SQ times out.
 *
 * Note multiple threads may be entering this function
 * Our goal is to reduce the number of aborts that are
 * performed.
 *  Acquire abort_mutex on the controller
 *  Check if the command which timed out, already completed or not
 *  If the command is completed, we do not need to perform abort
 * If the command is not completed, perform the abort, release
 * mutex and return.
 */
int azihsm_abort(struct azihsm_ctrl *ctrl, struct azihsm_ioq *ioq,
		 struct completion *completion_object, bool crash,
		 u32 abort_type)
{
	struct device *dev = &ctrl->pdev->dev;
	int rc = 0, err = 0;
	int que_id = 0;
	bool lvl1_abort = PERFORM_L1_ABORT(abort_type);

	/*
	 * We will not derference the queue id.
	 * when the controller is crashed, we will
	 * get the queue as NULL. We will directly
	 * perfrom level-2 abort. Do not dereference
	 * the ioq pointer, blindly.
	 */

	if (ioq)
		que_id = ioq->id;

	AZIHSM_DEV_LOG_ENTRY(
		dev,
		"[ENTRY:%s] ctrl:%p ioq:%p ioq id[%d] level one abort count:%d cpl_object:%p crash:%d\n",
		__func__, ctrl, ioq, que_id, ctrl->level_one_abort_count,
		completion_object, crash);

	mutex_lock(&ctrl->abort_mutex);

	/* Indicate that a abort is starting */
	AZIHSM_CTRL_SET_ABORT_STATE(ctrl,
				    AZIHSM_CONTROLLER_ABORT_IS_IN_PROGRESS);

	if (!AZIHSM_CTRL_ST_ISRDY(ctrl)) {
		/*
		 * This condition is possible if a previous
		 *  thread performed abort, went to level 2 abort
		 *  and that failed. In that case, device is not
		 *  available anymore
		 */
		AZIHSM_DEV_LOG_EXIT(
			dev,
			"[INFO:%s] ctrl:%p ioq:%p ioq id[%d] crash:[%d] Controller is not usable\n",
			__func__, ctrl, ioq, que_id, crash);

		/* Clear The Abort State */
		AZIHSM_CTRL_SET_ABORT_STATE(ctrl,
					    AZIHSM_CONTROLLER_IS_NOT_IN_ABORT);

		mutex_unlock(&ctrl->abort_mutex);
		return AZIHSM_ABORT_LEVEL_TWO_FAILED;
	}

	/*
	 * This thread is here now. No other thread is going to come here
	 * because we are holding the abort mutex.
	 *
	 * There are two possibilites:-
	 * 1. Earlier thread came in and already did a abort on this command.
	 *    In which case, this command would already be completed.
	 * 2. If the command is not completed, it means that the abort is
	 *    not executed yet, and it is the responsibility of this thread
	 *    to execute the abort.
	 *
	 * So the abort algorithm works like this:-
	 * 1. Acqurie the Abort mutex.
	 * 2. Check if the command is completed already. If it did, just return.
	 * 3. If the command is not completed, Perform the abort task.
	 * 4. Release the mutex.
	 * 5. Return.
	 *
	 */

	/*
	 * Small wait for 100 Jiffies just to check if the command is completed or not.
	 * If the command is completed, we are good. We do not need to do anything.
	 * This can happen if some other thread acquired the mutex and completed
	 * abort while this thread was waiting on the mutex.
	 * If the command is completed, Just return from there abort function.
	 *
	 */
	if (completion_object) {
		err = wait_for_completion_timeout(completion_object, 100);
		if (err != 0) {
			AZIHSM_DEV_LOG_EXIT(
				dev,
				"[INFO:%s] ctrl:%p ioq:%p ioq id[%d] [crash:%d] level one abort count:%d Skipping Abort [Already Completed]\n",
				__func__, ctrl, ioq, que_id, crash,
				ctrl->level_one_abort_count);

			/* Clear The Abort State */
			AZIHSM_CTRL_SET_ABORT_STATE(
				ctrl, AZIHSM_CONTROLLER_IS_NOT_IN_ABORT);

			mutex_unlock(&ctrl->abort_mutex);
			return 0;
		}
	}

	/* 
	 * Command is not completed and it will never be completed
	 * by any other thread. We are holding the abort mutex.
	 * We need to perform abort here.
	 * - Set the abort in progress
	 * - Perform the abort with mutex held
	 * - Make sure that the command is completed
	 * - return.
	 *
	 */

	if (lvl1_abort)
		rc = azihsm_level_one_abort(ctrl, ioq, crash);

	if (rc != AZIHSM_IOQ_LEVEL_ONE_ABORT_SUCCESS || !lvl1_abort) {
		AZIHSM_DEV_LOG_ERROR(
			dev,
			"[%s] [ctrl:%p] [ioq:%p] [crash:%d] [lvl1_abort:%d] level one abort failed/skipped. Moving to level two abort\n",
			__func__, ctrl, ioq, crash, lvl1_abort);

		/*
		 * if we are PF and level 2 abort is enabled
		 * or we are VF
		 */
		if ((ctrl->is_pf && (true == azihsm_pf_lvl2_abort_enabled)) ||
		    !ctrl->is_pf) {
			AZIHSM_DEV_LOG_ERROR(
				dev,
				"[%s] ctrl:%p ioq:%p is_pf[%s] doing level 2 abort\n",
				__func__, ctrl, ioq,
				(ctrl->is_pf ? "YES" : "NO"));
			rc = azihsm_level_two_abort(ctrl, abort_type);
			ctrl->level_one_abort_count = 0;
		}

		if (rc) {
			AZIHSM_DEV_LOG_ERROR(
				dev, "[MCR] level 2 abort failed ctrl:%p\n",
				ctrl);
			/* mark the controller as uninitialized */
			AZIHSM_CTRL_ST_RESET(ctrl);
		} else {
			AZIHSM_DEV_LOG_INFO(
				dev, "[MCR] level 2 abort success. ctrl:%p\n",
				ctrl);
		}
	}

	if (completion_object) {
		// This command should have been completed for sure now, lets make sure of that
		err = wait_for_completion_timeout(completion_object, 100);
		WARN_ON(err == 0);
		if (err == 0) {
			AZIHSM_DEV_LOG_ERROR(
				dev,
				"[Fatal Error:%s] ctrl:%p abort is done. Cmd Initiated Abort Did Not Complete After Abort\n",
				__func__, ctrl);
		}
	}
	/* mark that the abort is done */
	AZIHSM_CTRL_SET_ABORT_STATE(ctrl, AZIHSM_CONTROLLER_IS_NOT_IN_ABORT);

	AZIHSM_DEV_LOG_EXIT(
		dev,
		"[Exit:%s] ctrl:%p return:%d abort is done. Controller is not in abort\n",
		__func__, ctrl, rc);

	mutex_unlock(&ctrl->abort_mutex);
	return rc;
}

/*
 * azihsm_health_monitor:
 * This function runs in the context of kernel Worker process
 * so
 * 1. It can acquire mutex and spin locks
 * 2. Interrupts are enabled
 * 3. Can sleep
 * These are the three things we need for crash recovery.
 *
 */
void azihsm_health_monitor(struct work_struct *work)
{
	int ret = 0;
	union azihsm_ctrl_reg_csts csts;
	struct device *dev = NULL;
	struct azihsm_ctrl *ctrl = NULL;

	struct azihsm_health_mon *hmon = container_of(
		to_delayed_work(work), struct azihsm_health_mon, hmon_work);

	if (!hmon) {
		pr_info("[Invalid Params:Exit] %s hmon: NULL\n", __func__);
		return;
	}

	if (!hmon->ctrl || !hmon->init_done) {
		pr_info("[Invalid Params:Exit] %s hmon:%p hmon->ctrl:%p hmon->init_done:%d\n",
			__func__, hmon, hmon->ctrl, hmon->init_done);

		return;
	}

	ctrl = hmon->ctrl;
	dev = &ctrl->pdev->dev;

	csts.val = readl(&ctrl->reg->csts);

	if (csts.fld.cfs) {
		AZIHSM_DEV_LOG_ERROR(
			dev,
			"[%s] ==== Health Monitor Detected FW Crash [Csts:%d] # PERFORMING RECOVERY # =====\n",
			__func__, csts.val);

		ret = azihsm_abort(ctrl, NULL, NULL, true, ABORT_TYPE_TIMEOUT);
		if (ret) {
			AZIHSM_DEV_LOG_ERROR(
				dev,
				"[Exit:%s] ctrl:%p ==== FAILED Recovering Controller =====\n",
				__func__, ctrl);

			return;
		}

		AZIHSM_DEV_LOG_INFO(
			dev,
			"[Exit:%s] ctrl:%p ==== Controller Recovery Success =====\n",
			__func__, ctrl);
	}

	schedule_delayed_work(&hmon->hmon_work, AZIHSM_HEALTH_MON_TIME);
}
