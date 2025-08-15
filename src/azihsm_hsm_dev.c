// SPDX-License-Identifier: GPL-2.0

#include "azihsm_errors.h"
#include "azihsm_hsm_dev.h"
#include "azihsm.h"
#include "azihsm_hsm_dev_ioctl.h"
#include "azihsm_aes_dev_ioctl.h"
#include "azihsm_hsm_cmd.h"
#include "azihsm_abort.h"

#include <linux/idr.h>
#include <linux/mutex.h>
#include <linux/uaccess.h>
#include <linux/vmalloc.h>
#include <linux/moduleparam.h>
#include <linux/version.h>

#define AZIHSM_HSM_DEV_COUNT (16 * 65)
static DEFINE_IDA(azihsm_hsm_dev_ida);

static struct class *azihsm_hsm_dev_class;
static unsigned int azihsm_hsm_dev_major;

static void azihsm_hsm_close_sessions(struct azihsm_hsm_fd_ctxt *ctxt)
{
	/* walk through all open sessions and close them */
	int i;

	/*
	 * We need this check here becuase while the IOs are
	 * running the controller may hit level two abort.
	 * If the level two abort fails, we cannot recover from it.
	 *
	 */
	if (!AZIHSM_CTRL_ST_ISRDY(ctxt->hsm->ctrl)) {
		AZIHSM_DEV_LOG_ERROR(
			&ctxt->hsm->pdev->dev,
			"[%s: !!ERROR!! Should Never Happen] Device Is Not Ready.Close Session Returning Without Closing Sessions\n",
			__func__);

		return;
	}

	for (i = 0; i < AZIHSM_MAX_SESSIONS_PER_FD; i++) {
		if (ctxt->sessions[i].valid) {
			azihsm_hsm_force_close_session(ctxt->hsm,
						       ctxt->sessions[i].id);
			ctxt->sessions[i].valid = 0;
			ctxt->sessions[i].id = 0;
			ctxt->sessions[i].short_app_id = 0;
			ctxt->sessions[i].short_app_id_is_valid = 0;
		}
	}
}

static void azihsm_hsm_fill_error_sts(struct azihsm_hsm *hsm,
				      struct azihsm_cp_generic_cmd *cmd,
				      u32 hsm_cmd_sts)
{
	u32 status_code = 0;

	switch (hsm_cmd_sts) {
	case AZIHSM_IOQ_CMD_STS_ABORTED:
	case AZIHSM_IOQ_CMD_STS_QDISABLED: {
		status_code = GENERATE_STATUS_CODE(AZIHSM_STS_SRC_ABORT,
						   AZIHSM_ABORT_CMD_ABORTED);
		break;
	}

	case AZIHSM_IOQ_CMD_STS_ABORT_IN_PROGRESS: {
		status_code = GENERATE_STATUS_CODE(AZIHSM_STS_SRC_ABORT,
						   AZIHSM_ABORT_IN_PROGRESS);
		break;
	}

	case AZIHSM_CTRL_NOT_READY:
	case AZIHSM_IOQ_CMD_STS_QSELECT_FAILED: {
		status_code = GENERATE_STATUS_CODE(
			AZIHSM_STS_SRC_ABORT,
			AZIHSM_CP_GENERIC_IOCTL_DEVICE_ERROR);
		break;
	}

	default:
		return; // Return without modifying the status code.

	} //switch

	cmd->out.u.generic.ioctl_extended_status = status_code;
}

static int azihsm_hsm_passthrough_cmd(
	struct azihsm_hsm *hsm, const __u16 opc, const __u16 cmdset,
	const __u8 psdt, dma_addr_t src_buf_first_4K_pa,
	dma_addr_t src_buf_second_4K_pa, const __u32 src_buf_length,
	dma_addr_t dst_buf_first_4K_pa, dma_addr_t dst_buf_second_4K_pa,
	const __u32 dst_buf_length,
	union azihsm_hsm_generic_cmd_sqe_src_data *src_data,
	struct azihsm_hsm_cmd_generic_cqe *cqe, int *cpl_sts)
{
	struct azihsm_hsm_generic_cmd hsm_generic_cmd;
	int err;

	*cpl_sts = AZIHSM_IOQ_CMD_STS_SUCCESS;
	memset(&hsm_generic_cmd, 0, sizeof(hsm_generic_cmd));
	hsm_generic_cmd.tag = -1;
	init_completion(&hsm_generic_cmd.cmpl);
	hsm_generic_cmd.completion_status = AZIHSM_IOQ_CMD_STS_UNDEFINED;

	hsm_generic_cmd.sqe.psdt = (psdt & 0x3);
	hsm_generic_cmd.sqe.set = (cmdset & 0xf);
	hsm_generic_cmd.sqe.opc = (opc & 0x3ff);

	hsm_generic_cmd.sqe.src_data = *src_data;

	hsm_generic_cmd.sqe.src_len = src_buf_length;
	hsm_generic_cmd.sqe.dst_len = dst_buf_length;

	hsm_generic_cmd.sqe.src.prp.fst = src_buf_first_4K_pa;
	hsm_generic_cmd.sqe.src.prp.snd = src_buf_second_4K_pa;

	hsm_generic_cmd.sqe.dst.prp.fst = dst_buf_first_4K_pa;
	hsm_generic_cmd.sqe.dst.prp.snd = dst_buf_second_4K_pa;

	err = azihsm_hsm_generic_cmd_process(hsm, &hsm_generic_cmd);

	// Return a copy of the cqe if the caller asked for it
	// The cqe has all the information that is needed
	if (cqe)
		*cqe = hsm_generic_cmd.cqe;

	*cpl_sts = hsm_generic_cmd.completion_status;
	return err;
}

/**
 * azihsm_hsm_force_close_session
 * Function to forcibly close a session.
 * Since forcibly closing a session can cause application
 * problems (sessions are owned by applications), this function
 * should only be used when the application has ended without closing
 * sessions
 *
 * Uses a new opcode (HSM cmdset) encoded within the
 * same cmdset.
 */
void azihsm_hsm_force_close_session(struct azihsm_hsm *hsm,
				    const u16 session_id)
{
	union azihsm_hsm_generic_cmd_sqe_src_data src_data;
	u32 cpl_sts_out = 0;

	mutex_lock(&hsm->ctrl->abort_mutex);
	memset(&src_data, 0, sizeof(src_data));
	src_data.session_data.session_id = session_id;
	src_data.session_data.session_ctrl_flags.opcode =
		AZIHSM_OPCODE_FLOW_CLOSE_SESSION;
	src_data.session_data.session_ctrl_flags.in_session_cmd = 1;
	(void)azihsm_hsm_passthrough_cmd(hsm, AZIHSM_HSM_FLUSH_SESSION_OPCODE,
					 CP_CMD_SESSION_GENERIC, 0, 0, 0, 0, 0,
					 0, 0, &src_data, NULL, &cpl_sts_out);

	hsm->ctrl->session_flush_cnt += 1;
	mutex_unlock(&hsm->ctrl->abort_mutex);
	/* no need for the cqe contents */
}

/*
 * azihsm_hsm_process_session_in_cmd_completion
 *  Process session information that is returned in the completion
 *  of a command (cqe).
 *
 *  Note device side logic may not have the capability to validate sessions
 *  in which case the version in the cqe should be earlier versions
 *
 * Parameters :
 *	ctxt (Context associated with a file handle on which the ioctl was sent)
 *	src_data ---> The 20 bytes of data that was associated with the command
 *	cqe --> The whole CQE that is associated with the command
 *
 * If opcode is open session
 *   store the session id received in the response (cqe) in the session slot
 *   in the array. We did verify that we had an open slot before sending the
 *   request to the device so this should not fail.
 *
 * If opcode is close session
 *  Whether the CQE status is success or failure, if the safe to close session bit
 *  is set to 1, close the session. Otherwise, the session is not closed.
 *
 * If opcode is in session there is nothing to do.
 *   When the request was sent, we did verify that the session was valid so
 *   the response does not require any further processing.
 */
static void azihsm_hsm_process_session_in_cmd_completion(
	struct azihsm_hsm_fd_ctxt *ctxt,
	union azihsm_hsm_generic_cmd_sqe_src_data *src_data,
	struct azihsm_hsm_cmd_generic_cqe *cqe)
{
	int i;
	u8 session_found = 0;

	if (cqe->psf.fld.sc) {
		AZIHSM_DEV_LOG_ERROR(
			ctxt->hsm->cdev_dev,
			"[%s:ERROR: ctxt:%p] Processing session information in CQE. opcode[%d] completion status is failure[0x%x]\n",
			__func__, ctxt,
			src_data->session_data.session_ctrl_flags.opcode,
			cqe->psf.fld.sc);

		/*
		 * if opcode is close session and safe to close session is 1, then close the session
		 */
		if (cqe->cqe_data.session_data.session_ctrl_flags
			    .in_session_cmd &&
		    (src_data->session_data.session_ctrl_flags.opcode ==
		     AZIHSM_OPCODE_FLOW_CLOSE_SESSION)) {
			for (i = 0; i < AZIHSM_MAX_SESSIONS_PER_FD; i++) {
				if (ctxt->sessions[i].valid &&
				    ctxt->sessions[i].id ==
					    src_data->session_data.session_id &&
				    cqe->cqe_data.session_data
					    .session_ctrl_flags
					    .safe_to_close_session) {
					ctxt->sessions[i].valid = 0;
					ctxt->sessions[i].id = (u16)-1;
					ctxt->sessions[i].short_app_id_is_valid =
						false;
					ctxt->sessions[i].short_app_id = (u8)-1;
				}
			}
		}
		return;
	}

	/*
	 * Per session handling design, opcode in completion must be the same
	 * as the opcode in the submission
	 */
	if (cqe->cqe_data.session_data.session_ctrl_flags.opcode !=
	    src_data->session_data.session_ctrl_flags.opcode) {
		AZIHSM_DEV_LOG_ERROR(
			ctxt->hsm->cdev_dev,
			"[%s:ERROR:ctxt:%p] Processing session information in CQE. opcode[%d] in completion does not match in sqe[%d]\n",
			__func__, ctxt,
			cqe->cqe_data.session_data.session_ctrl_flags.opcode,
			src_data->session_data.session_ctrl_flags.opcode);
		return;
	}

	if (cqe->cqe_data.session_data.session_ctrl_flags.in_session_cmd) {
		switch (src_data->session_data.session_ctrl_flags.opcode) {
		case AZIHSM_OPCODE_FLOW_OPEN_SESSION:
			/*
			 * Need to store this new session in our array of sessions
			 * Before sending the command to the device, we did verify that
			 * we had an open slot.
			 */
			for (i = 0; i < AZIHSM_MAX_SESSIONS_PER_FD; i++) {
				if (false == ctxt->sessions[i].valid) {
					ctxt->sessions[i].valid = true;
					ctxt->sessions[i].id =
						cqe->cqe_data.session_data
							.session_id;

					/* If the CQE contains a valid short app id
					 *  save that away.
					 *  We will use the short app id in the
					 *  fast path(aes)
					 */
					if (cqe->cqe_data.session_data
						    .session_ctrl_flags
						    .short_app_id_is_valid) {
						ctxt->sessions[i].short_app_id =
							cqe->cqe_data
								.session_data
								.short_app_id;
						ctxt->sessions[i]
							.short_app_id_is_valid =
							true;
					}
					break;
				}
			}

			if (i == AZIHSM_MAX_SESSIONS_PER_FD) {
				AZIHSM_DEV_LOG_ERROR(
					ctxt->hsm->cdev_dev,
					"[%s:ERROR ctxt:%p] Processing session information in CQE. Opening session. New session[%d] received but no space available. Max[%d]\n",
					__func__, ctxt,
					cqe->cqe_data.session_data.session_id,
					AZIHSM_MAX_SESSIONS_PER_FD);
			}
			break;

		case AZIHSM_OPCODE_FLOW_CLOSE_SESSION:
			/*
			 * Free up the space for this session since
			 * it is closed on the device
			 */
			for (i = 0; i < AZIHSM_MAX_SESSIONS_PER_FD; i++) {
				if (ctxt->sessions[i].valid &&
				    ctxt->sessions[i].id ==
					    src_data->session_data.session_id &&
				    cqe->cqe_data.session_data
					    .session_ctrl_flags
					    .safe_to_close_session) {
					ctxt->sessions[i].valid = 0;
					ctxt->sessions[i].id = (u16)-1;
					ctxt->sessions[i].short_app_id_is_valid =
						false;
					ctxt->sessions[i].short_app_id = (u8)-1;
					session_found = 1;
					break;
				}
			}

			if (!session_found) {
				AZIHSM_DEV_LOG_ERROR(
					ctxt->hsm->cdev_dev,
					"[%s:ERROR ctxt:%p] Processing session information in CQE. Closing session[%d]. Command sent to device but session not found in slot. Maxslots=%d\n",
					__func__, ctxt,
					src_data->session_data.session_id,
					AZIHSM_MAX_SESSIONS_PER_FD);
			}
			break;
		}
	}
}

/*
 * Function :- azihsm_hsm_validate_session_in_ioctl_cmd
 * Driver received an ioctl with the opcode and session
 * We need to do further processing before queueing the SQE
 * to the device.
 *
 * Returns a non-zero value to indicate failure if any validation
 * fails else returns 0
 *
 * Validation details
 *  In open session, verify we have space to store session coming back
 *  In close session and in session opcodes, verify we have an existing
 *  session id and that the session id in the request matches this session
 *  id
 */
static int azihsm_hsm_validate_session_in_ioctl_cmd(
	struct azihsm_hsm_fd_ctxt *ctxt, struct azihsm_cp_generic_cmd *cmd,
	union azihsm_hsm_generic_cmd_sqe_src_data *src_data)
{
	u8 session_ctrl_opcode =
		cmd->in.u.session_data.session_control_flags.u.opcode;
	int i;
	u8 free_slot_found = 0;
	u8 session_found = 0;

	if (!AZIHSM_IOCTL_OPCODE_SESSION_VALID(session_ctrl_opcode)) {
		AZIHSM_DEV_LOG_ERROR(
			ctxt->hsm->cdev_dev,
			"[%s:ERROR ctxt:%p] Ioctl buffer validation failed. Opcode provided=%d in ioctl is not valid\n",
			__func__, ctxt, session_ctrl_opcode);
		cmd->out.u.generic.ioctl_extended_status =
			AZIHSM_CP_GENERIC_IOCTL_INVALID_SESSION_OPCODE;
		return -EINVAL;
	}

	/*
	 * If the application is trying to close a session or perform
	 * an insession command, check that a session is already opened
	 */
	if ((session_ctrl_opcode == AZIHSM_OPCODE_FLOW_CLOSE_SESSION) ||
	    (session_ctrl_opcode == AZIHSM_OPCODE_FLOW_IN_SESSION)) {
		for (i = 0; i < AZIHSM_MAX_SESSIONS_PER_FD; i++) {
			if (ctxt->sessions[i].valid) {
				session_found = 1;
				break;
			}
		}
		if (!session_found) {
			AZIHSM_DEV_LOG_ERROR(
				ctxt->hsm->cdev_dev,
				"[%s:ERROR ctxt:%p] Ioctl buffer validation failed. opcode[%d] No open session found in file handle context\n",
				__func__, ctxt, session_ctrl_opcode);
			cmd->out.u.generic.ioctl_extended_status =
				AZIHSM_CP_GENERIC_IOCTL_NO_EXISTING_SESSION;
			return -EINVAL;
		}

		if (cmd->in.u.session_data.session_control_flags.u
			    .session_id_is_valid) {
			if (ctxt->sessions[i].id !=
			    cmd->in.u.session_data.session_id) {
				AZIHSM_DEV_LOG_ERROR(
					ctxt->hsm->cdev_dev,
					"[%s:ERROR ctxt:%p] Ioctl buffer validation failed. Existing session id=%d does not match id in request[%d]\n",
					__func__, ctxt, ctxt->sessions[i].id,
					cmd->in.u.session_data.session_id);
				cmd->out.u.generic.ioctl_extended_status =
					AZIHSM_CP_GENERIC_IOCTL_SESSION_ID_MISMATCH;
				return -EINVAL;
			}
		} else {
			AZIHSM_DEV_LOG_ERROR(
				ctxt->hsm->cdev_dev,
				"[%s:ERROR ctxt:%p] Ioctl buffer validation failed. opcode[%d] Caller trying to close a non-present session\n",
				__func__, ctxt, session_ctrl_opcode);
			cmd->out.u.generic.ioctl_extended_status =
				AZIHSM_CP_GENERIC_IOCTL_SESSION_ID_MISMATCH;
			return -EINVAL;
		}
	}

	/* if opcode is open session, ensure we have space in our slots to store a new session.
	 *  It may fail on the other end but we do not submit to device if we do not have space
	 */
	if (session_ctrl_opcode == AZIHSM_OPCODE_FLOW_OPEN_SESSION) {
		for (i = 0; i < AZIHSM_MAX_SESSIONS_PER_FD; i++) {
			if (ctxt->sessions[i].valid == 0) {
				free_slot_found = 1;
				break;
			}
		}

		if (free_slot_found == 0) {
			AZIHSM_DEV_LOG_ERROR(
				ctxt->hsm->cdev_dev,
				"[%s:ERROR ctxt:%p] Ioctl buffer validation failed. A new session is being opened but reached the maximum # of open sessions[%d]\n",
				__func__, ctxt, AZIHSM_MAX_SESSIONS_PER_FD);

			cmd->out.u.generic.ioctl_extended_status =
				AZIHSM_CP_GENERIC_IOCTL_OPEN_SESSION_SESSION_LIMIT_REACHED;
			return -EINVAL;
		}
	}

	if (!cmd->in.src_buf && cmd->in.src_length) {
		AZIHSM_DEV_LOG_ERROR(
			ctxt->hsm->cdev_dev,
			"[%s:ERROR Invalid Source Buffer and Length[buff->%p:len->%d]\n",
			__func__, cmd->in.src_buf, cmd->in.src_length);

		cmd->out.u.generic.ioctl_extended_status =
			AZIHSM_CP_GENERIC_IOCTL_INVALID_INPUT_BUFFER;
		return -EINVAL;
	}

	if (!access_ok(cmd->in.src_buf, cmd->in.src_length)) {
		AZIHSM_DEV_LOG_ERROR(
			ctxt->hsm->cdev_dev,
			"[%s:ERROR  Source Buffer Does Not Have read Access [buff->%p:len->%d]\n",
			__func__, cmd->in.src_buf, cmd->in.src_length);

		cmd->out.u.generic.ioctl_extended_status =
			AZIHSM_CP_GENERIC_IOCTL_INVALID_INPUT_BUFFER;

		return -EINVAL;
	}

	if (!cmd->in.dst_buf && cmd->in.dst_length) {
		AZIHSM_DEV_LOG_ERROR(
			ctxt->hsm->cdev_dev,
			"[%s:ERROR Invalid Dest Buffer and Length[buff->%p:len->%d]\n",
			__func__, cmd->in.dst_buf, cmd->in.dst_length);

		cmd->out.u.generic.ioctl_extended_status =
			AZIHSM_CP_GENERIC_IOCTL_INVALID_OUTPUT_BUFFER;
		return -EINVAL;
	}

	if (!access_ok(cmd->in.dst_buf, cmd->in.dst_length)) {
		AZIHSM_DEV_LOG_ERROR(
			ctxt->hsm->cdev_dev,
			"[%s:ERROR  Destination Buffer Does Not Have Write Access [buff->%p:len->%d]\n",
			__func__, cmd->in.dst_buf, cmd->in.dst_length);

		cmd->out.u.generic.ioctl_extended_status =
			AZIHSM_CP_GENERIC_IOCTL_INVALID_OUTPUT_BUFFER;

		return -EINVAL;
	}

	// Done with checks. Translate from user buffer to
	// sqe src_data field.
	// advertise as supporting version of sqe carrying session information
	// until it gets turned off
	//
	/*
	 * Note about the following code
	 * open session does not carry any session id in its command.
	 * But there is a specific test in open_app_session_with_invalid
	 * session that provides a session id in the open and expects that
	 * to fail at the device. So we have to support it
	 */

	src_data->session_data.session_ctrl_flags.opcode = session_ctrl_opcode;
	if ((session_ctrl_opcode == AZIHSM_OPCODE_FLOW_CLOSE_SESSION) ||
	    (session_ctrl_opcode == AZIHSM_OPCODE_FLOW_IN_SESSION) ||
	    (session_ctrl_opcode == AZIHSM_OPCODE_FLOW_OPEN_SESSION)) {
		if (cmd->in.u.session_data.session_control_flags.u
			    .session_id_is_valid)
			src_data->session_data.session_ctrl_flags
				.in_session_cmd = 1;
		src_data->session_data.session_id =
			cmd->in.u.session_data.session_id;
	}

	return 0;
}

/**
 * azihsm_ioctl_hsm_free_dma_buffer_pools
 * Function to free DMA buffer pools for user source and
 * destination buffers allocated during processing of a
 * command.
 *
 * Takes the VA and PA of the 2 4K buffers of the user source
 * and destination buffers.
 *
 *
 * Parameters
 * hsm
 * src_first_4K_va and src_first_4K_pa are the kernel va and
 * device va of the first 4K buffer for user source buffer
 *
 * src_second_4K_va and src_second_4K_va are the kernel va and
 * device va of the 2nd 4k buffer for source buffer
 *
 * dst_first_4K_va and dst_first_4K_pa are the kernel va and
 * device va of the first 4K buffer for user destination buffer
 *
 * dst_second_4K_va and dst_second_4K_va are the kernel va and
 * device va of the 2nd 4k buffer for user destination buffer
 *
 * Return value None
 */

static void azihsm_ioctl_hsm_free_dma_buffer_pools(
	struct azihsm_hsm *hsm, void *src_first_4K_va,
	dma_addr_t src_first_4K_pa, void *src_second_4K_va,
	dma_addr_t src_second_4K_pa, void *dst_first_4K_va,
	dma_addr_t dst_first_4K_pa, void *dst_second_4K_va,
	dma_addr_t dst_second_4K_pa)
{
	if (src_first_4K_va && src_first_4K_pa)
		dma_pool_free(hsm->page_pool, src_first_4K_va, src_first_4K_pa);

	if (src_second_4K_va && src_second_4K_pa)
		dma_pool_free(hsm->page_pool, src_second_4K_va,
			      src_second_4K_pa);

	if (dst_first_4K_va && dst_first_4K_pa)
		dma_pool_free(hsm->page_pool, dst_first_4K_va, dst_first_4K_pa);

	if (dst_second_4K_va && dst_second_4K_pa)
		dma_pool_free(hsm->page_pool, dst_second_4K_va,
			      dst_second_4K_pa);
}

/**
 * Function :- azihsm_ioctl_hsm_copy_user_buffers_to_dma_pool
 * This function takes a user ioctl command argument for the HSM
 * generic command and creates kernel buffers to act as bounce
 * buffers for both source and destination.
 *
 * Once the buffers are created, this function also copies from
 * user provided source buffer to the kernel source buffer.
 *
 * If this function fails in creating the dma buffer pools or
 * in copying user buffers to dma buffer pools, a non-zero value
 * is returned. On success, this function returns 0.
 *
 * Caller must make sure to free the dma buffer pools on a success from
 * this function. If function returns failure, any DMA buffers created
 * are freed up.
 *
 * Caller should ensure that user source buffer is no longer than 8K
 * in length (virtually contiguous)
 *
 * Parameters:
 * hsm
 * user_generic_cmd (Ioctl buffer)
 * src_first_4K_va and src_first_4K_pa are the va and pa returned from
 *   this function on a success. PA is the device logical address and
 *   VA is the kernel virtual address for the first 4K buffer for the
 *   source bounce buffer.
 *
 * src_second_4K_va and src_second_4K_pa are the va and pa returned from
 *   this function on a success. PA is the device logical address and
 *   VA is the kernel va for the second 4K buffer for the source bounce
 *   buffer
 *
 * dst_first_4K_va and dst_first_4K_pa are the va and pa returned from
 *   this function on a success. PA is the device logical address and
 *   VA is the kernel virtual address for the first 4K for the
 *   destination bounce buffer.
 *
 * dst_second_4K_va and dst_second_4K_pa are the va and pa returned from
 *   this function on a success. PA is the device logical address and
 *   VA is the kernel va for the second 4K buffer for the destination bounce
 *   buffer
 *
 * User source buffer (8K max length) is described in the ioctl buffer
 *
 * Returns 0 on success
 * Returns -ENOMEM if any of the buffers (DMA buffers) could not be
 * allocated
 * Returns -EINVAL if buffers could be allocated but copying from user
 * buffers to the DMA buffers did not succeed
 */

static int azihsm_ioctl_hsm_copy_user_buffers_to_dma_pool(
	struct azihsm_hsm *hsm, struct azihsm_cp_generic_cmd *user_generic_cmd,
	void **src_first_4K_va, dma_addr_t *src_first_4K_pa,
	void **src_second_4K_va, dma_addr_t *src_second_4K_pa,
	void **dst_first_4K_va, dma_addr_t *dst_first_4K_pa,
	void **dst_second_4K_va, dma_addr_t *dst_second_4K_pa)
{
	int err = 0;
	__u32 rem;
	__u8 *user_src_buf;
	__u32 user_dst_buf_length, user_src_buf_length;

	user_src_buf = user_generic_cmd->in.src_buf;

	user_src_buf_length = user_generic_cmd->in.src_length;
	user_dst_buf_length = user_generic_cmd->in.dst_length;

	*src_first_4K_va = *src_second_4K_va = *dst_first_4K_va =
		*dst_second_4K_va = NULL;
	*src_first_4K_pa = *src_second_4K_pa = *dst_first_4K_pa =
		*dst_second_4K_pa = 0;
	/*
	 * Allocate DMA buffer pools for input buffer only if the buffer is
	 * non-zero in length
	 */
	if (user_src_buf_length) {
		*src_first_4K_va = dma_pool_alloc(hsm->page_pool, GFP_KERNEL,
						  src_first_4K_pa);
		if (!*src_first_4K_va) {
			AZIHSM_DEV_LOG_ERROR(
				hsm->cdev_dev,
				"[%s:ERROR] dma_pool_alloc failed for first 4k of input buffer\n",
				__func__);
			user_generic_cmd->out.u.generic.ioctl_extended_status =
				AZIHSM_CP_GENERIC_IOCTL_NO_MEMORY;
			return -ENOMEM;
		}

		if (user_src_buf_length > SZ_4K) {
			*src_second_4K_va = dma_pool_alloc(
				hsm->page_pool, GFP_KERNEL, src_second_4K_pa);
			if (!*src_second_4K_va) {
				AZIHSM_DEV_LOG_ERROR(
					hsm->cdev_dev,
					"[%s:ERROR] dma_pool_alloc failed for 2nd 4k of input buffer\n",
					__func__);
				err = -ENOMEM;
				user_generic_cmd->out.u.generic
					.ioctl_extended_status =
					AZIHSM_CP_GENERIC_IOCTL_NO_MEMORY;
				goto dma_pool_alloc_fail;
			}
		}
	}

	if (user_dst_buf_length) {
		*dst_first_4K_va = dma_pool_alloc(hsm->page_pool, GFP_KERNEL,
						  dst_first_4K_pa);
		if (!*dst_first_4K_va) {
			err = -ENOMEM;
			AZIHSM_DEV_LOG_ERROR(
				hsm->cdev_dev,
				"[%s:ERROR] dma_pool_alloc failed for first 4k of output buffer\n",
				__func__);
			user_generic_cmd->out.u.generic.ioctl_extended_status =
				AZIHSM_CP_GENERIC_IOCTL_NO_MEMORY;
			goto dma_pool_alloc_fail;
		}

		if (user_dst_buf_length > SZ_4K) {
			*dst_second_4K_va = dma_pool_alloc(
				hsm->page_pool, GFP_KERNEL, dst_second_4K_pa);
			if (!*dst_second_4K_va) {
				err = -ENOMEM;
				AZIHSM_DEV_LOG_ERROR(
					hsm->cdev_dev,
					"[%s:ERROR] dma_pool_alloc failed for second 4k of output buffer\n",
					__func__);
				user_generic_cmd->out.u.generic
					.ioctl_extended_status =
					AZIHSM_CP_GENERIC_IOCTL_NO_MEMORY;
				goto dma_pool_alloc_fail;
			}
		}
	}

	/*
	 * Copy from user buffer to our dma buffers keeping in mind
	 * that user buffer is at most 8k in length
	 */
	if (user_src_buf_length && user_src_buf) {
		if (user_src_buf_length > SZ_4K)
			rem = user_src_buf_length - SZ_4K;
		else
			rem = 0;

		if (copy_from_user(*src_first_4K_va,
				   (void __user *)user_src_buf,
				   (rem == 0) ? user_src_buf_length : SZ_4K)) {
			AZIHSM_DEV_LOG_ERROR(
				hsm->cdev_dev,
				"[%s:ERROR]. failure in copying first 4k of user buffer length=%d\n",
				__func__,
				(rem == 0) ? user_src_buf_length : SZ_4K);
			user_generic_cmd->out.u.generic.ioctl_extended_status =
				AZIHSM_CP_GENERIC_IOCTL_INVALID_INPUT_BUFFER;
			err = -EINVAL;
			goto dma_pool_alloc_fail;
		}

		if (rem) {
			if (copy_from_user(
				    *src_second_4K_va,
				    (void __user *)((u8 *)user_src_buf + SZ_4K),
				    rem)) {
				AZIHSM_DEV_LOG_ERROR(
					hsm->cdev_dev,
					"[%s:ERROR]. unable to copy 2nd 4K of user buffer length=%d\n",
					__func__, rem);
				user_generic_cmd->out.u.generic
					.ioctl_extended_status =
					AZIHSM_CP_GENERIC_IOCTL_INVALID_INPUT_BUFFER;
				err = -EINVAL;
				goto dma_pool_alloc_fail;
			}
		}
	}

	return 0;

dma_pool_alloc_fail:
	azihsm_ioctl_hsm_free_dma_buffer_pools(
		hsm, *src_first_4K_va, *src_first_4K_pa, *src_second_4K_va,
		*src_second_4K_pa, *src_first_4K_va, *src_first_4K_pa,
		*src_second_4K_va, *src_second_4K_pa);

	return err;
}

/**
 * Function :- azihsm_ioctl_hsm_copy_device_data_to_user_buffers
 * This function copies data back from the kernel destination bounce buffers
 * (2 4K) to the user destination buffer.
 * This function must ONLY be invoked after the command has completed at the device
 * and CQE has been received.
 *
 * hsm
 * user_generic_cmd : User ioctl buffer that contains the user destination buffer
 *   (virtual address)
 *
 * buf_first_4K_va and buf_second_4K_va are the kernel virtual addresses for the
 * kernel destination bounce buffers. It is assumed that the device data returned is
 * in these buffers.
 *
 * output_byte_count. Number of bytes to copy from kernel destination bounce buffers to
 * user destination buffer. Maximum value is 8k. Caller has to ensure that this value is
 * no greater than 4K.
 *
 * Returns 0 on success or a non-zero value on failure.
 */
static int azihsm_ioctl_hsm_copy_device_data_to_user_buffers(
	struct azihsm_hsm *hsm, struct azihsm_cp_generic_cmd *user_generic_cmd,
	void *buf_first_4K_va, void *buf_second_4K_va, __u32 output_byte_count)
{
	__u32 rem;

	/* calculate if the # of bytes to be copied is
	 *  greater than 4K
	 */
	if (output_byte_count > SZ_4K)
		rem = output_byte_count - SZ_4K;
	else
		rem = 0;

	if (output_byte_count && user_generic_cmd->in.dst_buf) {
		if (copy_to_user((void __user *)user_generic_cmd->in.dst_buf,
				 buf_first_4K_va,
				 (rem == 0) ? output_byte_count : SZ_4K)) {
			user_generic_cmd->out.u.generic.ioctl_extended_status =
				AZIHSM_CP_GENERIC_IOCTL_INVALID_OUTPUT_BUFFER;

			// Make Sure That the byte count is cleared
			user_generic_cmd->out.u.generic.byte_count = 0;

			AZIHSM_DEV_LOG_ERROR(
				hsm->cdev_dev,
				"[%s:INFO hsm:%p]. Unable to copy to user destination buffer\n",
				__func__, hsm);
			return -EINVAL;
		}

		if (copy_to_user((void __user *)(user_generic_cmd->in.dst_buf +
						 SZ_4K),
				 buf_second_4K_va, rem)) {
			user_generic_cmd->out.u.generic.ioctl_extended_status =
				AZIHSM_CP_GENERIC_IOCTL_INVALID_OUTPUT_BUFFER;

			// Make Sure That the byte count is cleared
			user_generic_cmd->out.u.generic.byte_count = 0;

			AZIHSM_DEV_LOG_ERROR(
				hsm->cdev_dev,
				"[%s:INFO hsm:%p]. Unable to copy to user destination buffer\n",
				__func__, hsm);
			return -EINVAL;
		}
	}

	return 0;
}

/**
 * azihsm_ioctl_hsm_process_generic_ioctl_session
 * Main handler for the ioctl using the session handling
 * semantics.
 *
 * Note device may still be only having FW that does not
 * validate sessions. We have to be able to handle
 * both types of devices correctly.
 */
static int azihsm_ioctl_hsm_process_generic_ioctl_session(
	struct azihsm_hsm_fd_ctxt *ctxt, struct azihsm_hsm *hsm,
	struct azihsm_cp_generic_cmd *user_generic_cmd, unsigned long arg)
{
	int err = -ENOMEM;
	int cpl_sts_out = AZIHSM_IOQ_CMD_STS_SUCCESS;
	dma_addr_t src_buf_first_4K_pa = 0, src_buf_second_4K_pa = 0;
	dma_addr_t dst_buf_first_4K_pa = 0, dst_buf_second_4K_pa = 0;

	void *src_buf_first_4K_va = NULL;
	void *src_buf_second_4K_va = NULL;

	void *dst_buf_first_4K_va = NULL;
	void *dst_buf_second_4K_va = NULL;

	__u32 user_dst_buf_length;
	__u32 output_byte_count = 0;

	struct azihsm_hsm_cmd_generic_cqe cqe;
	union azihsm_hsm_generic_cmd_sqe_src_data src_data = { 0 };

	user_generic_cmd->out.ctxt = user_generic_cmd->in.ctxt;

	user_dst_buf_length = user_generic_cmd->in.dst_length;

	err = azihsm_hsm_validate_session_in_ioctl_cmd(ctxt, user_generic_cmd,
						       &src_data);
	if (err) {
		AZIHSM_DEV_LOG_ERROR(
			&hsm->pdev->dev,
			"[%s:ERROR] Session IOCTL Validation Failed Err:%d",
			__func__, err);

		goto error;
	}

	/*
	 * Map the user src and destination buffers to the device
	 * Copy the data from the user source buffer to the device
	 * source buffer before we issue the command to the device
	 */
	err = azihsm_ioctl_hsm_copy_user_buffers_to_dma_pool(
		hsm, /* file handle context */
		user_generic_cmd, /* User ioctl buffer */
		&src_buf_first_4K_va, &src_buf_first_4K_pa,
		&src_buf_second_4K_va, &src_buf_second_4K_pa,
		&dst_buf_first_4K_va, &dst_buf_first_4K_pa,
		&dst_buf_second_4K_va, &dst_buf_second_4K_pa);

	if (err) {
		/*
		 * Function would have filled up the extended status
		 */

		AZIHSM_DEV_LOG_ERROR(
			&hsm->pdev->dev,
			"[%s:ERROR] Copy User Buffers For Dma Pool Failure Err: %d",
			__func__, err);

		goto error;
	}

	err = azihsm_hsm_passthrough_cmd(
		hsm, user_generic_cmd->in.opc, user_generic_cmd->in.cmdset, 0,
		src_buf_first_4K_pa, src_buf_second_4K_pa,
		user_generic_cmd->in.src_length, dst_buf_first_4K_pa,
		dst_buf_second_4K_pa, user_dst_buf_length, &src_data, &cqe,
		&cpl_sts_out);

	if (err < 0) {
		// EAGAIN is returned when abort is in progress or the command is
		// aborted.
		if (err == -EAGAIN) {
			azihsm_hsm_fill_error_sts(hsm, user_generic_cmd,
						  cpl_sts_out);
		}

		AZIHSM_DEV_LOG_ERROR(
			&hsm->pdev->dev,
			"[%s:ERROR] Mcr Pass Through Cmd Failed Err: %d extended_sts:0x%x",
			__func__, err,
			user_generic_cmd->out.u.generic.ioctl_extended_status);

		goto dma_pool_alloc_fail;
	}

	/* copy status from cqe and bytes returned back into user output buffer
	 */

	user_generic_cmd->out.status = cqe.psf.fld.sc;
	user_generic_cmd->out.u.generic.byte_count =
		(u32)cqe.cqe_data.session_data.byte_count;

	if (user_generic_cmd->in.cmdset == CP_CMD_SESSION_GENERIC) {
		/*
		 * Do session handling from the cqe data
		 * (opcodes in command for open session, close session and in session
		 *  need handling)
		 */
		(void)azihsm_hsm_process_session_in_cmd_completion(
			ctxt, &src_data, &cqe);
		output_byte_count = user_generic_cmd->out.u.generic.byte_count;

		/*
		 * The following condition if true means that the device
		 * has returned a byte count bigger than our output buffer
		 * The device has DMAd into kernel buffers (DMA pool)
		 * If this happens, normalize the # of bytes to copy and
		 * log an error
		 */
		if (output_byte_count > user_dst_buf_length) {
			AZIHSM_DEV_LOG_ERROR(
				&hsm->pdev->dev,
				"[%s:ERROR] Device has returned length=%d greater than expected size=%d\n",
				__func__, output_byte_count,
				user_dst_buf_length);

			output_byte_count = user_dst_buf_length;
		}

		user_generic_cmd->out.u.generic.byte_count = output_byte_count;

		// Copy the Destination Data Back To The User
		err = azihsm_ioctl_hsm_copy_device_data_to_user_buffers(
			ctxt->hsm, user_generic_cmd, dst_buf_first_4K_va,
			dst_buf_second_4K_va, output_byte_count);

		if (err) {
			// Just log the error to make sure but
			// Continue to copy the ioctl data structure
			// back to the user.
			AZIHSM_DEV_LOG_ERROR(
				&hsm->pdev->dev,
				"[%s:ERROR] Failed To Copy Device Data To User Buffer [Fst:%p, Snd:%p]  [CpySz:0x%x]\n",
				__func__, dst_buf_first_4K_va,
				dst_buf_second_4K_va, output_byte_count);
		}
	}

dma_pool_alloc_fail:
	azihsm_ioctl_hsm_free_dma_buffer_pools(
		hsm, src_buf_first_4K_va, src_buf_first_4K_pa,
		src_buf_second_4K_va, src_buf_second_4K_pa, dst_buf_first_4K_va,
		dst_buf_first_4K_pa, dst_buf_second_4K_va,
		dst_buf_second_4K_pa);

error:
	if (copy_to_user((void __user *)arg, user_generic_cmd,
			 sizeof(struct azihsm_cp_generic_cmd))) {
		err = -EFAULT;
		AZIHSM_DEV_LOG_ERROR(
			hsm->cdev_dev,
			"[%s:ERROR] Error copying ioctl buffer back to user",
			__func__);
	}

	return err;
}

#ifdef TEST_HOOK_SUPPORT
#pragma message("TEST HOOKS SUPPORT IS ENABLED")
/**
 * azihsm_ioctl_hsm_get_test_hook_data
 * Method to provide the test hook data to the application
 * Enabled only when the
 */
static int azihsm_ioctl_hsm_get_test_hook_data(struct azihsm_hsm *hsm,
					       unsigned long arg)
{
	int err = 0;
	struct azihsm_ctrl_test_hook_data info;
	size_t min_size = sizeof(info);

	AZIHSM_DEV_LOG_ENTRY(&hsm->pdev->dev, "%s hsm:%p", __func__, hsm);

	// We do not need data from the user space, but just to make sure
	// that the buffer is ok, copy the data from user.
	if (copy_from_user(&info, (void __user *)arg, min_size)) {
		err = -EFAULT;
		AZIHSM_DEV_LOG_ERROR(
			&hsm->pdev->dev,
			"[hsm-get-test-hook-data] copy from user failed\n");
		goto err;
	}

	info.abort_in_prog = AZIHSM_CTRL_GET_ABORT_STATE(hsm->ctrl);
	info.lvl1_abort_cnt = hsm->ctrl->level_one_abort_count;
	info.lvl2_abort_cnt = hsm->ctrl->level_two_abort_count;
	info.proc_not_own_fd = hsm->ctrl->proc_not_own_fd_cnt;
	info.session_flush_cnt = hsm->ctrl->session_flush_cnt;
	info.close_non_own_proc_cnt = hsm->ctrl->close_by_not_own_proc_cnt;

	if (copy_to_user((void __user *)arg, &info, min_size)) {
		err = -EFAULT;
		AZIHSM_DEV_LOG_ERROR(
			&hsm->pdev->dev,
			"[hsm-get-test-hook-data] copy to user failed");
	}

err:

	AZIHSM_DEV_LOG_EXIT(
		&hsm->pdev->dev,
		"%s hsm:%p err:%d [AbrtInProgrss:%d l1AbrtCnt:%d l1AbrtCnt:%d ProcNotOwnFd:%lldd, SessionFlushCnt:%lldd CloseByOtherProc:%lld ]",
		__func__, hsm, err, info.abort_in_prog, info.lvl1_abort_cnt,
		info.lvl2_abort_cnt, info.proc_not_own_fd,
		info.session_flush_cnt, info.close_non_own_proc_cnt);

	return err;
}
#endif // TEST_HOOK_SUPPORT

/*
 * azihsm_ioctl_hsm_get_device_info
 * Method to implement GET_DEVICE_INFO ioctl on the HSM interface.
 * This ioctl is the same as the GET_DEVICE_INFO on the management interface
 *  The management interface is only lighted up for PF.
 * This interface is available for
 */
static int azihsm_ioctl_hsm_get_device_info(struct azihsm_hsm *hsm,
					    unsigned long arg)
{
	int err = 0;
	struct azihsm_ctrl_dev_info info;
	size_t min_size =
		offsetofend(struct azihsm_ctrl_dev_info, device_entropy);

	AZIHSM_DEV_LOG_ENTRY(hsm->cdev_dev, "%s hsm:%p", __func__, hsm);
	if (copy_from_user(&info, (void __user *)arg, min_size)) {
		err = -EFAULT;
		AZIHSM_DEV_LOG_ERROR(
			hsm->cdev_dev,
			"[hsm-get-dev-info] copy from user failed\n");
		goto err;
	}

	if (info.argsz < sizeof(info)) {
		err = -EINVAL;
		AZIHSM_DEV_LOG_ERROR(
			hsm->cdev_dev,
			"[hsm-get-dev-info] invalid argument size");
		goto err;
	}

	err = azihsm_ctrl_dev_get_dev_info(hsm->ctrl, &info);
	if (copy_to_user((void __user *)arg, &info, min_size)) {
		err = -EFAULT;
		AZIHSM_DEV_LOG_ERROR(hsm->cdev_dev,
				     "[hsm-get-dev-info] copy to user failed");
	}

err:
	AZIHSM_DEV_LOG_EXIT(hsm->cdev_dev, "%s hsm:%p", __func__, hsm);
	return err;
}

static int azihsm_hsm_dev_open(struct inode *inode, struct file *file)
{
	struct azihsm_hsm_fd_ctxt *ctxt;
	int i;
	struct azihsm_hsm *hsm =
		container_of(inode->i_cdev, struct azihsm_hsm, cdev);

	ctxt = vmalloc(sizeof(struct azihsm_hsm_fd_ctxt));

	if (!ctxt)
		return -ENOMEM;

	memset(ctxt, 0, sizeof(*ctxt));

	for (i = 0; i < AZIHSM_MAX_SESSIONS_PER_FD; i++) {
		ctxt->sessions[i].id = (u16)-1;
		ctxt->sessions[i].valid = false;
		ctxt->sessions[i].short_app_id_is_valid = false;
		ctxt->sessions[i].short_app_id = (u8)-1;
	}

	// Initialize the context
	ctxt->hsm = hsm;
	ctxt->owning_task = task_tgid_nr(current);
	mutex_init(&ctxt->lock);

	// Save the context as private data so we can retrieve it later
	file->private_data = ctxt;
	return 0;
}

/*
 * Function :- azihsm_ioctl_hsm_validate_argument
 *  Validates that the argument to the HSM ioctl meets minimum
 *  requirements.
 *
 *  The buffer must have an ioctl header at offset 0.
 *  Length in the header must be at least equal to the expected length
 *  If source buffer length is greater than zero, source buffer must be non-NULL
 *  If destination buffer length is greater than zero, destination buffer must be NON-nULL
 *  Length of source and destination buffers must be less or equal to 8K.
 *
 * Returns 0 on success
 * Other values on failures.
 */
static int azihsm_ioctl_hsm_validate_argument(
	struct azihsm_hsm_fd_ctxt *ctxt, unsigned long arg,
	struct azihsm_cp_generic_cmd *user_generic_cmd)
{
	struct azihsm_ioctl_header hdr;
	const size_t required_size = sizeof(struct azihsm_cp_generic_cmd);

	if (copy_from_user(&hdr, (void __user *)arg,
			   sizeof(struct azihsm_ioctl_header))) {
		AZIHSM_DEV_LOG_ERROR(
			ctxt->hsm->cdev_dev,
			"[%s:ERROR] copy_from_user failed (for ioctl header) length=%d(expected)\n",
			__func__, (__u32)sizeof(struct azihsm_ioctl_header));
		return -EINVAL;
	}

	if (hdr.szioctldata < (__u32)required_size) {
		AZIHSM_DEV_LOG_ERROR(
			ctxt->hsm->cdev_dev,
			"[%s:ERROR] Length in ioctl header=%d is lesser than required size=%d\n",
			__func__, hdr.szioctldata, (__u32)required_size);
		return -EINVAL;
	}

	if (copy_from_user(user_generic_cmd, (void __user *)arg,
			   required_size)) {
		AZIHSM_DEV_LOG_ERROR(
			ctxt->hsm->cdev_dev,
			"[%s:ERROR] copy_from_user failed length=%d(expected)\n",
			__func__, (u32)required_size);
		return -EINVAL;
	}

	if (AZIHSM_CTRL_IS_ABORT_IN_PROGRESS(ctxt->hsm->ctrl)) {
		AZIHSM_DEV_LOG_ERROR(
			ctxt->hsm->cdev_dev,
			"HSM ioctl: An abort is currently in progress.\n");

		user_generic_cmd->out.u.generic.ioctl_extended_status =
			GENERATE_STATUS_CODE(AZIHSM_STS_SRC_ABORT,
					     AZIHSM_ABORT_IN_PROGRESS);

		return -EAGAIN;
	}

	if (!AZIHSM_CTRL_ST_ISRDY(ctxt->hsm->ctrl)) {
		AZIHSM_DEV_LOG_ERROR(
			&ctxt->hsm->pdev->dev,
			"HSM ioctl: Device is not ready. Unable to execute command on the device [Rdy_Sts:%d AbortSts:%d]\n",
			AZIHSM_CTRL_GET_STATE(ctxt->hsm->ctrl),
			AZIHSM_CTRL_GET_ABORT_STATE(ctxt->hsm->ctrl));

		user_generic_cmd->out.u.generic.ioctl_extended_status =
			AZIHSM_CP_GENERIC_IOCTL_DEVICE_ERROR;

		return -EAGAIN;
	}
	/*
	 * On the HSM channel, at present only commands with cmdset == Generic
	 * are supported. Fail everything else.
	 */

	if (user_generic_cmd->in.cmdset != CP_CMD_SESSION_GENERIC) {
		AZIHSM_DEV_LOG_ERROR(
			ctxt->hsm->cdev_dev,
			"[%s:ERROR] Ioctl buffer validation failed. Cmdset[%d] is not supported on this channel\n",
			__func__, user_generic_cmd->in.cmdset);
		user_generic_cmd->out.u.generic.ioctl_extended_status =
			AZIHSM_CP_GENERIC_IOCTL_INVALID_CMDSET;
		return -EINVAL;
	}

	if ((user_generic_cmd->in.src_length > (SZ_4K * 2))) {
		AZIHSM_DEV_LOG_ERROR(
			ctxt->hsm->cdev_dev,
			"[%s:ERROR]. Length of input buffer=%d greater than 8k\n",
			__func__, user_generic_cmd->in.src_length);
		user_generic_cmd->out.u.generic.ioctl_extended_status =
			AZIHSM_CP_GENERIC_IOCTL_INPUT_BUFFER_ABOVE_8K;
		return -EINVAL;
	}

	if ((user_generic_cmd->in.dst_length > (SZ_4K * 2))) {
		AZIHSM_DEV_LOG_ERROR(
			ctxt->hsm->cdev_dev,
			"[%s:ERROR]. Length of output buffer=%d greater than 8k\n",
			__func__, user_generic_cmd->in.dst_length);
		user_generic_cmd->out.u.generic.ioctl_extended_status =
			AZIHSM_CP_GENERIC_IOCTL_OUTPUT_BUFFER_ABOVE_8K;
		return -EINVAL;
	}

	/*
	 * If the length of the input buffer is zero but the user has
	 * provided a source buffer pointer, ioctl fails. Same for output buffer.
	 * It is ok for length and buffer to be NULL.
	 */
	if (!user_generic_cmd->in.src_length && user_generic_cmd->in.src_buf) {
		AZIHSM_DEV_LOG_ERROR(
			ctxt->hsm->cdev_dev,
			"[%s:ERROR] Input buffer is Not Null [%p] but length is zero [%d]\n",
			__func__, user_generic_cmd->in.src_buf,
			user_generic_cmd->in.src_length);

		user_generic_cmd->out.u.generic.ioctl_extended_status =
			AZIHSM_CP_GENERIC_IOCTL_INVALID_INPUT_BUFFER;
		return -EINVAL;
	}

	/*
	 * If the length of the input buffer is valid but the user has not
	 * provided a source buffer, ioctl fails. Same for output buffer.
	 * It is ok for length and buffer to be NULL.
	 */
	if (user_generic_cmd->in.src_length && !user_generic_cmd->in.src_buf) {
		AZIHSM_DEV_LOG_ERROR(
			ctxt->hsm->cdev_dev,
			"[%s:ERROR] Input buffer is non-zero length[%d] but input buffer is NULL\n",
			__func__, user_generic_cmd->in.src_length);
		user_generic_cmd->out.u.generic.ioctl_extended_status =
			AZIHSM_CP_GENERIC_IOCTL_INVALID_INPUT_BUFFER;
		return -EINVAL;
	}

	if (!user_generic_cmd->in.dst_length && user_generic_cmd->in.dst_buf) {
		AZIHSM_DEV_LOG_ERROR(
			ctxt->hsm->cdev_dev,
			"[%s:ERROR] Output buffer is Not Null [%p] but length is zero [%d]\n",
			__func__, user_generic_cmd->in.dst_buf,
			user_generic_cmd->in.dst_length);

		user_generic_cmd->out.u.generic.ioctl_extended_status =
			AZIHSM_CP_GENERIC_IOCTL_INVALID_OUTPUT_BUFFER;
		return -EINVAL;
	}

	if (user_generic_cmd->in.dst_length && !user_generic_cmd->in.dst_buf) {
		AZIHSM_DEV_LOG_ERROR(
			ctxt->hsm->cdev_dev,
			"[%s:ERROR] Output buffer is non-zero length[%d] but output buffer is NULL\n",
			__func__, user_generic_cmd->in.dst_length);
		user_generic_cmd->out.u.generic.ioctl_extended_status =
			AZIHSM_CP_GENERIC_IOCTL_INVALID_OUTPUT_BUFFER;
		return -EINVAL;
	}

	return 0;
}

static int azihsm_ioctl_reset_device(struct azihsm_ctrl *ctrl,
				     unsigned long arg)
{
	int err = 0;
	struct device *dev = &ctrl->pdev->dev;
	struct reset_device_data info;

	AZIHSM_DEV_LOG_ENTRY(dev, "%s", __func__);

	if (copy_from_user(&info, (void __user *)arg, sizeof(info))) {
		err = -EFAULT;
		AZIHSM_DEV_LOG_ERROR(dev, "[%s:%d] copy from user failed\n",
				     __func__, __LINE__);

		goto err;
	}

	if (info.hdr.szioctldata < sizeof(info)) {
		err = -EINVAL;
		AZIHSM_DEV_LOG_ERROR(dev, "[%s] invalid argument size [%d]",
				     __func__, info.hdr.szioctldata);

		goto err;
	}

	if (!AZIHSM_CTRL_ST_ISRDY(ctrl)) {
		err = -EINVAL;
		info.rst_out_data.abort_sts = ABORT_STATUS_INVALID_DEVICE_STATE;

		AZIHSM_DEV_LOG_ERROR(dev, "[%s] Invalid Device State [%d]",
				     __func__, AZIHSM_CTRL_GET_STATE(ctrl));

		if (copy_to_user((void __user *)arg, &info, sizeof(info))) {
			err = -EFAULT;
			AZIHSM_DEV_LOG_ERROR(dev, "[%s:%d] copy to user failed",
					     __func__, __LINE__);
		}

		return err;
	}

	if ((info.rst_in_data.abort_type <= ABORT_TYPE_RESERVED) ||
	    (info.rst_in_data.abort_type >= ABORT_TYPE_MAX)) {
		err = -EINVAL;
		info.rst_out_data.abort_sts = ABORT_STATUS_INVALID_TYPE;

		AZIHSM_DEV_LOG_ERROR(dev, "[%s] Invalid Abort Type [%d]",
				     __func__, info.rst_in_data.abort_type);

		if (copy_to_user((void __user *)arg, &info, sizeof(info))) {
			err = -EFAULT;
			AZIHSM_DEV_LOG_ERROR(dev, "[%s:%d] copy to user failed",
					     __func__, __LINE__);
		}

		return err;
	}

	if (AZIHSM_CTRL_IS_ABORT_IN_PROGRESS(ctrl)) {
		err = -EINVAL;
		info.rst_out_data.abort_sts = ABORT_STATUS_ALREADY_IN_PROGRESS;

		AZIHSM_DEV_LOG_ERROR(dev, "[%s] Abort Already In Progress [%d]",
				     __func__, info.rst_in_data.abort_type);

		if (copy_to_user((void __user *)arg, &info, sizeof(info))) {
			err = -EFAULT;
			AZIHSM_DEV_LOG_ERROR(dev, "[%s:%d] copy to user failed",
					     __func__, __LINE__);
		}
		return err;
	}

	info.rst_out_data.abort_sts = ABORT_STATUS_SUCCESS;
	err = azihsm_abort(ctrl, NULL, NULL, false,
			   info.rst_in_data.abort_type);
	if (err) {
		AZIHSM_DEV_LOG_ERROR(
			dev, "[%s] User Requested Abort Failed [err:%d]",
			__func__, err);
		info.rst_out_data.abort_sts = ABORT_STATUS_FAILED;
	}

	if (copy_to_user((void __user *)arg, &info, sizeof(info))) {
		err = -EFAULT;
		AZIHSM_DEV_LOG_ERROR(dev, "[%s:%d] copy to user failed",
				     __func__, __LINE__);
	}

err:
	AZIHSM_DEV_LOG_EXIT(dev, "%s", __func__);
	return err;
}

static long azihsm_hsm_dev_ioctl(struct file *file, unsigned int ioctl_value,
				 unsigned long arg)
{
	int err;
	struct azihsm_hsm_fd_ctxt *ctxt =
		(struct azihsm_hsm_fd_ctxt *)(file->private_data);
	struct azihsm_hsm *hsm;
	struct azihsm_cp_generic_cmd cmd;

	if (!ctxt) {
		AZIHSM_LOG_ERROR("%s failed. Ctxt is NULL. file:%p arg:%p\n",
				 __func__, file, (void *)arg);
		return -ENOTTY;
	}

	if (!ctxt->hsm) {
		AZIHSM_LOG_ERROR("%s HSM is NULL. ctxt: %p file:%p arg:%p\n",
				 __func__, ctxt, file, (void *)arg);
		return -ENOTTY;
	}

	if (ctxt->owning_task != task_tgid_nr(current)) {
		AZIHSM_DEV_LOG_ERROR(
			&ctxt->hsm->pdev->dev,
			"HSM ioctl: Task issuing ioctl[%d] is not the owner of the file handle[%d]\n",
			task_tgid_nr(current), ctxt->owning_task);

		ctxt->hsm->ctrl->proc_not_own_fd_cnt++;
		return -EACCES;
	}

	hsm = ctxt->hsm;
	memset(&cmd, 0, sizeof(cmd));

	switch (ioctl_value) {
	case AZIHSM_GET_DEV_INFO_IOCTL: {
		if (AZIHSM_CTRL_IS_ABORT_IN_PROGRESS(hsm->ctrl)) {
			AZIHSM_DEV_LOG_ERROR(
				&hsm->pdev->dev,
				"HSM ioctl: An abort is currently in progress on the controller. Retry command\n");

			return -EAGAIN;
		}

		if (!AZIHSM_CTRL_ST_ISRDY(hsm->ctrl)) {
			AZIHSM_DEV_LOG_ERROR(
				&ctxt->hsm->pdev->dev,
				"HSM DevInfo ioctl: Device is not ready. Unable to execute command on the device\n");
			return -ENOTTY;
		}

		err = azihsm_ioctl_hsm_get_device_info(ctxt->hsm, arg);
		if (err) {
			AZIHSM_DEV_LOG_ERROR(
				&hsm->pdev->dev,
				"HSM ioctl: HSM_GET_DEVICE_INFO failed. hsm=%p arg=%p\n",
				hsm, (void *)arg);
		}
		break;
	}

	case AZIHSM_CTRL_PATH_GENERIC_IOCTL_SESSION: {
		err = azihsm_ioctl_hsm_validate_argument(ctxt, arg, &cmd);
		if (err) {
			AZIHSM_DEV_LOG_ERROR(
				&hsm->pdev->dev,
				"HSM ioctl: CTRL_PATH_CMD_NEW_IOCTL_SESSION. validation of input buffer failed. hsm=%p arg=%p\n",
				hsm, (void *)arg);

			if (copy_to_user((void __user *)arg, &cmd,
					 sizeof(struct azihsm_cp_generic_cmd))) {
				err = -EFAULT;
				AZIHSM_DEV_LOG_ERROR(
					hsm->cdev_dev,
					"[%s:ERROR] Error copying ioctl buffer back to user",
					__func__);
			}
			break;
		}
		err = azihsm_ioctl_hsm_process_generic_ioctl_session(ctxt, hsm,
								     &cmd, arg);
		break;
	}

	case AZIHSM_AES_DEV_IOCTL_CMD_XTS:
	case AZIHSM_AES_DEV_IOCTL_CMD_GCM: {
		err = azihsm_aes_dev_ioctl(ctxt, &hsm->ctrl->aes, arg,
					   ioctl_value);
		if (err) {
			AZIHSM_DEV_LOG_ERROR(
				&hsm->pdev->dev,
				"[MCR:ERROR] AES:ioctl: aes context:%p AES ioctl[%d] arg = %p ioctl failed err:%d\n",
				&hsm->ctrl->aes, ioctl_value, (void *)arg, err);
		}
		break;
	}

#ifdef TEST_HOOK_SUPPORT
	case AZIHSM_GET_DRIVER_TEST_HOOK_DATA:
		err = azihsm_ioctl_hsm_get_test_hook_data(ctxt->hsm, arg);
		if (err) {
			AZIHSM_DEV_LOG_ERROR(
				&hsm->pdev->dev,
				"HSM ioctl: HSM_GET_DEVICE_INFO failed. hsm=%p arg=%p\n",
				hsm, (void *)arg);
		}
		break;
#endif // TEST_HOOK_SUPPORT

	case AZIHSM_IOCTL_RESET_DEVICE: {
		err = azihsm_ioctl_reset_device(hsm->ctrl, arg);
		if (err) {
			AZIHSM_DEV_LOG_ERROR(
				&hsm->pdev->dev,
				"[ERROR] MCR_IOCTL_RESET_DEVICE: ioctl [%d] arg [%p]failed with error {err:%d]\n",
				ioctl_value, (void *)arg, err);
		}
		break;
	}

	// Legacy ioctl where no session information is encoded into the
	// sqe.
	case AZIHSM_CTRL_PATH_GENERIC_IOCTL: // We do not handle this anymore
	default:
		AZIHSM_DEV_LOG_ERROR(&hsm->pdev->dev,
				     "%s. Unknown ioctl code:%d\n", __func__,
				     ioctl_value);
		err = -EBADRQC; // Invalid Request Code
	}

	return err;
}

static int azihsm_hsm_dev_close(struct inode *inode, struct file *file)
{
	struct azihsm_hsm_fd_ctxt *ctxt =
		(struct azihsm_hsm_fd_ctxt *)(file->private_data);

	if (!ctxt) {
		AZIHSM_LOG_ERROR("%s. Ctxt is NULL. inode:%p file:%p\n",
				 __func__, inode, file);
		return -EINVAL;
	}

	if (!ctxt->hsm) {
		AZIHSM_LOG_ERROR("%s. HSM is NULL. ctxt: %p inode:%p file:%p\n",
				 __func__, ctxt, inode, file);
		return -EINVAL;
	}

	if (ctxt->owning_task != task_tgid_nr(current)) {
		AZIHSM_DEV_LOG_ERROR(
			&ctxt->hsm->pdev->dev,
			"File close: Task issuing file close[%d] is not the owner of the file handle[%d]\n",
			task_tgid_nr(current), ctxt->owning_task);

		ctxt->hsm->ctrl->close_by_not_own_proc_cnt += 1;
		return -EINVAL;
	}
	/*
	 * Forcibly close all sessions open on this file handle
	 * Even when the process context is not the owner
	 */
	azihsm_hsm_close_sessions(ctxt);
	/* free the lock and the context structure */
	mutex_destroy(&ctxt->lock);
	vfree(ctxt);
	file->private_data = NULL;
	return 0;
}

const struct file_operations azihsm_hsm_dev_fops = {
	.owner = THIS_MODULE,
	.open = azihsm_hsm_dev_open,
	.unlocked_ioctl = azihsm_hsm_dev_ioctl,
	.release = azihsm_hsm_dev_close,
};

int azihsm_hsm_dev_alloc_minor(struct azihsm_hsm *hsm)
{
	int val;
	struct device *dev = &hsm->pdev->dev;

	val = ida_alloc(&azihsm_hsm_dev_ida, GFP_KERNEL);
	if (val < 0) {
		AZIHSM_DEV_LOG_ERROR(dev, "[%s] [ERROR] ida_alloc failed\n",
				     __func__);
		return -EINVAL;
	}

	hsm->major = azihsm_hsm_dev_major;
	hsm->minor = val;

	AZIHSM_DEV_LOG_INFO(
		dev,
		"[%s] [SUCCESS] minor number allocation success. major:%d minor:%d\n",
		__func__, hsm->major, hsm->minor);
	return 0;
}

int azihsm_hsm_dev_dealloc_minor(struct azihsm_hsm *hsm)
{
	struct device *dev = &hsm->pdev->dev;

	AZIHSM_DEV_LOG_INFO(dev, "[%s] Freeing up minor number:%d(major :%d)\n",
			    __func__, hsm->minor, hsm->major);
	ida_free(&azihsm_hsm_dev_ida, hsm->minor);
	return 0;
}

int azihsm_hsm_dev_init(struct azihsm_hsm *hsm, const bool abort)
{
	int err;
	dev_t devt;
	struct device *cdev_dev;
	struct device *dev = &hsm->pdev->dev;

	if (true == abort) {
		AZIHSM_DEV_LOG_INFO(
			dev, "[%s] Executing as part of abort. Doing nothing\n",
			__func__);
		return 0;
	}

	devt = MKDEV(hsm->major, hsm->minor);
	cdev_init(&hsm->cdev, &azihsm_hsm_dev_fops);
	hsm->cdev.owner = THIS_MODULE;

	err = cdev_add(&hsm->cdev, devt, 1);
	if (err) {
		AZIHSM_DEV_LOG_ERROR(dev, "cdev add failed for %s",
				     AZIHSM_HSM_DEV_NAME);
		goto cdev_add_fail;
	}

	cdev_dev = device_create(azihsm_hsm_dev_class, &hsm->pdev->dev, devt,
				 hsm, "azihsm%d", hsm->minor);
	if (IS_ERR(cdev_dev)) {
		err = PTR_ERR(cdev_dev);
		AZIHSM_DEV_LOG_ERROR(dev, "cdev dev create failed for %s",
				     AZIHSM_HSM_DEV_NAME);
		goto device_create_fail;
	}

	hsm->cdev_dev = cdev_dev;

	return 0;

device_create_fail:
	cdev_del(&hsm->cdev);
cdev_add_fail:
	return err;
}

void azihsm_hsm_dev_deinit(struct azihsm_hsm *hsm, const bool abort)
{
	if (true == abort)
		return;

	device_del(hsm->cdev_dev);
	cdev_del(&hsm->cdev);
	azihsm_hsm_dev_dealloc_minor(hsm);
}

int __init azihsm_hsm_dev_mod_init(void)
{
	int err;
	dev_t dev;

#if KERNEL_VERSION(6, 5, 0) > LINUX_VERSION_CODE
	azihsm_hsm_dev_class = class_create(THIS_MODULE, AZIHSM_HSM_DEV_NAME);
#else
	azihsm_hsm_dev_class = class_create(AZIHSM_HSM_DEV_NAME);
#endif
	if (IS_ERR(azihsm_hsm_dev_class)) {
		err = PTR_ERR(azihsm_hsm_dev_class);
		goto class_create_fail;
	}

	err = alloc_chrdev_region(&dev, 0, AZIHSM_HSM_DEV_COUNT,
				  AZIHSM_HSM_DEV_NAME);
	if (err)
		goto alloc_region_fail;

	azihsm_hsm_dev_major = MAJOR(dev);

	return 0;

alloc_region_fail:
	class_destroy(azihsm_hsm_dev_class);
class_create_fail:
	return err;
}

void __exit azihsm_hsm_dev_mod_exit(void)
{
	dev_t dev = MKDEV(azihsm_hsm_dev_major, 0);

	unregister_chrdev_region(dev, AZIHSM_HSM_DEV_COUNT);
	class_destroy(azihsm_hsm_dev_class);
}
