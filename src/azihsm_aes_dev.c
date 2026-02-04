// SPDX-License-Identifier: GPL-2.0

#include "azihsm_errors.h"
#include "azihsm_aes_dev.h"
#include "azihsm.h"
#include "azihsm_aes_dev_ioctl.h"
#include "azihsm_aes_cmd.h"
#include "azihsm_abort.h"
#include "azihsm_hsm.h"

#include <linux/idr.h>
#include <linux/uaccess.h>

#define AZIHSM_AES_DEV_COUNT (16 * 65)

/*
 * Function:- azihsm_aes_dev_cmd_set_output_data
 * Called after a FP command completes.
 * The CQE is in the aes_cmd->cqe field
 *
 * If cqe:status or cqe:err are non-zero the
 * operation is treated as having failed at the
 * device
 *
 */
static void azihsm_aes_dev_cmd_set_output_data(
	struct azihsm_aes *aes, struct azihsm_aes_cmd *aes_cmd,
	struct aes_ioctl_indata *in_data, struct aes_ioctl_outdata *out_data)
{
	void *src_cmd_spec = NULL;
	void *dst_cmd_spec = NULL;
	void *src_iv = NULL;
	void *dst_iv = NULL;
	u32 aligned_data_len;
	u8 __user *aligned_buffer_dst;

	out_data->result = aes_cmd->cqe.ph_sts.ph_sts_bits.sts;
	out_data->extended_status = aes_cmd->cqe.err;
	out_data->fips_approved = aes_cmd->cqe.fips_approved;

	// We made the src buffer len be aligned, so grab it now before we fix it
	aligned_data_len =  in_data->UserBuff.src_len-aes_cmd->unaligned_data_size;
	
	AZIHSM_DEV_LOG_ENTRY(
		&aes->pdev->dev,
		"set_output_data. aes:%p cmd status:%d opc:%d cipher:%d cqe err:%d\n",
		aes, aes_cmd->cqe.ph_sts.ph_sts_bits.sts,
		aes_cmd->sqe.attr.cmd_opc, aes_cmd->sqe.attr.cipher,
		aes_cmd->cqe.err);

	if ((aes_cmd->cqe.ph_sts.ph_sts_bits.sts != 0) ||
	    (aes_cmd->cqe.err != 0)) {
		return;
	}

	//
	// Additional checks in case FW has problems
	//

	// make sure the reported length does not exceed the actual space we were passed
	if (out_data->byte_count > in_data->UserBuff.dst_len) {
		AZIHSM_DEV_LOG_ERROR(
			&aes->pdev->dev,
			"[%s:ERROR] byte_count (%d) greater than size of dst buffer (%d) \n",
			__func__, out_data->byte_count, in_data->UserBuff.dst_len);
		return;
	}

	// If we allocated an unaligned buffer, then we should get the length back
	if (aes_cmd->aux_buffer_kva && !aes_cmd->cqe.unaligned_dst_data_len) {
		AZIHSM_DEV_LOG_ERROR(
			&aes->pdev->dev,
			"[%s:ERROR] Unaligned buffer allocated, but no length reported\n",
			__func__);
		out_data->byte_count = 0;
		out_data->extended_status = aes_cmd->cqe.ph_sts.ph_sts_bits.sts = AZIHSM_FP_IOCTL_DEVICE_ERROR;
		return;
	}

	// If we did NOT allocate an unaligned buffer, then we should NOT get a length back
	if (!aes_cmd->aux_buffer_kva && aes_cmd->cqe.unaligned_dst_data_len) {
		AZIHSM_DEV_LOG_ERROR(
			&aes->pdev->dev,
			"[%s:ERROR] Unaligned buffer not allocated, but a length is reported\n",
			__func__);
		out_data->byte_count = 0;
		out_data->extended_status = aes_cmd->cqe.ph_sts.ph_sts_bits.sts = AZIHSM_FP_IOCTL_DEVICE_ERROR;
		return;
	}

	// If we allocated an unaligned buffer, but the reported size exceeds what we allocated
	if (aes_cmd->aux_buffer_kva && (aes_cmd->cqe.unaligned_dst_data_len > aes_cmd->unaligned_data_size)) {
		AZIHSM_DEV_LOG_ERROR(
			&aes->pdev->dev,
			"[%s:ERROR] Invalid size reported for unaligned buffer\n",
			__func__);
		out_data->byte_count = 0;
		out_data->extended_status = aes_cmd->cqe.ph_sts.ph_sts_bits.sts = AZIHSM_FP_IOCTL_DEVICE_ERROR;
		return;
	}

	// If we allocated an unaligned buffer, but the reported size exceed the MAX
	if (aes_cmd->aux_buffer_kva && (aes_cmd->cqe.unaligned_dst_data_len > AZIHSM_MAX_UNALIGNED_DATA_SZ)) {
		AZIHSM_DEV_LOG_ERROR(
			&aes->pdev->dev,
			"[%s:ERROR] Invalid size reported for unaligned buffer\n",
			__func__);
		out_data->byte_count = 0;
		out_data->extended_status = aes_cmd->cqe.ph_sts.ph_sts_bits.sts = AZIHSM_FP_IOCTL_DEVICE_ERROR;
		return;
	}

	out_data->byte_count = aes_cmd->cqe.len;

	//
	// Copy additional AES GCM specific results out
	//
	if (aes_cmd->sqe.attr.cipher == AZIHSM_AES_CIPHER_GCM) {
		AZIHSM_DEV_LOG_INFO(
			&aes->pdev->dev,
			"set_output_data. Copying additional results\n");

		// aes_cmd->aux_buffer_kva is only allocated if the GCM workaround is enabled
		if (aes_cmd->aux_buffer_kva) {
			// We allocated an unaligned buffer, so
			// now we need to copy the results back
			// into the original destination buffer
			aligned_buffer_dst = (u8 *)(in_data->UserBuff.dst_ptr);

			// Copy the unaligned buffer data to the end of the aligned data
			if (copy_to_user( (void __user *)&aligned_buffer_dst[aligned_data_len], aes_cmd->aux_buffer_kva,
				aes_cmd->unaligned_data_size)) {
				AZIHSM_DEV_LOG_ERROR(
					&aes->pdev->dev,
					"[%s:ERROR] copy_to_user of unaligned data failed\n",
					__func__);
				out_data->byte_count = 0;
				out_data->extended_status = AZIHSM_FP_IOCTL_DEVICE_ERROR;
				return;
			}

			out_data->byte_count +=  aes_cmd->unaligned_data_size;
		}
	}

	//
	// For the GCM commands we will have to fill up the
	// Tag and IV when the encrypt command is completed
	//
	if ((aes_cmd->sqe.attr.cmd_opc == AZIHSM_AES_OP_ENCRYPT) &&
	    (aes_cmd->sqe.attr.cipher == AZIHSM_AES_CIPHER_GCM)) {
		//
		// Get the tag from the Cqe and fill it up in the
		// ioctl output data
		//
		src_cmd_spec = (void *)aes_cmd->cqe.cmd_spec.u.tag;
		dst_cmd_spec = (void *)out_data->cmd_spec;

		AZIHSM_DEV_LOG_INFO(
			&aes->pdev->dev,
			"set_output_data. aes:%p encryption done. Copying tag\n",
			aes);

		memcpy(dst_cmd_spec, src_cmd_spec, AZIHSM_AES_CMD_SPEC_SZ);

		//
		// Get the IV from the Cqe and fill it up in the
		// ioctl output data
		//
		src_iv = (void *)aes_cmd->cqe.iv_from_fw;
		dst_iv = (void *)out_data->iv_from_fw;

		AZIHSM_DEV_LOG_INFO(
			&aes->pdev->dev,
			"set_output_data. aes:%p encryption done. Copying IV\n",
			aes);

		memcpy(dst_iv, src_iv, AZIHSM_AES_IV_LEN);

	}
}

static void azihsm_aes_dev_sqe_fill_sgl_info(struct azihsm_aes_cmd *aes_cmd)
{
	u8 sqe_desc_type;
	u32 seg_sz = 0;

	//
	// Fill the information for the source buffer
	//
	if (aes_cmd->dma_io_src.uva) {
		sqe_desc_type = AZIHSM_SGL_DESCR_TYPE_SEGMENT;
		seg_sz = PAGE_SIZE;

		if (aes_cmd->dma_io_src.hw_seg_cnt == 1) {
			//
			// If there is only one segment, this means that
			// all the sgl entries fit on the first page itself.
			// We calculate the size accordingly
			//
			sqe_desc_type = AZIHSM_SGL_DESCR_TYPE_LAST_SEGMENT;
			seg_sz = sizeof(struct azihsm_aes_sgl_desc) *
				 aes_cmd->dma_io_src.sg_cnt;
		}

		aes_cmd->sqe.src_data.dptr.sgl.sgl_desc.addr =
			aes_cmd->dma_io_src.hw_sgl_mem_paddr;
		aes_cmd->sqe.src_data.dptr.sgl.sgl_desc.desc_type =
			sqe_desc_type;
		aes_cmd->sqe.src_data.dptr.sgl.sgl_desc.desc_sub_type =
			AZIHSM_SGL_DESCR_SUBTYPE_ADDRESS;
		aes_cmd->sqe.src_data.dptr.sgl.sgl_desc.len = seg_sz;

		//
		// Total Length Of The Data Transfer
		//
		aes_cmd->sqe.src_data.len = aes_cmd->dma_io_src.ubuff_sz;
	}

	//
	// Fill the information for the destination buffer
	//
	if (aes_cmd->dma_io_dst.uva) {
		sqe_desc_type = AZIHSM_SGL_DESCR_TYPE_SEGMENT;
		seg_sz = PAGE_SIZE;

		if (aes_cmd->dma_io_dst.hw_seg_cnt == 1) {
			//
			// If there is only one segment, this means that
			// all the sgl entries fit on the first page itself.
			// We calculate the size accordingly
			//
			sqe_desc_type = AZIHSM_SGL_DESCR_TYPE_LAST_SEGMENT;
			seg_sz = sizeof(struct azihsm_aes_sgl_desc) *
				 aes_cmd->dma_io_dst.sg_cnt;
		}

		aes_cmd->sqe.dst_data.dptr.sgl.sgl_desc.addr =
			aes_cmd->dma_io_dst.hw_sgl_mem_paddr;
		aes_cmd->sqe.dst_data.dptr.sgl.sgl_desc.desc_type =
			sqe_desc_type;
		aes_cmd->sqe.dst_data.dptr.sgl.sgl_desc.desc_sub_type =
			AZIHSM_SGL_DESCR_SUBTYPE_ADDRESS;
		aes_cmd->sqe.dst_data.dptr.sgl.sgl_desc.len = seg_sz;

		//
		// Total Length Of The Data Transfer
		//
		aes_cmd->sqe.dst_data.len = aes_cmd->dma_io_dst.ubuff_sz;
	}
}

static void azihsm_aes_dev_sqe_prep(struct azihsm_aes_cmd *aes_cmd,
				    struct aes_ioctl_indata *in_data)
/*
 * This function does not validate the input data at all
 * It jsut translates the input data paramters to create
 * submission queue entry.
 */
{
	struct azihsm_aes_sqe *sqe;

	aes_cmd->tag = -1;
	sqe = &aes_cmd->sqe;

	azihsm_aes_cmd_init(aes_cmd, in_data->op_code, AZIHSM_AES_PSDT_TYPE_SGL,
			    AZIHSM_AES_CMD_TYPE_AES, in_data->frame_type,
			    in_data->cipher);

	/*
	 * copy the session id and short app id from
	 * ioctl input buffer to the sqe
	 * These fields have already been validated
	 */
	aes_cmd->sqe.session_id = in_data->session_id;
	aes_cmd->sqe.short_app_id = in_data->short_app_id;

	if (in_data->cipher == AZIHSM_AES_CIPHER_XTS) {
		sqe->attr.dul = in_data->xts_or_gcm.xts.data_unit_len;
		sqe->cmd_spec.u.xts.key_id1 = in_data->xts_or_gcm.xts.key_id1;
		sqe->cmd_spec.u.xts.key_id2 = in_data->xts_or_gcm.xts.key_id2;

		memcpy(sqe->cmd_spec.u.xts.tweak, in_data->xts_or_gcm.xts.tweak,
		       AZIHSM_AES_TWEAK_LEN);
	}

	else if (in_data->cipher == AZIHSM_AES_CIPHER_GCM) {
		sqe->cmd_spec.u.gcm.key_id = in_data->xts_or_gcm.gcm.key_id;
		sqe->cmd_spec.u.gcm.actual_aad_len =
			in_data->xts_or_gcm.gcm.actual_aad_data_len;
		sqe->cmd_spec.u.gcm.aligned_aad_len =
			in_data->xts_or_gcm.gcm.aligned_aad_len;

		memcpy(sqe->cmd_spec.u.gcm.tag, in_data->xts_or_gcm.gcm.tag,
		       AZIHSM_AES_TAG_LEN);

		memcpy(sqe->cmd_spec.u.gcm.iv,
		       in_data->xts_or_gcm.gcm.init_vector, AZIHSM_AES_IV_LEN);
	}

	//
	// Setup the first scatter gather entries for the source
	// and data in SQE
	//
	azihsm_aes_dev_sqe_fill_sgl_info(aes_cmd);
}

/*
 * azihsm_aes_dev_validate_ioctl_cipher_xts
 * validate that the parameters for XTS cipher
 * are valid.
 *
 * The only parameter we can validate is that the
 * data unit length is valid.
 *
 * User source buffer length must always be a multiple
 * of data unit length otherwise we will fail the ioctl
 *
 * decode the value from the ioctl to the correct value
 */
static int azihsm_aes_dev_validate_ioctl_cipher_xts(
	struct azihsm_hsm *hsm, struct aes_ioctl_outdata *out_data,
	struct xts_params *xts, struct aes_ioctl_user_buffer *buffers)
{
	u32 dul = 0;

	if (buffers->dst_len < buffers->src_len) {
		AZIHSM_DEV_LOG_ERROR(
			hsm->cdev_dev,
			"[%s:ERROR] [XTS] Output buffer length:%d is not equal to input buffer length:%d\n",
			__func__, buffers->dst_len, buffers->src_len);
		out_data->extended_status =
			AZIHSM_FP_IOCTL_AES_XTS_IOCTL_VALIDATION_FAILED;
		return -EINVAL;
	}

	/* validate the data unit length */
	if (xts->data_unit_len > AZIHSM_AES_DUL_END) {
		AZIHSM_DEV_LOG_ERROR(hsm->cdev_dev, "[%s:ERROR] dul : %d is invalid\n",
				     __func__, xts->data_unit_len);
		out_data->extended_status =
			AZIHSM_FP_IOCTL_AES_XTS_IOCTL_VALIDATION_FAILED;
		return -EINVAL;
	}

	switch (xts->data_unit_len) {
	case AZIHSM_AES_DUL_FULL:
		dul = buffers->src_len;
		break;

	case AZIHSM_AES_DUL_SIZE_512:
		dul = 512;
		break;

	case AZIHSM_AES_DUL_SIZE_4096:
		dul = 4096;
		break;

	case AZIHSM_AES_DUL_SIZE_8192:
		dul = 8192;
		break;
	}

	if (!dul) {
		AZIHSM_DEV_LOG_ERROR(
			hsm->cdev_dev,
			"[%s:ERROR] input source buffer len[%d] is of zero length. dul:%d\n",
			__func__, buffers->src_len, dul);
		out_data->extended_status =
			AZIHSM_FP_IOCTL_AES_XTS_IOCTL_VALIDATION_FAILED;
		return -EINVAL;
	}

	if (buffers->src_len % dul) {
		AZIHSM_DEV_LOG_ERROR(
			hsm->cdev_dev,
			"[%s:ERROR] input source buffer len[%d] is not a multiple of dul[%d]\n",
			__func__, buffers->src_len, dul);
		out_data->extended_status =
			AZIHSM_FP_IOCTL_AES_XTS_IOCTL_VALIDATION_FAILED;
		return -EINVAL;
	}

	return 0;
}

/*
 * azihsm_aes_dev_validate_ioctl_cipher_gcm
 * the source buffer provided by the user
 * includes the AAD (if provided).
 * So validate the lengths of the input and
 * output buffers.
 * Input buffer must be the same length as the
 * output buffer (after aad is taken into consideration)
 */
static int azihsm_aes_dev_validate_ioctl_cipher_gcm(
	struct azihsm_hsm *hsm, struct aes_ioctl_outdata *out_data,
	struct gcm_params *gcm, struct aes_ioctl_user_buffer *buffers)
{
	if (gcm->actual_aad_data_len >= buffers->src_len) {
		AZIHSM_DEV_LOG_ERROR(
			hsm->cdev_dev,
			"[%s:ERROR] [GCM] AAD data length:%d is invalid. User source buffer length:%d\n",
			__func__, gcm->actual_aad_data_len, buffers->src_len);
		out_data->extended_status =
			AZIHSM_FP_IOCTL_AES_GCM_IOCTL_VALIDATION_FAILED;
		return -EINVAL;
	}

	if (AZIHSM_AES_GCM_WA_SUPPORTED(hsm->ctrl) && gcm->enable_gcm_workaround) {
		//
		// Application supports the GCM Alignment workaround
		// Check the params accordingly
		//
		if (gcm->aligned_aad_len < gcm->actual_aad_data_len) {
			AZIHSM_DEV_LOG_ERROR(
				hsm->cdev_dev,
				"[%s:ERROR] [GCM] aligned aad length:%d is less than actual aad len %d\n",
				__func__, gcm->aligned_aad_len, gcm->actual_aad_data_len);
			out_data->extended_status =
				AZIHSM_FP_IOCTL_AES_GCM_IOCTL_VALIDATION_FAILED;
			return -EINVAL;
		}
		if (!AZIHSM_IS_AAD_ALIGNED(gcm->aligned_aad_len, AZIHSM_AES_GCM_AAD_SZ_ALIGNMENT_BYTES)) {
			AZIHSM_DEV_LOG_ERROR(
				hsm->cdev_dev,
				"[%s:ERROR] [GCM] aligned_aad_len (%d) is Not Aligned %d\n",
				__func__,
				gcm->aligned_aad_len, AZIHSM_AES_GCM_AAD_SZ_ALIGNMENT_BYTES);
			out_data->extended_status =
				AZIHSM_FP_IOCTL_AES_GCM_IOCTL_VALIDATION_FAILED;
			return -EINVAL;
		}
	}

	if (buffers->dst_len < buffers->src_len - gcm->actual_aad_data_len) {
		AZIHSM_DEV_LOG_ERROR(
			hsm->cdev_dev,
			"[%s:ERROR] [GCM] dest length:%d is less than required size. src:%d aad:%d\n",
			__func__, buffers->dst_len, buffers->src_len,
			gcm->actual_aad_data_len);
		out_data->extended_status =
			AZIHSM_FP_IOCTL_AES_GCM_IOCTL_VALIDATION_FAILED;
		return -EINVAL;
	}

	return 0;
}

/*
 * Function :- azihsm_aes_dev_validate_ioctl
 * Validates that the input buffer to AES ioctl
 * a) Validate that the header size meets minimum requirements
 * b) Validate that FP queues are created
 * c) Validate the fields in the ioctl input buffer
 *
 * Parameters :-
 *   ctxt :- File context which has session information
 *   arg :- Address of ioctl buffer from user space
 *   aes_ioctl_buffer :- to be returned back to user
 *   ioctl_value :- Ioctl code from user
 *
 * Failure :- Returns non-zero value
 * If the user provided buffer is of correct size but still
 * validation fails, result field will have additional fields
 * to indicate the status code
 *
 * If this function succeeds, it is the responsibility of the caller
 * to copy eventual results to the user buffer.
 * If this function fails, this function will copy the data back to
 * the user using copy_to_user
 */
static int azihsm_aes_dev_validate_ioctl(
	struct azihsm_hsm_fd_ctxt *ctxt, unsigned long arg,
	struct aes_ioctl_inout_data *aes_ioctl_buffer, unsigned int ioctl_value)
{
	struct aes_ioctl_header aes_cmd_hdr;
	int rc = 0;
	const size_t required_size = sizeof(struct aes_ioctl_inout_data);
	u16 session_id_in_file_ctxt, session_id_in_ioctl_buffer;
	u8 short_app_id_in_file_ctxt, short_app_id_in_ioctl_buffer;

	AZIHSM_DEV_LOG_INFO(
		ctxt->hsm->cdev_dev,
		"[INFO:%s] AES IOCTL. performing validation. Expected size:%d AES ioctl header size:%d\n",
		__func__, (int)required_size,
		(int)sizeof(struct aes_ioctl_header));

	/* Input buffer must be at least header size */
	if (copy_from_user(&aes_cmd_hdr, (void __user *)arg,
			   sizeof(struct aes_ioctl_header))) {
		AZIHSM_DEV_LOG_ERROR(
			ctxt->hsm->cdev_dev,
			"[%s:ERROR] copy_from_user failed (for ioctl header) length=%d(expected)\n",
			__func__, (__u32)sizeof(struct aes_ioctl_inout_data));
		return -EINVAL;
	}

	/* Validate that the size of the buffer in the header is correct */
	if (aes_cmd_hdr.sz_ioc_data < (__u32)required_size) {
		AZIHSM_DEV_LOG_ERROR(
			ctxt->hsm->cdev_dev,
			"[%s:ERROR] Length in ioctl header=%d is lesser than required size=%d\n",
			__func__, aes_cmd_hdr.sz_ioc_data,
			(__u32)required_size);
		return -EINVAL;
	}

	/* verify that the full buffer matches what we are expecting */
	if (copy_from_user(aes_ioctl_buffer, (void __user *)arg,
			   required_size)) {
		AZIHSM_DEV_LOG_ERROR(
			ctxt->hsm->cdev_dev,
			"[%s:ERROR] copy_from_user failed length=%d(expected)\n",
			__func__, (u32)required_size);
		return -EINVAL;
	}

	/* TODO. Remove the following once tested */
	AZIHSM_DEV_LOG_INFO(
		ctxt->hsm->cdev_dev,
		"[INFO:%s] AES IOCTL. performing validation. Number of AES io queues:%d\n",
		__func__, ctxt->hsm->ctrl->aes.ioq_pool.ioq_cnt);

	if (AZIHSM_CTRL_IS_ABORT_IN_PROGRESS(ctxt->hsm->ctrl)) {
		AZIHSM_DEV_LOG_ERROR(
			ctxt->hsm->cdev_dev,
			"AES ioctl: An abort is currently in progress.\n");

		aes_ioctl_buffer->out_data.extended_status =
			GENERATE_STATUS_CODE(AZIHSM_STS_SRC_ABORT,
					     AZIHSM_ABORT_IN_PROGRESS);

		rc = -EAGAIN;
		goto validate_done;
	}

	if (!AZIHSM_CTRL_ST_ISRDY(ctxt->hsm->ctrl)) {
		AZIHSM_DEV_LOG_ERROR(
			ctxt->hsm->cdev_dev,
			"AES ioctl: Device is not ready. Unable to execute command on the device [Rdy_Sts:%d AbortSts:%d]\n",
			AZIHSM_CTRL_GET_STATE(ctxt->hsm->ctrl),
			AZIHSM_CTRL_GET_ABORT_STATE(ctxt->hsm->ctrl));

		aes_ioctl_buffer->out_data.extended_status =
			AZIHSM_FP_IOCTL_DEVICE_ERROR;

		rc = -EAGAIN;
		goto validate_done;
	}

	/*
	 *If no FP queues are created, cannot submit command
	 */
	if (!ctxt->hsm->ctrl->aes.ioq_pool.ioq_cnt) {
		aes_ioctl_buffer->out_data.extended_status =
			AZIHSM_FP_IOCTL_DEVICE_NO_FP_QUEUES;
		AZIHSM_DEV_LOG_ERROR(
			ctxt->hsm->cdev_dev,
			"[%s:ERROR] Device has reported 0 AES queues\n",
			__func__);
		rc = -EINVAL;
	}

	session_id_in_file_ctxt = ctxt->sessions[0].id;
	session_id_in_ioctl_buffer = aes_ioctl_buffer->in_data.session_id;

	short_app_id_in_file_ctxt = ctxt->sessions[0].short_app_id;
	short_app_id_in_ioctl_buffer = aes_ioctl_buffer->in_data.short_app_id;

	/* TODO. Remove the following once tested */
	AZIHSM_DEV_LOG_INFO(
		ctxt->hsm->cdev_dev,
		"[INFO:%s] AES IOCTL. performing validation. Session info[%d:%d:%d:%d:%s:%s]\n",
		__func__, session_id_in_file_ctxt, session_id_in_ioctl_buffer,
		short_app_id_in_file_ctxt, short_app_id_in_ioctl_buffer,
		true == ctxt->sessions[0].valid ? "SESSION ID IS VALID" :
						  "SESSION ID IS NOT VALID",
		true == ctxt->sessions[0].short_app_id_is_valid ?
			"SHORT APP ID IS VALID" :
			"SHORT APP ID IS NOT VALID");

	/*
	 * User must have created a session and a short app id on this
	 * file handle. If not, fail the ioctl
	 */
	if (false == ctxt->sessions[0].valid) {
		aes_ioctl_buffer->out_data.extended_status =
			AZIHSM_FP_IOCTL_NO_VALID_SESSION_ID;
		AZIHSM_DEV_LOG_ERROR(
			ctxt->hsm->cdev_dev,
			"[%s:ERROR] AES Ioctl. No session has been created on this file handle. ctxt=%p\n",
			__func__, ctxt);
		rc = -EINVAL;
	}

	/*
	 * verify that a short app id has been registered on this file handle
	 * A short app id must be registered on the file handle before any
	 *  fast path operations are allowed
	 */
	else if (false == ctxt->sessions[0].short_app_id_is_valid) {
		aes_ioctl_buffer->out_data.extended_status =
			AZIHSM_FP_IOCTL_NO_VALID_SHORT_APP_ID;
		AZIHSM_DEV_LOG_ERROR(
			ctxt->hsm->cdev_dev,
			"[%s:ERROR] AES Ioctl. Session[%d] has been created but no short app id has been created. ctxt=%p\n",
			__func__, ctxt->sessions[0].id, ctxt);
		rc = -EINVAL;
	}
	/*
	 * Verify that the session id in the ioctl input buffer matches the one registered on the file handle
	 */
	else if ((true == ctxt->sessions[0].valid) &&
		 (session_id_in_file_ctxt != session_id_in_ioctl_buffer)) {
		aes_ioctl_buffer->out_data.extended_status =
			AZIHSM_FP_IOCTL_SESSION_ID_DOES_NOT_MATCH;
		AZIHSM_DEV_LOG_ERROR(
			ctxt->hsm->cdev_dev,
			"[%s:ERROR] AES Ioctl. ctxt=%p Session id in ctxt[%d] does not match session id in ioctl[%d]\n",
			__func__, ctxt, session_id_in_file_ctxt,
			session_id_in_ioctl_buffer);
		rc = -EINVAL;
	}

	else if ((true == ctxt->sessions[0].short_app_id_is_valid) &&
		 (short_app_id_in_file_ctxt != short_app_id_in_ioctl_buffer)) {
		aes_ioctl_buffer->out_data.extended_status =
			AZIHSM_FP_IOCTL_SHORTAPP_ID_DOES_NOT_MATCH;
		AZIHSM_DEV_LOG_ERROR(
			ctxt->hsm->cdev_dev,
			"[%s:ERROR] AES Ioctl. ctxt=%p short app id in ctxt[%d] does not match short app id in ioctl[%d]\n",
			__func__, ctxt, short_app_id_in_file_ctxt,
			short_app_id_in_ioctl_buffer);
		rc = -EINVAL;
	}

	else if (AZIHSM_AES_OP_CODE_VALID(aes_ioctl_buffer->in_data.op_code) ==
		 false) {
		aes_ioctl_buffer->out_data.extended_status =
			AZIHSM_FP_IOCTL_INVALID_OPCODE;
		AZIHSM_DEV_LOG_ERROR(
			ctxt->hsm->cdev_dev,
			"[%s:ERROR] AES Ioctl. ctxt=%p opcode[%d] in ioctl is not valid\n",
			__func__, ctxt, aes_ioctl_buffer->in_data.op_code);
		rc = -EINVAL;
	}

	else if (AZIHSM_AES_CIPHER_VALID(aes_ioctl_buffer->in_data.cipher) ==
		 false) {
		aes_ioctl_buffer->out_data.extended_status =
			AZIHSM_FP_IOCTL_INVALID_CIPHER_TYPE;
		AZIHSM_DEV_LOG_ERROR(
			ctxt->hsm->cdev_dev,
			"[%s:ERROR] AES Ioctl. ctxt=%p cipher[%d] provided in ioctl input is not valid\n",
			__func__, ctxt, aes_ioctl_buffer->in_data.cipher);
		rc = -EINVAL;
	}

	else if ((ioctl_value == AZIHSM_AES_DEV_IOCTL_CMD_XTS) &&
		 (aes_ioctl_buffer->in_data.cipher != AZIHSM_AES_CIPHER_XTS)) {
		aes_ioctl_buffer->out_data.extended_status =
			AZIHSM_FP_IOCTL_INVALID_CIPHER_TYPE;
		AZIHSM_DEV_LOG_ERROR(
			ctxt->hsm->cdev_dev,
			"[%s:ERROR] AES Ioctl. ctxt=%p cipher[%d] (xts) provided in ioctl does not match ioctl code[%d]\n",
			__func__, ctxt, aes_ioctl_buffer->in_data.cipher,
			ioctl_value);
		rc = -EINVAL;
	}

	else if ((ioctl_value == AZIHSM_AES_DEV_IOCTL_CMD_GCM) &&
		 (aes_ioctl_buffer->in_data.cipher != AZIHSM_AES_CIPHER_GCM)) {
		aes_ioctl_buffer->out_data.extended_status =
			AZIHSM_FP_IOCTL_INVALID_CIPHER_TYPE;
		AZIHSM_DEV_LOG_ERROR(
			ctxt->hsm->cdev_dev,
			"[%s:ERROR] AES Ioctl. ctxt=%p cipher[%d](gcm) provided in ioctl does not match ioctl code[%d]\n",
			__func__, ctxt, aes_ioctl_buffer->in_data.cipher,
			ioctl_value);
		rc = -EINVAL;
	}

	if (rc)
		goto validate_done;

	/*
	 *do cipher specific checks
	 */
	if (aes_ioctl_buffer->in_data.cipher == AZIHSM_AES_CIPHER_XTS) {
		rc = azihsm_aes_dev_validate_ioctl_cipher_xts(
			ctxt->hsm, &aes_ioctl_buffer->out_data,
			&aes_ioctl_buffer->in_data.xts_or_gcm.xts,
			&aes_ioctl_buffer->in_data.UserBuff);
	} else if (aes_ioctl_buffer->in_data.cipher == AZIHSM_AES_CIPHER_GCM) {
		rc = azihsm_aes_dev_validate_ioctl_cipher_gcm(
			ctxt->hsm, &aes_ioctl_buffer->out_data,
			&aes_ioctl_buffer->in_data.xts_or_gcm.gcm,
			&aes_ioctl_buffer->in_data.UserBuff);
	}

	if (rc)
		goto validate_done;

	/* frame type must always be AES irrespective of whether it is XTS or GCM */
	if (AZIHSM_AES_FRAME_TYPE_VALID(aes_ioctl_buffer->in_data.frame_type) ==
	    false) {
		aes_ioctl_buffer->out_data.extended_status =
			AZIHSM_FP_IOCTL_INVALID_FRAME_TYPE;
		AZIHSM_DEV_LOG_ERROR(
			ctxt->hsm->cdev_dev,
			"[%s:ERROR] AES Ioctl. ctxt=%p frame type in ioctl is not AES.\n",
			__func__, ctxt);
		rc = -EINVAL;
	} else if (!aes_ioctl_buffer->in_data.UserBuff.src_ptr ||
		   !aes_ioctl_buffer->in_data.UserBuff.src_len) {
		aes_ioctl_buffer->out_data.extended_status =
			AZIHSM_FP_IOCTL_INVALID_INPUT_BUFFER;
		AZIHSM_DEV_LOG_ERROR(
			ctxt->hsm->cdev_dev,
			"[%s:ERROR] AES Ioctl. ctxt=%p source buffer is NULL or length is zero\n",
			__func__, ctxt);
		rc = -EINVAL;
	} else if (!aes_ioctl_buffer->in_data.UserBuff.dst_ptr ||
		   !aes_ioctl_buffer->in_data.UserBuff.dst_len) {
		aes_ioctl_buffer->out_data.extended_status =
			AZIHSM_FP_IOCTL_INVALID_OUTPUT_BUFFER;
		AZIHSM_DEV_LOG_ERROR(
			ctxt->hsm->cdev_dev,
			"[%s:ERROR] AES Ioctl. ctxt=%p destination buffer is NULL or length is zero\n",
			__func__, ctxt);
		rc = -EINVAL;
	}

	if (!access_ok(aes_ioctl_buffer->in_data.UserBuff.src_ptr,
		       aes_ioctl_buffer->in_data.UserBuff.src_len)) {
		aes_ioctl_buffer->out_data.extended_status =
			AZIHSM_FP_IOCTL_INVALID_INPUT_BUFFER;
		AZIHSM_DEV_LOG_ERROR(
			ctxt->hsm->cdev_dev,
			"[%s:ERROR  Source Buffer Does Not Have Access [buff->%p:len->%d]\n",
			__func__, aes_ioctl_buffer->in_data.UserBuff.src_ptr,
			aes_ioctl_buffer->in_data.UserBuff.src_len);
		rc = -EINVAL;
		goto validate_done;
	}

	if (!access_ok(aes_ioctl_buffer->in_data.UserBuff.dst_ptr,
		       aes_ioctl_buffer->in_data.UserBuff.dst_len)) {
		aes_ioctl_buffer->out_data.extended_status =
			AZIHSM_FP_IOCTL_INVALID_OUTPUT_BUFFER;
		AZIHSM_DEV_LOG_ERROR(
			ctxt->hsm->cdev_dev,
			"[%s:ERROR  Destination Buffer Does Not Have Access [buff->%p:len->%d]\n",
			__func__, aes_ioctl_buffer->in_data.UserBuff.dst_ptr,
			aes_ioctl_buffer->in_data.UserBuff.dst_len);

		rc = -EINVAL;
	}

validate_done:
	if (rc) {
		/* Above, we validated that the user provided buffer
		 *  is of the length so this copy to user should be ok
		 *  This is done so we can return the extended status back to
		 * caller
		 */
		if (copy_to_user((void __user *)arg, aes_ioctl_buffer,
				 sizeof(struct aes_ioctl_inout_data))) {
			rc = -EFAULT;
			AZIHSM_DEV_LOG_ERROR(
				ctxt->hsm->cdev_dev,
				"[%s:ERROR] Error copying ioctl buffer back to user",
				__func__);
		}
	} else {
		AZIHSM_DEV_LOG_INFO(
			ctxt->hsm->cdev_dev,
			"[%s:INFO] AES IOCTL buffer validation passed",
			__func__);
	}

	return rc;
}

/*
 * Right oow this function is filling up
 * status for abort conditions. We would want
 * To keep this separate for AES and CP paths
 * so that if we decide to call this function
 * generically for all errors, we should be able to
 * do that.
 */
static void azihsm_aes_fill_error_sts(struct azihsm_aes *aes,
				      struct aes_ioctl_outdata *out_data,
				      u32 cmd_cpl_sts)
{
	u32 status_code = 0;

	switch (cmd_cpl_sts) {
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

	case AZIHSM_IOQ_CMD_STS_QSELECT_FAILED: {
		status_code = GENERATE_STATUS_CODE(
			AZIHSM_STS_SRC_ABORT, AZIHSM_FP_IOCTL_DEVICE_ERROR);
		break;
	}

	default:
		return; // Return without modifying the status code.

	} //switch

	out_data->extended_status = status_code;
}

static int
azihsm_aes_dev_enc_dec_ioctl(struct azihsm_aes *aes,
			     struct aes_ioctl_inout_data *aes_ioctl_buf,
			     unsigned long arg)
{
	int rc = 0;
	struct aes_ioctl_indata *in_data = NULL;
	struct aes_ioctl_outdata *out_data = NULL;
	struct azihsm_aes_cmd aes_cmd = { 0 };
	u8 __user *unaligned_buffer_src, *unaligned_buffer_dst;

	aes_cmd.completion_status = AZIHSM_IOQ_CMD_STS_UNDEFINED;

	in_data = &aes_ioctl_buf->in_data;
	out_data = &aes_ioctl_buf->out_data;

	dump_aes_in_data(in_data);

	// Check to see if the DDI and the FW both support the GCM alignent workaround
	if ( aes->ctrl->aes_gcm_align_workaround &&
			aes_ioctl_buf->in_data.cipher == AZIHSM_AES_CIPHER_GCM &&
			aes_ioctl_buf->in_data.xts_or_gcm.gcm.enable_gcm_workaround) {
		aes_cmd.unaligned_data_size = aes_ioctl_buf->in_data.UserBuff.src_len % AZIHSM_AES_GCM_DATA_SZ_ALIGNMENT_BYTES;

		if (aes_cmd.unaligned_data_size) {
			/* We need to make some adjustments for the AES GCM Alignment workaround */
			AZIHSM_DEV_LOG_DEBUG(
				&aes->pdev->dev,
				"Unaliged Length %d", aes_cmd.unaligned_data_size);
			// Because this is only allocated if all of the above conditions are met, it can serve as a flag later on
			aes_cmd.aux_buffer_kva = dma_alloc_coherent(&aes->pdev->dev, aes_cmd.unaligned_data_size,
							&aes_cmd.hw_addr, GFP_KERNEL);
			if (!aes_cmd.aux_buffer_kva) {
				AZIHSM_DEV_LOG_DEBUG(
					&aes->pdev->dev,
					"Failed to DMA alloc unaligned data buffer");
				out_data->extended_status = AZIHSM_FP_IOCTL_NO_MEMORY;
				return -EIO;
			}

		}

		// Now, we need to adjust the buffer lengths before we allocate the SGLs
		in_data->UserBuff.src_len -= aes_cmd.unaligned_data_size;
		in_data->UserBuff.dst_len -= aes_cmd.unaligned_data_size;
		unaligned_buffer_src = (u8 *)(in_data->UserBuff.src_ptr);
		unaligned_buffer_dst = (u8 *)(in_data->UserBuff.dst_ptr);
	}

	// This should not happen, but just be paranoid for now
	if(aes_cmd.aux_buffer_kva && !aes_cmd.unaligned_data_size) {
		AZIHSM_DEV_LOG_DEBUG(
			&aes->pdev->dev,
			"BAD: kva %d 0x%p",
			aes_cmd.unaligned_data_size,
			aes_cmd.aux_buffer_kva);
	}


	//
	// Create the SGL for the source buffer
	//
	if( in_data->UserBuff.src_len != 0 && in_data->UserBuff.dst_len != 0 ) {
		rc = azihsm_dma_io_init(aes->pdev, in_data->UserBuff.src_ptr,
					in_data->UserBuff.src_len, DMA_TO_DEVICE,
					&aes_cmd.dma_io_src);

		if (rc) {
			//
			// For this failure the cleanup is called internally
			// by the function.
			//
			AZIHSM_DEV_LOG_ERROR(
				&aes->pdev->dev,
				"%s:Failed To Create SGL For Src Buff[%d]\n", __func__,
				rc);

			out_data->extended_status = AZIHSM_FP_IOCTL_NO_MEMORY;
			return -EIO;
		}

		//
		// Create the NVME SGL for the source buffer
		//
		rc = azihsm_dma_io_xlat(&aes_cmd.dma_io_src);
		if (rc) {
			AZIHSM_DEV_LOG_ERROR(
				&aes->pdev->dev,
				"%s: Failed to Create the NVME Sgl For Src[%d]\n",
				__func__, rc);

			azihsm_dma_io_cleanup(&aes_cmd.dma_io_src);
			out_data->extended_status = AZIHSM_FP_IOCTL_NO_MEMORY;
			return -EIO;
		}

		//
		// Create the SGL for the destination buffer
		//
		rc = azihsm_dma_io_init(aes->pdev, in_data->UserBuff.dst_ptr,
					in_data->UserBuff.dst_len, DMA_FROM_DEVICE,
					&aes_cmd.dma_io_dst);

		if (rc) {
			AZIHSM_DEV_LOG_ERROR(
				&aes->pdev->dev,
				"%s: Failed To Create SGL For Dst Buff[%d]\n", __func__,
				rc);

			//
			// Cleanup for the dst dma io is done internally
			// by the function.
			//
			azihsm_dma_io_cleanup(&aes_cmd.dma_io_src);
			out_data->extended_status = AZIHSM_FP_IOCTL_NO_MEMORY;
			return rc;
		}

		//
		// Create the NVME SGL for the destination buffer
		//
		rc = azihsm_dma_io_xlat(&aes_cmd.dma_io_dst);
		if (rc) {
			AZIHSM_DEV_LOG_ERROR(
				&aes->pdev->dev,
				"%s: Failed to Create the NVME Sgl For Dst[%d]\n",
				__func__, rc);

			azihsm_dma_io_cleanup(&aes_cmd.dma_io_src);
			azihsm_dma_io_cleanup(&aes_cmd.dma_io_dst);
			out_data->extended_status = AZIHSM_FP_IOCTL_NO_MEMORY;
			return rc;
		}
	} else {
		in_data->UserBuff.src_ptr = NULL;
		in_data->UserBuff.dst_ptr = NULL;
	}

	//
	// Now we have everything ready, prepare the SQE
	// We have done enough validations, this function
	// cannot fail.
	//
	azihsm_aes_dev_sqe_prep(&aes_cmd, in_data);

	//
	// The SQE gets zero'd out in the prep call above, so we have to wait
	// until after this to do the GCM Alignment workaround adjustments
	//

	// aes_cmd.aux_buffer_kva is only allocated if the GCM workaround is enabled
	if(aes_cmd.aux_buffer_kva) {
		// We allocated the unaligned buffer above, so now we
		// update the SQE to use it

		AZIHSM_DEV_LOG_DEBUG(
			&aes->pdev->dev,
			"Unaligned DMA: auxkva 0x%p hw_addr 0x%016llx",
			aes_cmd.aux_buffer_kva,
			aes_cmd.hw_addr);

		aes_cmd.sqe.cmd_spec.u.gcm.unaligned_src_data_len = aes_cmd.unaligned_data_size;
		aes_cmd.sqe.cmd_spec.u.gcm.unaligned_dst_data_len = aes_cmd.unaligned_data_size;
		aes_cmd.sqe.cmd_spec.u.gcm.unaligned_src_data_addr_low  = (u32)((u64)aes_cmd.hw_addr    &0xffffffff);
		aes_cmd.sqe.cmd_spec.u.gcm.unaligned_src_data_addr_high = (u32)((u64)(aes_cmd.hw_addr>>32)&0xffffffff);
		aes_cmd.sqe.cmd_spec.u.gcm.unaligned_dst_data_addr_low  = (u32)((u64)aes_cmd.hw_addr    &0xffffffff);
		aes_cmd.sqe.cmd_spec.u.gcm.unaligned_dst_data_addr_high = (u32)((u64)(aes_cmd.hw_addr>>32)&0xffffffff);

		AZIHSM_DEV_LOG_DEBUG(
			&aes->pdev->dev,
			"unaligned buffer: %d @ 0x%x%08x",
			aes_cmd.sqe.cmd_spec.u.gcm.unaligned_src_data_len,
			aes_cmd.sqe.cmd_spec.u.gcm.unaligned_src_data_addr_high,
			aes_cmd.sqe.cmd_spec.u.gcm.unaligned_src_data_addr_low);
		
		// Copy the unaligned data at the end of the UserBuffer
		// into the DMA buffer we allocated above. This looks like we are
		// accessing data past the end of teh buffer, but the data was passed
		// in by the user as part of the original src_len.
		if (copy_from_user(aes_cmd.aux_buffer_kva, (void __user *)&unaligned_buffer_src[in_data->UserBuff.src_len],
			aes_cmd.unaligned_data_size)) {
			AZIHSM_DEV_LOG_ERROR(
				&aes->pdev->dev,
				"[%s:ERROR] copy_from_user of unaligned data failed\n",
				__func__);
			// Free up the DMA buffers
			azihsm_dma_io_cleanup(&aes_cmd.dma_io_src);
			azihsm_dma_io_cleanup(&aes_cmd.dma_io_dst);

			dma_free_coherent(&aes->pdev->dev, aes_cmd.unaligned_data_size,
					aes_cmd.aux_buffer_kva, aes_cmd.hw_addr);

			aes_cmd.aux_buffer_kva = 0;
			aes_cmd.unaligned_data_size = 0;
			return -EINVAL;
		}

	}

	dump_aes_cmd_sqe(&aes_cmd);

	dump_aes_in_data(in_data);

	//
	// fire the command and get the response
	//
	rc = azihsm_aes_cmd_process(aes, &aes_cmd);
	if (rc) {
		azihsm_dma_io_cleanup(&aes_cmd.dma_io_src);
		azihsm_dma_io_cleanup(&aes_cmd.dma_io_dst);

		// aes_cmd.aux_buffer_kva is only allocated if the GCM workaround is enabled
		if (aes_cmd.aux_buffer_kva) {
			dma_free_coherent(&aes->pdev->dev, aes_cmd.unaligned_data_size,
					aes_cmd.aux_buffer_kva, aes_cmd.hw_addr);
			aes_cmd.aux_buffer_kva = 0;
			aes_cmd.unaligned_data_size = 0;
		}

		azihsm_aes_fill_error_sts(aes, out_data,
					  aes_cmd.completion_status);

		AZIHSM_DEV_LOG_ERROR(
			&aes->pdev->dev,
			"%s: azihsm_aes_cmd_process Failed [rc:%d] [extended_sts:0x%x]\n",
			__func__, rc, out_data->extended_status);

		return rc;
	}

	if (aes_cmd.aux_buffer_kva) {
		in_data->UserBuff.src_ptr = unaligned_buffer_src;
		in_data->UserBuff.src_len += aes_cmd.unaligned_data_size;
		in_data->UserBuff.dst_ptr = unaligned_buffer_dst;
		in_data->UserBuff.dst_len += aes_cmd.unaligned_data_size;
	}

	//
	// Everything went well setup the output data
	// cleanup the command and copy to user
	//
	azihsm_aes_dev_cmd_set_output_data(aes, &aes_cmd, in_data, out_data);

	dump_aes_cmd_cqe(&aes_cmd);

	dump_aes_out_data(out_data);

	azihsm_dma_io_cleanup(&aes_cmd.dma_io_src);
	azihsm_dma_io_cleanup(&aes_cmd.dma_io_dst);

	// aes_cmd.aux_buffer_kva is only allocated if the GCM workaround is enabled
	if (aes_cmd.aux_buffer_kva) {
		dma_free_coherent(&aes->pdev->dev, aes_cmd.unaligned_data_size,
				aes_cmd.aux_buffer_kva, aes_cmd.hw_addr);
		aes_cmd.aux_buffer_kva = 0;
		aes_cmd.unaligned_data_size = 0;
	}
	return rc;
}

/*
 * azihsm_aes_dev_ioctl
 * Main entry point for processing AES IOCTL for
 * GCM and XTS encryption and decryption
 *
 * ctxt : HSM file context
 * This structure contains information on all the
 * sessions that are open on this file handle
 *
 * aes :- AES state of the controller
 * arg : Address of the ioctl buffer in user address space
 * ioctl_code :- Indicates XTS or GCM
 *
 * Returns 0 on success and a non-zero value on failure.
 */
int azihsm_aes_dev_ioctl(struct azihsm_hsm_fd_ctxt *ctxt,
			 struct azihsm_aes *aes, unsigned long arg,
			 unsigned int ioctl_code)
{
	int err = 0;
	struct aes_ioctl_inout_data aes_ioctl_buffer = { 0 };

	// Validate the ioctl
	err = azihsm_aes_dev_validate_ioctl(ctxt, arg, &aes_ioctl_buffer,
					    ioctl_code);

	if (err) {
		AZIHSM_DEV_LOG_ERROR(
			&aes->pdev->dev,
			"%s: AES ioctl validation failed. ioctl_code:0x%x ioctl_status:0x%x extended status:0x%x\n",
			__func__, ioctl_code, err,
			aes_ioctl_buffer.out_data.extended_status);
		return err;
	}

	err = azihsm_aes_dev_enc_dec_ioctl(aes, &aes_ioctl_buffer, arg);
	if (err) {
		AZIHSM_DEV_LOG_ERROR(
			&aes->pdev->dev,
			"%s: AES ioctl failed. ioctl_code:0x%x ioctl_status:0x%x extended status:0x%x\n",
			__func__, ioctl_code, err,
			aes_ioctl_buffer.out_data.extended_status);
	}

	err = copy_to_user((void *)arg, (void *)&aes_ioctl_buffer,
			   sizeof(struct aes_ioctl_inout_data));

	if (err)
		AZIHSM_DEV_LOG_ERROR(&aes->pdev->dev,
				     "[%s:] copy To user failed", __func__);
	return err;
}


/*
 * Debug routines
 */
void
dump_aes_in_data(struct aes_ioctl_indata *in_data)
{
	u8 *iv,*tag;
	AZIHSM_LOG_INFO("AES INDATA: %p\n"
			"op_code: %d\n"
			"cipher: %d\n"
			"UserBuff: src: %d 0x%p\n"
			"UserBuff: dst: %d 0x%p\n"
			"frame_type: %d\n"
			,
			in_data,
			in_data->op_code,
			in_data->cipher,
			in_data->UserBuff.src_len,
			in_data->UserBuff.src_ptr,
			in_data->UserBuff.dst_len,
			in_data->UserBuff.dst_ptr,
			in_data->frame_type
			);

	if ( in_data->cipher == AZIHSM_AES_CIPHER_GCM ) {
		iv = in_data->xts_or_gcm.gcm.init_vector;
		tag = in_data->xts_or_gcm.gcm.tag;
		AZIHSM_LOG_INFO("INDATA GCM Params:\n"
				"  key_id: %d\n"
				"  tag: %02x%02x%02x%02x%02x%02x%02x%02x"
				               "%02x%02x%02x%02x%02x%02x%02x%02x\n"
				"  init_vector: %02x%02x%02x%02x%02x%02x%02x%02x"
				               "%02x%02x%02x%02x%02x\n"
				"  actual_aad_len: %d\n"
				"  aligned_aad_len: %d\n"
				"  enable_gcm_workaround: %d\n"
				,
				in_data->xts_or_gcm.gcm.key_id,
				tag[0], tag[1], tag[2], tag[3], tag[4], tag[5], tag[6], tag[7],
				tag[8], tag[9], tag[10], tag[11], tag[12], tag[13], tag[14], tag[15],
				iv[0], iv[1], iv[2], iv[3], iv[4], iv[5], iv[6], iv[7],
				iv[8], iv[9], iv[10], iv[11], iv[12],
				in_data->xts_or_gcm.gcm.actual_aad_data_len,
				in_data->xts_or_gcm.gcm.aligned_aad_len,
				in_data->xts_or_gcm.gcm.enable_gcm_workaround
				);
	} else if ( in_data->cipher == AZIHSM_AES_CIPHER_XTS ) {
		AZIHSM_LOG_INFO("INDATA XTS Params:\n"
				"  data_unit_len: %d\n"
				"  key_id1: %x\n"
				"  key_id2: %x\n"
				,
				in_data->xts_or_gcm.xts.data_unit_len,
				in_data->xts_or_gcm.xts.key_id1,
				in_data->xts_or_gcm.xts.key_id2
				);
	} else {
		AZIHSM_LOG_INFO("Unknown cpiher!?!?!?!");
	}
}

void
dump_aes_out_data(struct aes_ioctl_outdata *out_data)
{
	u8 *cmd_spec,*iv;

	cmd_spec=out_data->cmd_spec;
	iv=out_data->iv_from_fw;
	AZIHSM_LOG_INFO("AES OUTDATA: 0x%p\n"
			"result: %d\n"
			"cmd_spec: %02x%02x%02x%02x%02x%02x%02x%02x"
			          "%02x%02x%02x%02x%02x%02x%02x%02x\n"
			"byte_count: %d\n"
			"extended_status: %d\n"
			"fips_approved: %d\n"
			"iv_from_fw: %02x%02x%02x%02x%02x%02x%02x%02x"
			            "%02x%02x%02x%02x\n"
			,
			out_data,
			out_data->result,
			cmd_spec[0], cmd_spec[1], cmd_spec[2], cmd_spec[3],
			cmd_spec[4], cmd_spec[5], cmd_spec[6], cmd_spec[7],
			cmd_spec[8], cmd_spec[9], cmd_spec[10], cmd_spec[11],
			cmd_spec[12], cmd_spec[13], cmd_spec[14], cmd_spec[15],
			out_data->byte_count,
			out_data->extended_status,
			out_data->fips_approved,
			iv[0], iv[1], iv[2], iv[3], iv[4], iv[5], iv[6], iv[7],
			iv[8], iv[9], iv[10], iv[11]
			);
}

void
dump_aes_cmd_sqe(struct azihsm_aes_cmd *cmd)
{
	u8 *iv,*tag;
	/* sqe */
	AZIHSM_LOG_INFO("AES SQE: 0x%p\n"
			"attr: opc=%u psdt=%u cmd_type=%u cipher=%u dul=%u\n"
			"cmd_id %u\n"
			"session_id %u\n"
			"short_app_id %u\n"
			"sgl src_data: %u @ 0x%llx\n"
			"sgl dst_data: %u @ 0x%llx\n"
			"frame_type %u\n"
			,
			&cmd->sqe,
			cmd->sqe.attr.cmd_opc,
			cmd->sqe.attr.psdt,
			cmd->sqe.attr.cmd_type,
			cmd->sqe.attr.cipher,
			cmd->sqe.attr.dul,
			cmd->sqe.cmd_id,
			cmd->sqe.session_id,
			cmd->sqe.short_app_id,
			cmd->sqe.src_data.len,
			cmd->sqe.src_data.dptr.sgl.sgl_desc.addr,
			cmd->sqe.dst_data.len,
			cmd->sqe.dst_data.dptr.sgl.sgl_desc.addr,
			cmd->sqe.frame_type
		     );
	if( cmd->sqe.attr.cipher == AZIHSM_AES_CIPHER_GCM ) {
		iv = cmd->sqe.cmd_spec.u.gcm.iv,
		tag = cmd->sqe.cmd_spec.u.gcm.tag;
		AZIHSM_LOG_INFO("SQE GCM:\n"
			"key_id: %d\n"
			"actual_aad_len: %d\n"
			"  tag: %02x%02x%02x%02x%02x%02x%02x%02x"
			               "%02x%02x%02x%02x%02x%02x%02x%02x\n"
			"  init_vector: %02x%02x%02x%02x%02x%02x%02x%02x"
			               "%02x%02x%02x%02x%02x\n"
			"aligned_aad_len: %d\n"
			"unaligned_src_data_len: %d\n"
			"unaligned_dst_data_len: %d\n"
			"unaligned_src_data_addr: 0x%016x%016x\n"
			"unaligned_dst_data_addr: 0x%016x%016x\n"
			,
			cmd->sqe.cmd_spec.u.gcm.key_id,
			cmd->sqe.cmd_spec.u.gcm.actual_aad_len,
			tag[0], tag[1], tag[2], tag[3], tag[4], tag[5], tag[6], tag[7],
			tag[8], tag[9], tag[10], tag[11], tag[12], tag[13], tag[14], tag[15],
			iv[0], iv[1], iv[2], iv[3], iv[4], iv[5], iv[6], iv[7],
			iv[8], iv[9], iv[10], iv[11], iv[12],
			cmd->sqe.cmd_spec.u.gcm.aligned_aad_len,
			cmd->sqe.cmd_spec.u.gcm.unaligned_src_data_len,
			cmd->sqe.cmd_spec.u.gcm.unaligned_dst_data_len,
			cmd->sqe.cmd_spec.u.gcm.unaligned_src_data_addr_high,
			cmd->sqe.cmd_spec.u.gcm.unaligned_src_data_addr_low,
			cmd->sqe.cmd_spec.u.gcm.unaligned_dst_data_addr_high,
			cmd->sqe.cmd_spec.u.gcm.unaligned_dst_data_addr_low
			);
	}
	/* cqe */
	/* dma_io_src */
	/* dma_io_src */
	/* io_data */
}


void
dump_aes_cmd_cqe(struct azihsm_aes_cmd *cmd)
{
	u8 *iv;
	/* sqe */
	/* cqe */
	iv = cmd->cqe.iv_from_fw;
	AZIHSM_LOG_INFO("AES CQE:\n"
			"attr: opc=%u psdt=%u cmd_type=%u cipher=%u dul=%u\n"
			"cmd_id %u\n"
			"iv_from_fw: %02x%02x%02x%02x%02x%02x%02x%02x"
			               "%02x%02x%02x%02x%02x\n"
			"unaligned_dst_data_len %u\n"
			"fips_approved: %u\n"
			"len: %u\n"
			"sq_head: %u\n"
			"sq_id: %u\n"
			"err: %u\n"
			"phase: %u %u\n"
			,
			cmd->cqe.attr.cmd_opc,
			cmd->cqe.attr.psdt,
			cmd->cqe.attr.cmd_type,
			cmd->cqe.attr.cipher,
			cmd->cqe.attr.dul,
			cmd->cqe.cmd_id,
			iv[0], iv[1], iv[2], iv[3], iv[4], iv[5], iv[6], iv[7],
			iv[8], iv[9], iv[10], iv[11], iv[12],
			cmd->cqe.unaligned_dst_data_len,
			cmd->cqe.fips_approved,
			cmd->cqe.len,
			cmd->cqe.sq_head,
			cmd->cqe.sq_id,
			cmd->cqe.err,
			cmd->cqe.ph_sts.ph_sts_bits.phase,
			cmd->cqe.ph_sts.ph_sts_bits.sts
		     );
	/* dma_io_src */
	/* dma_io_src */
	/* io_data */
}

