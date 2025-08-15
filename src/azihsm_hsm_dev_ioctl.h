/* SPDX-License-Identifier: GPL-2.0 */

#ifndef _LINUX_AZIHSM_HSM_DEV_IOCTL_H
#define _LINUX_AZIHSM_HSM_DEV_IOCTL_H

#include <linux/types.h>
#include <linux/ioctl.h>
#include "azihsm_ctrl_dev_ioctl.h"

enum CP_CMD_SET { CP_CMD_SESSION_GENERIC = 0x0 };

#define AZIHSM_OPCODE_FLOW_NO_SESSION 0
#define AZIHSM_OPCODE_FLOW_OPEN_SESSION 1
#define AZIHSM_OPCODE_FLOW_CLOSE_SESSION 2
#define AZIHSM_OPCODE_FLOW_IN_SESSION 3

#define AZIHSM_IOCTL_OPCODE_SESSION_VALID(_op_code)        \
	((_op_code == AZIHSM_OPCODE_FLOW_NO_SESSION) ||    \
	 (_op_code == AZIHSM_OPCODE_FLOW_OPEN_SESSION) ||  \
	 (_op_code == AZIHSM_OPCODE_FLOW_CLOSE_SESSION) || \
	 (_op_code == AZIHSM_OPCODE_FLOW_IN_SESSION))

/*
 * struct azihsm_ioctl_header
 * All ioctls must have the following header at offset 0
 * szioctldata -> Has the length of the full ioctl
 * appcmdid --> User specific context that is echoed back in the output buffer
 * timeout ---> timeout specified (Usage depends on ioctl)
 * flags ---> Undefined at this time (always 0)
 */

struct azihsm_ioctl_header {
	__u32 szioctldata; //Total Size of the input and output data
	__u32 appcmdid;
	__u32 timeout;
	__u32 flags;
};

union SessionControlFlags {
	struct _flags {
		/// opcode carried in the sqe
		/// specifies whether the opcode
		/// is of type open, close, in or
		/// none
		__u8 opcode : 2;

		/// valid_session_id
		/// When set to true, this indicates
		/// that the session id in the SQE is
		/// defined.
		__u8 session_id_is_valid : 1;
		__u8 rsvd : 5;
	} u;

	__u8 val;
};

/*
 * definitions for the new ioctl buffer
 * Encompass the functionality in the new
 * SQE and CQE formats.
 * Ioctl buffer with 2 8K buffers cannot be
 * allocated on the stack
 *  So pass pointers to source and destination
 *  buffers
 *
 *  azihsm_cp_generic_ioctl_indata and
 *  azihsm_cp_generic_ioctl_indata are input and output
 *  buffers for the ioctl for sending commands to the device
 *  without session validation support.
 *  Same input and output structures are used for both legacy
 *  and session ioctls.
 */

struct azihsm_cp_generic_ioctl_indata {
	__u64 ctxt;
	__u16 opc;
	__u16 cmdset;
	__u8 psdt;

	__u32 src_length;
	__u8 *src_buf;
	__u32 dst_length;
	__u8 *dst_buf;
	union {
		__u8 val[20];
		struct {
			__u16 key_id;
			__u8 rsvd[18];
		} key;

		struct {
			union SessionControlFlags session_control_flags;
			__u8 rsvd1;
			__u16 session_id;
			__u8 rsvd2[16];
		} session_data;
	} u;
};

/*
 * azihsm_cp_generic_ioctl_outdata
 * Contains output data returned by the driver upon
 * completion of a ioctl.
 *
 * ctxt: Application defined context that is provided
 *  in the input buffer that is echoed by the driver back
 *  in the output buffer. THis allows the application to
 *  associate a request with its completion
 *
 *  status: This contains status for the execution of the
 *     command on the device. This is Lion device specific.
 *     A value of zero implies success. All other values indicate
 *     failure.
 *
 *  byte_count. Indicates the number of bytes returned by the device
 *    in the user buffers (provided in the input buffer).
 *    The meaning of this field is defined by the application.
 *
 *  ioctl_extended_status.
 *    Used to return specific error values by the driver in case
 *    a ioctl fails. This field is defined only if the ioctl has failed.
 *    For example driver is not able to allocate memory or driver has
 *    triggered session specific failures. Please refer to
 *    AZIHSM_CP_GENERIC_IOCTL_ERROR_STATUS codes for all possible values.
 *    A value of 0 means success
 */

struct azihsm_cp_generic_ioctl_outdata {
	__u64 ctxt;
	__u32 status;
	union {
		__u8 val[8];
		struct {
			__u16 key_id;
			__u16 rsvd_1;
			__u32 rsvd_2;
		} key;

		struct {
			__u32 byte_count;
			__u32 ioctl_extended_status;
		} generic;
	} u;
};

struct azihsm_cp_generic_cmd {
	struct azihsm_ioctl_header hdr;
	struct azihsm_cp_generic_ioctl_indata in;
	struct azihsm_cp_generic_ioctl_outdata out;
};

/*AZIHSM_CTRL_PATH_GENERIC_IOCTL
 * Legacy ioctl for HSM commands over the HSM channel
 * This ioctl can be used when session data is not sent over the
 * channel.
 * This ioctl uses the azihsm_cp_generic_cmd for the ioctl buffer
 */
#define AZIHSM_CTRL_PATH_GENERIC_IOCTL \
	_IOWR('B', 0x2, struct azihsm_cp_generic_cmd)

/*AZIHSM_CTRL_PATH_GENERIC_IOCTL_SESSION
 * This ioctl also uses the azihsm_cp_generic_cmd for the ioctl buffer
 * Session aware ioctl that allows caller to pass session opcode
 * and session id as part of the command to the device
 * Please refer to the design document for session handling
 */
#define AZIHSM_CTRL_PATH_GENERIC_IOCTL_SESSION \
	_IOWR('B', 0x3, struct azihsm_cp_generic_cmd)

/*
 * ioctl :- AZIHSM_GET_DEV_INFO_IOCTL
 * This ioctl is used to query device information.
 * This is available on the hsm interface
 */
#define AZIHSM_GET_DEV_INFO_IOCTL _IOWR('B', 0x4, struct azihsm_ctrl_dev_info)

#ifdef TEST_HOOK_SUPPORT
struct azihsm_ctrl_test_hook_data {
	u32 abort_in_prog; // Is Abort In Progress
	u32 lvl1_abort_cnt; /* Number Of Times Leve1-1 Abort Has Happened*/
	u32 lvl2_abort_cnt; /* Number Of Times Level-2 Abort Has Happened*/
	u64 proc_not_own_fd; /* Driver detected Owning Process Is NOT Firing IOCTL */
	u64 session_flush_cnt; /* Number Of Times Driver Issues Flush Session (On FD Close)*/
	u64 close_non_own_proc_cnt; /* Number Of Times FD Closed By Process Not Owning The FD*/
};

/*
 * ioctl :- AZIHSM_GET_DRIVER_TEST_HOOK_DATA
 * This ioctl is used to query the driver test hooks data
 * Only available when TEST_HOOK_SUPPORT Flag is defined
 */
#define AZIHSM_GET_DRIVER_TEST_HOOK_DATA \
	_IOWR('B', 0x5, struct azihsm_ctrl_test_hook_data)
#endif //TEST_HOOK_SUPPORT

typedef enum {
	ABORT_TYPE_RESERVED = 0, // RESERVED For Driver Use
	ABORT_TYPE_APP_L2_CTRL_NSSR =
		1, // Application Initiated L2 Abort With NSSR
	ABORT_TYPE_APP_L2_CTRL_RESET =
		2, // Application Initiated L2 Abort With CTRL Disable and enable
	ABORT_TYPE_MAX = ABORT_TYPE_APP_L2_CTRL_RESET + 1,
} abort_type;

typedef enum {
	ABORT_STATUS_SUCCESS = 0, // Abort Successful
	ABORT_STATUS_ALREADY_IN_PROGRESS = 1, // Abort Already Done
	ABORT_STATUS_INVALID_DEVICE_STATE =
		2, // Device is not in the state to perform abort
	ABORT_STATUS_FAILED = 3, // Abort Failed
	ABORT_STATUS_INVALID_TYPE = 4, // Invalid Abort Type
	ABORT_STATUS_TIMED_OUT =
		5, // Driver could not complete the abort in time
	ABORT_STATUS_NOT_SUPPORTED = 6, // Abort Not Supported
} abort_status;

struct reset_device_ioctl_indata {
	u32 abort_type;
	u32 rsvd[20];
};

struct reset_device_ioctl_outdata {
	u32 abort_sts;
	u32 rsvd[20];
};

struct reset_device_data {
	struct azihsm_ioctl_header hdr;
	u64 ctxt;
	struct reset_device_ioctl_indata rst_in_data;
	struct reset_device_ioctl_outdata rst_out_data;
	u32 rsvd[20];
};

#define AZIHSM_IOCTL_RESET_DEVICE _IOWR('B', 0x6, struct reset_device_data)

#endif //_LINUX_AZIHSM_HSM_DEV_IOCTL_H
