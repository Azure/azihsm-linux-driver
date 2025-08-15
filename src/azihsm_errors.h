/* SPDX-License-Identifier: GPL-2.0 */
#ifndef _LINUX_AZIHSM_ERROR_CODES_H_
#define _LINUX_AZIHSM_ERROR_CODES_H_

enum azihsm_sts_source {
	AZIHSM_STS_SRC_NONE =
		0, // If the IOCTL is malformed and fails even before the function is identified
	AZIHSM_STS_SRC_DEVICE =
		1, // Error code is a device generated error code
	AZIHSM_STS_SRC_CP = 2, // Error code is a CP PATH generated error code
	AZIHSM_STS_SRC_FP = 3, // ERROR code is FP generated error code
	AZIHSM_STS_SRC_ABORT =
		4, // ERROR code is a ABORT path generated error code
};

/*
 * Enumeration for all possible error codes
 * on the fast path ioctl interface
 * Starts at offset 100 to keep it consistent with
 * Windows.
 */
enum AZIHSM_FP_IOCTL_ERROR_STATUS {
	AZIHSM_FP_IOCTL_NO_MEMORY = 100,
	AZIHSM_FP_IOCTL_INVALID_INPUT_BUFFER = 101,
	AZIHSM_FP_IOCTL_INPUT_BUFFER_ACCESS_ERROR = 102,
	AZIHSM_FP_IOCTL_INVALID_OUTPUT_BUFFER = 103,
	AZIHSM_FP_IOCTL_OUTPUT_BUFFER_ACCESS_ERROR = 104,
	AZIHSM_FP_IOCTL_PROCESS_NOT_OWNER_OF_FD = 105,
	AZIHSM_FP_IOCTL_DEVICE_ERROR = 106,
	AZIHSM_FP_IOCTL_SESSION_ID_DOES_NOT_MATCH = 107,
	AZIHSM_FP_IOCTL_SHORTAPP_ID_DOES_NOT_MATCH = 108,
	AZIHSM_FP_IOCTL_NO_VALID_SESSION_ID = 109,
	AZIHSM_FP_IOCTL_NO_VALID_SHORT_APP_ID = 110,
	AZIHSM_FP_IOCTL_DEVICE_NO_FP_QUEUES = 111,
	AZIHSM_FP_IOCTL_INVALID_CIPHER_TYPE = 112,
	AZIHSM_FP_IOCTL_INVALID_FRAME_TYPE = 113,
	AZIHSM_FP_IOCTL_INVALID_OPCODE = 114,
	AZIHSM_FP_IOCTL_INPUT_BUFFER_ABOVE_MAX = 115,
	AZIHSM_FP_IOCTL_OUTPUT_BUFFER_ABOVE_MAX = 116,
	AZIHSM_FP_IOCTL_AES_GCM_IOCTL_VALIDATION_FAILED = 117,
	AZIHSM_FP_IOCTL_AES_XTS_IOCTL_VALIDATION_FAILED = 118,
};

enum AZIHSM_CP_GENERIC_IOCTL_ERROR_STATUS {
	AZIHSM_CP_GENERIC_IOCTL_NO_MEMORY = 1,
	AZIHSM_CP_GENERIC_IOCTL_INVALID_CMDSET = 2,
	AZIHSM_CP_GENERIC_IOCTL_INPUT_BUFFER_ABOVE_8K = 3,
	AZIHSM_CP_GENERIC_IOCTL_OUTPUT_BUFFER_ABOVE_8K = 4,
	AZIHSM_CP_GENERIC_IOCTL_INVALID_INPUT_BUFFER = 5,
	AZIHSM_CP_GENERIC_IOCTL_INPUT_BUFFER_ACCESS_ERROR = 6,
	AZIHSM_CP_GENERIC_IOCTL_INVALID_OUTPUT_BUFFER = 7,
	AZIHSM_CP_GENERIC_IOCTL_OUTPUT_BUFFER_ACCESS_ERROR = 8,
	AZIHSM_CP_GENERIC_IOCTL_PROCESS_NOT_OWNER_OF_FD = 9,
	AZIHSM_CP_GENERIC_IOCTL_DEVICE_ERROR = 10,
	AZIHSM_CP_GENERIC_IOCTL_OPEN_SESSION_SESSION_LIMIT_REACHED = 11,
	AZIHSM_CP_GENERIC_IOCTL_NO_EXISTING_SESSION = 12,
	AZIHSM_CP_GENERIC_IOCTL_INVALID_SESSION_OPCODE = 13,
	AZIHSM_CP_GENERIC_IOCTL_SESSION_ID_MISMATCH = 14,

	/*
	 * This status code indicates that the command could not
	 * be submitted to the device because either all queues are
	 * full or all devices are disabled
	 * Normally these conditions are transient and expected to clear
	 * up. The application can choose to wait for some time and resubmit
	 * the same command
	 */
	AZIHSM_CP_GENERIC_IOCTL_RETRY_CMD = 15,
};

enum AZIHSM_ABORT_IOCTL_ERROR_STATUS {
	AZIHSM_ABORT_IN_PROGRESS = 1,
	AZIHSM_ABORT_CMD_ABORTED = 2,
};

/*
 * This macro returns a 32 bit error code which is upper 8-bits is the
 * Source Of The Status code and the lower 24 bits is the actual code.
 * A SOURCE from where the error code is generated.
 * Note: We are just using this for ABORT path right now.
 * To Do :- We will cleanup the error codes in all the paths step by step
 * as all the test cases will need to be updated.
 */
#define GENERATE_STATUS_CODE(_sts_src, _sts) (((_sts_src) << 24) | (_sts))

#endif
