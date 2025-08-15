/* SPDX-License-Identifier: GPL-2.0 */
#ifndef _LINUX_AZIHSM_HSM_CMD_H
#define _LINUX_AZIHSM_HSM_CMD_H

#include <linux/kernel.h>
#include <linux/completion.h>

#define AZIHSM_HSM_CMD_CQE_SIZE 16
#define AZIHSM_HSM_CMD_SQE_SIZE 64
#define AZIHSM_HSM_CMD_AES_KEY_LEN 32

#define AZIHSM_HSM_CMD_GENERIC_SQE_SIZE 64
#define AZIHSM_HSM_CMD_GENERIC_CQE_SIZE 16

#define AZIHSM_HSM_SQE_SESSION_VERSION 1
#define AZIHSM_HSM_SQE_NO_SESSION_VERSION 0

#define AZIHSM_HSM_CQE_SESSION_VERSION 1
#define AZIHSM_HSM_CQE_NO_SESSION_VERSION 0

#define AZIHSM_HSM_NORMAL_CMD_OPCODE 0
#define AZIHSM_HSM_FLUSH_SESSION_OPCODE 1

union azihsm_hsm_cmd_sqe_dptr {
	u8 val[16];
	struct {
		u64 fst;
		u64 snd;
	} prp;
};

/*
 * struct azihsm_hsm_session_ctrl_flags
 * 1 byte structure for encoding session information
 *  in sqe and cqe
 *
 * opcode :- indicates the flow (open, close, in session or not)
 *  The encoding for no session provides backwards compatibility
 * in_session_cmd :- If 1, indicates that the session id is valid
 *          In a SQE, this bit indicates that the session_id field
 *          is defined (Used with close session and in session)
 *
 *          In a CQE, this bit indicates that the session_id field
 *          is defined ()
 * short_app_id_is_valid :-
 *    If 1, indicates that a short app id is present in the CQE.
 *    This is returned by the device on a successful open app session
 *         command completion.
 *    This field is only valid in the flags embedded in the CQE
 *
 * safe_to_close_session
 *    When this bit is 1 in a CQE, the session can be closed.
 *    This bit is relevant in CQE even when the CQE status indicates
 *    failure
 */
struct __packed azihsm_hsm_session_ctrl_flags {
	u8 opcode : 2;
	u8 in_session_cmd : 1;
	u8 short_app_id_is_valid : 1;
	u8 safe_to_close_session : 1;
	u8 rsvd : 3;
};

static_assert(sizeof(struct azihsm_hsm_session_ctrl_flags) == 1);

union __packed azihsm_hsm_generic_cmd_sqe_src_data {
	struct _azihsm_hsm_sqe_session {
		struct azihsm_hsm_session_ctrl_flags session_ctrl_flags;
		u8 rsvd_1[3];
		u16 session_id;
		u8 rsvd_2[14];
	} session_data;

	u8 val[20];
};

/*
 * azihsm_hsm_cmd_generic_sqe
 * SQE sent over the HSM queues have the following format.
 *  To deal with different versions of driver and device,
 *  a versioning scheme is introduced.
 *
 * ver == 0 refers to the current sqe format where no
 * session information is encoded into the src data field
 * of the sqe (All 0s)
 *
 * ver == 1 refers to the next version of the sqe format where
 * session information is encoded into the src data field of
 * the sqe (contains opcode, session id)
 */
struct __packed azihsm_hsm_cmd_generic_sqe {
	u32 opc : 10;
	u32 set : 4;
	u32 psdt : 2;
	u32 cid : 16;
	u32 src_len;
	union azihsm_hsm_cmd_sqe_dptr src;
	u32 dst_len;
	union azihsm_hsm_cmd_sqe_dptr dst;
	union azihsm_hsm_generic_cmd_sqe_src_data src_data;
};

static_assert(sizeof(struct azihsm_hsm_cmd_generic_sqe) ==
	      AZIHSM_HSM_CMD_GENERIC_SQE_SIZE);

union __packed azihsm_hsm_generic_cmd_cqe_data {
	struct _azihsm_hsm_cqe_session {
		u16 byte_count;
		struct azihsm_hsm_session_ctrl_flags session_ctrl_flags;
		u8 rsvd_1;
		u16 session_id;
		u8 short_app_id;
		u8 rsvd_2;
	} session_data;

	u8 val[8];
};
/*
 * azihsm_hsm_cmd_generic_cqe
 * CQE for HSM related completions
 */
struct __packed azihsm_hsm_cmd_generic_cqe {
	union azihsm_hsm_generic_cmd_cqe_data cqe_data;
	u16 sqhd;
	u16 sqid;
	u16 cid;
	union {
		u16 val;
		struct {
			u16 p : 1;
			u16 sc : 11;
			u16 rsvd_2 : 4;
		} fld;
	} psf;
};

static_assert(sizeof(struct azihsm_hsm_cmd_generic_cqe) ==
	      AZIHSM_HSM_CMD_GENERIC_CQE_SIZE);

struct azihsm_hsm_generic_cmd {
	struct azihsm_hsm_cmd_generic_sqe sqe;
	struct azihsm_hsm_cmd_generic_cqe cqe;
	unsigned int io_data;
	struct completion cmpl;

	/*
	 * completion_status
	 * Indicates either normal completion by
	 * device or completion due to command being
	 * aborted
	 */
	int completion_status;
	int tag;
};

#endif // _LINUX_AZIHSM_HSM_CMD_H
