/* SPDX-License-Identifier: GPL-2.0 */

#ifndef _LINUX_AZIHSM_AES_DEV_IOCTL_H
#define _LINUX_AZIHSM_AES_DEV_IOCTL_H

#include <linux/types.h>
#include <linux/ioctl.h>
#include "azihsm_hsm.h"

#define AZIHSM_AES_TAG_LEN 16
#define AZIHSM_AES_TWEAK_LEN 16
#define AZIHSM_AES_IV_LEN 12
#define AZIHSM_AES_CMD_SPEC_SZ 16

#define AZIHSM_AES_GCM_AAD_SZ_ALIGNMENT_BYTES	32
#define AZIHSM_AES_GCM_DATA_SZ_ALIGNMENT_BYTES	16
#define AZIHSM_MAX_UNALIGNED_DATA_SZ		(AZIHSM_AES_GCM_DATA_SZ_ALIGNMENT_BYTES - 1)
#define AZIHSM_IS_AAD_ALIGNED(_size,_align) (((_size) % (_align)) == 0)

//Define the fast path operation codes here
enum azihsm_aes_op_code {
	AZIHSM_AES_OP_CODE_START = 0,
	AZIHSM_AES_OP_ENCRYPT = AZIHSM_AES_OP_CODE_START,
	AZIHSM_AES_OP_DECRYPT = 1,
	AZIHSM_AES_OP_CODE_END = AZIHSM_AES_OP_DECRYPT
};

#define AZIHSM_AES_OP_CODE_VALID(_x) \
	((_x >= AZIHSM_AES_OP_CODE_START) && (_x <= AZIHSM_AES_OP_CODE_END))

enum azihsm_aes_cipher {
	AZIHSM_AES_CIPHER_START = 0,
	AZIHSM_AES_CIPHER_GCM = AZIHSM_AES_CIPHER_START,
	AZIHSM_AES_CIPHER_XTS = 1,
	AZIHSM_AES_CIPHER_END = AZIHSM_AES_CIPHER_XTS
};

#define AZIHSM_AES_CIPHER_VALID(_x) \
	((_x >= AZIHSM_AES_CIPHER_START) && (_x <= AZIHSM_AES_CIPHER_END))

enum azihsm_aes_frame_type { AZIHSM_AES_FRAME_TYPE_AES = 1 };

#define AZIHSM_AES_FRAME_TYPE_VALID(_x) (_x == AZIHSM_AES_FRAME_TYPE_AES)

struct aes_ioctl_header {
	u32 sz_ioc_data;
	u32 app_cmd_id;
	u32 time_out;
	u32 flags;
};

struct aes_ioctl_user_buffer {
	void *src_ptr;
	u32 src_len;
	void *dst_ptr;
	u32 dst_len;
};

enum aes_xts_data_unit {
	AZIHSM_AES_DUL_START = 0,
	AZIHSM_AES_DUL_FULL = AZIHSM_AES_DUL_START, /**< Full transfer size */
	AZIHSM_AES_DUL_SIZE_512 = 1, /**< 512 bytes size */
	AZIHSM_AES_DUL_SIZE_4096 = 2, /**< 4096 bytes size */
	AZIHSM_AES_DUL_SIZE_8192 = 3, /**< 8192 bytes size */
	AZIHSM_AES_DUL_END = AZIHSM_AES_DUL_SIZE_8192
};

#define AZIHSM_AES_DUL_VALID(_x) \
	((_x >= AZIHSM_AES_DUL_START) && (_x <= AZIHSM_AES_DUL_END))

struct gcm_params {
	u32 key_id;				/**< key identifier to use for the GCM operation **/
	u8 tag[AZIHSM_AES_TAG_LEN];		/**< Tag Buffer Returned On Encryption*/
	u8 init_vector[AZIHSM_AES_IV_LEN];	/**< Initialization vector */
	u32 actual_aad_data_len;		/**< Actual Additional length|Excluding Padding */
	u32 aligned_aad_len;			/**< Total Aad length|Including Padding */
	u8 enable_gcm_workaround;		/**< New version of Application, Aligned AAD*/
	u8 resvd1[3];				/**< 4 Byte Alignment*/
};

static_assert(sizeof(struct gcm_params) == 44);

struct xts_params {
	u16 data_unit_len; /**< Type aes_xts_data_unit >*/
	u16 rsvd;
	u32 key_id1; /**< Key ID 1*/
	u32 key_id2; /**< Key ID 2*/
	u8 tweak[AZIHSM_AES_TWEAK_LEN]; /**< Tweak */
};

static_assert(sizeof(struct xts_params) == 28);

struct aes_ioctl_indata {
	__u64 ctxt;
	u8 op_code;
	u8 cipher;
	u16 rsvd1;
	struct aes_ioctl_user_buffer UserBuff;
	u8 frame_type;
	u16 session_id;
	u8 short_app_id;
	union {
		struct xts_params xts;
		struct gcm_params gcm;
	} xts_or_gcm;

	u32 rsvd[30];
};

static_assert(sizeof(struct aes_ioctl_indata) == 224);

/*
 * struct aes_ioctl_outdata
 * Output buffer whose contents are filled
 * by the driver upon completion of an ioctl
 *
 * ctxt --> Echoed back by driver from input buffer
 * result -> Value returned from device upon completion of command
 * cmd_spec --> command specific contents
 * extended_status ---> Filled up by driver to provide additional
 *   failure if ioctl fails
 *   If the return value from ioctl is failure, applications should
 *   inspect this field to retrieve from information about failure
 */
struct aes_ioctl_outdata {
	__u64 ctxt;
	u32 result;
	u8 cmd_spec[AZIHSM_AES_CMD_SPEC_SZ];
	u32 byte_count;
	u32 extended_status;
	bool fips_approved;
	u8 rsvd[3];
	u8 iv_from_fw[AZIHSM_AES_IV_LEN];
	u32 rsvd1[26];
};

struct aes_ioctl_inout_data {
	struct aes_ioctl_header ioctl_header;
	struct aes_ioctl_indata in_data;
	struct aes_ioctl_outdata out_data;
};

/*
 * fast path ioctls share the same address space
 * as the slow path ioctls. The fast path ioctls
 * start at an offset of 0xB.
 *
 * AZIHSM_AES_DEV_IOCTL_CMD_XTS ===> ioctl code for xts
 *  encryption and decryption
 *
 * AZIHSM_AES_DEV_IOCTL_CMD_GCM ===> ioctl code for gcm
 *  encryption and decryption
 */
#define AZIHSM_AES_DEV_IOCTL_CMD_XTS \
	_IOWR('B', 0xB, struct aes_ioctl_inout_data)
#define AZIHSM_AES_DEV_IOCTL_CMD_GCM \
	_IOWR('B', 0xC, struct aes_ioctl_inout_data)

int azihsm_aes_dev_ioctl(struct azihsm_hsm_fd_ctxt *ctxt,
			 struct azihsm_aes *aes, unsigned long arg,
			 unsigned int ioctl_code);

void dump_aes_in_data(struct aes_ioctl_indata *in);
void dump_aes_out_data(struct aes_ioctl_outdata *out);

#endif //_LINUX_AZIHSM_AES_DEV_IOCTL_H
