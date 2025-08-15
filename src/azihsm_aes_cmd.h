/* SPDX-License-Identifier: GPL-2.0 */
#ifndef _LINUX_AZIHSM_AES_CMDS_H
#define _LINUX_AZIHSM_AES_CMDS_H

#include <linux/kernel.h>
#include <linux/completion.h>
#include "azihsm_aes_dev_ioctl.h"
#include "azihsm_dma_io.h"

enum azihsm_aes_cmd_type { AZIHSM_AES_CMD_TYPE_AES = 5 };

enum azihsm_aes_psdt_type {
	AZIHSM_AES_PSDT_TYPE_PRP = 0,
	AZIHSM_AES_PSDT_TYPE_SGL = 1
};

// Enabled Byte Packing from Here
#pragma pack(push)
#pragma pack(1)

/*
 * This structure defines the command attributes
 * field of the CQE
 */
struct azihsm_aes_cmd_attr {
	u16 cmd_opc : 1; // Operation Code
	u16 rsvd1 : 1;
	u16 psdt : 1; // PRP or SGL enum PSDT_TYPE
	u16 cmd_type : 3; // Command type
	u16 rsvd2 : 2;
	u16 cipher : 1; // Cipher
	u16 rsvd3 : 5;
	u16 dul : 2; // Data Unit len
};

static_assert(sizeof(struct azihsm_aes_cmd_attr) == sizeof(u16));

#define AZIHSM_AES_SGL_DESC_SZ 16

struct azihsm_aes_sgl_desc {
	u64 addr;
	u32 len;
	u8 Rsvd[3];
	u8 desc_sub_type : 4;
	u8 desc_type : 4;
};

static_assert(sizeof(struct azihsm_aes_sgl_desc) == AZIHSM_AES_SGL_DESC_SZ);

#define AZIHSM_AES_SQE_DATA_SZ 20

/*
 * This structure describes the single data transfer parameters
 * for a sgl/prp transfer for the AES path data transfer
 */
struct azihsm_aes_sqe_data {
	u32 len;

	union {
		u64 fst_snd[2];
		struct {
			u64 fst; //First PRP Entry
			u64 snd; //Second PRP Entry
		} prp;

		struct {
			struct azihsm_aes_sgl_desc sgl_desc;
		} sgl;

	} dptr;
};

static_assert(sizeof(struct azihsm_aes_sqe_data) == AZIHSM_AES_SQE_DATA_SZ);

#define AZIHSM_AES_TAG_LEN 16
#define AZIHSM_AES_KEY_LEN 32
#define AZIHSM_AES_IV_LEN 12
#define AZIHSM_AES_TWEAK_LEN 16

#define AZIHSM_AES_SQE_CMD_SPECIFIC_SZ 63

struct azihsm_aes_sqe_cmd_specific {
	union {
		struct {
			u8 rsvd1[3];
			u32 key_id; // Key Identifier
			u32 rsvd2;
			u8 tag[AZIHSM_AES_TAG_LEN]; // AES Tag
			u8 iv[AZIHSM_AES_IV_LEN]; // AES Initialization Vector
			u32 add_data_len; // Additional Data Length
			u32 rsvd3[5];
		} gcm;

		struct {
			u8 rsvd1[3];
			u32 key_id1; // Key Identifier 1
			u32 key_id2; // Key Identifier 2
			u8 tweak[AZIHSM_AES_TWEAK_LEN];
			u32 rsvd2[9];
		} xts;

	} u;
};

static_assert(sizeof(struct azihsm_aes_sqe_cmd_specific) ==
	      AZIHSM_AES_SQE_CMD_SPECIFIC_SZ);

#define AZIHSM_AES_SQE_SZ 128

struct azihsm_aes_sqe {
	u32 rsvd1;
	struct azihsm_aes_cmd_attr attr;
	u16 cmd_id;
	u32 session_id : 16;
	u32 short_app_id : 8;
	u32 rsvd2 : 8;
	u32 rsvd3[3];
	struct azihsm_aes_sqe_data src_data;
	struct azihsm_aes_sqe_data dst_data;
	u8 frame_type; // azihsm_aes_frame_type
	struct azihsm_aes_sqe_cmd_specific cmd_spec;
};

static_assert(sizeof(struct azihsm_aes_sqe) == AZIHSM_AES_SQE_SZ);

#pragma pack(pop)
//Byte packing Disabled. For 64 bit compilers the packing is 8 bytes

#define AZIHSM_AES_CQE_CMD_SPEC_SZ 16

struct azihsm_aes_cqe_cmd_spec {
	union {
		u8 val[16];
		u8 tag[16];
	} u;
};

static_assert(sizeof(struct azihsm_aes_cqe_cmd_spec) ==
	      AZIHSM_AES_CQE_CMD_SPEC_SZ);

#define AZIHSM_AES_CQE_SZ 64

struct azihsm_aes_cqe {
	struct azihsm_aes_cmd_attr attr; /**< Attributes */
	u16 cmd_id; /**< Command ID */
	struct azihsm_aes_cqe_cmd_spec cmd_spec; /**< Command specific data */
	u32 iv_from_fw[3];
	u32 rsvd[5];
	u32 len;
	u16 sq_head; /**< Submission queue head */
	u16 sq_id; /**< Submission queue ID */
	u16 err;
	union {
		u16 ph_sts_val; /**< Phase & Status field value */
		struct {
			u16 phase : 1; /**< Phase */
			u16 sts : 15; /**< Status code */
		} ph_sts_bits;
	} ph_sts;
};

static_assert(sizeof(struct azihsm_aes_cqe) == AZIHSM_AES_CQE_SZ);

struct azihsm_aes_cmd {
	struct azihsm_aes_sqe sqe;
	struct azihsm_aes_cqe cqe;
	struct azihsm_dma_io dma_io_src;
	struct azihsm_dma_io dma_io_dst;
	unsigned int io_data;
	struct completion cmpl;

	/*
	 * Status indicates whether command is
	 * completed normally by device or
	 * completed due to command being aborted
	 */
	int completion_status;

	/*
	 * A tag identifies this context in the
	 * context store where this command is submitted
	 * Initialized to -1 and then to a valid value
	 */
	int tag;
};

void azihsm_aes_cmd_init(struct azihsm_aes_cmd *cmd, const u8 opc,
			 const u8 psdt, const u8 cmd_type, const u8 frame_type,
			 const u8 cipher);

int azihsm_aes_cmd_process(struct azihsm_aes *aes, struct azihsm_aes_cmd *cmd);

#endif // _LINUX_AZIHSM_AES_CMDS_H
