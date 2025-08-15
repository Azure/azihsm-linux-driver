/* SPDX-License-Identifier: GPL-2.0 */

#ifndef _LINUX_AZIHSM_CTRL_CMD_H
#define _LINUX_AZIHSM_CTRL_CMD_H

#include <linux/kernel.h>
#include <linux/completion.h>
#include "azihsm_ioq.h"

#define AZIHSM_CTRL_CMD_CQE_SIZE 16
#define AZIHSM_CTRL_CMD_SQE_SIZE 64

struct azihsm_ctrl;
struct azihsm_ioq;

union azihsm_ctrl_cmd_cqe_cs {
	u32 val;
	struct {
		u16 sq : 16;
		u16 cq : 16;
	} queue_cnt;
};

struct azihsm_ctrl_cmd_cqe {
	union azihsm_ctrl_cmd_cqe_cs cs;
	u32 rsvd;
	u16 sqhd;
	u16 sqid;
	u16 cid;
	union {
		u16 val;
		struct {
			u16 p : 1;
			u16 sc : 11;
			u16 rsvd : 4;
		} fld;
	} psf;
};
static_assert(sizeof(struct azihsm_ctrl_cmd_cqe) == AZIHSM_CTRL_CMD_CQE_SIZE);

struct azihsm_ctrl_cmd_sqe_hdr {
	u8 opc;
	u8 rsvd1 : 6;
	u8 psdt : 2;
	u16 cid;
	u32 rsvd2[3];
	u64 mptr;
	union {
		u8 val[16];
		struct {
			u64 fst;
			u64 snd;
		} prp;
	} dptr;
};

struct azihsm_ctrl_cmd_sqe_any {
	struct azihsm_ctrl_cmd_sqe_hdr hdr;
	u32 dw10;
	u32 dw11;
	u32 dw12;
	u32 dw13;
	u32 dw14;
	u32 dw15;
};

static_assert(sizeof(struct azihsm_ctrl_cmd_sqe_any) ==
	      AZIHSM_CTRL_CMD_SQE_SIZE);

struct azihsm_ctrl_cmd_sqe_delete_cq {
	struct azihsm_ctrl_cmd_sqe_hdr hdr;
	u16 id;
	u8 rsvd[22];
};

static_assert(sizeof(struct azihsm_ctrl_cmd_sqe_delete_cq) ==
	      AZIHSM_CTRL_CMD_SQE_SIZE);

struct azihsm_ctrl_cmd_sqe_create_cq {
	struct azihsm_ctrl_cmd_sqe_hdr hdr;
	u32 id : 16;
	u32 size : 16;
	u32 pc : 1;
	u32 ien : 1;
	u32 rsvd1 : 14;
	u32 ivec : 16;
	u32 rsvd2[4];
};

static_assert(sizeof(struct azihsm_ctrl_cmd_sqe_create_cq) ==
	      AZIHSM_CTRL_CMD_SQE_SIZE);

struct azihsm_ctrl_cmd_sqe_delete_sq {
	struct azihsm_ctrl_cmd_sqe_hdr hdr;
	u16 id;
	u8 rsvd[22];
};

static_assert(sizeof(struct azihsm_ctrl_cmd_sqe_delete_sq) ==
	      AZIHSM_CTRL_CMD_SQE_SIZE);

struct azihsm_ctrl_cmd_sqe_create_sq {
	struct azihsm_ctrl_cmd_sqe_hdr hdr;
	u32 id : 16;
	u32 size : 16;
	u32 pc : 1;
	u32 qprio : 2;
	u32 rsvd1 : 13;
	u32 cqid : 16;
	u32 rsvd2[4];
};

static_assert(sizeof(struct azihsm_ctrl_cmd_sqe_create_cq) ==
	      AZIHSM_CTRL_CMD_SQE_SIZE);

struct azihsm_ctrl_cmd_sqe_ident {
	struct azihsm_ctrl_cmd_sqe_hdr hdr;
	u32 cns : 8;
	u32 rsvd1 : 8;
	u32 ctrl_id : 16;
	u32 rsvd2[5];
};

static_assert(sizeof(struct azihsm_ctrl_cmd_sqe_ident) ==
	      AZIHSM_CTRL_CMD_SQE_SIZE);

struct azihsm_ctrl_cmd_sqe_abort {
	struct azihsm_ctrl_cmd_sqe_hdr hdr;
	u32 sqid : 16;
	u32 cid : 16;
	u32 rsvd[5];
};

static_assert(sizeof(struct azihsm_ctrl_cmd_sqe_abort) ==
	      AZIHSM_CTRL_CMD_SQE_SIZE);

union azihsm_ctrl_cmd_feat_data {
	u32 val;
	struct {
		u16 sq_cnt;
		u16 cq_cnt;
	} queue_cnt;
};

static_assert(sizeof(union azihsm_ctrl_cmd_feat_data) == 4);

struct azihsm_ctrl_cmd_sqe_set_feat {
	struct azihsm_ctrl_cmd_sqe_hdr hdr;
	u32 feat_id : 8;
	u32 rsvd1 : 24;
	union azihsm_ctrl_cmd_feat_data data;
	u32 rsvd2[4];
};

static_assert(sizeof(struct azihsm_ctrl_cmd_sqe_set_feat) ==
	      AZIHSM_CTRL_CMD_SQE_SIZE);

struct azihsm_ctrl_cmd_sqe_get_feat {
	struct azihsm_ctrl_cmd_sqe_hdr hdr;
	u32 feat_id : 8;
	u8 rsvd1[23];
};

static_assert(sizeof(struct azihsm_ctrl_cmd_sqe_get_feat) ==
	      AZIHSM_CTRL_CMD_SQE_SIZE);

struct azihsm_ctrl_cmd_sqe_set_res_cnt {
	struct azihsm_ctrl_cmd_sqe_hdr hdr;
	u32 ctrl_id;
	u32 cnt;
	u8 rsvd2[16];
};

static_assert(sizeof(struct azihsm_ctrl_cmd_sqe_set_res_cnt) ==
	      AZIHSM_CTRL_CMD_SQE_SIZE);

union azihsm_ctrl_cmd_sqe {
	struct azihsm_ctrl_cmd_sqe_any any;
	struct azihsm_ctrl_cmd_sqe_delete_cq delete_cq;
	struct azihsm_ctrl_cmd_sqe_create_cq create_cq;
	struct azihsm_ctrl_cmd_sqe_delete_sq delete_sq;
	struct azihsm_ctrl_cmd_sqe_create_sq create_sq;
	struct azihsm_ctrl_cmd_sqe_ident ident;
	struct azihsm_ctrl_cmd_sqe_abort abort;
	struct azihsm_ctrl_cmd_sqe_set_feat set_feat;
	struct azihsm_ctrl_cmd_sqe_get_feat get_feat;
	struct azihsm_ctrl_cmd_sqe_set_res_cnt set_res_cnt;
};

static_assert(sizeof(union azihsm_ctrl_cmd_sqe) == AZIHSM_CTRL_CMD_SQE_SIZE);

struct azihsm_ctrl_cmd {
	union azihsm_ctrl_cmd_sqe sqe;
	struct azihsm_ctrl_cmd_cqe cqe;
	unsigned int io_data;
	struct completion cmpl;
	int completion_status;
};

struct azihsm_ctrl_cmd_ctrl_res {
	u32 rt : 3;
	u32 rsvd1 : 13;
	u32 ctrl_id : 16;
	u32 cnt : 16;
	u8 rsvd_vs[4090];
};

static_assert(sizeof(struct azihsm_ctrl_cmd_ctrl_res) == 4096);

enum azihsm_ctrl_cmd_op {
	AZIHSM_CTRL_CMD_OP_DELETE_SQ = 0x00,
	AZIHSM_CTRL_CMD_OP_CREATE_SQ = 0x01,
	AZIHSM_CTRL_CMD_OP_DELETE_CQ = 0x04,
	AZIHSM_CTRL_CMD_OP_CREATE_CQ = 0x05,
	AZIHSM_CTRL_CMD_OP_IDENT = 0x06,
	AZIHSM_CTRL_CMD_OP_ABORT = 0x08,
	AZIHSM_CTRL_CMD_OP_SET_FEAT = 0x09,
	AZIHSM_CTRL_CMD_OP_GET_FEAT = 0x0A,
	AZIHSM_CTRL_CMD_OP_SET_RES_CNT = 0xC3,
	AZIHSM_CTRL_CMD_OP_GET_RES_CNT = 0xC4
};

enum azihsm_ctrl_cmd_cns {
	AZIHSM_CTRL_CMD_CNS_CTRL = 0x01,
	AZIHSM_CTRL_CMD_CNS_CTRL_RES = 0xC0,
};

enum azihsm_ctrl_cmd_feat_id {
	AZIHSM_CTRL_CMD_FEAT_ID_HSM_QUEUE_CNT = 0x07,
	AZIHSM_CTRL_CMD_FEAT_ID_AES_QUEUE_CNT = 0xC1,
};

int azihsm_ctrl_cmd_ident(struct azihsm_ctrl *ctrl, dma_addr_t prp1);

int azihsm_ctrl_cmd_set_feat(struct azihsm_ctrl *ctrl, u32 feat_id,
			     union azihsm_ctrl_cmd_feat_data data);

int azihsm_ctrl_cmd_get_feat(struct azihsm_ctrl *ctrl, u32 feat_id,
			     union azihsm_ctrl_cmd_feat_data *data);

int azihsm_ctrl_cmd_set_res_cnt(struct azihsm_ctrl *ctrl, u16 ctrl_id, u16 cnt);

int azihsm_ctrl_cmd_get_res_cnt(struct azihsm_ctrl *ctrl, u16 ctrl_id,
				u16 *cnt);

int azihsm_ctrl_cmd_set_hsm_queue_cnt(struct azihsm_ctrl *ctrl, u16 *cnt);

int azihsm_ctrl_cmd_set_aes_queue_cnt(struct azihsm_ctrl *ctrl, u16 *cnt);

int azihsm_ctrl_cmd_create_cq(struct azihsm_ctrl *ctrl, dma_addr_t prp1, u16 id,
			      u16 size, u16 vec);

int azihsm_ctrl_cmd_delete_cq(struct azihsm_ctrl *ctrl, u16 id);

int azihsm_ctrl_cmd_create_sq(struct azihsm_ctrl *ctrl, dma_addr_t prp1, u16 id,
			      u16 cq_id, u16 size, enum azihsm_ioq_pri pri);

int azihsm_ctrl_cmd_delete_sq(struct azihsm_ctrl *ctrl, u16 id);

#endif //_LINUX_AZIHSM_CTRL_CMD_H
