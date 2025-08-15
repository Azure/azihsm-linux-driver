/* SPDX-License-Identifier: GPL-2.0 */
#ifndef _LINUX_AZIHSM_CTRL_H
#define _LINUX_AZIHSM_CTRL_H

#include <linux/kernel.h>
#include <linux/pci.h>
#include <linux/dmapool.h>
#include <linux/fs.h>
#include <linux/cdev.h>
#include <linux/random.h>

#include "azihsm_ioq.h"
#include "azihsm_hsm.h"
#include "azihsm_aes.h"
#include "azihsm_ctrl_dev_ioctl.h"

#define AZIHSM_CTRL_IDENT_SN_LEN 32
#define AZIHSM_CTRL_IDENT_MN_LEN 4
#define AZIHSM_CTRL_IDENT_FR_LEN 32
#define AZIHSM_CTRL_DEV_DRV_REV_LEN 32
#define AZIHSM_CTRL_DEV_NAME "azihsm-ctrl"

#define AZIHSM_DEVICE_INFO_ENTROPY_DATA_VALID 0x00000001

#define CP_SQE_SZ_POWOFTWO 6
#define CP_CQE_SZ_POWOFTWO 4
#define FP_SQE_SZ_POWOFTWO 7
#define FP_CQE_SZ_POWOFTWO 6

#define CP_SQE_SZ 64 // Size of Each Slot
#define CP_CQE_SZ 16 // Size of Each Cpl Q Entry
#define FP_SQE_SZ 128 // Size of Each Slot For Submission Queue
#define FP_CQE_SZ 64 // Size of Each Slot For Completion Queue Entry

/* maximum number of level one abort that is done before level 2 abort kicks in */
#define MAX_LVL_ONE_ABORT_COUNT 5

struct azihsm_dev;

union azihsm_ctrl_reg_cap {
	u64 val;
	struct {
		u16 mqes;
		u32 cqr : 1;
		u32 ams : 2;
		u32 rsvd1 : 5;
		u8 to;
		u32 dstrd : 4;
		u32 ssrs : 1;
		u32 css : 8;
		u32 rsvd2 : 3;
		u32 mpsmin : 4;
		u32 mpsmax : 4;
		u8 rsvd;
	} fld;
};

static_assert(sizeof(union azihsm_ctrl_reg_cap) == sizeof(u64));

union azihsm_ctrl_reg_vs {
	u32 val;
	struct {
		u8 ter;
		u8 mnr;
		u16 mjr;
	} fld;
};

static_assert(sizeof(union azihsm_ctrl_reg_vs) == sizeof(u32));

union azihsm_ctrl_reg_cc {
	u32 val;
	struct {
		u32 en : 1;
		u32 rsvd1 : 3;
		u32 css : 3;
		u32 mps : 4;
		u32 ams : 3;
		u32 shn : 2;
		u32 cp_iosqes : 4;
		u32 cp_iocqes : 4;
		u32 fp_iosqes : 4;
		u32 fp_iocqes : 4;
	} fld;
};

static_assert(sizeof(union azihsm_ctrl_reg_cc) == sizeof(u32));

union azihsm_ctrl_reg_csts {
	u32 val;
	struct {
		u32 rdy : 1;
		u32 cfs : 1;
		u32 shst : 2;
		u32 ssro : 1;
		u32 pp : 1;
		u32 rsvd : 26;
	} fld;
};

static_assert(sizeof(union azihsm_ctrl_reg_csts) == sizeof(u32));

union azihsm_ctrl_reg_aqa {
	u32 val;
	struct {
		u16 asqs;
		u16 acqs;
	} fld;
};

static_assert(sizeof(union azihsm_ctrl_reg_aqa) == sizeof(u32));

#define NVME_SS_RESET_SIGNATURE 0x4E564D65
struct __packed azihsm_ctrl_reg {
	union azihsm_ctrl_reg_cap cap;
	union azihsm_ctrl_reg_vs vs;
	u64 rsvd1;
	union azihsm_ctrl_reg_cc cc;
	u32 rsvd2;
	union azihsm_ctrl_reg_csts csts;
	u32 ssr; // Subsystem Reset Register
	union azihsm_ctrl_reg_aqa aqa;
	u64 asq;
	u64 acq;
	u32 rsvd4[1010];
};

static_assert(sizeof(struct azihsm_ctrl_reg) == SZ_4K);

union azihsm_ctrl_ident_qes {
	u8 val;
	struct {
		u8 max : 4;
		u8 min : 4;
	} fld;
};

/**
 * @brief Controller Identity
 *
 */
struct azihsm_ctrl_ident {
	u16 vid;
	u16 ssvid;
	char sn[AZIHSM_CTRL_IDENT_SN_LEN];
	char fr[AZIHSM_CTRL_IDENT_FR_LEN];
	u8 rsvd[4];
	u8 cp_mdts;
	u8 rsvd1;
	u16 ctrl_id;
	u8 acl;
	union azihsm_ctrl_ident_qes cp_sqes;
	union azihsm_ctrl_ident_qes cp_cqes;
	u8 rsvd2;
	u16 cp_maxcmd;
	u8 fp_mdts;
	union azihsm_ctrl_ident_qes fp_sqes;
	union azihsm_ctrl_ident_qes fp_cqes;
	u8 rsvd3;
	u16 fp_maxcmd;
	u16 oacs;
	u16 rsvd4;
	u32 sgls;
	u32 ver;
	u8 ctrl_type;
	u8 frmw;
};

static_assert(sizeof(struct azihsm_ctrl_ident) == 104);

/*
 * AZIHSM_CTRL_STATE
 * This state is used to make sure that we have a proper
 * Initialized state in place before the interrupts are fired.
 * If a controller raises a interrupt while the initialization
 * or the tear down of the contoller is in progress, we will end
 * up in a situation where we will either dereferce a null
 * pointer or access invalid address.
 */
enum AZIHSM_CTRL_STATE {
	CTRL_NOT_INITIALIZED = 0, // Controller is not initialized.
	CTRL_INIT_IN_PROGRESS = 1, // Controller is being initialized
	CTRL_READY = 2, // Controller is ready and will generate interrupts
};

enum _AZIHSM_ABORT_STATE {
	AZIHSM_CONTROLLER_IS_NOT_IN_ABORT = 0, // there is no abort in progress
	AZIHSM_CONTROLLER_ABORT_IS_IN_PROGRESS = 1, // abort is in progress
};

#define AZIHSM_CTRL_ST_RESET(_ctrl) \
	atomic_set(&(_ctrl->state), CTRL_NOT_INITIALIZED)

#define AZIHSM_CTRL_ST_IN_PROGRESS(_ctrl) \
	atomic_set(&_ctrl->state, CTRL_INIT_IN_PROGRESS)

#define AZIHSM_CTRL_ST_READY(_ctrl) atomic_set(&_ctrl->state, CTRL_READY)
#define AZIHSM_CTRL_GET_STATE(_ctrl) (atomic_read(&_ctrl->state))
#define AZIHSM_CTRL_ST_ISRDY(_ctrl) (AZIHSM_CTRL_GET_STATE(_ctrl) == CTRL_READY)

#define AZIHSM_CTRL_GET_ABORT_STATE(ctrl) (atomic_read(&(ctrl)->abort_state))
#define AZIHSM_CTRL_IS_ABORT_IN_PROGRESS(ctrl) \
	(AZIHSM_CTRL_GET_ABORT_STATE(ctrl) ==  \
	 AZIHSM_CONTROLLER_ABORT_IS_IN_PROGRESS)
#define AZIHSM_CTRL_SET_ABORT_STATE(ctrl, state) \
	atomic_set(&ctrl->abort_state, state)

struct azihsm_ctrl_cfg {
	struct pci_dev *pdev;
	void __iomem *ctrl_reg;
	void __iomem *db_reg;
	size_t irq_cnt;
	bool is_pf;
};

/*
 * This is a health monitor to detect if the controller
 * has crashed. Once the crash is detected the timer will
 * schedule a work item to handle the crash recovery.
 * The Crash recovery needs to be performed in context
 * of a process. We will need to use a work item
 * so that we can acquire the mutex to handle aborts etc.
 *
 */
struct azihsm_health_mon {
	struct delayed_work hmon_work;
	void *ctrl; // The context to be used in work function.
	bool init_done; // If the structure is initialized or not
};

struct azihsm_ctrl {
	struct pci_dev *pdev;
	struct azihsm_ctrl_reg __iomem *reg;
	void __iomem *db_reg;
	size_t irq_cnt;
	bool is_pf;
	char drv_rev[AZIHSM_CTRL_DEV_DRV_REV_LEN];
	struct dma_pool *page_pool;
	struct azihsm_ioq ioq;
	struct tasklet_struct tasklet;
	struct azihsm_ctrl_ident *ident;
	dma_addr_t ident_dma_addr;
	struct azihsm_hsm hsm;
	struct azihsm_aes aes;
	atomic_t state; // AZIHSM_CTRL_STATE
	struct azihsm_ctrl_cfg saved_cfg;

	u32 level_one_abort_count; // Number of times level-1 abort has happened
	u32 level_two_abort_count; // Number of times level-2 abort has happened
	u64 proc_not_own_fd_cnt; // Incremented When IOCTL is issued by a process which does not own FD
	u64 session_flush_cnt; // Number Of Times Driver issued Flush Session Internally
	u64 close_by_not_own_proc_cnt; // The process owning the file is not the one closing it.

	/*
	 * Mutex acquired by the thread that starts
	 * the abort.
	 */
	struct mutex abort_mutex;

	/*
	 * Flag set to indicate that a abort is in progress
	 * on this controller.
	 * This could either be level one or level 2
	 * Should only be set holding the abort_mutex
	 */
	atomic_t abort_state;

	/*
	 * The health monitor for detecting controller crash
	 *
	 */
	struct azihsm_health_mon hmon;

	/*
	 * entropy_data
	 * Per device entropy_data
	 */
	char entropy_data[AZIHSM_CTRL_DEV_INFO_ENTROPY_LENGTH];

	/*
	 * TRUE if ctrl_irq is allocated
	 * FALSE if ctrl_irq is not allocated or is freed up
	 * Protects us against double free of control irq
	 * (IRQ bound to admin queue)
	 */
	bool ctrl_irq_allocated;
};

int azihsm_ctrl_init(struct azihsm_ctrl *ctrl,
		     const struct azihsm_ctrl_cfg *cfg, const bool abort);

void azihsm_ctrl_deinit(struct azihsm_ctrl *ctrl, const bool abort,
			u32 abort_type);

void azihsm_ctrl_sw_disable(struct azihsm_ctrl *ctrl, const bool abort);
int azihsm_ctrl_hw_disable(struct azihsm_ctrl *ctrl);
int azihsm_ctrl_hw_nssr(struct azihsm_ctrl *ctrl);
int azihsm_ctrl_hw_enable(struct azihsm_ctrl *ctrl);
int azihsm_ctrl_sw_enable(struct azihsm_ctrl *ctrl, const bool abort);
#endif // _LINUX_AZIHSM_CTRL_H
