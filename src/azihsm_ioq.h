/* SPDX-License-Identifier: GPL-2.0 */

#ifndef _LINUX_AZIHSM_IOQ_H
#define _LINUX_AZIHSM_IOQ_H

#include <linux/kernel.h>
#include <linux/sbitmap.h>
#include <linux/xarray.h>
#include <linux/device.h>
#include <linux/mutex.h>
#include <linux/sysfs.h>
#include <linux/kobject.h>
#include <linux/ktime.h>

#define MCR_MIN(_x, _y) (((_x) < (_y)) ? (_x) : (_y))
// Definitions of indices used
// to index into the attribute array
// for a SQ
// See the counter documentation for
// more information on the meaning of
// these counters
#define SQ_ATTRIBUTE_INDEX_NUM_CMDS_PENDING_IN_HW 0
#define SQ_ATTRIBUTE_INDEX_NUM_LEVEL1_ABORT 1
#define SQ_ATTRIBUTE_INDEX_MIN_TIME_TO_COMPLETE_IO 2
#define SQ_ATTRIBUTE_INDEX_MAX_TIME_TO_COMPLETE_IO 3
#define SQ_ATTRIBUTE_INDEX_AVG_TIME_TO_COMPLETE_IO 4
#define SQ_ATTRIBUTE_INDEX_TOTAL_IOS_IN_ERROR 5
#define SQ_ATTRIBUTE_INDEX_TOTAL_IOS_SUBMITTED_TO_HW 6
#define SQ_ATTRIBUTE_INDEX_TOTAL_IOS_COMPLETED_BY_HW 7
#define SQ_ATTRIBUTE_INDEX_NUM_IOS_TIMEDOUT 8
#define SQ_ATTRIBUTE_INDEX_COMPLETIONS_PER_SECOND 9

/*
 * SQ_SURFACED_ATTRIBUTES_COUNT
 * must always equal to the number of attributes we
 * are exposing per IOQ
 */
#define SQ_SURFACED_ATTRIBUTES_COUNT 10

enum azihsm_ioq_type {
	AZIHSM_IOQ_TYPE_CTRL = 0,
	AZIHSM_IOQ_TYPE_HSM = 1,
	AZIHSM_IOQ_TYPE_AES = 2,
};

/*
 * enum azihsm_ioq_pri - IO queue priority
 */
enum azihsm_ioq_pri {
	AZIHSM_IOQ_PRI_HIGH = 0x01,
	AZIHSM_IOQ_PRI_LOW = 0x03,
};

/**
 * struct azihsm_ioq_cq - IO completion queue
 */
struct azihsm_ioq_cq {
	u16 id;
	u16 size;
	u16 cqe_size;
	void *db;
	size_t mem_size;
	void *mem;
	dma_addr_t dma_addr;
	u32 head;
	u32 phase;
	struct device *dev;
	u16 (*cqe_get_cid)(void *cqe);
	u16 (*cqe_get_phase)(void *cqe);
};

#define HSM_IOQ_ATTRIBUTE_CNTR_TYPE_NORMAL 0
#define HSM_IOQ_ATTRIBUTE_CNTR_TYPE_PER_TIME 1

/*
 * hsm_ioq_attribute_info
 * All counters of all IOQs (cp and fp)
 * have the following structure in sysfs
 * attributes
 * sq_attribute :- sysfs attribute
 * context. To be used in show and store
 * counter :- Counter value to be returned
 * cntr_type
 *   if 0 this is a regular counter
 *   else 1 this is a completions per second
 *     counter
 */
struct hsm_ioq_attribute_info {
	struct kobj_attribute sq_attribute;
	void *context;
	atomic_t counter;
	u8 cntr_type;
};

/**
 * struct azihsm_ioq_sq - IO submission queue
 *
 * sq_head_ptr_on_compl.
 *   Field updated based on last completion::sq_head
 *
 * sq_attributes_array
 *   Array of all attributes exposed for a given SQ
 *   These are exposed in /sys virtual filesystem
 *
 * sq_attribute_group
 *   group for all attributes above.
 */
struct azihsm_ioq_sq {
	u16 sqe_size;
	u16 id;
	u16 size;
	void *db;
	struct device *dev;
	size_t mem_size;
	void *mem;
	dma_addr_t dma_addr;
	u32 tail;
	atomic_t sq_head_ptr_on_compl;
	struct hsm_ioq_attribute_info
		hsm_ioq_attribute_array[SQ_SURFACED_ATTRIBUTES_COUNT];
	struct attribute *p_attrib_array[SQ_SURFACED_ATTRIBUTES_COUNT + 1];
	struct attribute_group sq_attribute_group;
	/**
	 * @sysfs_kobj: kobject for this
	 * queue in sysfs
	 */
	struct kobject *sq_sysfs_kobj;
	s64 min_time_for_completion;
	s64 max_time_for_completion;
	s64 avg_time_for_completion;

	unsigned long prev_completions;
	u64 prev_time_us;
};

/**
 * struct azihsm_ioq_store - IO store
 */
struct azihsm_ioq_store {
	u16 id;
	u16 size;
	void (*set_io_data)(void *ptr, unsigned int data);
	unsigned int (*get_io_data)(void *ptr);
	struct sbitmap_queue bitmap;
	struct xarray ctx_store;
};

/**
 * struct azihsm_ioq_ops - IO queue operations
 */
struct azihsm_ioq_ops {
	/**
	 * @page_size: Retrieve the page size
	 */
	size_t (*page_size)(void);

	/**
	 * @set_io_data: Store data associated with the io
	 */
	void (*set_io_data)(void *cmd, unsigned int data);

	/**
	 * @get_tag_data: Retrieve data associated with the io
	 */
	unsigned int (*get_io_data)(void *cmd);

	/**
	 * @sqe_size: Completion queue entry size
	 */
	u16 (*cqe_size)(void);

	/**
	 * @cqe: Retrieve completion queue entry for the command
	 */
	void *(*cqe)(void *cmd);

	/**
	 * @cqe_get_cid: Function to retrieve the command id
	 */
	u16 (*cqe_get_cid)(void *cqe);

	/**
	 * @cqe_get_phase: Retrieve the phase bit for completion queue entry
	 */
	u16 (*cqe_get_phase)(void *cqe);

	/**
	 * @cqe_get_sq_head: Retrieve the Head Of The submission Queue
	 */
	u16 (*cqe_get_sq_head)(void *cqe);

	/**
	 * @sqe_size: Submission queue entry size
	 */
	u16 (*sqe_size)(void);

	/**
	 * @sqe: Retrieve submission queue entry for the command
	 */
	void *(*sqe)(void *cmd);

	/**
	 * @sqe_set_cid: Set submission queue entry command id
	 */
	void (*sqe_set_cid)(void *cqe, u16 cid);

	/**
	 * @complete_cmd: Complete command
	 */
	int (*complete_cmd)(void *cmd, const int completion_code);

	/**
	 * @get_tag :- Get tag associated with a command
	 * The tag identifies the command in the context store
	 */
	int (*get_tag)(void *cmd);

	/*
	 * @set_tag. Set the tag associate with a command
	 */
	void (*set_tag)(void *cmd, const int tag);
};

/**
 * struct azihsm_ioq_cfg - IO queue config
 */
struct azihsm_ioq_cfg {
	/**
	 * @id: Queue id
	 */
	u16 id;

	/**
	 * @size: Number of entries in the queue
	 */
	u16 size;

	/**
	 * @pri: Queue priority
	 */
	enum azihsm_ioq_pri pri;

	/**
	 * @vec: Interrupt vector
	 */
	u16 vec;

	/**
	 * @db: Doorbell page address
	 */
	void *db;

	/**
	 * @ops: Queue operations
	 */
	struct azihsm_ioq_ops *ops;

	/**
	 * @dev: The device
	 */
	struct device *dev;

	/**
	 * @ioq_type: Type
	 */
	enum azihsm_ioq_type ioq_type;

	/**
	 * @parent_sysfs_kobj:
	 * Parent kobject to use
	 * in sysfs
	 */
	struct kobject *parent_sysfs_kobj;

	/**
	 *  @sz_sysfs_name:
	 * name to be used in sysfs
	 */
	char sz_sysfs_name[32];
};

/**
 * struct azihsm_ioq - IO queue
 */
struct azihsm_ioq {
	/**
	 * @id: Queue id
	 */
	u16 id;

	/**
	 * @size: Number of entries in the queue
	 */
	u16 size;

	/**
	 * @pri: Queue priority
	 */
	enum azihsm_ioq_pri pri;

	/**
	 * @vec: Interrupt vector
	 */
	u16 vec;

	/**
	 * @dev: The device
	 */
	struct device *dev;

	/**
	 * @ops: Queue operations
	 */
	struct azihsm_ioq_ops *ops;

	/**
	 * @cq: Completion queue
	 */
	struct azihsm_ioq_cq cq;

	/**
	 * @sq: Submission queue
	 */
	struct azihsm_ioq_sq sq;

	/**
	 * @store: IO store
	 */
	struct azihsm_ioq_store store;

	/**
	 * @submit_lock: Submission lock
	 */
	struct mutex submit_lock;

	/**
	 * @cmpl_lock: Completion lock
	 */
	spinlock_t cmpl_lock;

	/**
	 * @ioq_disabled: SQ is disabled
	 * temporary state to indicate commands
	 * cannot be submitted on the SQ
	 * Callers should be holding the submit_lock
	 * on the ioq
	 */

	bool ioq_disabled;
};

/**
 * azihsm_ioq_init() - Initialize the IO queue
 * @ioq: IO queue
 * @cfg: IO queue configuration
 *
 * Return: Zero on success or negative errno on failure.
 */
int azihsm_ioq_init(struct azihsm_ioq *ioq, struct azihsm_ioq_cfg *cfg);

/**
 * azihsm_ioq_deinit() - Deinitialize the IO queue
 * @ioq: IO queue
 */
void azihsm_ioq_deinit(struct azihsm_ioq *ioq);

/**
 * azihsm_ioq_id() - Retrieve queue id
 * @ioq: IO queue
 *
 * Return: Queue id
 */
u16 azihsm_ioq_id(struct azihsm_ioq *ioq);

/**
 * azihsm_ioq_size() - Retrieve queue size
 * @ioq: IO queue
 *
 * Return: Queue size
 */
u16 azihsm_ioq_size(struct azihsm_ioq *ioq);

/**
 * azihsm_ioq_pri() - Retrieve queue size
 * @ioq: IO queue
 *
 * Return: Queue priority
 */
enum azihsm_ioq_pri azihsm_ioq_pri(struct azihsm_ioq *ioq);

/**
 * azihsm_ioq_vec() - Retrieve interrupt vector
 * @ioq: IO queue
 *
 * Return: Interrupt vector
 */
u16 azihsm_ioq_vec(struct azihsm_ioq *ioq);

/**
 * azihsm_ioq_cq_dma_addr() - Retrieve completion queue DMA address
 * @ioq: IO queue
 *
 * Return: Completion queue DMA address
 */
dma_addr_t azihsm_ioq_cq_dma_addr(struct azihsm_ioq *ioq);

/**
 * azihsm_ioq_sq_dma_addr() - Retrieve submission queue DMA address
 * @ioq: IO queue
 *
 * Return: Submission queue DMA address
 */
dma_addr_t azihsm_ioq_sq_dma_addr(struct azihsm_ioq *ioq);

/**
 * azihsm_ioq_submit_cmd() - Submit IO command
 * @ioq: IO queue
 * @cmd: IO command
 * @tag: Tag associated with the submission
 *
 * Return: Zero on success or negative errno on failure.
 */
int azihsm_ioq_submit_cmd(struct azihsm_ioq *ioq, void *cmd, u16 *tag);

/**
 * azihsm_ioq_complete_cmd() - Complete commands
 * @ioq: IO queue
 *
 * This function is called from the ISR bottom half. It loops the completion
 * queue and completes all commands that can be completed
 */
void azihsm_ioq_complete_cmds(struct azihsm_ioq *ioq);

/**
 * azihsm_ioq_cancel_cmd() - Cancel IO command
 * @ioq: IO queue
 * @tag: Tag associated with the submission
 */
void azihsm_ioq_cancel_cmd(struct azihsm_ioq *ioq, u16 tag);

struct azihsm_ctrl;

/**
 * azihsm_ctrl_cmd_delete_sq(). Delete a SQ
 * @ctrl : Ctrl interface
 * @id : Id of the queue
 */
int azihsm_ctrl_cmd_delete_sq(struct azihsm_ctrl *ctrl, u16 id);

void *azihsm_ioq_store_ctx(struct azihsm_ioq_store *store, u16 tag);

void azihsm_ioq_store_free_ctx(struct azihsm_ioq_store *store, u16 tag);

void azihsm_ioq_sq_restart(struct azihsm_ioq *ioq);

#endif // _LINUX_AZIHSM_IOQ_H
