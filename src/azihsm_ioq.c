// SPDX-License-Identifier: GPL-2.0

#include "azihsm_errors.h"
#include "azihsm_ioq.h"
#include "azihsm_abort.h"
#include <linux/wait.h>
#include <linux/sched/signal.h>
#include <linux/dma-mapping.h>
#include <linux/atomic.h>
#include "azihsm_log.h"

#define NUM_MICROSEC_IN_ONE_SEC (1000000)

/*
 * sq_attributes_name_array
 * sysfs attributes per IOQ
 * All CP and FP IOQs have the same
 * sysfs attributes
 */
const char *sq_attributes_name_array[SQ_SURFACED_ATTRIBUTES_COUNT] = {
	"num_cmds_pending_in_hw",    "num_level1_aborts",
	"min_time_to_complete_io",   "max_time_to_complete_io",
	"avg_time_to_complete_io",   "total_ios_in_error",
	"total_ios_submitted_to_hw", "total_ios_completed_by_hw",
	"total_ios_timedout",	     "completions_per_sec",
};

/*
 * azihsm_sq_attr_show
 * Returns the value of the sysfs counter
 * attr :- sysfs attribute
 * buf :- Buffer to return the value
 *
 * this function is invoked for all IOQ counters
 * If the attribute is time based counter
 * (currently it is just cps), calculate the
 * virtual counter value and return this value
 */
static ssize_t azihsm_sq_attr_show(struct kobject *kobj,
				   struct kobj_attribute *attr, char *buf)
{
	unsigned long curr_completions;
	unsigned long completions_per_sec;
	u64 curr_time_in_ns, curr_time_in_us;
	u64 time_diff_in_us;
	struct azihsm_ioq_sq *sq;
	struct hsm_ioq_attribute_info *info =
		container_of(attr, struct hsm_ioq_attribute_info, sq_attribute);

	if (info->cntr_type == HSM_IOQ_ATTRIBUTE_CNTR_TYPE_NORMAL)
		return sprintf(buf, "%d\n", atomic_read(&info->counter));

	/*
	 * There is only one counter which has the meaning of rate
	 * If we had more than one, we can get the name of the attribute
	 * and handle the counter correctly
	 */
	sq = info->context;

	/*
	 * take a snapshot of total ios completed by hw
	 */
	curr_completions = atomic_read(
		&sq->hsm_ioq_attribute_array
			 [SQ_ATTRIBUTE_INDEX_TOTAL_IOS_COMPLETED_BY_HW]
				 .counter);
	curr_time_in_ns = ktime_get_ns();
	curr_time_in_us = curr_time_in_ns / 1000;
	time_diff_in_us = curr_time_in_us - sq->prev_time_us;

	if (time_diff_in_us == 0)
		completions_per_sec = sq->prev_completions;
	else
		completions_per_sec =
			(curr_completions - sq->prev_completions) *
			NUM_MICROSEC_IN_ONE_SEC / time_diff_in_us;

	sq->prev_completions = curr_completions;
	sq->prev_time_us = curr_time_in_us;
	return sprintf(buf, "%lu\n", completions_per_sec);
}

static inline size_t align_up(size_t bytes, size_t align)
{
	return ((bytes + align - 1) & ~(align - 1));
}

static int azihsm_ioq_cq_init(struct azihsm_ioq_cq *cq,
			      struct azihsm_ioq_cfg *cfg)
{
	int err;
	size_t mem_size;
	void *mem;
	dma_addr_t dma_addr;
	u16 cqe_size = cfg->ops->cqe_size();
	size_t page_size = cfg->ops->page_size();

	//
	// In the case of abort, this function may be called
	// without being invoked as a part of initialization.
	// There is no harm in re-initing this structure
	//
	memset(cq, 0, sizeof(*cq));
	mem_size = align_up(cqe_size * cfg->size, page_size);
	mem = dma_alloc_coherent(cfg->dev, mem_size, &dma_addr, GFP_KERNEL);
	if (!mem) {
		err = -ENOMEM;
		AZIHSM_DEV_LOG_ERROR(cfg->dev,
				     "[%s] DMA alloc failure. qid=%d, size=%ld",
				     __func__, cfg->id, mem_size);
		goto dma_alloc_fail;
	}

	cq->cqe_size = cfg->ops->cqe_size();
	cq->id = cfg->id;
	cq->size = cfg->size;
	cq->db = (u8 *)cfg->db + ((2 * cfg->id + 1) * 4);
	cq->cqe_get_phase = cfg->ops->cqe_get_phase;
	cq->cqe_get_cid = cfg->ops->cqe_get_cid;
	cq->dev = cfg->dev;
	cq->mem_size = mem_size;
	cq->mem = mem;
	cq->dma_addr = dma_addr;
	cq->head = 0;
	cq->phase = 0;

	return 0;

dma_alloc_fail:
	return err;
}

static void azihsm_ioq_cq_deinit(struct azihsm_ioq_cq *cq)
{
	if (cq->mem) {
		dma_free_coherent(cq->dev, cq->mem_size, cq->mem, cq->dma_addr);
		cq->mem = NULL;
	}

	memset(cq, 0, sizeof(*cq));
}

static inline void *azihsm_ioq_cq_head(struct azihsm_ioq_cq *cq)
{
	return (u8 *)cq->mem + cq->cqe_size * cq->head;
}

static inline bool azihsm_ioq_cq_empty(struct azihsm_ioq_cq *cq)
{
	void *cqe = azihsm_ioq_cq_head(cq);

	return cq->phase == cq->cqe_get_phase(cqe) ? true : false;
}

static inline u16 azihsm_ioq_cq_peek_tag_unsafe(struct azihsm_ioq_cq *cq)
{
	void *cqe = azihsm_ioq_cq_head(cq);

	return cq->cqe_get_cid(cqe);
}

static void azihsm_ioq_cq_dequeue_unsafe(struct azihsm_ioq_cq *cq, void *cqe)
{
	void *head_cqe = azihsm_ioq_cq_head(cq);

	// Copy the CQE from the completion queue to the
	// passed in cqe address
	memcpy(cqe, head_cqe, cq->cqe_size);

	cq->head += 1;
	if (cq->head == cq->size) {
		cq->head = 0;
		cq->phase = !cq->phase;
	}

	writel(cq->head, cq->db);
}

static void azihsm_ioq_sq_update_head(struct azihsm_ioq_sq *sq,
				      unsigned int sq_head)
{
	atomic_set(&sq->sq_head_ptr_on_compl, sq_head);
}

/*
 * Function :- azihsm_ioq_cq_consume_head
 * Dequeues the cqe at the head of the completion queue
 * and then consumes it. The function will also update the
 * head pointer on the submission queue.
 * ioq :- Identifies the ioq on which the operation
 * needs to be performed
 */
static void azihsm_ioq_cq_consume_head(struct azihsm_ioq *ioq)
{
	u16 tag;
	u16 sq_head = 0;
	void *cqe;
	struct azihsm_ioq_cq *cq = &ioq->cq;

	cqe = azihsm_ioq_cq_head(cq);
	tag = cq->cqe_get_cid(cqe);
	azihsm_ioq_cq_dequeue_unsafe(cq, cqe);

	// get the submission queue head from here
	sq_head = ioq->ops->cqe_get_sq_head(cqe);

	// update the head of the SQ as indicated in the CQE
	azihsm_ioq_sq_update_head(&ioq->sq, sq_head);
}

static int azihsm_ioq_sq_init(struct azihsm_ioq_sq *sq,
			      struct azihsm_ioq_cfg *cfg)
{
	int err;
	int i;
	size_t mem_size;
	void *mem;
	dma_addr_t dma_addr;
	u16 sqe_size = cfg->ops->sqe_size();
	size_t page_size = cfg->ops->page_size();

	//
	// First initialize everytihng so that
	// we have a clean slate to start with.
	// When we do abort this function may be called
	// from the abort path without the initialization
	// code. No Harm in initializing again.
	//
	memset(sq, 0, sizeof(*sq));

	mem_size = align_up(sqe_size * cfg->size, page_size);
	mem = dma_alloc_coherent(cfg->dev, mem_size, &dma_addr, GFP_KERNEL);
	if (!mem) {
		err = -ENOMEM;
		AZIHSM_DEV_LOG_ERROR(
			cfg->dev, "[%s]: DMA alloc failure. qid=%d, size=%ld",
			__func__, cfg->id, mem_size);
		goto dma_alloc_fail;
	}

	sq->sqe_size = cfg->ops->sqe_size();
	sq->id = cfg->id;
	sq->size = cfg->size;
	sq->db = (u8 *)cfg->db + ((2 * cfg->id) * 4);
	sq->dev = cfg->dev;
	sq->mem_size = mem_size;
	sq->mem = mem;
	sq->dma_addr = dma_addr;
	sq->tail = 0;
	atomic_set(&sq->sq_head_ptr_on_compl, 0);
	/*
	 * Attributes are only created if the
	 * SQ is for Control path or fast path
	 * For SQ#0 (admin SQ), a different set
	 * of attributes are created
	 */
	if (!sq->id)
		return 0;

	/*
	 * Initialize the attribute array and attribute group
	 */
	for (i = 0; i < SQ_SURFACED_ATTRIBUTES_COUNT; i++) {
		sysfs_attr_init(&sq->hsm_ioq_attribute_array[i].sq_attribute);
		/*
		 * context is the sq
		 */
		sq->hsm_ioq_attribute_array[i].context = (void *)sq;
		sq->hsm_ioq_attribute_array[i].sq_attribute.attr.name =
			sq_attributes_name_array[i];
		sq->hsm_ioq_attribute_array[i].sq_attribute.attr.mode = 0664;
		sq->hsm_ioq_attribute_array[i].sq_attribute.show =
			azihsm_sq_attr_show;
		sq->hsm_ioq_attribute_array[i].sq_attribute.store = NULL;
		atomic_set(&sq->hsm_ioq_attribute_array[i].counter, 0);
		sq->p_attrib_array[i] =
			&sq->hsm_ioq_attribute_array[i].sq_attribute.attr;
		if (i == SQ_ATTRIBUTE_INDEX_COMPLETIONS_PER_SECOND)
			sq->hsm_ioq_attribute_array[i].cntr_type =
				HSM_IOQ_ATTRIBUTE_CNTR_TYPE_PER_TIME;
		else
			sq->hsm_ioq_attribute_array[i].cntr_type =
				HSM_IOQ_ATTRIBUTE_CNTR_TYPE_NORMAL;
	}

	sq->p_attrib_array[SQ_SURFACED_ATTRIBUTES_COUNT] = NULL;
	sq->sq_attribute_group.attrs = sq->p_attrib_array;

	/*
	 * create a node in sysfs at the parent
	 *  level
	 */
	sq->sq_sysfs_kobj = kobject_create_and_add(cfg->sz_sysfs_name,
						   cfg->parent_sysfs_kobj);

	if (!sq->sq_sysfs_kobj) {
		/*TODO should this failure result in driver not loading */
		AZIHSM_DEV_LOG_ERROR(
			cfg->dev,
			"[%s]: kobject_create_and_add failed. qid=%d\n",
			__func__, cfg->id);
		err = -ENOMEM;
		goto free_dma_alloc;
	}

	/*
	 * create the attribute group
	 */
	err = sysfs_create_group(sq->sq_sysfs_kobj, &sq->sq_attribute_group);
	if (err) {
		/*
		 * TODO does failure in allocating attributes
		 * result in failure loading
		 */
		AZIHSM_DEV_LOG_ERROR(cfg->dev,
				     "[%s]: sysfs_create_group failed qid=%d\n",
				     __func__, cfg->id);
		kobject_put(sq->sq_sysfs_kobj);
		sq->sq_sysfs_kobj = NULL;
		goto free_dma_alloc;
	}

	sq->prev_completions = 0;
	sq->prev_time_us = ktime_get_ns() / 1000;

	return 0;

free_dma_alloc:
	dma_free_coherent(sq->dev, sq->mem_size, sq->mem, sq->dma_addr);
	sq->mem = NULL;

dma_alloc_fail:
	return err;
}

static void azihsm_ioq_sq_deinit(struct azihsm_ioq_sq *sq)
{
	AZIHSM_LOG_ENTRY("%s Deleting q=%d", __func__, sq->id);

	if (sq->mem) {
		dma_free_coherent(sq->dev, sq->mem_size, sq->mem, sq->dma_addr);
		sq->mem = NULL;
	}

	if (sq->sq_sysfs_kobj) {
		sysfs_remove_group(sq->sq_sysfs_kobj, &sq->sq_attribute_group);
		kobject_put(sq->sq_sysfs_kobj);
		sq->sq_sysfs_kobj = NULL;
	}

	memset(sq, 0, sizeof(*sq));
	AZIHSM_LOG_EXIT("%s ", __func__);
}

static inline void *azihsm_ioq_sq_tail(struct azihsm_ioq_sq *sq)
{
	return (u8 *)sq->mem + sq->sqe_size * sq->tail;
}

static int azihsm_ioq_sq_enqueue(struct azihsm_ioq_sq *sq, void *sqe)
{
	void *tail_sqe = azihsm_ioq_sq_tail(sq);

	memcpy(tail_sqe, sqe, sq->sqe_size);

	sq->tail += 1;
	if (sq->tail == sq->size)
		sq->tail = 0;

	writel(sq->tail, sq->db);

	return 0;
}

static int azihsm_ioq_store_alloc_tag(struct azihsm_ioq_store *store,
				      unsigned int *cpu)
{
	int tag;
	struct sbitmap_queue *sbq = &store->bitmap;
	struct sbq_wait_state *ws = &sbq->ws[0];
	DEFINE_SBQ_WAIT(wait);

	tag = sbitmap_queue_get(sbq, cpu);
	if (tag != -1)
		return tag;

	for (;;) {
		sbitmap_prepare_to_wait(sbq, ws, &wait, TASK_UNINTERRUPTIBLE);

		if (signal_pending_state(TASK_INTERRUPTIBLE, current)) {
			tag = -EINTR;
			break;
		}

		tag = sbitmap_queue_get(sbq, cpu);
		if (tag != -1)
			break;

		schedule();
	}

	sbitmap_finish_wait(sbq, ws, &wait);

	return tag;
}

static void azihsm_ioq_store_free_tag(struct azihsm_ioq_store *store, int tag,
				      unsigned int cpu)
{
	sbitmap_queue_clear(&store->bitmap, tag, cpu);
}

static int azihsm_ioq_store_init(struct azihsm_ioq_store *store,
				 struct azihsm_ioq_cfg *cfg)
{
	int err;

	err = sbitmap_queue_init_node(&store->bitmap, (cfg->size - 1), -1,
				      false, GFP_KERNEL, NUMA_NO_NODE);
	if (err) {
		AZIHSM_DEV_LOG_ERROR(
			cfg->dev,
			"[%s]:sbitmap_queue_init_node failure qid=%d cfgsize=%d\n",
			__func__, cfg->id, cfg->size);
		goto sbitmap_alloc_fail;
	}

	xa_init(&store->ctx_store);

	store->id = cfg->id;
	store->size = (cfg->size - 1);
	store->set_io_data = cfg->ops->set_io_data;
	store->get_io_data = cfg->ops->get_io_data;

	return 0;

sbitmap_alloc_fail:
	return err;
}

static void azihsm_ioq_store_deinit(struct azihsm_ioq_store *store)
{
	xa_destroy(&store->ctx_store);
	sbitmap_queue_free(&store->bitmap);
}

/*
 * Please note that this function waits for the context to be
 * available. This function puts the thread in blocked state.
 * This function cannot be called with schduler disabled, which
 * basically means that you should not call this function with
 * any spin locks held.
 */
static int azihsm_ioq_store_alloc_ctx(struct azihsm_ioq_store *store, void *ctx,
				      u16 *tag)
{
	int err;
	int bitmap_tag;
	unsigned int cpu;

	bitmap_tag = azihsm_ioq_store_alloc_tag(store, &cpu);
	if (bitmap_tag < 0) {
		err = bitmap_tag;
		goto tag_alloc_fail;
	}

	err = xa_insert_bh(&store->ctx_store, bitmap_tag, ctx, GFP_KERNEL);
	if (err)
		goto ctx_insert_fail;

	*tag = (u16)bitmap_tag;
	store->set_io_data(ctx, cpu);

	return 0;

ctx_insert_fail:
	azihsm_ioq_store_free_tag(store, bitmap_tag, cpu);
tag_alloc_fail:
	return err;
}

/*
 * should always be called with Completion Lock Held
 */
void azihsm_ioq_store_free_ctx(struct azihsm_ioq_store *store, u16 tag)
{
	unsigned int cpu;

	void *ctx = xa_load(&store->ctx_store, tag);

	if (ctx == NULL)
		return;

	cpu = store->get_io_data(ctx);

	xa_erase_bh(&store->ctx_store, tag);
	azihsm_ioq_store_free_tag(store, tag, cpu);
}

void *azihsm_ioq_store_ctx(struct azihsm_ioq_store *store, u16 tag)
{
	return xa_load(&store->ctx_store, tag);
}

int azihsm_ioq_init(struct azihsm_ioq *ioq, struct azihsm_ioq_cfg *cfg)
{
	int err;

	// First clear the IOCQ and IOSQ right here so that if the
	// deinit is called we do not have garbabge pointers in any
	// of them and we do not clear something which we did not allocate
	memset(&ioq->cq, 0, sizeof(ioq->cq));
	memset(&ioq->sq, 0, sizeof(ioq->sq));

	err = azihsm_ioq_cq_init(&ioq->cq, cfg);
	if (err) {
		AZIHSM_DEV_LOG_ERROR(cfg->dev,
				     "%s azihsm_ioq_cq_init failed err:%d\n",
				     __func__, err);

		goto cq_init_fail;
	}

	if (cfg->ioq_type == AZIHSM_IOQ_TYPE_HSM)
		snprintf(cfg->sz_sysfs_name, sizeof(cfg->sz_sysfs_name),
			 "cp_sq%d", cfg->id);
	else
		snprintf(cfg->sz_sysfs_name, sizeof(cfg->sz_sysfs_name),
			 "fp_sq%d", cfg->id);

	err = azihsm_ioq_sq_init(&ioq->sq, cfg);

	if (err) {
		AZIHSM_DEV_LOG_ERROR(cfg->dev,
				     "%s azihsm_ioq_sq_init failed err:%d\n",
				     __func__, err);

		goto sq_init_fail;
	}

	err = azihsm_ioq_store_init(&ioq->store, cfg);
	if (err) {
		AZIHSM_DEV_LOG_ERROR(cfg->dev,
				     "%s azihsm_ioq_store_init failed err:%d\n",
				     __func__, err);

		goto store_init_fail;
	}

	ioq->ioq_disabled = false;
	mutex_init(&ioq->submit_lock);
	spin_lock_init(&ioq->cmpl_lock);

	ioq->id = cfg->id;
	ioq->size = cfg->size;
	ioq->vec = cfg->vec;
	ioq->dev = cfg->dev;
	ioq->ops = cfg->ops;
	ioq->pri = cfg->pri;

	return 0;

store_init_fail:
	azihsm_ioq_sq_deinit(&ioq->sq);
sq_init_fail:
	azihsm_ioq_cq_deinit(&ioq->cq);
cq_init_fail:
	return err;
}

void azihsm_ioq_deinit(struct azihsm_ioq *ioq)
{
	azihsm_ioq_store_deinit(&ioq->store);
	azihsm_ioq_sq_deinit(&ioq->sq);
	azihsm_ioq_cq_deinit(&ioq->cq);
}

u16 azihsm_ioq_id(struct azihsm_ioq *ioq)
{
	return ioq->id;
}

u16 azihsm_ioq_size(struct azihsm_ioq *ioq)
{
	return ioq->size;
}

enum azihsm_ioq_pri azihsm_ioq_pri(struct azihsm_ioq *ioq)
{
	return ioq->pri;
}

u16 azihsm_ioq_vec(struct azihsm_ioq *ioq)
{
	return ioq->vec;
}

dma_addr_t azihsm_ioq_cq_dma_addr(struct azihsm_ioq *ioq)
{
	return ioq->cq.dma_addr;
}

dma_addr_t azihsm_ioq_sq_dma_addr(struct azihsm_ioq *ioq)
{
	return ioq->sq.dma_addr;
}

/*
 * azihsm_ioq_submit_cmd
 *  Function to submit a command to a SQ in a IOQ.
 *  IOQ is a queue pair (SQ,CQ)
 *
 * Parameters
 *   ioq ---> queue pair
 *   cmd ---> Cmd to submit
 *   tag --> A unique unsigned 16-bit value that is used
 *     in the SQE.
      This is later used in the CQE to retrieve the SQE
      and other buffers associated with the request
 *  Returns 0 if successful
 *
 * Caller must have the mutex on the submit_lock on the ioq
 *  This is required because the tail on the SQ will be updated
 *  when the SQE is queued to the device
 *
 * Note :- The call azihsm_ioq_store_alloc_ctx will block until there
 * is a free slot available in the bitmap. The length of the bitmap
 * is the number of slots in the queue.
 *
 */
int azihsm_ioq_submit_cmd(struct azihsm_ioq *ioq, void *cmd, u16 *tag)
{
	int err = 0;
	u16 new_tag;
	void *sqe;

	err = azihsm_ioq_store_alloc_ctx(&ioq->store, cmd, &new_tag);
	if (err) {
		AZIHSM_DEV_LOG_ERROR(
			ioq->sq.dev,
			"[%s:ERROR] allocating context for cmd[%p] failed err=%d\n",
			__func__, cmd, err);

		err = -EAGAIN;
		goto store_alloc_fail;
	}

	spin_lock_bh(&ioq->cmpl_lock);
	//
	// We have number of tags same as queue depth
	// Ideally here we should never see a queue full
	// condition. The reality is that the queue full
	// condition is a function of how fast the hardware
	// is moving the head of submission queue. It is
	// very much possible that the completions happen
	// faster than head updates to CQE->Head. So it is possible
	// that the tags could be available but the SQ is
	// still full.
	//
	if (azihsm_sq_is_full(&ioq->sq)) {
		AZIHSM_DEV_LOG_ERROR(ioq->sq.dev,
				     "[%s] Queue Full When Tag Available\n",
				     __func__);

		err = -EAGAIN;
		goto enqueue_fail;
	}

	sqe = ioq->ops->sqe(cmd);
	ioq->ops->sqe_set_cid(sqe, new_tag);

	*tag = new_tag;
	if (ioq->ops->set_tag)
		ioq->ops->set_tag(cmd, new_tag);

	err = azihsm_ioq_sq_enqueue(&ioq->sq, sqe);
	if (err) {
		AZIHSM_DEV_LOG_ERROR(
			ioq->sq.dev,
			"[%s:ERROR] Enqueuing sq failed. sqe=%p err=%d\n",
			__func__, sqe, err);

		goto enqueue_fail;
	}

	spin_unlock_bh(&ioq->cmpl_lock);
	return 0;

enqueue_fail:
	azihsm_ioq_store_free_ctx(&ioq->store, new_tag);
	spin_unlock_bh(&ioq->cmpl_lock);

store_alloc_fail:
	return err;
}

void azihsm_ioq_complete_cmds(struct azihsm_ioq *ioq)
{
	u16 tag;
	void *cmd;
	void *cqe;
	u32 sq_head;

	if (!ioq) {
		AZIHSM_LOG_ERROR("[%s] IOQ Null Pointer", __func__);
		return;
	}

	// This function is called from the bottom half. The spinlock is needed
	// to handle the race condition where the command might have timed out
	// and in process of being cancelled while the bottom half is trying
	// to complete it. This can happen under following conditions
	// - The command is delayed in the device
	// - The timeout value for the command is small
	spin_lock_bh(&ioq->cmpl_lock);

	while (!azihsm_ioq_cq_empty(&ioq->cq)) {
		// Peek the tag of the item at the top of the queue
		tag = azihsm_ioq_cq_peek_tag_unsafe(&ioq->cq);

		// Retrieve the command from the store
		cmd = azihsm_ioq_store_ctx(&ioq->store, tag);
		if (!cmd) {
			// The item at the head has been canceled or
			// completed (abort) which is why we could not
			// we find it in the context store
			// Advance past this item to process other
			// items in the CQ
			azihsm_ioq_cq_consume_head(ioq);

			dev_warn(ioq->dev,
				 "Command %d not found in IO queue %d", tag,
				 ioq->id);
			continue;
		}

		// Retrieve the address of the Completion Queue Entry
		cqe = ioq->ops->cqe(cmd);

		// Dequeue the completion queue entry and copy it into cmd
		// The cqe data from the completion queue is copied in to
		// cqe pointer in this function call.
		azihsm_ioq_cq_dequeue_unsafe(&ioq->cq, cqe);

		// get the submission queue head from here
		sq_head = ioq->ops->cqe_get_sq_head(cqe);

		// update the head of the SQ before calling the complion
		azihsm_ioq_sq_update_head(&ioq->sq, sq_head);

		// Free the tag so it can be used for future commands
		azihsm_ioq_store_free_ctx(&ioq->store, tag);

		// Indicate completion of the command
		ioq->ops->complete_cmd(cmd, AZIHSM_IOQ_CMD_STS_SUCCESS);
	}

	spin_unlock_bh(&ioq->cmpl_lock);
}

//azihsm_ioq_cancel_cmd
//ioq :- io queue
//tag : Implicitly identifies the command
//in the context store
//
// This function must only be called by the thread
// that submitted the command.
//
// This command just frees up the command from the context store
// There is no reason to complete the command because this
// function is only called by the thread submitting the command
//
// Note there is no guarantee that the command is in the context
// store. It might already have been completed by the abort handler
// or the completion handler
//
void azihsm_ioq_cancel_cmd(struct azihsm_ioq *ioq, u16 tag)
{
	// This function is called from the process context to cancel timedout
	// commands
	spin_lock_bh(&ioq->cmpl_lock);

	AZIHSM_DEV_LOG_INFO(ioq->sq.dev,
			    "[%s:INFO] Canceling command on ioq:%d tag:%d\n",
			    __func__, ioq->id, tag);

	azihsm_ioq_store_free_ctx(&ioq->store, tag);

	spin_unlock_bh(&ioq->cmpl_lock);
}

void azihsm_ioq_sq_restart(struct azihsm_ioq *ioq)
{
	/* Reset the tail and head pointers on the SQ */
	atomic_set(&ioq->sq.sq_head_ptr_on_compl, 0);
	ioq->sq.tail = 0;
}
