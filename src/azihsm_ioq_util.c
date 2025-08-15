// SPDX-License-Identifier: GPL-2.0
#include <linux/kernel.h>
#include <linux/completion.h>
#include "azihsm_ioq_util.h"
#include "azihsm_abort.h"
#include "azihsm_log.h"
/*
 *	azihsm_ioq_find_queue_for_submission
 *	This function is called to find a
 *	free or available queue to submit
 *	a command (Queue in a pool)
 *
 *	Note :- Multiple threads could be
 *	executing this function
 *
 *	Every pool has a current SQ to use
 *	Every time a command is to be
 *	submitted, the search for a SQ to use
 *	starts at this current SQ.
 *		The index of the current SQ is
 *		updated to go to the next SQ in
 *		the pool (round robin)
 *
 *	Parameters :-
 *		ioq_pool :- IOQ pool
 *		ioq_pool_start_id :- Start id of the pool
 *
 *		dev :- To use for logging
 *		pool_lock :- Mutex to be used
 *			for updating the pool round robin
 *			index
 *
 *	Returns :- A pointer to a IOQ in the pool
 *	to use for submission.
 */
struct azihsm_ioq *azihsm_ioq_find_queue_for_submission(
	struct azihsm_ioq_pool *ioq_pool, const int ioq_pool_start_id,
	struct device *dev, struct mutex *pool_lock)
{
	const int rr_queue_index = ioq_pool->ioq_select_id;
	int next_q = 0;
	struct azihsm_ioq *ioq = NULL;
	struct azihsm_ioq *rr_ioq = NULL;
	int q_id;
	const u16 q_count = ioq_pool->ioq_cnt;

	mutex_lock(pool_lock);

	/*	get the pointer to the round robin queue */
	rr_ioq = (struct azihsm_ioq *)xa_load(&ioq_pool->ioqs, rr_queue_index);

	/*	update the index of the queue for the next command */
	next_q = rr_queue_index;

	/*	Update the index of the next SQ to use */
	next_q = (next_q + 1);

	/*	account for loop around
	 *	AES queues start from 256 and if the # of AES queues
	 *	are 2, the valid indexes are 256 and 257
	 */
	if (next_q == (ioq_pool_start_id + q_count))
		next_q = ioq_pool_start_id;

	ioq_pool->ioq_select_id = next_q;

	mutex_unlock(pool_lock);

	/*	start from the round robin index
	 *	Find a queue that is not disabled and not full
	 *	and return that queue
	 *	As an example if the current queue is at 257 and the number of
	 *	queue is 3, in this loop we search the queues from 257 to 258
	 *	inclusive. Any queue we find that is not disabled and not full
	 *	return this queue
	 */
	for (q_id = rr_queue_index; q_id < ioq_pool_start_id + q_count;
	     q_id++) {
		ioq = (struct azihsm_ioq *)xa_load(&ioq_pool->ioqs, q_id);

		if (ioq == NULL) {
			/* This cannot happen because the queue_index is valid */
			AZIHSM_DEV_LOG_ERROR(
				dev,
				"IOQPool:%p Find next queue. queue_index:%d is not valid\n",
				ioq_pool, q_id);
			BUG();
			return NULL;
		}

		mutex_lock(&ioq->submit_lock);

		if ((azihsm_is_ioq_disabled(ioq) == false) &&
		    !azihsm_sq_is_full(&ioq->sq)) {
			mutex_unlock(&ioq->submit_lock);
			return ioq;
		}
		mutex_unlock(&ioq->submit_lock);
	}

	/* do another search from first queue to current queue */
	for (q_id = ioq_pool_start_id; q_id < rr_queue_index; q_id++) {
		ioq = (struct azihsm_ioq *)xa_load(&ioq_pool->ioqs, q_id);
		if (ioq == NULL) {
			AZIHSM_DEV_LOG_ERROR(
				dev,
				"IOQPool:%p failure. Unable to get ioq at index = %d. Moving to next IOQ\n",
				ioq_pool, q_id);
			continue;
		}

		/* Acquire the lock on the SQ */
		mutex_lock(&ioq->submit_lock);

		if (azihsm_is_ioq_disabled(ioq) == true) {
			AZIHSM_DEV_LOG_ERROR(
				dev,
				"IOQPool:%p SQ[%d] is disabled. Abort in progress. Retry command\n",
				ioq_pool, ioq->id);
			mutex_unlock(&ioq->submit_lock);
			continue;
		}

		if (azihsm_sq_is_full(&ioq->sq)) {
			AZIHSM_DEV_LOG_ERROR(
				dev,
				"IOQPool:%p SQ[%d] is full. Trying next available SQ\n",
				ioq_pool, ioq->id);
			mutex_unlock(&ioq->submit_lock);
			continue;
		}

		mutex_unlock(&ioq->submit_lock);
		return ioq;
	}

	if (rr_ioq) {
		mutex_lock(&rr_ioq->submit_lock);
		if (azihsm_is_ioq_disabled(rr_ioq) == true)
			rr_ioq = NULL;
		mutex_unlock(&rr_ioq->submit_lock);
	}

	return rr_ioq;
}
