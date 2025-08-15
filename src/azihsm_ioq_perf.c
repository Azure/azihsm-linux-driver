// SPDX-License-Identifier: GPL-2.0

#include "azihsm_ioq_perf.h"

/*
 * azihsm_ioq_perf_update_cntrs_before_submission
 * Function called to update per IOQ and global
 * counters before submitting a command (IO) to
 * device
 * Counters updated are per IOQ
 *  increment ios submitted to hw
 *  increment commands pending in HW
 * global counters
 *  total submissions to hw
 * hsm
 * ioq --> Whose counters need to be updated
 */
void azihsm_ioq_perf_update_cntrs_before_submission(struct azihsm_hsm *hsm,
						    struct azihsm_ioq *ioq)
{
	atomic_inc(&ioq->sq.hsm_ioq_attribute_array
			    [SQ_ATTRIBUTE_INDEX_TOTAL_IOS_SUBMITTED_TO_HW]
				    .counter);

	atomic_inc(&ioq->sq.hsm_ioq_attribute_array
			    [SQ_ATTRIBUTE_INDEX_NUM_CMDS_PENDING_IN_HW]
				    .counter);

	atomic_inc(
		&hsm->hsm_global_attribute_array
			 [AZIHSM_HSM_GLOBAL_ATTRIBUTE_TOTAL_SUBMISSIONS_TO_HW]
				 .counter);
}

/*
 * azihsm_ioq_perf_update_cntrs_after_submission
 * hsm
 * ioq --> whose counters need to be updated
 * submission_time  Time submitted
 * completion_time  Time command completed
 */
void azihsm_ioq_perf_update_cntrs_after_submission(struct azihsm_hsm *hsm,
						   struct azihsm_ioq *ioq,
						   ktime_t *submission_time,
						   ktime_t *completion_time)
{
	s64 elapsed_time;
	s64 total_submissions;
	s64 total_time_cur;
	/* calculate time for the command to complete */
	elapsed_time =
		ktime_to_ns(ktime_sub(*completion_time, *submission_time));

	if (elapsed_time >= ioq->sq.max_time_for_completion)
		ioq->sq.max_time_for_completion = elapsed_time;

	if (!ioq->sq.min_time_for_completion)
		ioq->sq.min_time_for_completion = elapsed_time;
	else if (elapsed_time <= ioq->sq.min_time_for_completion)
		ioq->sq.min_time_for_completion = elapsed_time;

	atomic_set(&ioq->sq.hsm_ioq_attribute_array
			    [SQ_ATTRIBUTE_INDEX_MAX_TIME_TO_COMPLETE_IO]
				    .counter,
		   ioq->sq.max_time_for_completion);
	atomic_set(&ioq->sq.hsm_ioq_attribute_array
			    [SQ_ATTRIBUTE_INDEX_MIN_TIME_TO_COMPLETE_IO]
				    .counter,
		   ioq->sq.min_time_for_completion);

	/*
	 * average time is total time taken for all submissions until now
	 *  plus time taken for this command
	 */
	total_submissions =
		atomic_read(
			&ioq->sq.hsm_ioq_attribute_array
				 [SQ_ATTRIBUTE_INDEX_TOTAL_IOS_SUBMITTED_TO_HW]
					 .counter) -
		1;
	total_time_cur = ioq->sq.avg_time_for_completion * total_submissions +
			 elapsed_time;
	ioq->sq.avg_time_for_completion =
		(total_time_cur / (total_submissions + 1));
	atomic_set(&ioq->sq.hsm_ioq_attribute_array
			    [SQ_ATTRIBUTE_INDEX_AVG_TIME_TO_COMPLETE_IO]
				    .counter,
		   ioq->sq.avg_time_for_completion);

	atomic_inc(&ioq->sq.hsm_ioq_attribute_array
			    [SQ_ATTRIBUTE_INDEX_TOTAL_IOS_COMPLETED_BY_HW]
				    .counter);

	atomic_dec(&ioq->sq.hsm_ioq_attribute_array
			    [SQ_ATTRIBUTE_INDEX_NUM_CMDS_PENDING_IN_HW]
				    .counter);

	atomic_inc(
		&hsm->hsm_global_attribute_array
			 [AZIHSM_HSM_GLOBAL_ATTRIBUTE_TOTAL_COMPLETIONS_FROM_HW]
				 .counter);
}
