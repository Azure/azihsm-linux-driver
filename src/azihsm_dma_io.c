// SPDX-License-Identifier: GPL-2.0

//#define DMA_IO_DEBUG_ON 1

#include <linux/mm.h>
#include "azihsm_ioq.h"
#include "azihsm_dma_io.h"
#include "azihsm_log.h"

#define azihsm_dma_io_get_sgle_paddr(_dmaio, _ix) \
	(cpu_to_le64(sg_dma_address(&_dmaio->sg[_ix])))
#define azihsm_dma_io_get_sgle_len(_dmaio, _ix) \
	(cpu_to_le32(sg_dma_len(&_dmaio->sg[_ix])))

#ifdef DMA_IO_DEBUG_ON
static void azihsm_dma_io_dbg_dump(struct azihsm_dma_io *dma_io, bool dump_all)
/*
 * This function is just a debugging function.
 *
 *
 */
{
	u32 idx = 0;
	u32 tot_len = 0;

	AZIHSM_DEV_LOG_ENTRY(&dma_io->pdev->dev,
			     "%s: dma_io Dump\n"
			     "pg_sg_mem:%p\n"
			     "pages Array: %p\n"
			     "page_cnt:%u\n"
			     "sg:%p\n"
			     "sg_cnt:%d\n"
			     "uva: %p\n"
			     "ubuff_sz:%d\n"
			     "dir:%d\n"
			     "hw_sgl_mem_kva:%p\n"
			     "hw_sgl_mem_paddr:%llx\n"
			     "coh_mem_sz:%d\n"
			     "hw_seg_cnt:%d\n",
			     __func__, dma_io->pg_sg_mem, dma_io->pages,
			     dma_io->page_cnt, dma_io->sg, dma_io->hw_seg_cnt,
			     dma_io->uva, dma_io->ubuff_sz, dma_io->dir,
			     dma_io->hw_sgl_mem_kva, dma_io->hw_sgl_mem_paddr,
			     dma_io->coh_mem_sz, dma_io->hw_seg_cnt);

	if (false == dump_all)
		return;

	if (dma_io->pages && dma_io->page_cnt) {
		tot_len = 0;
		AZIHSM_LOG_DEBUG("OS SGL =======\n");

		for (idx = 0; idx < dma_io->sg_cnt; idx++) {
			AZIHSM_LOG_DEBUG(
				"sg[%d]: addr:%llx Len:%d", idx,
						azihsm_dma_io_get_sgle_paddr(dma_io, idx),
						azihsm_dma_io_get_sgle_len(dma_io, idx));

			tot_len += azihsm_dma_io_get_sgle_len(dma_io, idx);
		}
	}
	AZIHSM_LOG_DEBUG("OS SGL Dump Complete");

	/*
	 * Total DMA transfer that is being setup is
	 * using the SGL should be  same that what
	 * the user requested
	 */
	WARN_ON(tot_len != dma_io->ubuff_sz);

	if (dma_io->hw_sgl_mem_kva && dma_io->hw_seg_cnt) {
		AZIHSM_LOG_DEBUG(
			"TO DO: Dumping HW SGL Assmues contiguous memory\nHW Desc Dump =======\n");

		/*
		 * TO DO
		 * Entire memory is contiguous for the driver to access
		 * Later when we use page pool and the memory is not
		 * contiguous this will result in crash.
		 */
		struct azihsm_dma_io_sgl_desc *p_hw_desc =
			(struct azihsm_dma_io_sgl_desc *)dma_io->hw_sgl_mem_kva;

		tot_len = 0;
		for (idx = 0; idx < dma_io->sg_cnt; idx++) {
			AZIHSM_LOG_DEBUG(
				"sg[%d]: addr:%llx Len:%d DescType:%d DescSubType:%d", idx,
				p_hw_desc->addr, p_hw_desc->len,
				p_hw_desc->desc_type, p_hw_desc->desc_sub_type);

			tot_len += p_hw_desc->len;
			p_hw_desc++;
		}
		AZIHSM_LOG_DEBUG("HW SGL Dump Complete");
	}

	//
	// Total DMA transfer that is being setup
	// in HW Desc should be same that what
	// the user requested
	//
	WARN_ON(tot_len != dma_io->ubuff_sz);

AZIHSM_DEV_LOG_EXIT(&dma_io->pdev->dev, "DMA Buffer Dump Complete");
}
#endif

static int azihsm_dma_io_compute_pages(void *ubuff, u32 ubuff_sz)
{
	u32 n_pages = 0;
	unsigned long start = 0, end = 0, uaddr = 0, count = 0;

	uaddr = (unsigned long)ubuff;
	count = (unsigned long)ubuff_sz;

	end = (uaddr + count + PAGE_SIZE - 1) >> PAGE_SHIFT;
	start = uaddr >> PAGE_SHIFT;

	n_pages = end - start;
	return n_pages;
}

static void azihsm_dma_io_unpin_pages(struct azihsm_dma_io *dma_io)
{
	struct page *page = NULL;
	u32 i = 0;
	bool dirty = false;

	if (!dma_io)
		return;

	dirty = (dma_io->dir == DMA_FROM_DEVICE) ||
		(dma_io->dir == DMA_BIDIRECTIONAL);

#ifdef FOLL_PIN
	if (dma_io->page_cnt)
		unpin_user_pages_dirty_lock(dma_io->pages, dma_io->page_cnt,
					    dirty);

	i = 0;
	page = NULL;

#else
	for (i = 0; i < dma_io->page_cnt; i++) {
		page = dma_io->pages[i];
		if (page) {
			if (!PageReserved(page) && dirty)
				set_page_dirty_lock(page);

			put_page(page);
		}
	}
#endif

	dma_io->page_cnt = 0;
}

static void azihsm_dma_io_free_coh_mem(struct azihsm_dma_io *dma_io)
{
	if (dma_io->hw_sgl_mem_kva) {
		dma_free_coherent(&dma_io->pdev->dev, dma_io->coh_mem_sz,
				  dma_io->hw_sgl_mem_kva,
				  dma_io->hw_sgl_mem_paddr);

		dma_io->hw_sgl_mem_kva = NULL;
		dma_io->hw_sgl_mem_paddr = (dma_addr_t)NULL;
		dma_io->coh_mem_sz = 0;
	}
}

static int azihsm_dma_io_alloc_coh_mem(struct azihsm_dma_io *dma_io)
{
	u32 seg_cnt = 0;
	u32 data_desc_cnt_per_seg =
		(PAGE_SIZE / sizeof(struct azihsm_dma_io_sgl_desc)) - 1;

	/*
	 * How many segments would you need.
	 * Each segment is one page.
	 */
	seg_cnt = (dma_io->sg_cnt / data_desc_cnt_per_seg) + 1;

	// Total memory size
	dma_io->coh_mem_sz = (seg_cnt * PAGE_SIZE);

	dma_io->hw_sgl_mem_kva =
		dma_alloc_coherent(&dma_io->pdev->dev, dma_io->coh_mem_sz,
				   &dma_io->hw_sgl_mem_paddr, GFP_KERNEL);

	if (!dma_io->hw_sgl_mem_kva) {
		AZIHSM_DEV_LOG_ERROR(&dma_io->pdev->dev,
				     "%s: DMA alloc failure. size=%d", __func__,
				     dma_io->coh_mem_sz);

		return -ENOMEM;
	}

	return 0;
}

static int azihsm_dma_io_create_sgl(struct pci_dev *pdev,
				    struct azihsm_dma_io *dma_io)
{
	u32 first_pglen = 0;
	u32 first_pgoffset = 0;
	u32 pg_idx = 0;
	u32 sz_to_consume = dma_io->ubuff_sz;

	/*< Create the SGL table using the Page array */
	sg_init_table(dma_io->sg, dma_io->page_cnt);

	first_pgoffset = ((unsigned long)dma_io->uva) & ~PAGE_MASK;
	first_pglen = PAGE_SIZE - first_pgoffset;
	if (dma_io->page_cnt == 1)
		first_pglen = dma_io->ubuff_sz;

	/*< First page is special, cause you have to take care of the offset*/
	/*
	 *Set the first page in SGL
	 */
	sg_set_page(&dma_io->sg[pg_idx], // Pointer to the first SGL element
		    dma_io->pages[pg_idx], // Pointer to the fist page
		    first_pglen, // The length of the first page
		    first_pgoffset); // The offset of the first page

	/*< Update the index and consumed size */
	pg_idx++;
	sz_to_consume -= first_pglen;

	while (sz_to_consume > 0) {
		u32 curr_pg_sz = PAGE_SIZE;

		if (sz_to_consume < PAGE_SIZE)
			curr_pg_sz = sz_to_consume;

		/*
		 *Set the next page in SGL
		 */
		sg_set_page(
			&dma_io->sg[pg_idx], // Pointer to the SGL element
			dma_io->pages[pg_idx], // Pointer to the page
			curr_pg_sz, // The length of the data in this page
			0); // The offset which will only be non zero in first page

		pg_idx++;
		sz_to_consume -= curr_pg_sz;
	}

	/*< Lets just make sure that the above code worked as we wxpwected it to */
	BUG_ON(sz_to_consume != 0);

	dma_io->sg_cnt = dma_map_sg(&pdev->dev, dma_io->sg, dma_io->page_cnt,
				    dma_io->dir);

	if (dma_io->sg_cnt <= 0) {
		AZIHSM_DEV_LOG_ERROR(&pdev->dev,
				     "%s: dma_map_sg Failed [%d:%d][EIO]\n",
				     __func__, dma_io->sg_cnt,
				     dma_io->page_cnt);

		azihsm_dma_io_cleanup(dma_io);
		return -EIO;
	}

	return 0;
}

/**
 * Description:
 * This function performs three major operations
 * 1. Initialized the dma_io object with some basic information
 * 2. Pins the pages.
 * 3. Creates the SGL from the pinned pages.
 * 4. PCI map the SGL.
 * 4. Allocate the CPU and HW accessible coherent memory.
 *
 * Limitations:
 * This function must be called from the context of the user
 * mode process. This accesses the current pointer which
 * is only available from the context of the user mode process.
 *
 */
int azihsm_dma_io_init(
	struct pci_dev *pdev, void *uva, /*< user buffer vir addr*/
	u32 ubuff_sz, /*< size of the user buffer*/
	enum dma_data_direction dir, /*< DMA direction*/
	struct azihsm_dma_io *dma_io) /*< The DMA IO structure to prepare*/
{
	u32 pg_cnt = 0;
	int npages_pinned = 0;
	int rw_flags = 0;
	u32 sz_to_alloc = 0;
	int rc = 0;

	if (!pdev)
		return -EINVAL;

	if (!uva || !ubuff_sz || !dma_io) {
		AZIHSM_DEV_LOG_ERROR(&pdev->dev,
				     "%s: Invalid Arguments [EINVAL]\n",
				     __func__);

		return -EINVAL;
	}

	memset(dma_io, 0, sizeof(struct azihsm_dma_io));
	dma_io->pdev = pdev;
	dma_io->dir = dir;
	dma_io->uva = uva;
	dma_io->ubuff_sz = ubuff_sz;

	pg_cnt = azihsm_dma_io_compute_pages(uva, ubuff_sz);

	if (!pg_cnt || ((uva + ubuff_sz) < uva)) {
		AZIHSM_DEV_LOG_ERROR(
			&pdev->dev,
			"%s: Failed To Compute Pages Correctly [EINVAL]\n",
			__func__);

		return -EINVAL;
	}

	/*<If you need the write access */
	if (dir == DMA_BIDIRECTIONAL || dir == DMA_FROM_DEVICE)
		rw_flags = FOLL_WRITE;

	/*
	 * < Pin the pages and set the pages array
	 * From Kernel 5.6 onwards, you will have to use pin_user_page_fast rather than
	 * get user page fast.
	 * https://elixir.bootlin.com/linux/latest/source/mm/gup.c#L2178
	 * https://stackoverflow.com/questions/58413297/how-to-avoid-high-cpu-usage-while-reading-writing-character-device
	 */

	// The size of the scatter gather list that we need
	sz_to_alloc = sizeof(struct scatterlist) * pg_cnt;

	//Add the size of the page array that we need to allocate
	sz_to_alloc += sizeof(struct page *) * pg_cnt;

	dma_io->pg_sg_mem = kzalloc(sz_to_alloc, GFP_KERNEL);

	if (dma_io->pg_sg_mem == NULL)
		return -EIO;

	//
	// Point the pages and sg to their memory
	//
	dma_io->pages = (struct page **)dma_io->pg_sg_mem;
	dma_io->sg = (struct scatterlist *)(dma_io->pg_sg_mem +
					    (sizeof(struct page *) * pg_cnt));

#ifdef FOLL_PIN
	npages_pinned = pin_user_pages_fast((unsigned long)uva, pg_cnt,
					    rw_flags, dma_io->pages);
#else
	npages_pinned = get_user_pages_fast((unsigned long)uva, pg_cnt,
					    rw_flags, dma_io->pages);
#endif

	AZIHSM_DEV_LOG_INFO(&pdev->dev,
			    "%s: Pages Pinned [Requested:%d Pinned:%d] [EIO]\n",
			    __func__, pg_cnt, npages_pinned);

	// get_user_pages_fast can return a zero or negative values on invalid addresses
	if (npages_pinned <= 0) {
		AZIHSM_DEV_LOG_ERROR(
			&pdev->dev,
			"%s: Failed To Get User Pages [Requested:%d Error:%d] [EIO]\n",
			__func__, pg_cnt, npages_pinned);

		// Just free the memory and reutrn
		kfree(dma_io->pg_sg_mem);
		dma_io->pg_sg_mem = NULL;
		dma_io->pages = NULL;
		dma_io->sg = NULL;
		return -EIO;
	}

	dma_io->page_cnt = npages_pinned;

	if (npages_pinned < pg_cnt) {
		AZIHSM_DEV_LOG_ERROR(
			&pdev->dev,
			"%s: Failed Pinning Pages [Requested:%d Pinned:%d] [EIO]\n",
			__func__, pg_cnt, npages_pinned);

		azihsm_dma_io_cleanup(dma_io);
		return -EIO;
	}

	rc = azihsm_dma_io_create_sgl(pdev, dma_io);

	if (rc) {
		AZIHSM_DEV_LOG_ERROR(&pdev->dev,
				     "%s: Failed Creating SGL rc:%d\n",
				     __func__, rc);

		azihsm_dma_io_cleanup(dma_io);
		return rc;
	}

	AZIHSM_DEV_LOG_INFO(
		&pdev->dev,
		"%s: SGL Created With [Sge Cnt %d:Pg Cnt%d] Entries\n",
		__func__, dma_io->sg_cnt, dma_io->page_cnt);

	/*
	 * Allocate the memory for the hardware scatter gather
	 * and free it in finish. This memory will be a coherent
	 * memory accessible by both CPU and the hardware.
	 *
	 */
	rc = azihsm_dma_io_alloc_coh_mem(dma_io);
	if (rc) {
		AZIHSM_DEV_LOG_ERROR(&pdev->dev,
				     "%s: Coherent Mem Alloc Failed\n",
				     __func__);

		azihsm_dma_io_cleanup(dma_io);
		return rc;
	}

	AZIHSM_DEV_LOG_INFO(&pdev->dev, "%s: Done Success\n", __func__);

	return rc;
}

void azihsm_dma_io_cleanup(struct azihsm_dma_io *dma_io)
{
	/*
	 * Before you unpin the pages, unmap the
	 * pci mapping.
	 */
	if (dma_io->sg_cnt > 0) {
		dma_unmap_sg(&dma_io->pdev->dev, dma_io->sg, dma_io->sg_cnt,
			     dma_io->dir);

		dma_io->sg_cnt = 0;
	}

	/*
	 * If there are any pages pinned,
	 * unpin them
	 */
	azihsm_dma_io_unpin_pages(dma_io);

	/*
	 * free the memory that we allocated for
	 * the pages pointer array and the sg list
	 */
	kfree(dma_io->pg_sg_mem);
	dma_io->pg_sg_mem = NULL;
	dma_io->sg = NULL;
	dma_io->pages = NULL;

	/*
	 * Free the coherent memory that you
	 * allocated.
	 */
	azihsm_dma_io_free_coh_mem(dma_io);

	// Clear the entire structure
	memset(dma_io, 0, sizeof(struct azihsm_dma_io));
}

/**
 * @brief This function takes the SGL present in dma_io
 * and translates it to hardware specific sgl.
 *
 * This function assumes that the following are true:
 * 1. The SGL is already created in dma_io->sg
 * 2. The coherent memory to create the hw specific sgl
 *	  is already allocated.
 *
 * If the function detects error, it will not perform cleanup
 * but it will return a error.
 */
int azihsm_dma_io_xlat(struct azihsm_dma_io *dma_io)
{
	u32 desc_cnt_per_seg =
		PAGE_SIZE / sizeof(struct azihsm_dma_io_sgl_desc);
	u32 data_desc_cnt_per_seg = desc_cnt_per_seg - 1;
	u32 rem_eles = 0; // Remaining elements which we are suppose to process
	u32 sys_sgl_idx = 0; // Index in to system SGL
	u32 hw_sgl_idx = 0; // Index in to translated sgl
	u32 seg_idx = 0; // Index in to segments
	u32 xfer_len_done = 0; // Total length translated
	u32 sgl_desc_to_process = 0;
	bool last_seg = false;
	u32 next_desc_len = 0;
	u64 next_seg_addr = 0;

	struct azihsm_dma_io_sgl_seg *seg_base =
		(struct azihsm_dma_io_sgl_seg *)dma_io->hw_sgl_mem_kva;
	struct azihsm_dma_io_sgl_seg *seg_curr = NULL;
	struct azihsm_dma_io_sgl_desc *hw_sgl_desc_crr = NULL;

	if (!dma_io || !dma_io->hw_sgl_mem_kva || !dma_io->sg_cnt) {
		AZIHSM_DEV_LOG_ERROR(
			&dma_io->pdev->dev,
			"%s: DMA_IO not initialized to create HW SGL [EINVAL]\n",
			__func__);

		return -EINVAL;
	}

	// We have to add all the pci mapped sgl entries in to the
	// hardware SGL
	rem_eles = dma_io->sg_cnt;

	while (rem_eles) {
		hw_sgl_idx = 0;

		seg_curr = &seg_base[seg_idx];

		// Clear the segment
		memset(seg_curr, 0, sizeof(struct azihsm_dma_io_sgl_seg));

		// Start from the first Scatter Gather Element Of The Segment
		// and populate the entire segment
		hw_sgl_desc_crr = &seg_curr->sgl_ele[0];
		sgl_desc_to_process = MCR_MIN(rem_eles, data_desc_cnt_per_seg);

		for (; hw_sgl_idx < sgl_desc_to_process; hw_sgl_idx++) {
			hw_sgl_desc_crr->addr = azihsm_dma_io_get_sgle_paddr(
				dma_io, sys_sgl_idx);
			hw_sgl_desc_crr->len =
				azihsm_dma_io_get_sgle_len(dma_io, sys_sgl_idx);
			hw_sgl_desc_crr->desc_type =
				AZIHSM_SGL_DESCR_TYPE_DATA_BLOCK;
			hw_sgl_desc_crr->desc_sub_type =
				AZIHSM_SGL_DESCR_SUBTYPE_ADDRESS;

			xfer_len_done += hw_sgl_desc_crr->len;
			hw_sgl_desc_crr++;
			sys_sgl_idx++;
			rem_eles--;
		}

		/*
		 * When you come out of the for loop, at max 255 descirptors will
		 * be populated in the segment. Now the last descriptor could be a
		 * AZIHSM_SGL_DESCR_TYPE_LAST_SEGMENT indicating that the next segment is the last
		 * segment or it would be a AZIHSM_SGL_DESCR_TYPE_SEGMENT indicating that
		 * there are more segments to follow.
		 */

		if (rem_eles) {
			/*
			 * Next descriptor will always be page size unless it
			 * is the last descripptor
			 */
			next_desc_len = PAGE_SIZE;

			last_seg = (rem_eles <= data_desc_cnt_per_seg);

			if (last_seg) {
				/*
				 * If we are going to add the last segment descriptor
				 * we will have to set the length to the size of
				 * all the remaining NVME_SGL_DESCRIPTORs that are
				 * going to be inserted in the last segment. This is
				 * the only way for the hardware to pull the last page.
				 */
				next_desc_len =
					rem_eles *
					sizeof(struct azihsm_dma_io_sgl_desc);
			}

			//Point to the next segment
			seg_idx++;

			// Put the address of the next segment
			next_seg_addr = (u64)dma_io->hw_sgl_mem_paddr +
					((u64)seg_idx * PAGE_SIZE);

			hw_sgl_desc_crr->addr = next_seg_addr;
			hw_sgl_desc_crr->len = next_desc_len;
			hw_sgl_desc_crr->desc_type =
				(last_seg) ?
					AZIHSM_SGL_DESCR_TYPE_LAST_SEGMENT :
					AZIHSM_SGL_DESCR_TYPE_SEGMENT;

			hw_sgl_desc_crr->desc_sub_type =
				AZIHSM_SGL_DESCR_SUBTYPE_ADDRESS;
		} //if(rem_eles)
	}

	if (xfer_len_done != dma_io->ubuff_sz) {
		AZIHSM_DEV_LOG_ERROR(
			&dma_io->pdev->dev,
			"%s: SGL created For Sz:%d Should Have been :%d\n",
			__func__, xfer_len_done, dma_io->ubuff_sz);

		return -EIO;
	}

	/*
	 * Save the number of segments created
	 * a 1 based value.
	 */
	dma_io->hw_seg_cnt = seg_idx + 1;

#ifdef DMA_IO_DEBUG_ON
	azihsm_dma_io_dbg_dump(dma_io, true);
#endif

	return 0;
}
