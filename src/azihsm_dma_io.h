/* SPDX-License-Identifier: GPL-2.0 */

#ifndef _AZIHSM_DMA_IO_HEADER_
#define _AZIHSM_DMA_IO_HEADER_

#include <linux/kernel.h>
#include <linux/pci.h>
#include <linux/device.h>
#include <linux/errno.h>
#include <linux/dma-mapping.h>
#include <linux/dma-direction.h>

#define MC_DMA_IO_SGL_DESC_SZ 16

enum azihsm_dma_io_sgl_desc_type {
	AZIHSM_SGL_DESCR_TYPE_DATA_BLOCK = (u8)0x0,
	AZIHSM_SGL_DESCR_TYPE_BIT_BUCKET = (u8)0x1,
	AZIHSM_SGL_DESCR_TYPE_SEGMENT = (u8)0x2,
	AZIHSM_SGL_DESCR_TYPE_LAST_SEGMENT = (u8)0x3,
	AZIHSM_SGL_DESCR_TYPE_KEYED_DATA_BLOCK = (u8)0x4,
	AZIHSM_SGL_DESCR_TYPE_VENDOR_SPECIFIC = (u8)0xf,
};

enum azihsm_dma_io_sgl_desc_sub_type {
	AZIHSM_SGL_DESCR_SUBTYPE_ADDRESS = (u8)0x0,
};

struct azihsm_dma_io_sgl_desc {
	u64 addr;
	u32 len;
	u8 Rsvd[3];

	u8 desc_sub_type : 4;
	u8 desc_type : 4;
};

static_assert(sizeof(struct azihsm_dma_io_sgl_desc) == MC_DMA_IO_SGL_DESC_SZ);

//
// Just define how the Segment Looks like.
// Will make the code easy to write and read
//
struct azihsm_dma_io_sgl_seg {
	struct azihsm_dma_io_sgl_desc
		sgl_ele[PAGE_SIZE / sizeof(struct azihsm_dma_io_sgl_desc)];
};
static_assert(sizeof(struct azihsm_dma_io_sgl_seg) == PAGE_SIZE);

struct azihsm_dma_io {
	struct pci_dev *pdev;
	u8 *pg_sg_mem; /*<  Only CPU access memory for scatterlist and page array */
	struct page **pages; /*< The pages array describing the user buffer */
	u32 page_cnt; /*< The number of pages pinned  */

	struct scatterlist *sg; /*< The scatter gather list */
	u32 sg_cnt; /*< number of elements in the sg list */

	void *uva; /*< User mode Virtual Address */
	u32 ubuff_sz; /*< User Buffer Size */
	enum dma_data_direction dir;

	void *hw_sgl_mem_kva; /*< The memory that is allocated to create hw sgl */
	dma_addr_t hw_sgl_mem_paddr; /*< device accessible address for SGL*/
	u32 coh_mem_sz; /*< The size of the coherent memory*/
	u32 hw_seg_cnt; /*< Number of SG segments created*/
};

int azihsm_dma_io_init(struct pci_dev *pdev, void *uva, u32 user_buff_sz,
		       enum dma_data_direction dir,
		       struct azihsm_dma_io *dma_io);

int azihsm_dma_io_xlat(struct azihsm_dma_io *dma_io);

void azihsm_dma_io_cleanup(struct azihsm_dma_io *dma_io);

#endif
