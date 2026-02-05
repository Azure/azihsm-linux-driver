// SPDX-License-Identifier: GPL-2.0

#include <linux/module.h>

#include "azihsm.h"

#define PCI_VENDOR_ID_MSFT 0x1414
#define PCI_DEVICE_ID_MCR 0xC003
#define BAR0_LEN SZ_4K
#define BAR2_LEN SZ_4K
#define BAR4_LEN SZ_4K
#define MIN_MSIX_CNT 3
#define MAX_MSIX_CNT 32
#define AZIHSM_DEFAULT_ABORT_TIMEOUT_IN_SECS (6) /* seconds */

/*
 * by default log_mask is configured to always log
 * errors
 */
unsigned int log_mask = AZIHSM_LOG_LEVEL_ERROR;
module_param(log_mask, uint, 0644);
MODULE_PARM_DESC(log_mask, "Log level mask for controlling logging output");

/**
 * module parameter :- abort_timeout_in_sec
 * Driver parameter :- azihsm_abort_timeout_in_sec
 *
 * Default value is AZIHSM_DEFAULT_ABORT_TIMEOUT
 * timeout for HSM and AES commands submitted to device (in seconds)
 * If commands do not complete within this timeout period,
 * level 1 abort is initiated on the queue.
 *
 * Applies to both PF and VF
 */
static int azihsm_abort_timeout_in_sec = AZIHSM_DEFAULT_ABORT_TIMEOUT_IN_SECS;
module_param_named(abort_timeout_in_sec, azihsm_abort_timeout_in_sec, int,
		   0444);
MODULE_PARM_DESC(abort_timeout_in_sec, "MCR abort timeout in seconds");

/**
 * abort timeout in jiffies.
 * converted from seconds to jiffies
 * seconds are provided by user via module parameter
 * or default
 */
int azihsm_abort_timeout_in_jiffies;

/**
 * module parameter :- pf_lvl2_abort_enabled
 *  Driver parameter :- azihsm_pf_lvl2_abort_enabled
 *
 * Default value is true
 * If PF and set to TRUE, when level 1 abort fails
 * level 2 abort is initiated.
 * Otherwise level 2 abort is not initiated.
 *
 * Note this parameter has no effect on a VF driver
 */
bool azihsm_pf_lvl2_abort_enabled = true;
module_param_named(pf_lvl2_abort_enabled, azihsm_pf_lvl2_abort_enabled, bool,
		   0444);
MODULE_PARM_DESC(pf_lvl2_abort_enabled, "PF uses level 2 abort if true");

/**
 * module parameter :- num_hsm_slots
 * Driver parameter is azihsm_num_hsm_slots
 * Number of slots in each HSM queue
 * All HSM queues will have the same number of slots
 * Default value is 16
 */
int azihsm_num_hsm_slots = 16;
module_param_named(num_hsm_slots, azihsm_num_hsm_slots, int, 0444);
MODULE_PARM_DESC(num_hsm_slots, "Number of slots in each HSM queue");

/**
 * module parameter :- num_aes_slots
 * Driver parameter is azihsm_num_aes_slots
 * Number of slots in each AES queue
 * All AES queues will have the same number of slots
 * Default value is 16
 */
int azihsm_num_aes_slots = 16;
module_param_named(num_aes_slots, azihsm_num_aes_slots, int, 0444);
MODULE_PARM_DESC(num_aes_slots, "Number of slots in each AES queue");

static const char azihsm_driver_name[] = "azihsm";

static bool azihsm_is_pf(struct pci_dev *pdev)
{
	int ret = pci_find_ext_capability(pdev, PCI_EXT_CAP_ID_SRIOV);

	return ret ? true : false;
}

static int azihsm_remap_bars(struct pci_dev *pdev)
{
	int err;
	struct azihsm_dev *mdev = pci_get_drvdata(pdev);

	if (pci_resource_len(pdev, 0) != BAR0_LEN) {
		err = -ENOMEM;
		AZIHSM_DEV_LOG_ERROR(&pdev->dev, "Invalid BAR0 size\n");
		goto invalid_bar0;
	}

	mdev->bar0 = ioremap(pci_resource_start(pdev, 0), BAR0_LEN);
	if (!mdev->bar0) {
		err = -ENOMEM;
		AZIHSM_DEV_LOG_ERROR(&pdev->dev, "BAR0 remap error\n");
		goto invalid_bar0;
	}

	if (pci_resource_len(pdev, 2) != BAR2_LEN) {
		err = -ENOMEM;
		AZIHSM_DEV_LOG_ERROR(&pdev->dev, "Invalid BAR2 size\n");
		goto invalid_bar2;
	}

	mdev->bar2 = ioremap(pci_resource_start(pdev, 2), BAR2_LEN);
	if (!mdev->bar2) {
		err = -ENOMEM;
		AZIHSM_DEV_LOG_ERROR(&pdev->dev, "BAR2 remap error\n");
		goto invalid_bar2;
	}

	if (pci_resource_len(pdev, 4) != BAR4_LEN) {
		err = -ENOMEM;
		AZIHSM_DEV_LOG_ERROR(&pdev->dev, "Invalid BAR4 size\n");
		goto invalid_bar4;
	}

	mdev->bar4 = ioremap(pci_resource_start(pdev, 4), BAR4_LEN);
	if (!mdev->bar4) {
		err = -ENOMEM;
		AZIHSM_DEV_LOG_ERROR(&pdev->dev, "BAR4 remap error\n");
		goto invalid_bar4;
	}

	return 0;

invalid_bar4:
	iounmap(mdev->bar2);
	mdev->bar2 = NULL;
invalid_bar2:
	iounmap(mdev->bar0);
	mdev->bar0 = NULL;
invalid_bar0:
	return err;
}

static void azihsm_unmap_bars(struct pci_dev *pdev)
{
	struct azihsm_dev *mdev = pci_get_drvdata(pdev);

	if (mdev->bar0 != NULL) {
		iounmap(mdev->bar0);
		mdev->bar0 = NULL;
	}

	if (mdev->bar2 != NULL) {
		iounmap(mdev->bar2);
		mdev->bar2 = NULL;
	}

	if (mdev->bar4 != NULL) {
		iounmap(mdev->bar4);
		mdev->bar4 = NULL;
	}
}

/**
 * azihsm_alloc_vf_context
 * Allocates context for all the VFs that are configured
 * by system FW(BIOS) on this device.
 * This function is a no-op if the PF does not support
 * SRIOV, SRIOV is not configured or this is invoked on a VF
 *
 * Return value :- None
 * The context must be freed when the driver is unloaded
 */
static void azihsm_alloc_vf_context(struct pci_dev *pdev,
				    struct azihsm_mgmt *mgmt)
{
	int pos;
	u16 vfid;

	mgmt->vf_context = NULL;
	pos = pci_find_ext_capability(pdev, PCI_EXT_CAP_ID_SRIOV);
	if (pos) {
		/* read the registers we care about */
		pci_read_config_word(pdev, pos + PCI_SRIOV_CTRL,
				     &mgmt->pf_sriov_ctrl_reg);
		pci_read_config_word(pdev, pos + PCI_SRIOV_TOTAL_VF,
				     &mgmt->pf_sriov_total_vf_reg);
		pci_read_config_word(pdev, pos + PCI_SRIOV_NUM_VF,
				     &mgmt->pf_sriov_num_vf_reg);

		AZIHSM_DEV_LOG_INFO(
			&pdev->dev,
			"[%s]: mgmt:%p Found SRIOV cap at offset:%d ctrl_reg:0x%x TotalVFs:%d NumVFs:%d\n",
			__func__, mgmt, pos, mgmt->pf_sriov_ctrl_reg,
			mgmt->pf_sriov_total_vf_reg, mgmt->pf_sriov_num_vf_reg);

		if (mgmt->pf_sriov_num_vf_reg) {
			mgmt->vf_context =
				kcalloc(mgmt->pf_sriov_num_vf_reg,
					sizeof(struct azihsm_per_vf_context),
					GFP_KERNEL);
			if (!mgmt->vf_context)
				return;
			/*
			 * initialize the controller id for each vf
			 * Note. The mapping of controller id to vf is
			 * fixed for now (Controller id is vfid+1)
			 * Later we may have an interface that the FW provides
			 * to retrieve these mappings
			 * Resoure count has to be set via management app
			 */
			for (vfid = 0; vfid < mgmt->pf_sriov_num_vf_reg;
			     vfid++) {
				mgmt->vf_context[vfid].ctrl_id = vfid + 1;
			}
		}
	}
}

static int azihsm_probe(struct pci_dev *pdev, const struct pci_device_id *id)
{
	int err, irq_cnt;
	struct azihsm_dev *mdev;
	struct azihsm_ctrl_cfg ctrl_cfg = { 0 };

	AZIHSM_DEV_LOG_ENTRY(&pdev->dev, "[ENTRY] pdev:%p driver version %s\n",
			     pdev, AZIHSM_DRIVER_VERSION);

	err = pci_enable_device_mem(pdev);
	if (err) {
		AZIHSM_DEV_LOG_ERROR(&pdev->dev,
				     "MMIO initialization failed\n");
		goto fail;
	}

	err = dma_set_mask_and_coherent(&pdev->dev, DMA_BIT_MASK(64));
	if (err) {
		AZIHSM_DEV_LOG_ERROR(
			&pdev->dev, "64-bit DMA configuration failed pdev:%p\n",
			pdev);
		goto dma_set_mask_fail;
	}

	err = pci_request_mem_regions(pdev, azihsm_driver_name);
	if (err) {
		AZIHSM_DEV_LOG_ERROR(&pdev->dev,
				     "Memory region discovery failed pdev:%p\n",
				     pdev);
		goto dma_set_mask_fail;
	}

	pci_set_master(pdev);

	mdev = kzalloc(sizeof(*mdev), GFP_KERNEL);
	if (!mdev) {
		err = -ENOMEM;
		AZIHSM_DEV_LOG_ERROR(&pdev->dev,
				     "Device alloc failure pdev:%p\n", pdev);
		goto mdev_fail;
	}

	pci_set_drvdata(pdev, mdev);
	mdev->pdev = pdev;

	err = azihsm_remap_bars(pdev);
	if (err) {
		AZIHSM_DEV_LOG_ERROR(
			&pdev->dev, "azihsm_remap_bars failed pdev:%p\n", pdev);
		goto remap_fail;
	}

	irq_cnt = pci_alloc_irq_vectors(pdev, MIN_MSIX_CNT, MAX_MSIX_CNT,
					PCI_IRQ_MSIX);
	if (irq_cnt < 0) {
		err = irq_cnt;
		AZIHSM_DEV_LOG_ERROR(&pdev->dev,
				     "PCI alloc IRQ failure, pdev:%p err=%d\n",
				     pdev, err);
		goto alloc_irq_fail;
	}

	mdev->irq_cnt = irq_cnt;

	ctrl_cfg.pdev = pdev;
	ctrl_cfg.ctrl_reg = mdev->bar0;
	ctrl_cfg.db_reg = mdev->bar2;
	ctrl_cfg.irq_cnt = mdev->irq_cnt;
	ctrl_cfg.is_pf = azihsm_is_pf(pdev);
	mdev->mgmt.pdev = pdev;
	if (ctrl_cfg.is_pf) {
		mdev->mgmt.is_pf = true;
		azihsm_alloc_vf_context(pdev, &mdev->mgmt);

		/*
		 * light up the management interface once
		 * VF context can be allocated
		 * TODO. What should be the policy to load the
		 * driver if the management interface cannot be
		 * lighted up.
		 */
		if (mdev->mgmt.vf_context)
			(void)azihsm_mgmt_if_dev_init(&mdev->mgmt, false);
	}

	/* save away the config we are using. We will need this for level 2 abort*/
	mdev->ctrl.saved_cfg = ctrl_cfg;

	err = azihsm_ctrl_init(&mdev->ctrl, &ctrl_cfg, false);
	if (err) {
		AZIHSM_DEV_LOG_ERROR(&pdev->dev,
				     "azihsm_ctrl_init failed pdev:%p err=%d\n",
				     pdev, err);
		goto ctrl_init_fail;
	}

	AZIHSM_DEV_LOG_EXIT(&pdev->dev, "[EXIT] pdev:%p driver version %s\n",
			    pdev, AZIHSM_DRIVER_VERSION);

	return 0;

ctrl_init_fail:
	pci_free_irq_vectors(pdev);
alloc_irq_fail:
	azihsm_unmap_bars(pdev);
remap_fail:
	kfree(mdev);
mdev_fail:
	pci_release_mem_regions(pdev);
dma_set_mask_fail:
	pci_disable_device(pdev);
fail:
	return err;
}

static void azihsm_remove(struct pci_dev *pdev)
{
	struct azihsm_dev *mdev = pci_get_drvdata(pdev);

	AZIHSM_DEV_LOG_ENTRY(&pdev->dev, "%s pdev:%p mdev:%p\n", __func__, pdev,
			     mdev);

	azihsm_ctrl_deinit(&mdev->ctrl, false, ABORT_TYPE_TIMEOUT);
	if (mdev->mgmt.vf_context)
		azihsm_mgmt_if_dev_deinit(&mdev->mgmt, false);
	pci_free_irq_vectors(pdev);
	azihsm_unmap_bars(pdev);
	pci_set_drvdata(pdev, NULL);
	if (mdev->mgmt.vf_context != NULL) {
		kfree(mdev->mgmt.vf_context);
		mdev->mgmt.vf_context = NULL;
	}
	kfree(mdev);
	pci_release_mem_regions(pdev);
	pci_disable_device(pdev);
}

static void azihsm_shutdown(struct pci_dev *pdev)
{
	struct azihsm_dev *mdev = pci_get_drvdata(pdev);

	AZIHSM_DEV_LOG_ENTRY(&pdev->dev, "pdev:%p\n", pdev);
	azihsm_ctrl_hw_disable(&mdev->ctrl);
	pci_set_drvdata(pdev, NULL);
	pci_release_mem_regions(pdev);
	pci_disable_device(pdev);
	AZIHSM_DEV_LOG_EXIT(&pdev->dev, "pdev:%p\n", pdev);
}

static const struct pci_device_id azihsm_id_table[] = {
	{ PCI_DEVICE(PCI_VENDOR_ID_MSFT, PCI_DEVICE_ID_MCR) },
	{ 0 },
};

MODULE_DEVICE_TABLE(pci, azihsm_id_table);

static struct pci_driver azihsm_driver = {
	.name = azihsm_driver_name,
	.id_table = azihsm_id_table,
	.probe = azihsm_probe,
	.remove = azihsm_remove,
	.shutdown = azihsm_shutdown,
	.sriov_configure = pci_sriov_configure_simple,
};

static int __init azihsm_init(void)
{
	int err;

	AZIHSM_LOG_ENTRY("%s", __func__);

	/*
	 * adjust the timeout if required
	 * the minimum is defined in
	 * AZIHSM_DEFAULT_ABORT_TIMEOUT_IN_SECS
	 */
	if (azihsm_abort_timeout_in_sec < AZIHSM_DEFAULT_ABORT_TIMEOUT_IN_SECS)
		azihsm_abort_timeout_in_sec =
			AZIHSM_DEFAULT_ABORT_TIMEOUT_IN_SECS;

	azihsm_abort_timeout_in_jiffies =
		msecs_to_jiffies(azihsm_abort_timeout_in_sec * 1000);

	/*
	 * Protect against user misprogramming of module parameters
	 * On hvlite, any value less than 2 causes command completion to not
	 * happen.
	 */
	if (azihsm_num_hsm_slots < 2)
		azihsm_num_hsm_slots = 2;

	if (azihsm_num_aes_slots < 2)
		azihsm_num_aes_slots = 2;

	AZIHSM_LOG_INFO(
		"azihsm command timeout in secs[%d] in jiffies[%d] pf level2 enabled[%s] #of HSM slots[%d] #of AES slots[%d]\n",
		azihsm_abort_timeout_in_sec, azihsm_abort_timeout_in_jiffies,
		azihsm_pf_lvl2_abort_enabled ? "YES" : "NO",
		azihsm_num_hsm_slots, azihsm_num_aes_slots);

	/* initialize the management interface */
	err = azihsm_mgmt_if_dev_mod_init();
	if (err) {
		AZIHSM_LOG_ERROR(
			"[ERROR] %s azihsm_mgmt_if_init failed err:%d\n",
			__func__, err);
		goto err;
	}

	err = azihsm_hsm_dev_mod_init();
	if (err) {
		AZIHSM_LOG_ERROR(
			"[ERROR] %s azihsm_hsm_dev_mod_init failed err:%d\n",
			__func__, err);
		goto err;
	}

	err = pci_register_driver(&azihsm_driver);
	if (err) {
		AZIHSM_LOG_ERROR(
			"[ERROR] %s pci_register_driver failed err:%d\n",
			__func__, err);
		goto err;
	}

	AZIHSM_LOG_EXIT("%s\n", __func__);
	return 0;

err:
	return err;
}

static void __exit azihsm_exit(void)
{
	AZIHSM_LOG_ENTRY("%s\n", __func__);
	pci_unregister_driver(&azihsm_driver);
	azihsm_hsm_dev_mod_exit();
	azihsm_mgmt_if_dev_mod_exit();
	AZIHSM_LOG_EXIT("%s\n", __func__);
}

module_init(azihsm_init);
module_exit(azihsm_exit);

MODULE_AUTHOR(
	"Vishal Soni <vsoni@microsoft.com>, Ajitabh Saxena <ajisaxena@microsoft.com>, RK Saripalli <rsaripalli@microsoft.com>");
MODULE_DESCRIPTION("Azure Integrated HSM Driver");
MODULE_LICENSE("GPL");
MODULE_VERSION(AZIHSM_DRIVER_VERSION);
