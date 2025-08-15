// SPDX-License-Identifier: GPL-2.0
#include "azihsm_mgmt.h"
#include "azihsm_ctrl_cmd.h"
#include "azihsm.h"
#include "azihsm_mgmt_dev_ioctl.h"

#include <linux/idr.h>
#include <linux/uaccess.h>
#include <linux/version.h>

static struct class *azihsm_mgmt_if_dev_class;
static unsigned int azihsm_mgmt_if_dev_major;
static DEFINE_IDA(azihsm_mgmt_if_dev_ida);

static int azihsm_mgmt_dev_get_res_cnt(struct azihsm_mgmt *mgmt,
				       unsigned long arg)
{
	int err;
	struct azihsm_mgmt_if_res_cnt info;
	size_t min_size = offsetofend(struct azihsm_mgmt_if_res_cnt, status);
	struct azihsm_dev *azihsmdev =
		container_of(mgmt, struct azihsm_dev, mgmt);

	AZIHSM_DEV_LOG_ENTRY(mgmt->cdev_dev, "[ENTRY] %s azihsm_mgmt:%p",
			     __func__, mgmt);

	if (copy_from_user(&info, (void __user *)arg, min_size)) {
		err = -EFAULT;
		AZIHSM_DEV_LOG_ERROR(mgmt->cdev_dev,
				     "[%s] copy from user failed", __func__);
		goto err;
	}

	if (info.argsz < sizeof(info)) {
		err = -EINVAL;
		AZIHSM_DEV_LOG_ERROR(mgmt->cdev_dev, "[%s] invalid arg size",
				     __func__);
		goto err;
	}

	/* Not PF or vf context is not allocated
	 */
	if ((false == mgmt->is_pf) || (mgmt->vf_context == NULL)) {
		info.status = AZIHSM_MGMT_STATUS_NOT_PF;
		err = -EINVAL;
		AZIHSM_DEV_LOG_ERROR(
			mgmt->cdev_dev,
			"[%s] Operation not supported on a non-PF\n", __func__);
		goto error;
	}

	/* validate the VF index */
	if (info.vf_idx >= mgmt->pf_sriov_num_vf_reg) {
		info.status = AZIHSM_MGMT_STATUS_INVALID_VF_IDX;
		err = -EINVAL;
		AZIHSM_DEV_LOG_ERROR(mgmt->cdev_dev,
				     "[%s] Invalid PF index[%d] NumVFs:%d\n",
				     __func__, info.vf_idx,
				     mgmt->pf_sriov_num_vf_reg);
		goto error;
	}

	err = azihsm_ctrl_cmd_get_res_cnt(&azihsmdev->ctrl,
					  mgmt->vf_context[info.vf_idx].ctrl_id,
					  &info.res_cnt);
	if (err) {
		info.status = AZIHSM_IOCTL_MGMT_STATUS_GET_RES_CNT_FAILED;
		AZIHSM_DEV_LOG_ERROR(mgmt->cdev_dev,
				     "[%s] GET_RESOURCE_CNT failed. VF[%d]\n",
				     __func__, info.vf_idx);
	} else {
		info.status = AZIHSM_MGMT_STATUS_SUCCESS;
		AZIHSM_DEV_LOG_INFO(
			mgmt->cdev_dev,
			"[%s] GET_RESOURCE_CNT SUCCESS. VF[%d] resource cnt[%d]\n",
			__func__, info.vf_idx, info.res_cnt);
	}

error:

	if (copy_to_user((void __user *)arg, &info, min_size)) {
		err = -EFAULT;
		AZIHSM_DEV_LOG_ERROR(mgmt->cdev_dev, "[%s] copy to user failed",
				     __func__);
		goto err;
	}

	AZIHSM_DEV_LOG_EXIT(mgmt->cdev_dev, "[EXIT] %s azihsm_mgmt:%p",
			    __func__, mgmt);

err:
	return err;
}

static int azihsm_mgmt_dev_set_res_cnt(struct azihsm_mgmt *mgmt,
				       unsigned long arg)
{
	int err;
	struct azihsm_mgmt_if_res_cnt info;
	size_t min_size = offsetofend(struct azihsm_mgmt_if_res_cnt, status);
	struct azihsm_dev *azihsmdev =
		container_of(mgmt, struct azihsm_dev, mgmt);

	AZIHSM_DEV_LOG_ENTRY(mgmt->cdev_dev, "[ENTRY] %s azihsm_mgmt:%p",
			     __func__, mgmt);

	if (copy_from_user(&info, (void __user *)arg, min_size)) {
		err = -EFAULT;
		AZIHSM_DEV_LOG_ERROR(mgmt->cdev_dev,
				     "[%s] copy from user failed", __func__);
		goto err;
	}

	if (info.argsz < sizeof(info)) {
		err = -EINVAL;
		AZIHSM_DEV_LOG_ERROR(mgmt->cdev_dev, "[%s] invalid arg size",
				     __func__);
		goto err;
	}

	/* Not PF or vf context is not allocated
	 */
	if ((false == mgmt->is_pf) || (mgmt->vf_context == NULL)) {
		info.status = AZIHSM_MGMT_STATUS_NOT_PF;
		err = -EINVAL;
		AZIHSM_DEV_LOG_ERROR(
			mgmt->cdev_dev,
			"[%s] Operation not supported on a non-PF\n", __func__);
		goto error;
	}

	/* validate the VF index */
	if (info.vf_idx >= mgmt->pf_sriov_num_vf_reg) {
		info.status = AZIHSM_MGMT_STATUS_INVALID_VF_IDX;
		err = -EINVAL;
		AZIHSM_DEV_LOG_ERROR(mgmt->cdev_dev,
				     "[%s] Invalid PF index[%d]\n", __func__,
				     info.vf_idx);
		goto error;
	}

	err = azihsm_ctrl_cmd_set_res_cnt(&azihsmdev->ctrl,
					  mgmt->vf_context[info.vf_idx].ctrl_id,
					  info.res_cnt);
	if (err) {
		info.status = AZIHSM_MGMT_STATUS_SET_RES_CNT_FAILED;
		AZIHSM_DEV_LOG_ERROR(
			mgmt->cdev_dev,
			"[%s] SET_RESOURCE_CNT failed. VF[%d] resource cnt[%d]\n",
			__func__, info.vf_idx, info.res_cnt);
	} else {
		info.status = AZIHSM_MGMT_STATUS_SUCCESS;
		AZIHSM_DEV_LOG_INFO(
			mgmt->cdev_dev,
			"[%s] SET_RESOURCE_CNT SUCCESS. VF[%d] resource cnt[%d]\n",
			__func__, info.vf_idx, info.res_cnt);
	}

error:

	if (copy_to_user((void __user *)arg, &info, min_size)) {
		err = -EFAULT;
		AZIHSM_DEV_LOG_ERROR(mgmt->cdev_dev, "[%s] copy to user failed",
				     __func__);
		goto err;
	}

	AZIHSM_DEV_LOG_EXIT(mgmt->cdev_dev, "[EXIT] %s azihsm_mgmt:%p",
			    __func__, mgmt);

err:
	return err;
}

static int azihsm_mgmt_dev_get_vf_count(struct azihsm_mgmt *mgmt,
					unsigned long arg)
{
	int err = 0;
	struct azihsm_mgmt_if_get_vf_count info;
	size_t min_size =
		offsetofend(struct azihsm_mgmt_if_get_vf_count, vf_count);

	AZIHSM_DEV_LOG_ENTRY(mgmt->cdev_dev, "[ENTRY] %s azihsm_mgmt:%p",
			     __func__, mgmt);

	if (copy_from_user(&info, (void __user *)arg, min_size)) {
		err = -EFAULT;
		AZIHSM_DEV_LOG_ERROR(mgmt->cdev_dev,
				     "[MGMT:%s] copy from user failed",
				     __func__);
		goto err;
	}

	if (info.argsz < sizeof(info)) {
		err = -EINVAL;
		AZIHSM_DEV_LOG_ERROR(mgmt->cdev_dev, "[%s] invalid arg size",
				     __func__);
		goto err;
	}

	/* Not PF or vf context is not allocated
	 */
	if ((false == mgmt->is_pf) || (mgmt->vf_context == NULL)) {
		err = -EINVAL;
		AZIHSM_DEV_LOG_ERROR(
			mgmt->cdev_dev,
			"[%s] Operation not supported on a non-PF\n", __func__);
		goto error;
	}

	info.vf_count = mgmt->pf_sriov_num_vf_reg;
	AZIHSM_DEV_LOG_INFO(mgmt->cdev_dev, "[%s] # of VF[%d]\n", __func__,
			    info.vf_count);
error:

	if (copy_to_user((void __user *)arg, &info, min_size)) {
		err = -EFAULT;
		AZIHSM_DEV_LOG_ERROR(mgmt->cdev_dev, "[%s] copy to user failed",
				     __func__);
		goto err;
	}

	AZIHSM_DEV_LOG_EXIT(mgmt->cdev_dev, "[EXIT] %s azihsm_mgmt:%p",
			    __func__, mgmt);

err:
	return err;
}

/**
 * Function :- azihsm_mgmt_dev_get_device_info
 * Implementation of the get_device_info ioctl on the management interface
 * Delegate it to the get_device_info on the control interface after doing
 * basic validation
 */
static int azihsm_mgmt_dev_get_device_info(struct azihsm_mgmt *mgmt,
					   unsigned long arg)
{
	struct azihsm_dev *azihsmdev =
		container_of(mgmt, struct azihsm_dev, mgmt);
	int err;
	struct azihsm_ctrl_dev_info info;
	size_t min_size =
		offsetofend(struct azihsm_ctrl_dev_info, device_entropy);

	AZIHSM_DEV_LOG_ENTRY(mgmt->cdev_dev, "[ENTRY] %s azihsm_mgmt:%p",
			     __func__, mgmt);
	if (copy_from_user(&info, (void __user *)arg, min_size)) {
		err = -EFAULT;
		AZIHSM_DEV_LOG_ERROR(mgmt->cdev_dev,
				     "[%s] copy from user failed\n", __func__);
		goto err;
	}

	if (info.argsz < sizeof(info)) {
		err = -EINVAL;
		AZIHSM_DEV_LOG_ERROR(mgmt->cdev_dev,
				     "[%s] invalid argument size\n", __func__);
		goto err;
	}

	err = azihsm_ctrl_dev_get_dev_info(&azihsmdev->ctrl, &info);

	if (copy_to_user((void __user *)arg, &info, min_size)) {
		err = -EFAULT;
		AZIHSM_DEV_LOG_ERROR(mgmt->cdev_dev, "[%s] copy to user failed",
				     __func__);
	}

err:
	AZIHSM_DEV_LOG_EXIT(mgmt->cdev_dev, "[EXIT] %s azihsm_mgmt:%p",
			    __func__, mgmt);
	return err;
}

static int azihsm_mgmt_if_dev_open(struct inode *inode, struct file *file)
{
	struct azihsm_mgmt *mgmt_if =
		container_of(inode->i_cdev, struct azihsm_mgmt, cdev);

	file->private_data = mgmt_if;

	return 0;
}

static long azihsm_mgmt_if_dev_ioctl(struct file *file, unsigned int cmd,
				     unsigned long arg)
{
	int err;
	struct azihsm_mgmt *mgmt = file->private_data;

	switch (cmd) {
	case AZIHSM_MGMT_IF_DEV_IOCTL_SET_RES_CNT:
		err = azihsm_mgmt_dev_set_res_cnt(mgmt, arg);
		break;

	case AZIHSM_MGMT_IF_DEV_IOCTL_GET_RES_CNT:
		err = azihsm_mgmt_dev_get_res_cnt(mgmt, arg);
		break;

	case AZIHSM_MGMT_IF_DEV_IOCTL_GET_VF_COUNT:
		err = azihsm_mgmt_dev_get_vf_count(mgmt, arg);
		break;

	case AZIHSM_MGMT_IF_DEV_IOCTL_GET_DEV_INFO:
		err = azihsm_mgmt_dev_get_device_info(mgmt, arg);
		break;

	default:
		AZIHSM_DEV_LOG_ERROR(
			mgmt->cdev_dev,
			"[ERROR] %s azihsm_mgmt:%p unknown ioctl:%d\n",
			__func__, mgmt, cmd);
		err = -EBADRQC;
	}

	return err;
}

static int azihsm_mgmt_if_dev_close(struct inode *inode, struct file *file)
{
	file->private_data = NULL;
	return 0;
}

const struct file_operations azihsm_mgmt_if_dev_fops = {
	.owner = THIS_MODULE,
	.open = azihsm_mgmt_if_dev_open,
	.unlocked_ioctl = azihsm_mgmt_if_dev_ioctl,
	.release = azihsm_mgmt_if_dev_close,
};

int azihsm_mgmt_if_dev_init(struct azihsm_mgmt *mgmt, const bool abort)
{
	int err;
	int minor;
	dev_t devt;
	struct device *dev;

	/* if this function is being called as part of abort process
	 *  should not need to allocate again
	 */
	AZIHSM_LOG_ENTRY("[ENTRY] %s mgmt:%p abort:%d\n", __func__, mgmt,
			 abort);
	if (true == abort) {
		AZIHSM_LOG_INFO(
			"[%s] Executing as part of abort. Doing nothing\n",
			__func__);
		return 0;
	}

	minor = ida_alloc(&azihsm_mgmt_if_dev_ida, GFP_KERNEL);
	if (minor < 0) {
		AZIHSM_LOG_ERROR("%s ida_alloc failed\n", __func__);
		err = minor;
		goto ida_alloc_fail;
	}

	mgmt->major = azihsm_mgmt_if_dev_major;
	mgmt->minor = minor;
	devt = MKDEV(mgmt->major, mgmt->minor);

	cdev_init(&mgmt->cdev, &azihsm_mgmt_if_dev_fops);
	mgmt->cdev.owner = THIS_MODULE;

	err = cdev_add(&mgmt->cdev, devt, 1);
	if (err) {
		AZIHSM_LOG_ERROR(
			"%s cdev_add failed major:%d minor:%d err:%d\n",
			__func__, mgmt->major, mgmt->minor, err);
		goto cdev_add_fail;
	}

	dev = device_create(azihsm_mgmt_if_dev_class, &mgmt->pdev->dev, devt,
			    mgmt, "azihsm-mgmt%d", mgmt->minor);
	if (IS_ERR(dev)) {
		AZIHSM_LOG_ERROR("%s device_create failed\n", __func__);
		err = PTR_ERR(dev);
		goto device_create_fail;
	}

	AZIHSM_LOG_EXIT("[SUCCESS] %s mgmt:%p abort:%d\n", __func__, mgmt,
			abort);

	mgmt->cdev_dev = dev;
	return 0;

device_create_fail:
	cdev_del(&mgmt->cdev);
cdev_add_fail:
	ida_free(&azihsm_mgmt_if_dev_ida, minor);
ida_alloc_fail:
	return 0;
}

void azihsm_mgmt_if_dev_deinit(struct azihsm_mgmt *mgmt, const bool abort)
{
	AZIHSM_LOG_ENTRY("%s\n", __func__);
	if (true == abort) {
		AZIHSM_LOG_INFO("%s . In abort. doing nothing\n", __func__);
		return;
	}
	device_del(mgmt->cdev_dev);
	cdev_del(&mgmt->cdev);
	ida_free(&azihsm_mgmt_if_dev_ida, mgmt->minor);
	AZIHSM_LOG_EXIT("%s\n", __func__);
}

int __init azihsm_mgmt_if_dev_mod_init(void)
{
	int err;
	dev_t dev;

	AZIHSM_LOG_ENTRY("%s\n", __func__);

#if KERNEL_VERSION(6, 5, 0) > LINUX_VERSION_CODE
	azihsm_mgmt_if_dev_class =
		class_create(THIS_MODULE, AZIHSM_MGMT_IF_DEV_NAME);
#else
	azihsm_mgmt_if_dev_class = class_create(AZIHSM_MGMT_IF_DEV_NAME);
#endif
	if (IS_ERR(azihsm_mgmt_if_dev_class)) {
		AZIHSM_LOG_ERROR("%s class_create on device name[%s] failed\n",
				 __func__, AZIHSM_MGMT_IF_DEV_NAME);
		err = PTR_ERR(azihsm_mgmt_if_dev_class);
		goto class_create_fail;
	}

	err = alloc_chrdev_region(&dev, 0, AZIHSM_MGMT_IF_DEV_COUNT,
				  AZIHSM_MGMT_IF_DEV_NAME);
	if (err) {
		AZIHSM_LOG_ERROR(
			"%s alloc_chrdev_region failed dev count:%d dev name:%s\n",
			__func__, AZIHSM_MGMT_IF_DEV_COUNT,
			AZIHSM_MGMT_IF_DEV_NAME);
		goto alloc_region_fail;
	}

	azihsm_mgmt_if_dev_major = MAJOR(dev);
	AZIHSM_LOG_EXIT("%s azihsm_mgmt_if_dev_major:%d\n", __func__,
			azihsm_mgmt_if_dev_major);
	return 0;

alloc_region_fail:
	class_destroy(azihsm_mgmt_if_dev_class);
class_create_fail:
	return err;
}

void __exit azihsm_mgmt_if_dev_mod_exit(void)
{
	dev_t dev = MKDEV(azihsm_mgmt_if_dev_major, 0);

	AZIHSM_LOG_ENTRY("%s major:%d\n", __func__, azihsm_mgmt_if_dev_major);
	unregister_chrdev_region(dev, AZIHSM_MGMT_IF_DEV_COUNT);
	class_destroy(azihsm_mgmt_if_dev_class);
	AZIHSM_LOG_EXIT("%s\n", __func__);
}
