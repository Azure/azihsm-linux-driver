// SPDX-License-Identifier: GPL-2.0-or-later
#ifndef _LINUX_AZIHSM_LOG_H
#define _LINUX_AZIHSM_LOG_H

#include <linux/module.h>
#include <linux/pci.h>
#include <linux/printk.h>
#include "azihsm.h"

#define AZIHSM_LOG_LEVEL_ERROR 0x1
#define AZIHSM_LOG_LEVEL_WARN 0x2
#define AZIHSM_LOG_LEVEL_INFO 0x4
#define AZIHSM_LOG_LEVEL_DEBUG 0x8
#define AZIHSM_LOG_LEVEL_ENTRY 0x10
#define AZIHSM_LOG_LEVEL_EXIT 0x20

extern unsigned int log_mask;

#define AZIHSM_LOG_MSG(level, fmt, ...)                                \
	do {                                                           \
		if (log_mask & level)                                  \
			pr_info("[%s | %s] " fmt, AZIHSM_DRIVER_VERSION, __func__, ##__VA_ARGS__); \
	} while (0)

#define AZIHSM_LOG_ERROR(fmt, ...) \
	AZIHSM_LOG_MSG(AZIHSM_LOG_LEVEL_ERROR, "ERROR: " fmt, ##__VA_ARGS__)
#define AZIHSM_LOG_WARN(fmt, ...) \
	AZIHSM_LOG_MSG(AZIHSM_LOG_LEVEL_WARN, "WARN: " fmt, ##__VA_ARGS__)
#define AZIHSM_LOG_INFO(fmt, ...) \
	AZIHSM_LOG_MSG(AZIHSM_LOG_LEVEL_INFO, "INFO: " fmt, ##__VA_ARGS__)

/*
 * DEBUG/ENTRY/EXIT logging is verbose and can expose internal driver
 * state (pointers, buffer contents, call flow) that must not be
 * compiled into production builds. These macros are only compiled in
 * when DEBUG is defined (see Makefile), which keeps this tracing
 * readily available for debug builds while the log_mask module
 * parameter still gates the actual runtime output. When DEBUG is not
 * defined, no_printk() is used so the calls still type-check but emit
 * no code and no strings in the compiled binary.
 */
#ifdef DEBUG
#define AZIHSM_LOG_DEBUG(fmt, ...) \
	AZIHSM_LOG_MSG(AZIHSM_LOG_LEVEL_DEBUG, "DEBUG: " fmt, ##__VA_ARGS__)
#define AZIHSM_LOG_ENTRY(fmt, ...) \
	AZIHSM_LOG_MSG(AZIHSM_LOG_LEVEL_ENTRY, "ENTRY: " fmt, ##__VA_ARGS__)
#define AZIHSM_LOG_EXIT(fmt, ...) \
	AZIHSM_LOG_MSG(AZIHSM_LOG_LEVEL_EXIT, "EXIT: " fmt, ##__VA_ARGS__)
#else
#define AZIHSM_LOG_DEBUG(fmt, ...) no_printk("DEBUG: " fmt, ##__VA_ARGS__)
#define AZIHSM_LOG_ENTRY(fmt, ...) no_printk("ENTRY: " fmt, ##__VA_ARGS__)
#define AZIHSM_LOG_EXIT(fmt, ...) no_printk("EXIT: " fmt, ##__VA_ARGS__)
#endif

/*
 * For dev_xxxx functions
 */
#define AZIHSM_DEV_LOG_MSG(dev, level, func, fmt, ...)                   \
	do {                                                             \
		if (log_mask & level)                                    \
			func(dev, "[%s | %s] " fmt, AZIHSM_DRIVER_VERSION, __func__, ##__VA_ARGS__); \
	} while (0)

#define AZIHSM_DEV_LOG_ERROR(dev, fmt, ...)                      \
	AZIHSM_DEV_LOG_MSG(dev, AZIHSM_LOG_LEVEL_ERROR, dev_err, \
			   "ERROR: " fmt, ##__VA_ARGS__)
#define AZIHSM_DEV_LOG_WARN(dev, fmt, ...)                                     \
	AZIHSM_DEV_LOG_MSG(dev, AZIHSM_LOG_LEVEL_WARN, dev_warn, "WARN: " fmt, \
			   ##__VA_ARGS__)
#define AZIHSM_DEV_LOG_INFO(dev, fmt, ...)                                     \
	AZIHSM_DEV_LOG_MSG(dev, AZIHSM_LOG_LEVEL_INFO, dev_info, "INFO: " fmt, \
			   ##__VA_ARGS__)

/* See the comment above AZIHSM_LOG_DEBUG for why these are gated on DEBUG. */
#ifdef DEBUG
#define AZIHSM_DEV_LOG_DEBUG(dev, fmt, ...)                       \
	AZIHSM_DEV_LOG_MSG(dev, AZIHSM_LOG_LEVEL_DEBUG, dev_info, \
			   "DEBUG: " fmt, ##__VA_ARGS__)
#define AZIHSM_DEV_LOG_ENTRY(dev, fmt, ...)                       \
	AZIHSM_DEV_LOG_MSG(dev, AZIHSM_LOG_LEVEL_ENTRY, dev_info, \
			   "ENTRY: " fmt, ##__VA_ARGS__)
#define AZIHSM_DEV_LOG_EXIT(dev, fmt, ...)                                     \
	AZIHSM_DEV_LOG_MSG(dev, AZIHSM_LOG_LEVEL_EXIT, dev_info, "EXIT: " fmt, \
			   ##__VA_ARGS__)
#else
#define AZIHSM_DEV_LOG_DEBUG(dev, fmt, ...) \
	do { (void)(dev); no_printk("DEBUG: " fmt, ##__VA_ARGS__); } while (0)
#define AZIHSM_DEV_LOG_ENTRY(dev, fmt, ...) \
	do { (void)(dev); no_printk("ENTRY: " fmt, ##__VA_ARGS__); } while (0)
#define AZIHSM_DEV_LOG_EXIT(dev, fmt, ...) \
	do { (void)(dev); no_printk("EXIT: " fmt, ##__VA_ARGS__); } while (0)
#endif
#define AZIHSM_DEV_LOG_ALWAYS(dev, fmt, ...)                                     \
	dev_err(dev, "[%s | %s] " fmt, AZIHSM_DRIVER_VERSION, __func__, ##__VA_ARGS__);
#endif // _LINUX_AZIHSM_LOG_H
