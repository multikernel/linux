/* SPDX-License-Identifier: GPL-2.0-only */
/*
 * SpacemiT UFS Host Controller driver
 *
 * Copyright (c) 2026 SpacemiT (Hangzhou) Technology Co. Ltd
 */

#ifndef _UFS_SPACEMIT_H_
#define _UFS_SPACEMIT_H_

#include <linux/regulator/consumer.h>
#include <linux/pm_qos.h>
#include <linux/workqueue.h>

/* Spacemit K3 UFS host controller vendor specific registers */
#define UFS_SYS1CLK_1US			0xC0
#define UFS_TX_SYMBOL_CLK_NS_US		0xC4
#define UFS_LOCAL_PORT_ID_REG		0xC8
#define UFS_PA_ERR_CODE			0xCC
#define UFS_RETRY_TIMER_REG		0xD0
#define UFS_PA_LINK_STARTUP_TIMER	0xD8
#define UFS_CFG1			0xDC

/* MPHY control registers */
#define UFS_PHY_MNG_BASE		0x1B00
#define UFS_MPHY_RST_CTRL		0x0
#define UFS_MPHY_PU_CTRL		0x4
#define UFS_MPHY_BKDR_CTRL		0x8
#define UFS_DEVICE_IO_CTRL		0xC

/* ATOP base*/
#define UFS_ATOP_BASE			0x1C00

#define UFS_SYSCLK			499
#define UFS_TX_SYMBO_CLK		0x800
#define UFS_MAX_LINKSTARTUP_TIMER	0xFFFFFFFF
#define UFS_DL_AFC0REQTIMEOUTVAL_MAX	0xFFFF

#define MPHY_TX_FSM_STATE		0x41
#define TX_FSM_HIBERN8			0x1
#define HBRN8_POLL_TOUT_MS		100
#define DEFAULT_CLK_RATE_HZ		1000000
#define BUS_VECTOR_NAME_LEN		32

#define UFS_HW_VER_MAJOR_SHFT		28
#define UFS_HW_VER_MAJOR_MASK		(0x000F << UFS_HW_VER_MAJOR_SHFT)
#define UFS_HW_VER_MINOR_SHFT		16
#define UFS_HW_VER_MINOR_MASK		(0x0FFF << UFS_HW_VER_MINOR_SHFT)
#define UFS_HW_VER_STEP_SHFT		0
#define UFS_HW_VER_STEP_MASK		(0xFFFF << UFS_HW_VER_STEP_SHFT)

#define UFS_SPACEMIT_K3_LIMIT_NUM_LANES_RX	2
#define UFS_SPACEMIT_K3_LIMIT_NUM_LANES_TX	2
#define UFS_SPACEMIT_K3_LIMIT_HSGEAR_RX		UFS_HS_G3
#define UFS_SPACEMIT_K3_LIMIT_HSGEAR_TX		UFS_HS_G3
#define UFS_SPACEMIT_K3_LIMIT_PWMGEAR_RX	UFS_PWM_G4
#define UFS_SPACEMIT_K3_LIMIT_PWMGEAR_TX	UFS_PWM_G4
#define UFS_SPACEMIT_K3_LIMIT_RX_PWR_PWM	SLOW_MODE
#define UFS_SPACEMIT_K3_LIMIT_TX_PWR_PWM	SLOW_MODE
#define UFS_SPACEMIT_K3_LIMIT_RX_PWR_HS		FAST_MODE
#define UFS_SPACEMIT_K3_LIMIT_TX_PWR_HS		FAST_MODE
#define UFS_SPACEMIT_K3_LIMIT_HS_RATE		PA_HS_MODE_B
#define UFS_SPACEMIT_K3_LIMIT_DESIRED_MODE	2

#define UFS_PA_VS_CONFIG_REG1			0x9000
#define UFS_DME_VS_CORE_CLK_CTRL		0xD002

#define UFS_HCLKDIV_REG 0xFC

struct ufs_spacemit_host {
	struct ufs_hba *hba;
	struct ufs_pa_layer_attr dev_req_params;
};

struct ufshcd_dme_attr_val {
	u32 attr_sel;
	u32 mib_val;
};
#endif /* _UFS_SPACEMIT_H_ */
