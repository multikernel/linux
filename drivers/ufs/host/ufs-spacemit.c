// SPDX-License-Identifier: GPL-2.0-only
/*
 * Copyright (c) 2026 SpacemiT (Hangzhou) Technology Co. Ltd
 */

#include <linux/clk.h>
#include <linux/delay.h>
#include <linux/io.h>
#include <linux/iopoll.h>
#include <linux/module.h>
#include <linux/of.h>
#include <linux/platform_device.h>
#include <linux/reset.h>
#include <linux/slab.h>

#include <ufs/ufshcd.h>
#include <ufs/ufshci.h>
#include <ufs/ufs_quirks.h>
#include <ufs/unipro.h>

#include "ufshcd-pltfrm.h"
#include "ufs-spacemit.h"

/* PA Layer Gettable and settable M-PHY Specific Attributes */
#define PA_TXHSG1SYNCLENGTH		0x1552
#define PA_TXHSG1PREPARELENGTH		0x1553
#define PA_TXHSG2SYNCLENGTH		0x1554
#define PA_TXHSG2PREPARELENGTH		0x1555
#define PA_TXHSG3SYNCLENGTH		0x1556
#define PA_TXHSG3PREPARELENGTH		0x1557
#define PA_TXMK2EXTENSION		0x155A
#define PA_PEERSCRAMBLING		0x155B
#define PA_TXSKIP			0x155C
#define PA_TXSKIPPERIOD			0x155D
#define PA_PEER_TX_LCC_ENABLE		0x155F

#define PA_SCRAMBLING			0x1585
#define PA_MK2EXTENSIONGUARDBAND	0x15AB

/* Special TX/RX Configuration Attributes */
#define RX_LS_PRE_LEN_CAP		0x008D
#define RX_LANE_HB8_BKDOOR_ATTR		0x00F4
#define RX_PWRM_CLOSURE_LEN_CAP		0x008E
#define RX_MIN_STALL_CAP		0x0088
#define RX_LANE_SOF_BKDOOR_ATT		0x00F2
#define RX_GARBAGE_COUNT_OFFSET		0x00F2

/* Special analog register */
#define ANA_EQ_CTRL_REG_ATTR		0x00CD
#define ANA_HSGEAR_CTRL_ATTR		0x00C1

/*
 * Keep UFS ACLK at a lower parent rate (409.6MHz) for stable init.
 * This mirrors the "ufs-low-aclk-freq" change from the other environment.
 */
#define UFS_ACLK_LOW_FREQ_HZ		409600000UL

/* PHY register magic values */
#define MPHY_PU_ALL			0x87f
#define MPHY_PU_WITH_HB8_RESET		0xb7f
#define MPHY_DEVICE_RESET_DEASSERT	0x101
#define MPHY_DEVICE_RESET_ASSERT	0x001
#define MPHY_PLL_LOCK_BIT		BIT(31)
#define MPHY_PLL_LOCK_TIMEOUT_US	10000

/* FSM states */
#define FSM_STATE_HIBERN8		0x1
#define FSM_STATE_ACTIVE		0x3
#define FSM_STATE_LS_BURST		0x5

#define VENDOR_DUMP_BUF_SIZE		2048
#define VENDOR_MAX_OFFSET		0xE0

/* M-PHY FSM states */
#define MPHY_RX_FSM_STATE	0xC1
#define MPHY_TX_FSM_STATE	0x41

static int ufs_spacemit_dme_set(struct ufs_hba *hba,
				const struct ufshcd_dme_attr_val *v, int n)
{
	int ret = 0;
	int attr_node = 0;

	for (attr_node = 0; attr_node < n; attr_node++) {
		ret = ufshcd_dme_set(hba, v[attr_node].attr_sel,
				     v[attr_node].mib_val);

		if (ret)
			return ret;
	}

	return 0;
}

static int ufs_spacemit_check_hibern8(struct ufs_hba *hba)
{
	u32 tx_fsm_val_0 = 0;
	u32 tx_fsm_val_1 = 0;
	int retries = DIV_ROUND_UP(HBRN8_POLL_TOUT_MS * 1000, 100);
	int err = 0;

	do {
		err = ufshcd_dme_get(hba,
				     UIC_ARG_MIB_SEL(MPHY_TX_FSM_STATE,
						     UIC_ARG_MPHY_TX_GEN_SEL_INDEX(0)),
				     &tx_fsm_val_0);
		err |= ufshcd_dme_get(hba,
				      UIC_ARG_MIB_SEL(MPHY_TX_FSM_STATE,
						      UIC_ARG_MPHY_TX_GEN_SEL_INDEX(1)),
				      &tx_fsm_val_1);
		if (err || (tx_fsm_val_0 == TX_FSM_HIBERN8 &&
			    tx_fsm_val_1 == TX_FSM_HIBERN8))
			break;

		usleep_range(100, 200);
	} while (--retries > 0);

	if (!err && retries <= 0) {
		err = ufshcd_dme_get(hba,
				     UIC_ARG_MIB_SEL(MPHY_TX_FSM_STATE,
						     UIC_ARG_MPHY_TX_GEN_SEL_INDEX(0)),
				     &tx_fsm_val_0);
		err |= ufshcd_dme_get(hba,
				      UIC_ARG_MIB_SEL(MPHY_TX_FSM_STATE,
						      UIC_ARG_MPHY_TX_GEN_SEL_INDEX(1)),
				      &tx_fsm_val_1);
	}

	if (err) {
		dev_err(hba->dev, "%s: unable to get TX_FSM_STATE, err %d\n",
			__func__, err);
	} else if (tx_fsm_val_0 != TX_FSM_HIBERN8 ||
		   tx_fsm_val_1 != TX_FSM_HIBERN8) {
		err = -ETIMEDOUT;
		dev_err(hba->dev,
			"%s: invalid TX_FSM_STATE, lane0 = %u, lane1 = %u\n",
			__func__, tx_fsm_val_0, tx_fsm_val_1);
	}

	return err;
}

static int ufs_spacemit_get_connected_tx_lanes(struct ufs_hba *hba, u32 *tx_lanes)
{
	int err;

	err = ufshcd_dme_get(hba, UIC_ARG_MIB(PA_CONNECTEDTXDATALANES), tx_lanes);
	if (err)
		dev_err(hba->dev, "%s: couldn't read PA_CONNECTEDTXDATALANES %d\n", __func__, err);

	return err;
}

static u32 ufs_spacemit_get_sys1clk_1us(struct ufs_hba *hba)
{
	struct ufs_clk_info *clki, *ufs_aclk = NULL;
	struct list_head *head = &hba->clk_list_head;
	unsigned long rate_hz = 0;

	if (!list_empty(head)) {
		list_for_each_entry(clki, head, list) {
			if (clki->name && !strcmp(clki->name, "aclk") && clki->clk) {
				ufs_aclk = clki;
				break;
			}
		}
	}

	if (ufs_aclk && ufs_aclk->clk)
		rate_hz = clk_get_rate(ufs_aclk->clk);

	if (!rate_hz)
		return 0;

	return DIV_ROUND_CLOSEST(rate_hz, 1000000);
}

static int ufs_spacemit_wait_mphy_pll_lock(struct ufs_hba *hba)
{
	u32 val;
	int err;

	err = read_poll_timeout(ufshcd_readl, val, val & MPHY_PLL_LOCK_BIT,
				10, MPHY_PLL_LOCK_TIMEOUT_US, false, hba,
				UFS_PHY_MNG_BASE + UFS_MPHY_PU_CTRL);

	if (err)
		dev_err(hba->dev, "M-PHY PLL lock timeout\n");

	return err;
}

/**
 * ufs_spacemit_mphy_init
 * @hba: host controller instance
 */
static int ufs_spacemit_mphy_init(struct ufs_hba *hba)
{
	int ret;

	/* reset all mphy logical */
	ufshcd_writel(hba, 0x003, UFS_PHY_MNG_BASE + 0x0);

	/* power up all */
	ufshcd_writel(hba, MPHY_PU_ALL, UFS_PHY_MNG_BASE + 0x4);

	/* asserted ana_rx_hb8_reset */
	ufshcd_writel(hba, 0xb7f, UFS_PHY_MNG_BASE + 0x4);
	fsleep(500);

	/* deasserted ana_rx_hb8_reset */
	ufshcd_writel(hba, MPHY_PU_ALL, UFS_PHY_MNG_BASE + 0x4);

	/* deasserted ufs device reset & refer clk output enable */
	ufshcd_writel(hba, 0x101, UFS_PHY_MNG_BASE + 0xC);
	fsleep(1000);

	ret = ufs_spacemit_wait_mphy_pll_lock(hba);
	if (ret < 0)
		return ret;

	dev_dbg(hba->dev, "M-PHY PLL locked successfully\n");

	ufshcd_writel(hba, 0x1, UFS_PHY_MNG_BASE + 0x08);

	ufshcd_writel(hba, 0x40, UFS_ATOP_BASE + (0xC2 << 2));

	ufshcd_writel(hba, 0x0, UFS_PHY_MNG_BASE + 0x08);

	fsleep(2000);

	dev_dbg(hba->dev, "M-PHY init completed\n");

	return 0;
}

static int ufs_spacemit_uniprov1p6_init(struct ufs_hba *hba)
{
	static const struct ufshcd_dme_attr_val setup_attrs[] = {
		{ UIC_ARG_MIB(0x1552), 0x4f }, /* PA_TXHSG1SYNCLENGTH */
		{ UIC_ARG_MIB(0x1553), 0xf }, /* PA_TXHSG1PREPARELENGTH */
		{ UIC_ARG_MIB(0x1554), 0x4f }, /* PA_TXHSG2SYNCLENGTH */
		{ UIC_ARG_MIB(0x1555), 0xf }, /* PA_TXHSG2PREPARELENGTH */
		{ UIC_ARG_MIB(0x1556), 0x4f }, /* PA_TXHSG3SYNCLENGTH */
		{ UIC_ARG_MIB(0x1557), 0xf }, /* PA_TXHSG3PREPARELENGTH */
		{ UIC_ARG_MIB(0x155A), 0x0 }, /* PA_TXMK2EXTENSION */
		{ UIC_ARG_MIB(0x155B), 0x1}, /* PA_PEERSCRAMBLING */
		{ UIC_ARG_MIB(0x155C), 0x1 }, /* PA_TXSKIP */
		{ UIC_ARG_MIB(0x155D), 250 }, /* PA_TXSKIPPERIOD */
		{ UIC_ARG_MIB(0x155E), 0x0 }, /* PA_LOCAL_TX_LCC_ENABLE */
		{ UIC_ARG_MIB(0x155F), 0x0 }, /* PA_PEER_TX_LCC_ENABLE */
		{ UIC_ARG_MIB(0x1585), 0x1 }, /* PA_SCRAMBLING */
		{ UIC_ARG_MIB(0x15AA), 0x1 }, /* PA_GRANULARITY */
		{ UIC_ARG_MIB(0x15AB), 0x0 }, /* PA_MK2EXTENSIONGUARDBAND */
		{ UIC_ARG_MIB(0x15A3), 15 }, /* PA_STALLNOCONFIGTIME */
		{ UIC_ARG_MIB(0x15A8), 0x64 }, /* PA_TACTIVATE */
		{ UIC_ARG_MIB(0x1564), 0x64 },	/* PA_TXTRAILINGCLOCKS */
		{ UIC_ARG_MIB_SEL(0x008D, 4), 0x0B }, /* RX_LS_PREPARELEN_TIME RX0 */
		{ UIC_ARG_MIB_SEL(0x008D, 5), 0x0B }, /* RX_LS_PREPARELEN_TIME RX1 */

		/* RX_HIBERNATE_BKEN RX0 */
		{ UIC_ARG_MIB_SEL(0x00F4, UIC_ARG_MPHY_RX_GEN_SEL_INDEX(0)), 0x9F },
		/* RX_HIBERNATE_BKEN RX1 */
		{ UIC_ARG_MIB_SEL(0x00F4, UIC_ARG_MPHY_RX_GEN_SEL_INDEX(1)), 0x9F },
		/* PWM_BURST_closure_length */
		{ UIC_ARG_MIB_SEL(0x008E, UIC_ARG_MPHY_RX_GEN_SEL_INDEX(0)),   15 },
		{ UIC_ARG_MIB_SEL(0x008E, UIC_ARG_MPHY_RX_GEN_SEL_INDEX(1)),   15 },
		/* min_stall_not_config_time */
		{ UIC_ARG_MIB_SEL(0x0088, UIC_ARG_MPHY_RX_GEN_SEL_INDEX(0)), 0xFF },
		{ UIC_ARG_MIB_SEL(0x0088, UIC_ARG_MPHY_RX_GEN_SEL_INDEX(1)), 0xFF },
		/* TX HB8_TIME CAP */
		{ UIC_ARG_MIB_SEL(0x000F, UIC_ARG_MPHY_TX_GEN_SEL_INDEX(0)), 0x64 },
		{ UIC_ARG_MIB_SEL(0x000F, UIC_ARG_MPHY_TX_GEN_SEL_INDEX(1)), 0x64 },
		/* RX HB8_TIME CAP */
		{ UIC_ARG_MIB_SEL(0x0092, UIC_ARG_MPHY_RX_GEN_SEL_INDEX(0)), 0x64 },
		{ UIC_ARG_MIB_SEL(0x0092, UIC_ARG_MPHY_RX_GEN_SEL_INDEX(1)), 0x64 },
		/* TX EQ 3DB */
		{ UIC_ARG_MIB_SEL(0x00CD, UIC_ARG_MPHY_TX_GEN_SEL_INDEX(0)),  0x5 },
		/* RX garbage cnt = 32 SI */
		{ UIC_ARG_MIB_SEL(0x00F2, UIC_ARG_MPHY_RX_GEN_SEL_INDEX(0)), 0x9F },
		{ UIC_ARG_MIB_SEL(0x00F2, UIC_ARG_MPHY_RX_GEN_SEL_INDEX(1)), 0x9F },
	};

	return ufs_spacemit_dme_set(hba, setup_attrs, ARRAY_SIZE(setup_attrs));
}

static void ufs_spacemit_set_dev_cap(struct ufs_host_params *host_params, u32 pwr_hs)
{
	if (!host_params)
		return;

	memset(host_params, 0, sizeof(struct ufs_host_params));
	host_params->tx_lanes = UFS_SPACEMIT_K3_LIMIT_NUM_LANES_TX;
	host_params->rx_lanes = UFS_SPACEMIT_K3_LIMIT_NUM_LANES_RX;
	host_params->hs_rx_gear = UFS_SPACEMIT_K3_LIMIT_HSGEAR_RX;
	host_params->hs_tx_gear = UFS_SPACEMIT_K3_LIMIT_HSGEAR_TX;
	host_params->pwm_rx_gear = UFS_SPACEMIT_K3_LIMIT_PWMGEAR_RX;
	host_params->pwm_tx_gear = UFS_SPACEMIT_K3_LIMIT_PWMGEAR_TX;
	host_params->rx_pwr_pwm = UFS_SPACEMIT_K3_LIMIT_RX_PWR_PWM;
	host_params->tx_pwr_pwm = UFS_SPACEMIT_K3_LIMIT_TX_PWR_PWM;
	host_params->rx_pwr_hs = pwr_hs;
	host_params->tx_pwr_hs = pwr_hs;
	host_params->hs_rate = UFS_SPACEMIT_K3_LIMIT_HS_RATE;
	host_params->desired_working_mode = UFS_HS_MODE;
}

static int ufs_spacemit_link_startup_pre_change(struct ufs_hba *hba)
{
	u32 value, sys1clk_1us;

	ufs_spacemit_mphy_init(hba);

	ufs_spacemit_uniprov1p6_init(hba);

	/* config sysclk and tx symbol clk before link startup */
	value = UFS_MAX_LINKSTARTUP_TIMER;

	/* clear bit0~bit3, select b0 design */
	value &= ~0xf;

	ufshcd_writel(hba, value, UFS_PA_LINK_STARTUP_TIMER);

	sys1clk_1us = ufs_spacemit_get_sys1clk_1us(hba);
	if (!sys1clk_1us)
		sys1clk_1us = DIV_ROUND_CLOSEST(UFS_ACLK_LOW_FREQ_HZ, 1000000);
	ufshcd_writel(hba, sys1clk_1us, UFS_SYS1CLK_1US);
	ufshcd_writel(hba, UFS_TX_SYMBO_CLK, UFS_TX_SYMBOL_CLK_NS_US);

	dev_dbg(hba->dev, "REG_UFS_SYS1CLK_1US: 0x%x\n",
		ufshcd_readl(hba, UFS_SYS1CLK_1US));
	dev_dbg(hba->dev, "REG_UFS_TX_SYMBOL_CLK_NS_US: 0x%x\n",
		ufshcd_readl(hba, UFS_TX_SYMBOL_CLK_NS_US));

	return 0;
}

static int ufs_spacemit_link_startup_post_change(struct ufs_hba *hba)
{
	/* Add 0xe8 make UFS2.1 run GEAR3 + 2Lane@409M */
	static const struct ufshcd_dme_attr_val setup_attrs[] = {
		{ UIC_ARG_MIB_SEL(0xe8, UIC_ARG_MPHY_TX_GEN_SEL_INDEX(0)), 0x97 },
		{ UIC_ARG_MIB_SEL(0xe8, UIC_ARG_MPHY_TX_GEN_SEL_INDEX(0)), 0xd7 },
		{ UIC_ARG_MIB_SEL(0xe8, UIC_ARG_MPHY_TX_GEN_SEL_INDEX(0)), 0x17 },
		{ UIC_ARG_MIB(DL_AFC0REQTIMEOUTVAL), UFS_DL_AFC0REQTIMEOUTVAL_MAX },
	};
	u32 tx_lanes;

	ufs_spacemit_dme_set(hba, setup_attrs, ARRAY_SIZE(setup_attrs));

	return ufs_spacemit_get_connected_tx_lanes(hba, &tx_lanes);
}

static int ufs_spacemit_link_startup_notify(struct ufs_hba *hba,
					    enum ufs_notify_change_status status)
{
	switch (status) {
	case PRE_CHANGE:
		ufs_spacemit_link_startup_pre_change(hba);
		break;
	case POST_CHANGE:
		ufs_spacemit_link_startup_post_change(hba);
		break;
	default:
		break;
	}

	return 0;
}

static int ufs_spacemit_negotiate_pwr_mode(struct ufs_hba *hba,
					   const struct ufs_pa_layer_attr *dev_max_params,
					   struct ufs_pa_layer_attr *dev_req_params)
{
	struct ufs_host_params host_params;
	int ret;

	ufs_spacemit_set_dev_cap(&host_params, FAST_MODE);
	ret = ufshcd_negotiate_pwr_params(&host_params, dev_max_params,
					  dev_req_params);
	if (ret) {
		dev_err(hba->dev, "Failed to negotiate power params: %d\n", ret);
		return ret;
	}

	dev_dbg(hba->dev,
		"Power mode config - gear_rx:%d, gear_tx:%d, lane_rx:%d, lane_tx:%d, pwr_rx:%d, pwr_tx:%d, hs_rate:%d\n",
		dev_req_params->gear_rx, dev_req_params->gear_tx, dev_req_params->lane_rx,
		dev_req_params->lane_tx, dev_req_params->pwr_rx, dev_req_params->pwr_tx,
		dev_req_params->hs_rate);

	return ret;
}

static int ufs_spacemit_pwr_change_notify(struct ufs_hba *hba,
					  enum ufs_notify_change_status status,
					  struct ufs_pa_layer_attr *dev_req_params)
{
	struct ufs_spacemit_host *host = ufshcd_get_variant(hba);
	int ret = 0;

	if (!dev_req_params) {
		dev_err(hba->dev, "Invalid Parameters\n");
		return -EINVAL;
	}

	switch (status) {
	case PRE_CHANGE:
		break;
	case POST_CHANGE:
		/* Cache the power mode parameters to use internally */
		memcpy(&host->dev_req_params, dev_req_params, sizeof(*dev_req_params));
		ret = ufs_spacemit_wait_mphy_pll_lock(hba);
		if (ret < 0)
			return ret;

		dev_dbg(hba->dev, "M-PHY PLL locked after power mode change\n");
		/* Set ANA_HSGEAR_CTRL_ATTR back to default value */
		ufshcd_dme_set(hba, UIC_ARG_MIB(ANA_HSGEAR_CTRL_ATTR), 0x00);
		break;
	default:
		return -EINVAL;
	}

	return ret;
}

static int ufs_spacemit_quirk_host_pa_saveconfigtime(struct ufs_hba *hba)
{
	int err;
	u32 pa_vs_config_reg1;

	err = ufshcd_dme_get(hba, UIC_ARG_MIB(UFS_PA_VS_CONFIG_REG1), &pa_vs_config_reg1);
	if (err)
		return err;

	/* Allow extension of MSB bits of PA_SaveConfigTime attribute */
	return ufshcd_dme_set(hba, UIC_ARG_MIB(UFS_PA_VS_CONFIG_REG1),
			      (pa_vs_config_reg1 | (1 << 12)));
}

static int ufs_spacemit_apply_dev_quirks(struct ufs_hba *hba)
{
	static const struct ufshcd_dme_attr_val setup_attrs[] = {
		/* LCC_DISABLE */
		{ UIC_ARG_MIB_SEL(TX_LCC_ENABLE, UIC_ARG_MPHY_TX_GEN_SEL_INDEX(0)), 0 },
		{ UIC_ARG_MIB_SEL(TX_LCC_ENABLE, UIC_ARG_MPHY_TX_GEN_SEL_INDEX(1)), 0 },
		/* TX_Min_ActivateTime */
		{ UIC_ARG_MIB_SEL(TX_MIN_ACTIVATETIME, UIC_ARG_MPHY_TX_GEN_SEL_INDEX(0)), 0x0 },
		{ UIC_ARG_MIB_SEL(TX_MIN_ACTIVATETIME, UIC_ARG_MPHY_TX_GEN_SEL_INDEX(1)), 0x0 },
		{ UIC_ARG_MIB(ANA_HSGEAR_CTRL_ATTR), 0x25 },
	};

	if (hba->dev_quirks & UFS_DEVICE_QUIRK_HOST_PA_SAVECONFIGTIME)
		ufs_spacemit_quirk_host_pa_saveconfigtime(hba);

	if (hba->dev_info.wmanufacturerid == UFS_VENDOR_WDC)
		hba->dev_quirks |= UFS_DEVICE_QUIRK_HOST_PA_TACTIVATE;

	ufs_spacemit_dme_set(hba, setup_attrs, ARRAY_SIZE(setup_attrs));

	return ufs_spacemit_wait_mphy_pll_lock(hba);
}

/**
 * ufs_spacemit_advertise_quirks - advertise the known Spacemit UFS controller quirks
 * @hba: host controller instance
 *
 * Spacemit UFS host controller might have some non standard behaviours (quirks)
 * than what is specified by UFSHCI specification. Advertise all such
 * quirks to standard UFS host controller driver so standard takes them into
 * account.
 */
static void ufs_spacemit_advertise_quirks(struct ufs_hba *hba)
{
	hba->quirks |= UFSHCD_QUIRK_BROKEN_AUTO_HIBERN8;
}

/**
 * ufs_spacemit_init - init phy and prepare clk
 * @hba: host controller instance
 */
static int ufs_spacemit_init(struct ufs_hba *hba)
{
	int err = 0;
	struct device *dev = hba->dev;
	struct ufs_spacemit_host *host;
	struct reset_control *rst;

	host = devm_kzalloc(dev, sizeof(*host), GFP_KERNEL);
	if (!host)
		return -ENOMEM;

	rst = devm_reset_control_get_exclusive_deasserted(dev, NULL);
	if (IS_ERR(rst))
		return dev_err_probe(dev, PTR_ERR(rst), "Failed to get reset control\n");

	host->hba = hba;
	ufshcd_set_variant(hba, host);
	ufs_spacemit_advertise_quirks(hba);

	err = ufshcd_vops_phy_initialization(host->hba);
	return err;
}

/**
 * ufs_spacemit_device_reset - Toggle device reset line
 * @hba: per-adapter instance
 *
 * Toggles the reset line to reset the attached UFS device.
 *
 * Returns: 0 on success
 */
static int ufs_spacemit_device_reset(struct ufs_hba *hba)
{
	/* Stop device ref_clk & asserted ufs device reset */
	ufshcd_writel(hba, 0x000, UFS_PHY_MNG_BASE + UFS_DEVICE_IO_CTRL);
	usleep_range(10, 15);

	/* Enable device ref_clk & de-asserted ufs device reset */
	ufshcd_writel(hba, MPHY_DEVICE_RESET_DEASSERT, UFS_PHY_MNG_BASE + UFS_DEVICE_IO_CTRL);
	usleep_range(10, 15);

	return 0;
}

/**
 * ufs_spacemit_event_notify - Handle UFS error events
 * @hba: host controller instance
 * @evt: event type
 * @data: event-specific data
 *
 * Handles error events from UFS core, dumps registers immediately
 * and schedules FSM state dump for later execution in workqueue context.
 */
static void ufs_spacemit_event_notify(struct ufs_hba *hba, enum ufs_event_type evt, void *data)
{
	switch (evt) {
	case UFS_EVT_PA_ERR:
		if (data)
			dev_warn(hba->dev, "PA error event, INT errors:0x%x, PA_ERR_CODE:0x%x\n",
				 hba->errors, *(u32 *)data);

		break;
	case UFS_EVT_DL_ERR:
		if (data)
			dev_warn(hba->dev, "DL error event, INT errors:0x%x, DL_ERR:0x%x\n",
				 hba->errors, *(u32 *)data);

		break;
	case UFS_EVT_ABORT:
		dev_warn(hba->dev, "Abort event, INT errors:0x%x\n", hba->errors);
		break;
	default:
		break;
	}
}

static void ufs_spacemit_pre_hibern8(struct ufs_hba *hba, enum uic_cmd_dme cmd)
{
	static const struct ufshcd_dme_attr_val setup_attrs[] = {
		{ UIC_ARG_MIB_SEL(0xf1, UIC_ARG_MPHY_RX_GEN_SEL_INDEX(0)), 0x84 },
		{ UIC_ARG_MIB_SEL(0xf1, UIC_ARG_MPHY_RX_GEN_SEL_INDEX(1)), 0x84 },
		{ UIC_ARG_MIB_SEL(0xf1, UIC_ARG_MPHY_RX_GEN_SEL_INDEX(0)), 0x85 },
		{ UIC_ARG_MIB_SEL(0xf1, UIC_ARG_MPHY_RX_GEN_SEL_INDEX(1)), 0x85 },
	};
	int ret;

	if (cmd == UIC_CMD_DME_HIBER_EXIT) {
		/* Enable reference clock */
		ufshcd_writel(hba, MPHY_DEVICE_RESET_DEASSERT,
			      UFS_PHY_MNG_BASE + UFS_DEVICE_IO_CTRL);

		/* Power up all */
		ufshcd_writel(hba, MPHY_PU_ALL, UFS_PHY_MNG_BASE + UFS_MPHY_PU_CTRL);

		/* Assert ana_rx_hb8_reset */
		ufshcd_writel(hba, MPHY_PU_WITH_HB8_RESET,
			      UFS_PHY_MNG_BASE + UFS_MPHY_PU_CTRL);
		fsleep(500);

		/* Deassert ana_rx_hb8_reset */
		ufshcd_writel(hba, MPHY_PU_ALL, UFS_PHY_MNG_BASE + UFS_MPHY_PU_CTRL);

		ret = ufs_spacemit_wait_mphy_pll_lock(hba);
		if (ret < 0)
			return;

		ufshcd_dme_set(hba, UIC_ARG_MIB(0xdd), 0x57);
		ufshcd_dme_set(hba, UIC_ARG_MIB(0xe8), 0x57);
	}

	if (cmd == UIC_CMD_DME_HIBER_ENTER)
		ufs_spacemit_dme_set(hba, setup_attrs, ARRAY_SIZE(setup_attrs));
}

static void ufs_spacemit_post_hibern8(struct ufs_hba *hba, enum uic_cmd_dme cmd)
{
	static const struct ufshcd_dme_attr_val setup_attrs[] = {
		{ UIC_ARG_MIB_SEL(0xf1, UIC_ARG_MPHY_RX_GEN_SEL_INDEX(0)), 0x84 },
		{ UIC_ARG_MIB_SEL(0xf1, UIC_ARG_MPHY_RX_GEN_SEL_INDEX(1)), 0x84 },
		{ UIC_ARG_MIB_SEL(0xf1, UIC_ARG_MPHY_RX_GEN_SEL_INDEX(0)), 0x80 },
		{ UIC_ARG_MIB_SEL(0xf1, UIC_ARG_MPHY_RX_GEN_SEL_INDEX(1)), 0x80 },
		{ UIC_ARG_MIB(0xdd), 0x57 },
		{ UIC_ARG_MIB(0xdd), 0xd7 },
		{ UIC_ARG_MIB(0xe8), 0x57 },
		{ UIC_ARG_MIB(0xe8), 0xd7 },
	};

	if (cmd == UIC_CMD_DME_HIBER_ENTER) {
		ufs_spacemit_check_hibern8(hba);

		ufs_spacemit_dme_set(hba, setup_attrs, ARRAY_SIZE(setup_attrs));

		/* Power down M-PHY */
		ufshcd_writel(hba, 0x0, UFS_PHY_MNG_BASE + UFS_MPHY_PU_CTRL);

		/* Keep reference clock enabled, assert device reset */
		ufshcd_writel(hba, MPHY_DEVICE_RESET_ASSERT,
			      UFS_PHY_MNG_BASE + UFS_DEVICE_IO_CTRL);
	}
}

/**
 * ufs_spacemit_hibern8_notify - Handle hibernate enter/exit
 * @hba: host controller instance
 * @cmd: UIC command (HIBER_ENTER or HIBER_EXIT)
 * @status: notification status
 *
 * Manages M-PHY power state during hibernate transitions.
 */
static void ufs_spacemit_hibern8_notify(struct ufs_hba *hba, enum uic_cmd_dme cmd,
					enum ufs_notify_change_status status)
{
	if (status == PRE_CHANGE)
		ufs_spacemit_pre_hibern8(hba, cmd);

	if (status == POST_CHANGE)
		ufs_spacemit_post_hibern8(hba, cmd);
}

/**
 * struct ufs_hba_spacemit_vops - UFS Spacemit specific variant operations
 *
 * The variant operations configure the necessary controller and PHY
 * handshake during initialization.
 */
static const struct ufs_hba_variant_ops ufs_hba_spacemit_vops = {
	.name = "ufshcd-spacemit",
	.init = ufs_spacemit_init,
	.link_startup_notify = ufs_spacemit_link_startup_notify,
	.negotiate_pwr_mode = ufs_spacemit_negotiate_pwr_mode,
	.pwr_change_notify = ufs_spacemit_pwr_change_notify,
	.device_reset = ufs_spacemit_device_reset,
	.event_notify = ufs_spacemit_event_notify,
	.apply_dev_quirks = ufs_spacemit_apply_dev_quirks,
	.hibern8_notify = ufs_spacemit_hibern8_notify,
};

static const struct of_device_id ufs_spacemit_of_match[] = {
	{ .compatible = "spacemit,k3-ufshc" },
	{ /* sentinel */ },
};
MODULE_DEVICE_TABLE(of, ufs_spacemit_of_match);

static int ufs_spacemit_probe(struct platform_device *pdev)
{
	return ufshcd_pltfrm_init(pdev, &ufs_hba_spacemit_vops);
}

static void ufs_spacemit_remove(struct platform_device *pdev)
{
	ufshcd_pltfrm_remove(pdev);
}

static struct platform_driver ufs_spacemit_pltform = {
	.probe	= ufs_spacemit_probe,
	.remove	= ufs_spacemit_remove,
	.driver	= {
		.name	= "ufshcd-spacemit",
		.of_match_table = of_match_ptr(ufs_spacemit_of_match),
	},
};
module_platform_driver(ufs_spacemit_pltform);

MODULE_DESCRIPTION("SpacemiT UFS Host Driver");
MODULE_LICENSE("GPL");
