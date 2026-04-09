/*
 * zpcimon - Report monitoring data to firmware
 *
 * Copyright IBM Corp. 2024
 *
 * s390-tools is free software; you can redistribute it and/or modify
 * it under the terms of the MIT license. See LICENSE for details.
 */
#include <errno.h>
#include <linux/if.h>
#include <stdbool.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

#include "lib/pci_list.h"
#include "lib/util_fmt.h"
#include "lib/util_libc.h"

#include "ethtool.h"
#include "link_mon.h"
#include "optics_info.h"
#include "optics_sclp.h"
#include "opticsmon.h"
#include "zpcimon.h"

static void optics_json_print(struct options *opts, struct zpci_netdev *nd, struct optics *oi)
{
	util_fmt_obj_start(FMT_DEFAULT, "netdev");
	util_fmt_pair(FMT_QUOTE, "name", nd->name);
	util_fmt_pair(FMT_QUOTE, "operstate", zpci_operstate_str(nd->operstate));
	util_fmt_obj_start(FMT_DEFAULT, "optics");
	util_fmt_pair(FMT_QUOTE, "type", optics_type_str(optics_type(oi)));
	util_fmt_pair(FMT_QUOTE, "rx_los", optics_los_str(optics_rx_los(oi)));
	util_fmt_pair(FMT_QUOTE, "tx_los", optics_los_str(optics_tx_los(oi)));
	util_fmt_pair(FMT_QUOTE, "tx_fault", optics_los_str(optics_tx_fault(oi)));
	if (opts->module_info)
		zpcimon_json_base64_pair("module_info", oi->raw, (int)oi->size);
	util_fmt_obj_end();
	util_fmt_obj_end();
}

static int opticsmon_collect_adapter_data(struct zpcimon_ctx *ctx, struct zpci_dev *zdev)
{
	struct options *opts = &ctx->opts;
	struct optics **ois;
	int num_ois = 0;
	char *pci_addr;
	int i, rc;

	/* Filter non-NIC devices and VFs */
	if (zpci_is_vf(zdev) || !zdev->num_netdevs)
		return -ENODEV;
	ois = (struct optics **)util_zalloc(sizeof(ois[0]) * zdev->num_netdevs);
	for (i = 0; i < zdev->num_netdevs; i++) {
		rc = ethtool_nl_get_optics(&ctx->opticsmon_ctx.ethtool_ctx, zdev->netdevs[i].name,
					   &ois[i]);
		if (rc)
			goto free_ois;
		num_ois++;
	}
	if (!opts->quiet) {
		util_fmt_obj_start(FMT_DEFAULT, "adapter");
		util_fmt_pair(FMT_QUOTE, "pft", zpci_pft_str(zdev));
		util_fmt_obj_start(FMT_DEFAULT, "ids");
		util_fmt_pair(FMT_QUOTE, "fid", "0x%0x", zdev->fid);
		if (zdev->uid_is_unique)
			util_fmt_pair(FMT_QUOTE, "uid", "0x%0x", zdev->uid);
		pci_addr = zpci_pci_addr(zdev);
		util_fmt_pair(FMT_QUOTE, "pci_address", pci_addr);
		free(pci_addr);
		util_fmt_obj_end();
		util_fmt_obj_start(FMT_LIST, "netdevs");
		for (i = 0; i < zdev->num_netdevs; i++)
			optics_json_print(opts, &zdev->netdevs[i], ois[i]);
		util_fmt_obj_end(); /* netdevs list */
		util_fmt_obj_end(); /* adapter */
		fflush(stdout);
	}
	if (opts->report) {
		for (i = 0; i < zdev->num_netdevs; i++) {
			rc = sclp_issue_optics_report(zdev, ois[i]);
			if (rc == -ENOTSUP) {
				fprintf(stderr, "Skipping %s which does not support reporting\n",
					zdev->netdevs[i].name);
			} else if (rc < 0) {
				fprintf(stderr, "Error issuing SCLP for optics data failed: %s\n",
					strerror(-rc));
			}
		}
	}
free_ois:
	for (i = 0; i < num_ois; i++)
		optics_free(ois[i]);
	free((void *)ois);
	return rc;
}

static void on_link_change(struct zpci_netdev *change_netdev, void *arg)
{
	struct zpcimon_ctx *ctx = arg;
	struct zpci_dev *zdev = NULL;
	struct zpci_netdev *netdev;
	int reloads = 1;

	do {
		if (ctx->zpci_list) {
			zdev = zpci_find_by_netdev(ctx->zpci_list, change_netdev->name,
						   &netdev);
			if (zdev) {
				/* Skip data collection if operational state is
				 * unchanged
				 */
				if (netdev->operstate == change_netdev->operstate)
					return;
				/* Update operation state for VFs even though
				 * they are skipped just for a consistent view
				 */
				netdev->operstate = change_netdev->operstate;
				/* Only collect optics data for PFs */
				if (!zpci_is_vf(zdev))
					opticsmon_collect_adapter_data(ctx, zdev);
				return;
			}
		}
		/* Could be uninitalized list or a new device, retry after reload  */
		zpci_list_reload(&ctx->zpci_list);
		reloads--;
	} while (reloads > 0);
}

static int opticsmon_open_monitor(struct zpcimon_ctx *ctx)
{
	int ret;

	ret = link_mon_nl_waitfd_create(&ctx->opticsmon_ctx.lctx, on_link_change, ctx);
	if (ret) {
		fprintf(stderr, "Failed to create link monitoring socket\n");
		ret = -EIO;
	}
	return ret;
}

static int opticsmon_get_monitor_fd(struct zpcimon_ctx *ctx)
{
	return link_mon_nl_waitfd_getfd(&ctx->opticsmon_ctx.lctx);
}

static void opticsmon_monitor_fd_handle(struct zpcimon_ctx *ctx)
{
	link_mon_nl_waitfd_read(&ctx->opticsmon_ctx.lctx);
}

static void opticsmon_close_monitor(struct zpcimon_ctx *ctx)
{
	link_mon_nl_waitfd_destroy(&ctx->opticsmon_ctx.lctx);
}

static int opticsmon_init(struct zpcimon_ctx *ctx)
{
	return ethtool_nl_connect(&ctx->opticsmon_ctx.ethtool_ctx);
}

static void opticsmon_destroy(struct zpcimon_ctx *ctx)
{
	ethtool_nl_close(&ctx->opticsmon_ctx.ethtool_ctx);
}

const struct zpcimon_ops opticsmon_ops = {
	.collect_adapter_data = opticsmon_collect_adapter_data,
	.open_monitor = opticsmon_open_monitor,
	.get_monitor_fd = opticsmon_get_monitor_fd,
	.monitor_fd_handle = opticsmon_monitor_fd_handle,
	.close_monitor = opticsmon_close_monitor,
	.init = opticsmon_init,
	.destroy = opticsmon_destroy,
};
