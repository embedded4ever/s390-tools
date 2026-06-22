/*
 * zpcimon - Report monitoring data to firmware
 *
 * Copyright IBM Corp. 2025
 *
 * s390-tools is free software; you can redistribute it and/or modify
 * it under the terms of the MIT license. See LICENSE for details.
 */
#include <err.h>
#include <errno.h>
#include <fcntl.h>
#include <stdbool.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>
#include <libnvme.h>

#include "lib/pci_list.h"
#include "lib/pci_sclp.h"
#include "lib/util_fmt.h"

#include "nvmemon.h"
#include "zpcimon.h"

static void nvme_json_print(struct zpcimon_ctx *ctx, struct zpci_dev *zdev, const char *name,
			    struct nvme_smart_log *log)
{
	zpci_adapter_json_print_start(zdev);
	util_fmt_obj_start(FMT_DEFAULT, "nvmedev");
	util_fmt_pair(FMT_QUOTE, "dev", name);
	if (ctx->opts.smart_blob)
		zpcimon_json_base64_pair("smart-log-raw", (uint8_t *)log, sizeof(*log));
	util_fmt_obj_end();
	zpci_adapter_json_print_end();
	fflush(stdout);
}

static int sclp_issue_nvme_smart_report(struct zpci_dev *zdev, const uint8_t *smart, int smart_len)
{
	char *pci_addr;
	int rc;

	if (zdev->pft != ZPCI_PFT_NVME)
		return -ENOTSUP;
	pci_addr = zpci_pci_addr(zdev);
	rc = zpci_sclp_issue_action(pci_addr, SCLP_ERRNOTIFY_AQ_NVME_SMART_DATA,
				    (char *)smart, smart_len, SCLP_ERRNOTIFY_ID_NVMEMON);
	free(pci_addr);
	return rc;
}

static int nvmemon_collect_adapter_data(struct zpcimon_ctx *ctx, struct zpci_dev *zdev)
{
	struct nvme_smart_log log = {};
	int nvme_fd, rc = -ENODEV;
	char *dev, *pci_addr;

	if (zdev->pft != ZPCI_PFT_NVME)
		return -ENODEV;

	pci_addr = zpci_pci_addr(zdev);
	dev = zpci_get_nvme_device_node(pci_addr);
	if (!dev)
		goto exit_free_addr;

	nvme_fd = openat(AT_FDCWD, dev, O_RDONLY);
	if (nvme_fd < 0) {
		warn("Failed to open %s", dev);
		rc = -errno;
		goto exit_free_dev;
	}

	rc = nvme_get_log_smart(nvme_fd, NVME_NSID_ALL, false, &log);
	if (rc) {
		warnx("Getting NVMe SMART log failed %d", rc);
		goto exit_close;
	}
	if (!ctx->opts.quiet)
		nvme_json_print(ctx, zdev, dev, &log);
	if (ctx->opts.report) {
		rc = sclp_issue_nvme_smart_report(zdev, (uint8_t *)&log, sizeof(log));
		if (rc < 0 && rc != -ENOTSUP)
			warnx("Error issuing SCLP for NVMe SMART log failed");
	}

exit_close:
	close(nvme_fd);
exit_free_dev:
	free(dev);
exit_free_addr:
	free(pci_addr);
	return rc;
}

const struct zpcimon_ops nvmemon_ops = {
	.collect_adapter_data = nvmemon_collect_adapter_data,
};
