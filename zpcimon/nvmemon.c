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
#include <libudev.h>

#include "lib/pci_list.h"
#include "lib/pci_sclp.h"
#include "lib/util_fmt.h"

#include "nvmemon.h"
#include "zpcimon.h"

/**
 * Reads a CPU native 128 bit unsigned integer from the binary buffer @data
 * containing the value in the 128 bit little endian format used by the
 * NVMe standard.
 *
 * @return the 128 bit value encoded in the data buffer.
 */
static __uint128_t nvme_le128_to_cpu(const __u8 data[16])
{
	__uint128_t u;
	int i;

	u = data[0];
	for (i = 1; i < (int)sizeof(u); i++)
		u |= (__uint128_t)data[i] << (8 * i);
	return u;
}

#define MAX_UINT128_DECIMAL_LEN (41) /* length of 2^128-1 in decimal + 0 byte */

/**
 * Write the decimal string representation of the passed unsigned 128 bit value @val into
 * the buffer @buf for output in JSON. The representation does not include
 * quotes.
 */
static void nvme_u128_to_json_val(__uint128_t val, char buf[MAX_UINT128_DECIMAL_LEN])
{
	const char *digit_ascii = "0123456789";
	int pos = MAX_UINT128_DECIMAL_LEN - 1;
	int mod_ten;
	int len;

	/* Write digits right to left at the end of res */
	do {
		mod_ten = val % 10;
		val /= 10;
		buf[pos--] = digit_ascii[mod_ten];
	} while (val);
	/* Move digits to the front */
	len = MAX_UINT128_DECIMAL_LEN - 1 - pos;
	memmove(buf, &buf[pos + 1], len);
	buf[len] = '\0';
}

static void nvme_json_print_smart_log(struct zpcimon_ctx *ctx, struct nvme_smart_log *log)
{
	char u128_num_buf[MAX_UINT128_DECIMAL_LEN];
	unsigned int temperature;

	/* While some fields in struct nvme_smart_log are __leXX
	 * temperature is an array of two u8 of the little endian data
	 * in Kelvin.
	 */
	temperature = log->temperature[1] << 8 | log->temperature[0];

	util_fmt_obj_start(FMT_DEFAULT, "smart-log");
	util_fmt_pair(FMT_DEFAULT, "critical_warning", "%d", log->critical_warning);
	util_fmt_pair(FMT_DEFAULT, "temperature", "%d", temperature);
	util_fmt_pair(FMT_DEFAULT, "avail_spare", "%d", log->avail_spare);
	util_fmt_pair(FMT_DEFAULT, "spare_thresh", "%d", log->spare_thresh);
	util_fmt_pair(FMT_DEFAULT, "percent_used", "%d", log->percent_used);
	util_fmt_pair(FMT_DEFAULT, "endurance_grp_critical_warning_summary", "%d",
		      log->endu_grp_crit_warn_sumry);
	nvme_u128_to_json_val(nvme_le128_to_cpu(log->data_units_read), u128_num_buf);
	util_fmt_pair(FMT_DEFAULT, "data_units_read", "%s", u128_num_buf);
	nvme_u128_to_json_val(nvme_le128_to_cpu(log->data_units_written), u128_num_buf);
	util_fmt_pair(FMT_DEFAULT, "data_units_written", "%s", u128_num_buf);
	nvme_u128_to_json_val(nvme_le128_to_cpu(log->host_reads), u128_num_buf);
	util_fmt_pair(FMT_DEFAULT, "host_read_commands", "%s", u128_num_buf);
	nvme_u128_to_json_val(nvme_le128_to_cpu(log->host_writes), u128_num_buf);
	util_fmt_pair(FMT_DEFAULT, "host_write_commands", "%s", u128_num_buf);
	nvme_u128_to_json_val(nvme_le128_to_cpu(log->ctrl_busy_time), u128_num_buf);
	util_fmt_pair(FMT_DEFAULT, "controller_busy_time", "%s", u128_num_buf);
	nvme_u128_to_json_val(nvme_le128_to_cpu(log->power_cycles), u128_num_buf);
	util_fmt_pair(FMT_DEFAULT, "power_cycles", "%s", u128_num_buf);
	/* 2^128 hours is 2.8*10^24 times the age of the universe ;) */
	nvme_u128_to_json_val(nvme_le128_to_cpu(log->power_on_hours), u128_num_buf);
	util_fmt_pair(FMT_DEFAULT, "power_on_hours", "%s", u128_num_buf);
	nvme_u128_to_json_val(nvme_le128_to_cpu(log->unsafe_shutdowns), u128_num_buf);
	util_fmt_pair(FMT_DEFAULT, "unsafe_shutdowns", "%s", u128_num_buf);
	nvme_u128_to_json_val(nvme_le128_to_cpu(log->media_errors), u128_num_buf);
	util_fmt_pair(FMT_DEFAULT, "media_errors", "%s", u128_num_buf);
	nvme_u128_to_json_val(nvme_le128_to_cpu(log->num_err_log_entries), u128_num_buf);
	util_fmt_pair(FMT_DEFAULT, "num_err_log_entries", "%s", u128_num_buf);
	util_fmt_pair(FMT_DEFAULT, "warning_temp_time", "%d", le32toh(log->warning_temp_time));
	util_fmt_pair(FMT_DEFAULT, "critical_comp_time", "%d", le32toh(log->critical_comp_time));
	util_fmt_pair(FMT_DEFAULT, "temperature_sensor_1", "%d", le16toh(log->temp_sensor[0]));
	util_fmt_pair(FMT_DEFAULT, "temperature_sensor_2", "%d", le16toh(log->temp_sensor[1]));
	util_fmt_pair(FMT_DEFAULT, "temperature_sensor_3", "%d", le16toh(log->temp_sensor[2]));
	util_fmt_pair(FMT_DEFAULT, "thm_temp1_trans_count", "%d",
		      le32toh(log->thm_temp1_trans_count));
	util_fmt_pair(FMT_DEFAULT, "thm_temp2_trans_count", "%d",
		      le32toh(log->thm_temp2_trans_count));
	util_fmt_pair(FMT_DEFAULT, "thm_temp1_total_time", "%d",
		      le32toh(log->thm_temp1_total_time));
	util_fmt_pair(FMT_DEFAULT, "thm_temp2_total_time", "%d",
		      le32toh(log->thm_temp2_total_time));
	util_fmt_obj_end(); /* smart-log */

	if (ctx->opts.smart_blob)
		zpcimon_json_base64_pair("smart-log-raw", (uint8_t *)log, sizeof(*log));
}

static void nvme_json_print(struct zpcimon_ctx *ctx, struct zpci_dev *zdev, const char *name,
			    struct nvme_smart_log *log)
{
	zpci_adapter_json_print_start(zdev);
	util_fmt_obj_start(FMT_DEFAULT, "nvmedev");
	util_fmt_pair(FMT_QUOTE, "dev", name);
	nvme_json_print_smart_log(ctx, log);
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

static int nvmemon_open_monitor(struct zpcimon_ctx *ctx)
{
	struct nvmemon_ctx *nctx = &ctx->nvmemon_ctx;
	int ret = -EINVAL;

	nctx->udev = udev_new();
	if (!nctx->udev)
		return -ENOMEM;

	nctx->mon = udev_monitor_new_from_netlink(nctx->udev, "kernel");
	if (!nctx->mon) {
		ret = -ENOMEM;
		goto error_udev;
	}

	if (udev_monitor_filter_add_match_subsystem_devtype(nctx->mon, "nvme", NULL) < 0)
		goto error_mon;

	/* Note: This explicit udev_monitor_enable_receiving() is deprecated and not needed anymore
	 * in udev v257+. It's harmless though so we do it for easier backporting.
	 */
	if (udev_monitor_enable_receiving(nctx->mon) < 0)
		goto error_mon;

	return 0;

error_mon:
	udev_monitor_unref(nctx->mon);
	nctx->mon = NULL;
error_udev:
	udev_unref(nctx->udev);
	nctx->udev = NULL;
	return ret;
}

static int nvmemon_get_monitor_fd(struct zpcimon_ctx *ctx)
{
	struct nvmemon_ctx *nctx = &ctx->nvmemon_ctx;

	if (!nctx->mon)
		return -1;
	return udev_monitor_get_fd(nctx->mon);
}

static void nvmemon_monitor_fd_handle(struct zpcimon_ctx *ctx)
{
	const char *action, *transport, *event_pci_addr;
	struct nvmemon_ctx *nctx = &ctx->nvmemon_ctx;
	struct udev_device *dev, *pci_dev;
	struct zpci_dev *zdev;
	char *zdev_pci_addr;

	dev = udev_monitor_receive_device(nctx->mon);
	if (!dev)
		return;

	action = udev_device_get_action(dev);
	transport = udev_device_get_property_value(dev, "NVME_TRTYPE");

	/* Change events are late enough that the /dev/nvmeX is ready for
	 * reading SMART data and we're only interested in directly PCIe
	 * attached NVMes
	 */
	if (action && strcmp(action, "change") == 0 && transport &&
	    strcmp(transport, "pcie") == 0) {
		pci_dev = udev_device_get_parent_with_subsystem_devtype(dev, "pci", NULL);
		if (!pci_dev)
			goto out;
		event_pci_addr = udev_device_get_sysname(pci_dev);
		if (!event_pci_addr)
			goto out;

		zpci_list_reload(&ctx->zpci_list);
		if (ctx->zpci_list) {
			util_list_iterate(ctx->zpci_list, zdev) {
				if (zdev->pft != ZPCI_PFT_NVME)
					continue;
				zdev_pci_addr = zpci_pci_addr(zdev);
				if (strcmp(zdev_pci_addr, event_pci_addr) == 0) {
					free(zdev_pci_addr);
					nvmemon_collect_adapter_data(ctx, zdev);
					break;
				}
				free(zdev_pci_addr);
			}
		}
	}
out:
	udev_device_unref(dev);
}

static void nvmemon_close_monitor(struct zpcimon_ctx *ctx)
{
	struct nvmemon_ctx *nctx = &ctx->nvmemon_ctx;

	if (nctx->mon) {
		udev_monitor_unref(nctx->mon);
		nctx->mon = NULL;
	}
	if (nctx->udev) {
		udev_unref(nctx->udev);
		nctx->udev = NULL;
	}
}

const struct zpcimon_ops nvmemon_ops = {
	.collect_adapter_data = nvmemon_collect_adapter_data,
	.open_monitor = nvmemon_open_monitor,
	.get_monitor_fd = nvmemon_get_monitor_fd,
	.monitor_fd_handle = nvmemon_monitor_fd_handle,
	.close_monitor = nvmemon_close_monitor,
};
