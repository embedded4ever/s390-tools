/*
 * Copyright IBM Corp. 2024
 *
 * s390-tools is free software; you can redistribute it and/or modify
 * it under the terms of the MIT license. See LICENSE for details.
 */
#ifndef ZPCIMON_ZPCIMON_H
#define ZPCIMON_ZPCIMON_H
#include <stdbool.h>
#include <stdint.h>

#include "lib/util_fmt.h"

#include "nvmemon.h"
#include "opticsmon.h"

#define API_LEVEL 1

struct options {
	uint32_t interval_seconds;

	bool monitor;
	bool report;
	bool quiet;
	enum util_fmt_t format;
	bool explicit_format;

	/* Optics Monitoring Specific */
	bool module_info;
	/* NVMe Monitoring Specific */
	bool smart_blob;
};

struct zpcimon_ctx {
	struct options opts;
	struct util_list *zpci_list;
	struct opticsmon_ctx opticsmon_ctx;
	struct nvmemon_ctx nvmemon_ctx;
};

struct zpcimon_ops {
	int (*collect_adapter_data)(struct zpcimon_ctx *ctx, struct zpci_dev *zdev);

	int (*open_monitor)(struct zpcimon_ctx *ctx);
	int (*get_monitor_fd)(struct zpcimon_ctx *ctx);
	void (*monitor_fd_handle)(struct zpcimon_ctx *ctx);
	void (*close_monitor)(struct zpcimon_ctx *ctx);

	int (*init)(struct zpcimon_ctx *ctx);
	void (*destroy)(struct zpcimon_ctx *ctx);
};

void zpci_list_reload(struct util_list **zpci_list);

void zpci_adapter_json_print_start(struct zpci_dev *zdev);
void zpci_adapter_json_print_end(void);
void zpcimon_json_base64_pair(char *name, uint8_t *buf, int len);
#endif /* ZPCIMON_ZPCIMON_H */
