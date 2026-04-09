/*
 * Copyright IBM Corp. 2025
 *
 * s390-tools is free software; you can redistribute it and/or modify
 * it under the terms of the MIT license. See LICENSE for details.
 */
#ifndef ZPCIMON_OPTICSMON_H
#define ZPCIMON_OPTICSMON_H
#include "ethtool.h"
#include "link_mon.h"

struct options;

struct opticsmon_ctx {
	struct ethtool_nl_ctx ethtool_ctx;
	struct link_mon_nl_ctx lctx;
};

extern const struct zpcimon_ops opticsmon_ops;
#endif /* ZPCIMON_OPTICSMON_H */
