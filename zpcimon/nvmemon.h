/*
 * Copyright IBM Corp. 2025
 *
 * s390-tools is free software; you can redistribute it and/or modify
 * it under the terms of the MIT license. See LICENSE for details.
 */
#ifndef ZPCIMON_NVMEMON_H
#define ZPCIMON_NVMEMON_H

#include <libudev.h>

struct nvmemon_ctx {
	struct udev *udev;
	struct udev_monitor *mon;
};

extern const struct zpcimon_ops nvmemon_ops;
#endif /* ZPCIMON_NVMEMON_H */
