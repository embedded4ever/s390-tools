/*
 * zpcimon - Report monitoring data to firmware
 *
 * Copyright IBM Corp. 2024
 *
 * s390-tools is free software; you can redistribute it and/or modify
 * it under the terms of the MIT license. See LICENSE for details.
 */
#include <errno.h>
#include <signal.h>
#include <stdbool.h>
#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>

#include <linux/if.h>
#include <sys/epoll.h>
#include <sys/signalfd.h>
#include <sys/timerfd.h>

#include <openssl/evp.h>

#include "lib/pci_list.h"
#include "lib/util_fmt.h"
#include "lib/util_libc.h"
#include "lib/util_opt.h"
#include "lib/util_prg.h"
#include "lib/util_time.h"
#include "lib/zt_common.h"

#include "opticsmon.h"
#include "zpcimon.h"
#include "zpcimon_cli.h"

#define API_LEVEL 1

struct zpcimon_monitor {
	const struct zpcimon_ops *ops;
	uint32_t initialized : 1;
	uint32_t opened : 1;
};

static struct zpcimon_monitor monitors[] = {
	{.ops = &opticsmon_ops, .initialized = 0, .opened = 0},
};

static const struct util_prg prg = {
	.desc = "Use zpcimon to monitor the health of PCI devices",
	.copyright_vec = { {
				   .owner = "IBM Corp.",
				   .pub_first = 2024,
				   .pub_last = 2024,
			   },
			   UTIL_PRG_COPYRIGHT_END }
};

static void parse_cmdline(int argc, char *argv[], struct options *opts)
{
	enum util_fmt_t fmt;
	uint32_t seconds;
	int cmd, ret;

	util_prg_init(&prg);
	util_opt_init(opt_vec, NULL);

	do {
		cmd = util_opt_getopt_long(argc, argv);

		switch (cmd) {
		case 'm':
			opts->monitor = true;
			break;
		case 'r':
			opts->report = true;
			break;
		case 'q':
			opts->quiet = true;
			break;
		case OPT_DUMP:
			opts->module_info = true;
			break;
		case OPT_FORMAT:
			if (!util_fmt_name_to_type(optarg, &fmt))
				errx(EXIT_FAILURE, "Unknown format %s", optarg);
			opts->format = fmt;
			opts->explicit_format = true;
			break;
		case 'i':
			ret = sscanf(optarg, "%u", &seconds);
			if (ret != 1) {
				fprintf(stderr,
					"Failed to parse interval argument \"%s\" as seconds\n",
					optarg);
				exit(EXIT_FAILURE);
			}
			if (seconds < SEC_PER_DAY)
				opts->interval_seconds = seconds;
			if (seconds < 1)
				opts->interval_seconds = 1;
			break;
		case 'h':
			util_prg_print_help();
			util_opt_print_help();
			exit(EXIT_SUCCESS);
		case 'v':
			util_prg_print_version();
			exit(EXIT_SUCCESS);
		case -1:
			/* End of options string */
			break;
		}
	} while (cmd != -1);
}

void zpci_adapter_json_print_start(struct zpci_dev *zdev)
{
	char *pci_addr;

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
}

void zpci_adapter_json_print_end(void)
{
	util_fmt_obj_end(); /* adapter */
}

void zpcimon_json_base64_pair(char *name, uint8_t *buf, int len)
{
	int b64_calclen, b64len;
	char *b64;

	b64_calclen = (len / 3) * 4;
	if (len % 3 > 0)
		b64_calclen += 4;

	b64 = util_zalloc(b64_calclen + 1); /* adds NUL byte */
	b64len = EVP_EncodeBlock((unsigned char *)b64, (unsigned char *)buf, len);
	if (b64len != b64_calclen) {
		warnx("encoding base64 via openssl failed\n");
		goto out;
	}
	util_fmt_pair(FMT_QUOTE, name, b64);
out:
	free(b64);
}

void zpci_list_reload(struct util_list **zpci_list)
{
	if (*zpci_list)
		zpci_free_dev_list(*zpci_list);
	*zpci_list = zpci_dev_list();
}

static void collect_all_adapter_data(struct zpcimon_ctx *ctx)
{
	struct zpci_dev *zdev;
	int i;

	zpci_list_reload(&ctx->zpci_list);
	util_list_iterate(ctx->zpci_list, zdev) {
		for (i = 0; i < (int)ARRAY_SIZE(monitors); i++)
			if (monitors[i].ops->collect_adapter_data)
				monitors[i].ops->collect_adapter_data(ctx, zdev);
	}
}

#define MAX_EVENTS 8

static int monitor_epoll_mon_fds_prepare(struct zpcimon_ctx *ctx, int epfd, int mon_fds[])
{
	struct epoll_event ev;
	int mon_idx;

	for (mon_idx = 0; mon_idx < (int)ARRAY_SIZE(monitors); mon_idx++) {
		if (!monitors[mon_idx].ops->get_monitor_fd) {
			mon_fds[mon_idx] = -1;
			continue;
		}
		mon_fds[mon_idx] = monitors[mon_idx].ops->get_monitor_fd(ctx);
		if (mon_fds[mon_idx] < 0)
			return -EIO;
		ev.events = EPOLLIN;
		ev.data.fd = mon_fds[mon_idx];
		if (epoll_ctl(epfd, EPOLL_CTL_ADD, mon_fds[mon_idx], &ev) == -1)
			return -EIO;
	}
	return 0;
}

static void monitor_epoll_mon_fds(struct zpcimon_ctx *ctx, struct epoll_event event,
				  const int mon_fds[])
{
	int mon_idx;

	for (mon_idx = 0; mon_idx < (int)ARRAY_SIZE(monitors); mon_idx++) {
		if (event.data.fd != mon_fds[mon_idx])
			continue;
		if (!monitors[mon_idx].ops->monitor_fd_handle)
			continue;
		monitors[mon_idx].ops->monitor_fd_handle(ctx);
	}
}

static int monitor_epoll(struct zpcimon_ctx *ctx, const int mon_fds[], int epfd, int sigfd,
			 int timerfd)
{
	struct epoll_event events[MAX_EVENTS];
	struct signalfd_siginfo fdsi;
	uint64_t expirations;
	ssize_t sread;
	int i, nfds;

	nfds = epoll_wait(epfd, events, MAX_EVENTS, -1);
	if (nfds < 0)
		return nfds;
	for (i = 0; i < nfds; i++) {
		/* signal fd */
		if (events[i].data.fd == sigfd) {
			sread = read(sigfd, &fdsi, sizeof(fdsi));
			if (sread != sizeof(fdsi))
				return -EIO;
			switch (fdsi.ssi_signo) {
			case SIGINT:
			case SIGTERM:
			case SIGQUIT:
				return -EINTR;
			/* Unexpected signal */
			default:
				return -EIO;
			}
			/* timer fd */
		} else if (events[i].data.fd == timerfd) {
			sread = read(timerfd, &expirations, sizeof(uint64_t));
			if (sread != sizeof(uint64_t))
				return -EIO;
			if (!expirations)
				continue;
			collect_all_adapter_data(ctx);
			/* netlink fd */
		} else {
			monitor_epoll_mon_fds(ctx, events[i], mon_fds);
		}
	}
	return 0;
}

static int monitor_wait_loop(struct zpcimon_ctx *ctx, int sigfd, int timerfd)
{
	int mon_fds[ARRAY_SIZE(monitors)];
	struct epoll_event ev;
	int epfd, ret = -EIO;

	epfd = epoll_create1(EPOLL_CLOEXEC);
	if (epfd < 0)
		return -EIO;

	ev.events = EPOLLIN;
	ev.data.fd = sigfd;
	if (epoll_ctl(epfd, EPOLL_CTL_ADD, sigfd, &ev) == -1)
		goto out_close;

	ev.events = EPOLLIN;
	ev.data.fd = timerfd;
	if (epoll_ctl(epfd, EPOLL_CTL_ADD, timerfd, &ev) == -1)
		goto out_close;

	ret = monitor_epoll_mon_fds_prepare(ctx, epfd, mon_fds);
	if (ret)
		goto out_close;

	while (1) {
		ret = monitor_epoll(ctx, mon_fds, epfd, sigfd, timerfd);
		if (ret)
			break;
	}
out_close:
	/* Getting interrupted by a signal is not an error */
	if (ret == -EINTR)
		ret = 0;
	close(epfd);
	return ret;
}

static void zpcimon_close_monitor(struct zpcimon_ctx *ctx)
{
	int i;

	for (i = 0; i < (int)ARRAY_SIZE(monitors); i++) {
		if (!monitors[i].ops->close_monitor || !monitors[i].opened)
			continue;
		monitors[i].ops->close_monitor(ctx);
		monitors[i].opened = 0;
	}
}

static int zpcimon_open_monitor(struct zpcimon_ctx *ctx)
{
	int i, ret = -ENXIO;

	for (i = 0; i < (int)ARRAY_SIZE(monitors); i++) {
		if (!monitors[i].ops->open_monitor || monitors[i].opened)
			continue;
		if (monitors[i].opened)
			goto error;
		ret = monitors[i].ops->open_monitor(ctx);
		if (ret)
			goto error;
		monitors[i].opened = 1;
	}
	return 0;

error:
	zpcimon_close_monitor(ctx);
	return ret;
}

static int monitor_mode(struct zpcimon_ctx *ctx)
{
	struct itimerspec timerspec;
	int sigfd, timerfd, ret;
	sigset_t mask;

	sigemptyset(&mask);
	sigaddset(&mask, SIGINT);
	sigaddset(&mask, SIGQUIT);
	sigaddset(&mask, SIGTERM);

	if (sigprocmask(SIG_BLOCK, &mask, NULL) == -1)
		return -EIO;

	sigfd = signalfd(-1, &mask, 0);
	if (sigfd == -1) {
		fprintf(stderr, "Failed to create signalfd\n");
		return -EIO;
	}

	timerfd = timerfd_create(CLOCK_MONOTONIC, 0);
	if (timerfd == -1) {
		fprintf(stderr, "Failed to create timerfd\n");
		ret = -EIO;
		goto close_signalfd;
	}

	/* Set initial expiration to 1 ns so we gather optics data at startup */
	timerspec.it_value.tv_sec = 0;
	timerspec.it_value.tv_nsec = 1;
	timerspec.it_interval.tv_sec = ctx->opts.interval_seconds;
	timerspec.it_interval.tv_nsec = 0;
	ret = timerfd_settime(timerfd, 0, &timerspec, NULL);
	if (ret == -1) {
		fprintf(stderr, "Failed to arm timer\n");
		goto close_timerfd;
	}

	util_fmt_init(stdout, ctx->opts.format, FMT_DEFAULT, API_LEVEL);
	ret = zpcimon_open_monitor(ctx);
	if (ret < 0)
		goto cleanup_fmt;

	ret = monitor_wait_loop(ctx, sigfd, timerfd);

	zpcimon_close_monitor(ctx);
cleanup_fmt:
	util_fmt_exit();
close_timerfd:
	close(timerfd);
close_signalfd:
	close(sigfd);
	return ret;
}

static int oneshot_mode(struct zpcimon_ctx *ctx)
{
	util_fmt_init(stdout, ctx->opts.format, FMT_DEFAULT, API_LEVEL);
	if (!ctx->opts.quiet)
		util_fmt_obj_start(FMT_LIST, "adapters");

	collect_all_adapter_data(ctx);

	if (!ctx->opts.quiet)
		util_fmt_obj_end();
	util_fmt_exit();

	return EXIT_SUCCESS;
}

static void zpcimon_destroy(struct zpcimon_ctx *ctx)
{
	int i;

	for (i = 0; i < (int)ARRAY_SIZE(monitors); i++) {
		if (!monitors[i].ops->destroy || !monitors[i].initialized)
			continue;
		monitors[i].ops->destroy(ctx);
		monitors[i].initialized = false;
	}
}

static int zpcimon_init(struct zpcimon_ctx *ctx)
{
	int i, ret = -ENXIO;

	for (i = 0; i < (int)ARRAY_SIZE(monitors); i++) {
		if (!monitors[i].ops->init)
			continue;
		if (monitors[i].initialized)
			goto error;
		ret = monitors[i].ops->init(ctx);
		if (ret)
			goto error;
		monitors[i].initialized = 1;
	}
	return 0;

error:
	zpcimon_destroy(ctx);
	return ret;
}

static bool is_supported_fmt(enum util_fmt_t fmt, bool monitor)
{
	switch (fmt) {
	case FMT_JSON:
	case FMT_PAIRS:
		return monitor ? false : true;
	case FMT_JSONL:
	case FMT_JSONSEQ:
		return monitor ? true : false;
	default:
		return false;
	}
}

static int set_format(struct options *opts)
{
	if (!opts->explicit_format)
		opts->format = (opts->monitor) ? FMT_JSONSEQ : FMT_JSON;

	if (!is_supported_fmt(opts->format, opts->monitor)) {
		warnx("Format %s is not supported in %s mode",
		      util_fmt_type_to_name(opts->format), (opts->monitor) ? "monitor" : "query");
		return -EINVAL;
	}
	return 0;
}

int main(int argc, char **argv)
{
	struct zpcimon_ctx ctx = { .opts = { .interval_seconds = SEC_PER_DAY } };
	int ret;

	parse_cmdline(argc, argv, &ctx.opts);
	ret = set_format(&ctx.opts);
	if (ret)
		return ret;
	ret = zpcimon_init(&ctx);
	if (ret)
		return ret;
	if (ctx.opts.monitor)
		ret = monitor_mode(&ctx);
	else
		ret = oneshot_mode(&ctx);
	zpcimon_destroy(&ctx);

	if (ctx.zpci_list)
		zpci_free_dev_list(ctx.zpci_list);

	return ret;
}
