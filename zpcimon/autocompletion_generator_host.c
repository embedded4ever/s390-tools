/*
 * SPDX-License-Identifier: MIT
 *
 * Copyright IBM Corp.
 */

#include "lib/util_autocomp.h"

#include "zpcimon_cli.h"

int main(void)
{
	generate_autocomp(opt_vec, "zpcimon");
	generate_autocomp(opt_vec, "opticsmon");

	return 0;
}
