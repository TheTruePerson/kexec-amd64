/*COMPLETED
 * kexec_mod_amd64: Kexec driver for AMD64.
 *
 * Copyright (C) 2021 Fabian Mastenbroek.
 * Ported to AMD64 architecture
 *
 * This program is free software; you can redistribute it and/or modify
 * it under the terms of the GNU General Public License as published by
 * the Free Software Foundation; either version 2 of the License, or
 * (at your option) any later version.
 */

#define MODULE_NAME "kexec_mod_amd64"
#define pr_fmt(fmt) MODULE_NAME ": " fmt

#include <linux/module.h>

#include "machine_kexec_compat.h"
#include "idmap.h"

MODULE_LICENSE("GPL v2");
MODULE_AUTHOR("Fabian Mastenbroek <mail.fabianm@gmail.com>");
MODULE_DESCRIPTION("Kexec backport as Kernel Module for AMD64");
MODULE_VERSION("1.1");

static int detect_vmx = 1;
module_param(detect_vmx, int, 0);
MODULE_PARM_DESC(detect_vmx,
		 "Attempt to detect VMX root mode (default = 1)");

static int shim_vmx = 0;
module_param(shim_vmx, int, 0);
MODULE_PARM_DESC(shim_vmx,
		 "Shim the VMCALL_SOFT_RESTART call for VMX root mode (default = 0)");

static int __init
kexecmod_amd64_init(void)
{
	int err;

	/* Load compatibility layer */
	if ((err = machine_kexec_compat_load(detect_vmx, shim_vmx)) != 0) {
		pr_err("Failed to load: %d\n", err);
		return err;
	}

	/* Build identity map for MMU */
	kexec_idmap_setup();

	return 0;
}

module_init(kexecmod_amd64_init)

static void __exit
kexecmod_amd64_exit(void)
{
	/* Unload compatibility layer */
	machine_kexec_compat_unload();
}

module_exit(kexecmod_amd64_exit);