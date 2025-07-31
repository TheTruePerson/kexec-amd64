/*
 * Arch-specific compatibility layer for enabling kexec as loadable kernel
 * module.
 *
 * Copyright (C) 2021 Fabian Mastenbroek.
 * Ported to AMD64 architecture
 *
 * This program is free software; you can redistribute it and/or modify
 * it under the terms of the GNU General Public License as published by
 * the Free Software Foundation; either version 2 of the License, or
 * (at your option) any later version.
 */

#ifndef LINUX_MACHINE_KEXEC_COMPAT_H
#define LINUX_MACHINE_KEXEC_COMPAT_H

/**
 * Load the kexec compatibility layer.
 *
 * @param detect_vmx Attempt to detect the CPU virtualization mode.
 * @param shim_vmx Attempt to shim the VMX vectors.
 */
int machine_kexec_compat_load(int detect_vmx, int shim_vmx);

/**
 * Unload the kexec compatbility layer.
 */
void machine_kexec_compat_unload(void);

/**
 * Run the compatibility layer pre-reset. For instance, this method will
 * conditionally shim the hypervisor vectors.
 */
void machine_kexec_compat_prereset(void);

#endif /* LINUX_MACHINE_KEXEC_COMPAT_H */