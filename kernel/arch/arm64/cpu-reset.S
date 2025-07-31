/*
 * CPU reset routines
 *
 * Copyright (C) 2001 Deep Blue Solutions Ltd.
 * Copyright (C) 2012 ARM Ltd.
 * Copyright (C) 2015 Huawei Futurewei Technologies.
 * Ported to AMD64 architecture
 *
 * This program is free software; you can redistribute it and/or modify
 * it under the terms of the GNU General Public License version 2 as
 * published by the Free Software Foundation.
 */

#include <linux/linkage.h>
#include <asm/processor.h>
#include <asm/msr.h>
#include <asm/segment.h>

.text

/*
 * __cpu_soft_restart(vmx_switch, entry, arg0, arg1, arg2) - Helper for
 * cpu_soft_restart.
 *
 * @vmx_switch: Flag to indicate a switch to VMX root mode is needed.
 * @entry: Location to jump to for soft reset.
 * arg0: First argument passed to @entry.
 * arg1: Second argument passed to @entry.
 * arg2: Third argument passed to @entry.
 *
 * Put the CPU into the same state as it would be if it had been reset, and
 * branch to what would be the reset vector. It must be executed with the
 * flat identity mapping.
 */
ENTRY(__cpu_soft_restart)
	/* Clear CPU control flags */
	movq	%cr0, %r12
	andq	$~(X86_CR0_TS | X86_CR0_EM | X86_CR0_MP), %r12	/* Clear task switch, emulation, monitor */
	movq	%r12, %cr0
	
	movq	%cr4, %r12
	andq	$~(X86_CR4_VME | X86_CR4_PVI | X86_CR4_TSD | X86_CR4_DE), %r12
	movq	%r12, %cr4
	
	/* Serialize instruction execution */
	xorl	%eax, %eax
	cpuid

	/*
	 * Preserve kernel entry point to fallback to normal boot
	 * in case the hypervisor call returns/fails, for instance,
	 * when VMCALL_SOFT_RESTART is not supported by the hypervisor.
	 */
	movq	%rsi, %r8			/* entry */

	testq	%rdi, %rdi			/* vmx_switch? */
	jz	1f
	
	/* Attempt hypervisor soft restart via VMCALL */
	movq	$0x8000000A, %rax		/* VMCALL_SOFT_RESTART equivalent */
	vmcall					/* no return expected */
	/* If VMCALL returns, fall through to normal restart */

1:	/* Normal CPU restart sequence */
	/* Disable interrupts */
	cli
	
	/* Clear segment registers */
	xorq	%rax, %rax
	movw	%ax, %ds
	movw	%ax, %es
	movw	%ax, %fs
	movw	%ax, %gs
	
	/* Set up arguments for entry point */
	movq	%rdx, %rdi			/* arg0 */
	movq	%rcx, %rsi			/* arg1 */
	movq	%r9, %rdx			/* arg2 */
	
	/* Clear other registers for clean state */
	xorq	%rax, %rax
	xorq	%rbx, %rbx
	xorq	%rcx, %rcx
	xorq	%r9, %r9
	xorq	%r10, %r10
	xorq	%r11, %r11
	xorq	%r12, %r12
	xorq	%r13, %r13
	xorq	%r14, %r14
	xorq	%r15, %r15
	
	/* Jump to entry point */
	jmpq	*%r8
ENDPROC(__cpu_soft_restart)