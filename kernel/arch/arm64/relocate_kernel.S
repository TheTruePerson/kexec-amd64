/*COMPLETED
 * kexec for amd64
 *
 * Copyright (C) Linaro.
 * Copyright (C) Huawei Futurewei Technologies.
 * Ported to AMD64 architecture
 *
 * This program is free software; you can redistribute it and/or modify
 * it under the terms of the GNU General Public License version 2 as
 * published by the Free Software Foundation.
 */

#include <linux/kexec.h>
#include <linux/linkage.h>

#include <asm/kexec.h>
#include <asm/page.h>
#include <asm/processor.h>
#include <asm/msr.h>

/*
 * amd64_relocate_new_kernel - Put a 2nd stage image in place and boot it.
 *
 * The memory that the old kernel occupies may be overwritten when coping the
 * new image to its final location.  To assure that the
 * amd64_relocate_new_kernel routine which does that copy is not overwritten,
 * all code and data needed by amd64_relocate_new_kernel must be between the
 * symbols amd64_relocate_new_kernel and amd64_relocate_new_kernel_end.  The
 * machine_kexec() routine will copy amd64_relocate_new_kernel to the kexec
 * control_code_page, a special page which has been set up to be preserved
 * during the copy operation.
 */
ENTRY(amd64_relocate_new_kernel)

	/* Setup the list loop variables. */
	movq	%rsi, %r9			/* r9 = kimage_start */
	movq	%rdi, %r8			/* r8 = kimage_head */
	
	/* Get cache line size from CPUID */
	movl	$0x80000006, %eax
	cpuid
	movl	%ecx, %eax
	andl	$0xFF, %eax			/* Extract L2 cache line size */
	movq	%rax, %r15			/* r15 = cache line size */
	
	xorq	%r14, %r14			/* r14 = entry ptr */
	xorq	%r13, %r13			/* r13 = copy dest */

	/* Clear CPU control flags for safe kernel switch */
	/* Disable interrupts */
	cli
	
	/* Clear various CPU features that might interfere */
	movq	%cr0, %rax
	andq	$~(X86_CR0_TS | X86_CR0_EM), %rax	/* Clear task switch and emulation */
	movq	%rax, %cr0
	
	/* Clear CR4 features */
	movq	%cr4, %rax
	andq	$~(X86_CR4_VME | X86_CR4_PVI | X86_CR4_TSD | X86_CR4_DE), %rax
	movq	%rax, %cr4

1:
	/* Check if the new image needs relocation. */
	testq	$IND_DONE, %r8
	jnz	.Ldone

.Lloop:
	movq	%r8, %r12
	andq	$PAGE_MASK, %r12		/* r12 = addr */

	/* Test the entry flags. */
.Ltest_source:
	testq	$IND_SOURCE, %r8
	jz	.Ltest_indirection

	/* Invalidate dest page from cache */
	movq	%r13, %rax			/* dest address */
	movq	$PAGE_SIZE, %rcx		/* page size */
	addq	%r13, %rcx			/* end address */
	
	/* Align to cache line boundary */
	movq	%r15, %rdx
	subq	$1, %rdx
	notq	%rdx
	andq	%rdx, %rax			/* align start */

2:	clflush	(%rax)				/* flush cache line */
	addq	%r15, %rax			/* next cache line */
	cmpq	%rcx, %rax
	jb	2b

	mfence					/* memory fence */

	/* Copy page: dest=r13, src=r12 */
	movq	%r13, %rdi			/* destination */
	movq	%r12, %rsi			/* source */
	movq	$PAGE_SIZE, %rcx		/* size */
	
	/* Fast page copy using rep movsq */
	shrq	$3, %rcx			/* convert to qwords */
	cld
	rep movsq

	/* dest += PAGE_SIZE */
	addq	$PAGE_SIZE, %r13
	jmp	.Lnext

.Ltest_indirection:
	testq	$IND_INDIRECTION, %r8
	jz	.Ltest_destination

	/* ptr = addr */
	movq	%r12, %r14
	jmp	.Lnext

.Ltest_destination:
	testq	$IND_DESTINATION, %r8
	jz	.Lnext

	/* dest = addr */
	movq	%r12, %r13

.Lnext:
	/* entry = *ptr++ */
	movq	(%r14), %r8
	addq	$8, %r14

	/* while (!(entry & DONE)) */
	testq	$IND_DONE, %r8
	jz	.Lloop

.Ldone:
	/* wait for writes from copy to finish */
	mfence
	
	/* Flush instruction cache by reloading code segment */
	pushq	$__KERNEL_CS
	leaq	1f(%rip), %rax
	pushq	%rax
	lretq
1:
	
	/* Serialize instruction execution */
	cpuid

	/* Start new image. */
	xorq	%rax, %rax			/* clear rax */
	xorq	%rbx, %rbx			/* clear rbx */
	xorq	%rcx, %rcx			/* clear rcx */
	xorq	%rdx, %rdx			/* clear rdx */
	xorq	%rsi, %rsi			/* clear rsi */
	xorq	%rdi, %rdi			/* clear rdi */
	xorq	%r8, %r8			/* clear r8 */
	xorq	%r10, %r10			/* clear r10 */
	xorq	%r11, %r11			/* clear r11 */
	xorq	%r12, %r12			/* clear r12 */
	xorq	%r13, %r13			/* clear r13 */
	xorq	%r14, %r14			/* clear r14 */
	xorq	%r15, %r15			/* clear r15 */
	
	jmpq	*%r9				/* jump to new kernel */

ENDPROC(amd64_relocate_new_kernel)

.align 8	/* To keep the 64-bit values below naturally aligned. */

.Lcopy_end:
.org	KEXEC_CONTROL_PAGE_SIZE

/*
 * amd64_relocate_new_kernel_size - Number of bytes to copy to the
 * control_code_page.
 */
.globl amd64_relocate_new_kernel_size
amd64_relocate_new_kernel_size:
	.quad	.Lcopy_end - amd64_relocate_new_kernel