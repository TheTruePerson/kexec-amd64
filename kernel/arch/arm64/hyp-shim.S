/*COMPLETED
 * Hypervisor stub shim
 *
 * Copyright (C) 2012 ARM Ltd.
 * Author:	Marc Zyngier <marc.zyngier@arm.com>
 * Ported to AMD64 architecture
 *
 * This program is free software; you can redistribute it and/or modify
 * it under the terms of the GNU General Public License version 2 as
 * published by the Free Software Foundation.
 *
 * This program is distributed in the hope that it will be useful,
 * but WITHOUT ANY WARRANTY; without even the implied warranty of
 * MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
 * GNU General Public License for more details.
 *
 * You should have received a copy of the GNU General Public License
 * along with this program.  If not, see <http://www.gnu.org/licenses/>.
 */

#include <linux/init.h>
#include <linux/version.h>
#include <linux/linkage.h>

#include <asm/processor.h>
#include <asm/msr.h>
#include <asm/segment.h>
#include <asm/page.h>

	.text
	.align 4096

ENTRY(__hyp_shim_vectors)
	// Exception vector table for VMX root mode
	.quad	vmx_sync_invalid		// Synchronous exception
	.quad	vmx_irq_invalid			// IRQ
	.quad	vmx_fiq_invalid			// NMI
	.quad	vmx_error_invalid		// Error exception

	.quad	vmx_sync_invalid		// Synchronous exception (ring 0)
	.quad	vmx_irq_invalid			// IRQ (ring 0)
	.quad	vmx_fiq_invalid			// NMI (ring 0)
	.quad	vmx_error_invalid		// Error exception (ring 0)

	.quad	guest_sync_shim			// Synchronous 64-bit guest
	.quad	guest_irq_invalid		// IRQ 64-bit guest
	.quad	guest_fiq_invalid		// NMI 64-bit guest
	.quad	guest_error_invalid		// Error 64-bit guest

	.quad	guest_sync_invalid		// Synchronous 32-bit guest
	.quad	guest_irq_invalid		// IRQ 32-bit guest
	.quad	guest_fiq_invalid		// NMI 32-bit guest
	.quad	guest_error_invalid		// Error 32-bit guest
ENDPROC(__hyp_shim_vectors)

	.align 4096

guest_sync_shim:
	// Save caller-saved registers
	pushq	%rax
	pushq	%rcx
	pushq	%rdx
	pushq	%rsi
	pushq	%rdi
	pushq	%r8
	pushq	%r9
	pushq	%r10
	pushq	%r11

	// Check if this is a VMCALL (equivalent to HVC on ARM)
	// Get VM exit reason from VMCS
	movl	$0x4402, %ecx		// VM_EXIT_REASON
	vmread	%rcx, %rax
	andl	$0xFFFF, %eax		// Mask to get basic exit reason
	cmpl	$18, %eax		// EXIT_REASON_VMCALL
	jne	2f			// Not a VMCALL trap

	// Restore registers for hypercall handling
	popq	%r11
	popq	%r10
	popq	%r9
	popq	%r8
	popq	%rdi
	popq	%rsi
	popq	%rdx
	popq	%rcx
	popq	%rax

	testq	%rdi, %rdi		// Check first argument (x0 equivalent)
	jz	1f
	// Set hypervisor vector base (equivalent to vbar_el2)
	movq	%rdi, %rax
	movl	$0x681E, %ecx		// MSR for hypervisor vector base
	movq	%rax, %rdx
	shrq	$32, %rdx
	wrmsr
	jmp	2f

1:	// Return hypervisor vector base
	movl	$0x681E, %ecx		// MSR for hypervisor vector base
	rdmsr
	shlq	$32, %rdx
	orq	%rdx, %rax
	movq	%rax, %rdi		// Return in first argument register

2:	cmpq	$0x8000000A, %rdi	// HVC_SOFT_RESTART equivalent
	jne	3f
	movq	%rdx, %rdi		// Move arguments around
	movq	%r10, %rdx
	movq	%rcx, %r10
	movq	%r8, %rcx
	jmpq	*%r10			// Jump to restart address, no return

	// Someone called kvm_call_hyp() against the hyp-stub...
3:	
#if LINUX_VERSION_CODE < KERNEL_VERSION(4,12,0)
	movq	$0x86000001, %rdi	// X86_EXCEPTION_HYP_GONE equivalent
#else
	movq	$0xbadca11, %rdi	// HVC_STUB_ERR equivalent
#endif

9:	// Resume guest execution
	vmresume
	// If vmresume fails, try vmlaunch
	vmlaunch
	// If both fail, halt
	hlt

guest_sync_shim_error:
	// Restore registers and handle error
	popq	%r11
	popq	%r10
	popq	%r9
	popq	%r8
	popq	%rdi
	popq	%rsi
	popq	%rdx
	popq	%rcx
	popq	%rax
	jmp	3b

ENDPROC(guest_sync_shim)

.macro invalid_vector	label
\label:
	// Save minimal context
	pushq	%rax
	pushq	%rbx
	
	// Set error code
	movq	$0xdeadbeef, %rax
	
	// Attempt to resume guest or halt
	popq	%rbx
	popq	%rax
	vmresume
	vmlaunch
	hlt
	jmp \label
ENDPROC(\label)
.endm

	invalid_vector	vmx_sync_invalid
	invalid_vector	vmx_irq_invalid
	invalid_vector	vmx_fiq_invalid
	invalid_vector	vmx_error_invalid
	invalid_vector	guest_sync_invalid
	invalid_vector	guest_irq_invalid
	invalid_vector	guest_fiq_invalid
	invalid_vector	guest_error_invalid

/**
 * __hyp_shim_size - Number of bytes to copy to the hyp shim page.
 */
.globl __hyp_shim_size
__hyp_shim_size:
	.quad	__hyp_shim_size - __hyp_shim_vectors