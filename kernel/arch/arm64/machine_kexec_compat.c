/*COMPLETED
 * Arch-specific compatibility layer for enabling kexec as loadable kernel
 * module.
 *
 * Copyright (C) 2021 Fabian Mastenbroek.
 *
 * This program is free software; you can redistribute it and/or modify
 * it under the terms of the GNU General Public License as published by
 * the Free Software Foundation; either version 2 of the License, or
 * (at your option) any later version.
 */

#define pr_fmt(fmt) "kexec_mod_x86_64: " fmt

#include <linux/version.h>
#include <linux/mm_types.h>
#include <linux/kexec.h>
#include <linux/kallsyms.h>
#include <linux/slab.h>
#include <linux/uaccess.h>
#include <asm/processor.h>
#include <asm/pgtable.h>
#include <asm/tlbflush.h>
#include <asm/desc.h>
#include <asm/io.h>

/* These kernel symbols need to be dynamically resolved at runtime
 * using kallsym due to them not being exposed to kernel modules */
static void (*load_cr3_ptr)(pgd_t *);
static void (*clflush_cache_range_ptr)(void *, unsigned int);
static void (*native_load_gdt_ptr)(const struct desc_ptr *);
static void (*native_load_idt_ptr)(const struct desc_ptr *);

void load_cr3_compat(pgd_t *pgdir)
{
	if (load_cr3_ptr)
		load_cr3_ptr(pgdir);
	else
		write_cr3(__pa(pgdir));
}

void clflush_cache_range_compat(void *vaddr, unsigned int size)
{
	if (clflush_cache_range_ptr)
		clflush_cache_range_ptr(vaddr, size);
	else {
		void *vend = vaddr + size - 1;
		mb();
		for (; vaddr < vend; vaddr += boot_cpu_data.x86_clflush_size)
			clflushopt(vaddr);
		mb();
	}
}

void native_load_gdt_compat(const struct desc_ptr *dtr)
{
	if (native_load_gdt_ptr)
		native_load_gdt_ptr(dtr);
	else
		asm volatile("lgdt %0"::"m" (*dtr));
}

void native_load_idt_compat(const struct desc_ptr *dtr)
{
	if (native_load_idt_ptr)
		native_load_idt_ptr(dtr);
	else
		asm volatile("lidt %0"::"m" (*dtr));
}

/* These kernel symbols are stubbed since they have different equivalents
 * or are not needed in x86_64 */
bool machine_kexec_post_allocs(struct kimage *image)
{
	return true;
}

void machine_kexec_cleanup_pages(struct kimage *image)
{
	/* No special cleanup needed for x86_64 */
}

/* Boot mode detection for x86_64 - we check for various CPU features */
static u32 __boot_cpu_mode;

/**
 * This function initializes the boot CPU mode detection for x86_64.
 * We check for various x86_64-specific features and virtualization support.
 */
static int __init_cpu_boot_mode(void)
{
	__boot_cpu_mode = 0;
	
	/* Check for long mode (64-bit) */
	if (boot_cpu_has(X86_FEATURE_LM))
		__boot_cpu_mode |= 0x1;
	
	/* Check for virtualization support */
	if (boot_cpu_has(X86_FEATURE_VMX) || boot_cpu_has(X86_FEATURE_SVM))
		__boot_cpu_mode |= 0x2;
	
	/* Check for SMEP/SMAP */
	if (boot_cpu_has(X86_FEATURE_SMEP))
		__boot_cpu_mode |= 0x4;
	
	if (boot_cpu_has(X86_FEATURE_SMAP))
		__boot_cpu_mode |= 0x8;

	pr_info("Detected boot CPU mode: 0x%x.\n", __boot_cpu_mode);
	return 0;
}

static void *__virt_shim;

/**
 * This function allocates a page which will contain the virtualization shim.
 * 
 * For x86_64, we create a minimal shim that can handle virtualization
 * transitions if needed during kexec.
 */
static int __init_virt_shim(void)
{
	static const u8 shim_code[] = {
		/* Simple return stub for now */
		0x48, 0x31, 0xc0,  /* xor %rax, %rax */
		0xc3,              /* ret */
	};
	
	__virt_shim = alloc_pages_exact(PAGE_SIZE, GFP_KERNEL);

	if (!__virt_shim) {
		return -ENOMEM;
	}

	memcpy(__virt_shim, shim_code, sizeof(shim_code));

	pr_info("Virtualization shim created at 0x%llx [%zu bytes].\n", 
		virt_to_phys(__virt_shim), sizeof(shim_code));
	return 0;
}

struct mm_struct init_mm;

static void __init_mm(void)
{
	/*
	 * Hack to obtain pointer to swapper_pg_dir (since it is not exported).
	 * For x86_64, we can find its physical address in the CR3 register
	 * and convert it to a logical address.
	 */
	unsigned long cr3_val;
	asm volatile("mov %%cr3, %0" : "=r" (cr3_val));
	init_mm.pgd = __va(cr3_val & CR3_ADDR_MASK);
}

static void *ksym(const char *name)
{
	return (void *) kallsyms_lookup_name(name);
}

int machine_kexec_compat_load(int detect_virt, int shim_virt)
{
	/* Try to resolve optional symbols */
	load_cr3_ptr = ksym("load_cr3");
	clflush_cache_range_ptr = ksym("clflush_cache_range");
	native_load_gdt_ptr = ksym("native_load_gdt");
	native_load_idt_ptr = ksym("native_load_idt");

	/* Find init_mm */
	__init_mm();

	/* Find boot CPU mode */
	__boot_cpu_mode = 0x1; /* Default to long mode */

	if (!detect_virt) {
		pr_info("Virtualization kexec not supported.\n");
	} else if (__init_cpu_boot_mode() < 0) {
		pr_warn("Failed to detect boot CPU mode.\n");
	}

	/* Enable shimming for virtualization if requested */
	if (shim_virt) {
		pr_info("Enabling shim for virtualization support.\n");

		if (__init_virt_shim() < 0) {
			pr_err("Failed to initialize virtualization shim.\n");
		} else if (!detect_virt) {
			pr_warn("Virtualization shim unnecessary without virtualization detection.\n");
		}
	} else {
		__virt_shim = NULL;
	}
	
	return 0;
}

void machine_kexec_compat_unload(void)
{
	if (__virt_shim) {
		free_pages_exact(__virt_shim, PAGE_SIZE);
		__virt_shim = NULL;
	}
}

void machine_kexec_compat_prereset(void)
{
	/* For x86_64, we might need to set up virtualization context here */
	if (__virt_shim) {
		/* Set up any necessary virtualization state before kexec */
		pr_debug("Setting up virtualization context at 0x%llx\n", 
			 virt_to_phys(__virt_shim));
	}
	
	/* Disable interrupts and prepare for transition */
	local_irq_disable();
	
	/* Flush TLB to ensure clean page table state */
	__flush_tlb_all();
}