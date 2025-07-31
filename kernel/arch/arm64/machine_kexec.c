/*COMPLETED
 * kexec for x86_64
 *
 * Copyright (C) 2002-2005 Eric Biederman <ebiederm@xmission.com>
 *
 * This program is free software; you can redistribute it and/or modify
 * it under the terms of the GNU General Public License version 2 as
 * published by the Free Software Foundation.
 */

#include <linux/interrupt.h>
#include <linux/irq.h>
#include <linux/kernel.h>
#include <linux/page-flags.h>
#include <linux/smp.h>
#include <linux/reboot.h>

#include <asm/processor.h>
#include <asm/page.h>
#include <asm/pgtable.h>
#include <asm/tlbflush.h>
#include <asm/mmu_context.h>
#include <asm/io.h>
#include <asm/apic.h>
#include <asm/cpufeature.h>
#include <asm/desc.h>
#include <asm/cacheflush.h>

#include "../../kexec.h"

/* Global variables for the x86_64_relocate_new_kernel routine. */
extern const unsigned char relocate_kernel[];
extern const unsigned long relocate_kernel_size;

static void init_level2_page(pmd_t *level2p, unsigned long addr)
{
	unsigned long end_addr;

	addr &= PAGE_MASK;
	end_addr = addr + PUD_SIZE;
	while (addr < end_addr) {
		set_pmd(level2p++, __pmd(addr | __PAGE_KERNEL_LARGE_EXEC));
		addr += PMD_SIZE;
	}
}

static int init_level3_page(struct kimage *image, pud_t *level3p,
				unsigned long addr, unsigned long last_addr)
{
	unsigned long end_addr;
	int result;

	result = 0;
	addr &= PAGE_MASK;
	end_addr = addr + PGDIR_SIZE;
	while ((addr < last_addr) && (addr < end_addr)) {
		struct page *page;
		pmd_t *level2p;

		page = kimage_alloc_control_pages(image, 0);
		if (!page) {
			result = -ENOMEM;
			goto out;
		}
		level2p = (pmd_t *)page_address(page);
		init_level2_page(level2p, addr);
		set_pud(level3p++, __pud(__pa(level2p) | _KERNPG_TABLE));
		addr += PUD_SIZE;
	}
	/* clear the unused entries */
	while (addr < end_addr) {
		pud_clear(level3p++);
		addr += PUD_SIZE;
	}
out:
	return result;
}

static int init_level4_page(struct kimage *image, pgd_t *level4p,
				unsigned long addr, unsigned long last_addr)
{
	unsigned long end_addr;
	int result;

	result = 0;
	addr &= PAGE_MASK;
	end_addr = addr + (PTRS_PER_PGD * PGDIR_SIZE);
	while ((addr < last_addr) && (addr < end_addr)) {
		struct page *page;
		pud_t *level3p;

		page = kimage_alloc_control_pages(image, 0);
		if (!page) {
			result = -ENOMEM;
			goto out;
		}
		level3p = (pud_t *)page_address(page);
		result = init_level3_page(image, level3p, addr, last_addr);
		if (result)
			goto out;
		set_pgd(level4p++, __pgd(__pa(level3p) | _KERNPG_TABLE));
		addr += PGDIR_SIZE;
	}
	/* clear the unused entries */
	while (addr < end_addr) {
		pgd_clear(level4p++);
		addr += PGDIR_SIZE;
	}
out:
	return result;
}

static void free_transition_pgtable(struct kimage *image)
{
	free_page((unsigned long)image->arch.pgd);
	image->arch.pgd = NULL;
}

static int init_transition_pgtable(struct kimage *image, pgd_t *pgd)
{
	unsigned long vaddr, paddr;
	int result;

	vaddr = (unsigned long)relocate_kernel;
	paddr = __pa(page_address(image->control_code_page)+(relocate_kernel-relocate_kernel));
	pgd += pgd_index(vaddr);
	result = init_level4_page(image, pgd, vaddr, vaddr + relocate_kernel_size);
	if (result)
		return result;

	/*
	 * Set up the identity mapping for the switchover.  These
	 * functions should be idempotent if/when called multiple times.
	 */
	for (vaddr = 0; vaddr < max_pfn << PAGE_SHIFT; vaddr += PGDIR_SIZE) {
		pgd = image->arch.pgd + pgd_index(vaddr);
		result = init_level4_page(image, pgd, vaddr,
					max_pfn << PAGE_SHIFT);
		if (result)
			return result;
	}

	return 0;
}

/**
 * kexec_image_info - For debugging output.
 */
#define kexec_image_info(_i) _kexec_image_info(__func__, __LINE__, _i)
static void _kexec_image_info(const char *func, int line,
			     const struct kimage *kimage)
{
       unsigned long i;

       pr_debug("%s:%d:\n", func, line);
       pr_debug("  kexec kimage info:\n");
       pr_debug("    start:       %lx\n", kimage->start);
       pr_debug("    head:        %lx\n", kimage->head);
       pr_debug("    nr_segments: %lu\n", kimage->nr_segments);

       for (i = 0; i < kimage->nr_segments; i++) {
	       pr_debug("      segment[%lu]: %016lx - %016lx, 0x%lx bytes, %lu pages\n",
			i,
			kimage->segment[i].mem,
			kimage->segment[i].mem + kimage->segment[i].memsz,
			kimage->segment[i].memsz,
			kimage->segment[i].memsz /  PAGE_SIZE);
       }
}

void machine_kexec_cleanup(struct kimage *kimage)
{
	free_transition_pgtable(kimage);
}
EXPORT_SYMBOL_GPL(machine_kexec_cleanup);

/**
 * machine_kexec_prepare - Prepare for a kexec reboot.
 *
 * Called from the core kexec code when a kernel image is loaded.
 * Set up the page table that will allow us to switch to the new kernel.
 */
int machine_kexec_prepare(struct kimage *kimage)
{
	unsigned long start_pgtable;
	int result;

	kexec_image_info(kimage);

	/* Calculate the offsets */
	start_pgtable = page_to_pfn(image->control_code_page) << PAGE_SHIFT;

	/* Setup the identity mapped 64bit page table */
	result = init_transition_pgtable(kimage, kimage->arch.pgd);
	if (result)
		return result;

	return 0;
}
EXPORT_SYMBOL_GPL(machine_kexec_prepare);

/**
 * kexec_list_flush - Helper to flush the kimage list to memory.
 */
static void kexec_list_flush(struct kimage *kimage)
{
       kimage_entry_t *entry;

       for (entry = &kimage->head; ; entry++) {
	       unsigned int flag;
	       void *addr;

	       /* flush the list entries. */
	       clflush_cache_range(entry, sizeof(kimage_entry_t));

	       flag = *entry & IND_FLAGS;
	       if (flag == IND_DONE)
		       break;

	       addr = __va(*entry & PAGE_MASK);

	       switch (flag) {
	       case IND_INDIRECTION:
		       /* Set entry point just before the new list page. */
		       entry = (kimage_entry_t *)addr - 1;
		       break;
	       case IND_SOURCE:
		       /* flush the source pages. */
		       clflush_cache_range(addr, PAGE_SIZE);
		       break;
	       case IND_DESTINATION:
		       break;
	       default:
		       BUG();
	       }
       }
}

/**
 * kexec_segment_flush - Helper to flush the kimage segments to memory.
 */
static void kexec_segment_flush(const struct kimage *kimage)
{
       unsigned long i;

       pr_debug("%s:\n", __func__);

       for (i = 0; i < kimage->nr_segments; i++) {
	       pr_debug("  segment[%lu]: %016lx - %016lx, 0x%lx bytes, %lu pages\n",
			i,
			kimage->segment[i].mem,
			kimage->segment[i].mem + kimage->segment[i].memsz,
			kimage->segment[i].memsz,
			kimage->segment[i].memsz /  PAGE_SIZE);

	       clflush_cache_range(__va(kimage->segment[i].mem),
				   kimage->segment[i].memsz);
       }
}

/**
 * machine_kexec - Do the kexec reboot.
 *
 * Called from the core kexec code for a sys_reboot with LINUX_REBOOT_CMD_KEXEC.
 */
void machine_kexec(struct kimage *kimage)
{
       unsigned long page_list[PAGES_NR];
       void *control_page;
       int save_ftrace_enabled;

       if (num_online_cpus() > 1) {
	       pr_err("kexec: error: multiple CPUs still online\n");
	       return;
       }

#ifdef CONFIG_FUNCTION_TRACER
       save_ftrace_enabled = ftrace_enabled;
       ftrace_enabled = 0;
#endif

       control_page = page_address(kimage->control_code_page);
       memcpy(control_page, relocate_kernel, relocate_kernel_size);

       kexec_image_info(kimage);

       pr_debug("%s:%d: control_code_page:        %p\n", __func__, __LINE__,
		kimage->control_code_page);
       pr_debug("%s:%d: control_page:             %p\n", __func__, __LINE__,
		control_page);
       pr_debug("%s:%d: relocate_kernel:          %p\n", __func__, __LINE__,
		relocate_kernel);
       pr_debug("%s:%d: relocate_kernel_size:     0x%lx(%lu) bytes\n",
		__func__, __LINE__, relocate_kernel_size,
		relocate_kernel_size);

       page_list[PA_CONTROL_PAGE] = __pa(control_page);
       page_list[VA_CONTROL_PAGE] = (unsigned long)control_page;
       page_list[PA_PGD] = __pa(kimage->arch.pgd);
       page_list[VA_PGD] = (unsigned long)kimage->arch.pgd;

       /* The segment registers are funny things, they have both a
	* visible and an invisible part.  Whenever the visible part is
	* set to a specific selector, the invisible part is loaded
	* with from a table in memory.  At no other time is the
	* descriptor table in memory accessed.
	*
	* I take advantage of this here by force loading the
	* segments, before I zap the gdt with an invalid value.
	*/
       load_segments();

       /* The gdt & idt are now invalid.
	* If you want to load them you must set up your own idt & gdt.
	*/
       idt_invalidate(phys_to_virt(0));
       set_gdt(phys_to_virt(0), 0);

       /* now call it */
       kexec_list_flush(kimage);

       /* Flush the new image if already in place. */
       if (kimage->head & IND_DONE)
	       kexec_segment_flush(kimage);

       pr_info("Starting new kernel\n");

       /* now call the assembly routine */
       relocate_kernel((unsigned long)kimage->head,
		      (unsigned long)page_list,
		      kimage->start,
		      kimage->preserve_context);

#ifdef CONFIG_FUNCTION_TRACER
       ftrace_enabled = save_ftrace_enabled;
#endif
}
EXPORT_SYMBOL_GPL(machine_kexec);