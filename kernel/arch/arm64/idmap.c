/*COMPLETED
 * Identity paging setup for kexec_mod.
 *
 * Copyright (C) 2021 Fabian Mastenbroek.
 *
 * This program is free software; you can redistribute it and/or modify
 * it under the terms of the GNU General Public License as published by
 * the Free Software Foundation; either version 2 of the License, or
 * (at your option) any later version.
 */

#define MODULE_NAME "kexec_mod_x86_64"
#define pr_fmt(fmt) MODULE_NAME ": " fmt

#include <asm/pgtable.h>
#include <asm/mmu_context.h>
#include <asm/tlbflush.h>
#include <asm/processor.h>

#include "idmap.h"

/* AMD64 uses 4-level page tables: PGD → PUD → PMD → PTE */
#define IDMAP_BLOCK_SHIFT	PMD_SHIFT
#define IDMAP_BLOCK_SIZE	PMD_SIZE
#define IDMAP_TABLE_SHIFT	PUD_SHIFT

#define block_index(addr) (((addr) >> IDMAP_BLOCK_SHIFT) & (PTRS_PER_PMD - 1))
#define block_align(addr) (((addr) >> IDMAP_BLOCK_SHIFT) << IDMAP_BLOCK_SHIFT)

/*
 * Initial memory map attributes for x86_64.
 */
#define PTE_FLAGS	(_PAGE_PRESENT | _PAGE_RW | _PAGE_ACCESSED)
#define PMD_FLAGS	(_PAGE_PRESENT | _PAGE_RW | _PAGE_ACCESSED | _PAGE_PSE)
#define PUD_FLAGS	(_PAGE_PRESENT | _PAGE_RW | _PAGE_ACCESSED)
#define PGD_FLAGS	(_PAGE_PRESENT | _PAGE_RW | _PAGE_ACCESSED)

#define MM_MMUFLAGS	PMD_FLAGS

/* Page tables for identity mapping */
pgd_t kexec_idmap_pgd[PTRS_PER_PGD] __attribute__ ((aligned (4096)));
pud_t kexec_idmap_pud[4 * PTRS_PER_PUD] __attribute__ ((aligned (4096)));
pmd_t kexec_idmap_pmd[4 * PTRS_PER_PMD] __attribute__ ((aligned (4096)));
pte_t kexec_idmap_pte[4 * PTRS_PER_PTE] __attribute__ ((aligned (4096)));

extern void __cpu_soft_restart_x86_64(unsigned long entry, 
	unsigned long arg0, unsigned long arg1, unsigned long arg2);

static pud_t *next_pud = kexec_idmap_pud;
static pmd_t *next_pmd = kexec_idmap_pmd;
static pte_t *next_pte = kexec_idmap_pte;

void kexec_idmap_setup(void)
{
	int i;
	unsigned long pa, pgd_idx, pud_idx, pmd_idx;
	pud_t *pud;
	pmd_t *pmd;
	void *ptrs[4] = {kexec_idmap_pgd,
			 kexec_idmap_pud,
			 kexec_idmap_pmd,
			 __cpu_soft_restart_x86_64};

	/* Clear all page tables */
	memset(kexec_idmap_pgd, 0, sizeof(kexec_idmap_pgd));
	memset(kexec_idmap_pud, 0, sizeof(kexec_idmap_pud));
	memset(kexec_idmap_pmd, 0, sizeof(kexec_idmap_pmd));
	memset(kexec_idmap_pte, 0, sizeof(kexec_idmap_pte));

	for (i = 0; i < sizeof(ptrs) / sizeof(ptrs[0]); i++) {
		pa = kexec_pa_symbol(ptrs[i]);
		if (!pa)
			continue;

		pgd_idx = pgd_index(pa);
		pud_idx = pud_index(pa);
		pmd_idx = pmd_index(pa);

		/* Set up PGD entry */
		if (pgd_none(kexec_idmap_pgd[pgd_idx])) {
			pud = next_pud;
			next_pud += PTRS_PER_PUD;
			set_pgd(&kexec_idmap_pgd[pgd_idx], 
				__pgd(kexec_pa_symbol(pud) | PGD_FLAGS));
			pr_info("Created new PGD entry for 0x%lx\n", pa);
		} else {
			pud = (pud_t *)__va(pgd_val(kexec_idmap_pgd[pgd_idx]) & PTE_PFN_MASK);
		}

		/* Set up PUD entry */
		if (pud_none(pud[pud_idx])) {
			pmd = next_pmd;
			next_pmd += PTRS_PER_PMD;
			set_pud(&pud[pud_idx], 
				__pud(kexec_pa_symbol(pmd) | PUD_FLAGS));
			pr_info("Created new PUD entry for 0x%lx\n", pa);
		} else {
			pmd = (pmd_t *)__va(pud_val(pud[pud_idx]) & PTE_PFN_MASK);
		}

		/* Set up PMD entry with large page (2MB) */
		set_pmd(&pmd[pmd_idx], __pmd(block_align(pa) | MM_MMUFLAGS));
		pr_info("Mapped 0x%lx -> 0x%lx (2MB page)\n", 
			block_align(pa), block_align(pa));
	}
}

void kexec_idmap_install(void)
{
	/* Flush all TLBs before switching page tables */
	__flush_tlb_all();
	
	/* Load the new page table */
	write_cr3(kexec_pa_symbol(kexec_idmap_pgd));
	
	/* Flush TLBs again after page table switch */
	__flush_tlb_all();
	
	pr_info("Identity mapping installed, CR3=0x%lx\n", 
		kexec_pa_symbol(kexec_idmap_pgd));
}

/**
 * Resolve the physical address of the specified pointer.
 * We cannot use __pa_symbol for symbols defined in our kernel module, so we need to walk
 * the page table manually.
 */
phys_addr_t kexec_pa_symbol(void *ptr)
{
	unsigned long va = (unsigned long) ptr;
	unsigned long page_offset;
	pgd_t *pgd;
	pud_t *pud;
	pmd_t *pmd;
	pte_t *ptep, pte;
	struct page *page = NULL;

	pgd = pgd_offset_k(va);
	if (pgd_none(*pgd) || pgd_bad(*pgd)) {
		return 0;
	}

	pud = pud_offset(pgd, va);
	if (pud_none(*pud) || pud_bad(*pud)) {
		return 0;
	}

	/* Check if this is a large PUD page (1GB) */
	if (pud_large(*pud)) {
		page_offset = va & (PUD_SIZE - 1);
		return (pud_pfn(*pud) << PAGE_SHIFT) | page_offset;
	}

	pmd = pmd_offset(pud, va);
	if (pmd_none(*pmd) || pmd_bad(*pmd)) {
		return 0;
	}

	/* Check if this is a large PMD page (2MB) */
	if (pmd_large(*pmd)) {
		page_offset = va & (PMD_SIZE - 1);
		return (pmd_pfn(*pmd) << PAGE_SHIFT) | page_offset;
	}

	ptep = pte_offset_map(pmd, va);
	if (!ptep) {
		return 0;
	}

	pte = *ptep;
	pte_unmap(ptep);
	
	if (pte_none(pte)) {
		return 0;
	}

	page = pte_page(pte);
	page_offset = va & ~PAGE_MASK;
	return page_to_phys(page) | page_offset;
}