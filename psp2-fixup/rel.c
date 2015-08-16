/*
 * Copyright (C) 2015 PSP2SDK Project
 *
 * This Source Code Form is subject to the terms of the Mozilla Public
 * License, v. 2.0. If a copy of the MPL was not distributed with this
 * file, You can obtain one at http://mozilla.org/MPL/2.0/.
 */

#include <errno.h>
#include <stdio.h>
#include <stdlib.h>
#include "elf.h"
#include "rel.h"
#include "scn.h"

Elf32_Rel *findRelByOffset(const scn_t *scn, Elf32_Addr offset,
	const char *strtab)
{
	Elf32_Half i;
	Elf32_Rel *ent;

	if (scn == NULL || scn->content == NULL || strtab == NULL)
		return NULL;

	ent = scn->content;
	for (i = 0; i < scn->shdr.sh_size; i += sizeof(Elf32_Rel)) {
		if (ent->r_offset == offset)
			return ent;

		ent++;
	}

	fprintf(stderr, "%s: Relocation entry for offset 0x%08X not found\n",
		strtab + scn->shdr.sh_name, offset);

	errno = EILSEQ;
	return NULL;
}

Elf32_Rela *findRelaByOffset(const scn_t *scn, Elf32_Addr offset,
	const char *strtab)
{
	Elf32_Half i;
	Elf32_Rela *ent;

	if (scn == NULL || scn->content == NULL || strtab == NULL)
		return NULL;

	ent = scn->content;
	for (i = 0; i < scn->shdr.sh_size; i += sizeof(Elf32_Rela)) {
		if (ent->r_offset == offset)
			return ent;

		ent++;
	}

	fprintf(stderr, "%s: Relocation entry for offset 0x%08X not found\n",
		strtab + scn->shdr.sh_name, offset);

	errno = EILSEQ;
	return NULL;
}

int relocate(FILE *fp, scn_t *scns,
	const char *strtab, const Elf32_Sym *symtab,
	scn_t **relScns, Elf32_Half relShnum)
{
	Elf32_Rela *buf, *cur;
	scn_t *scn, *dstScn;
	const Elf32_Rel *rel;
	const Elf32_Sym *sym;
	Elf32_Word i, type;
	int res;

	if (fp == NULL || scns == NULL || symtab == NULL || relScns == NULL)
		return EINVAL;

	while (relShnum) {
		scn = *relScns;

		if (scn->shdr.sh_type != SHT_REL)
			goto cont;

		if (scn->content == NULL) {
			res = loadScn(fp, scn, strtab + scn->shdr.sh_name);
			if (res)
				return res;
		}

		rel = scn->content;

		buf = malloc(scn->shdr.sh_size);
		cur = buf;

		dstScn = scns + scn->shdr.sh_info;

		for (i = 0; i < scn->orgSize; i += sizeof(*rel)) {
			cur->r_offset = rel->r_offset + dstScn->addrDiff;
			cur->r_info = rel->r_info;

			type = ELF32_R_TYPE(rel->r_info);
			sym = symtab + ELF32_R_SYM(rel->r_info);

			if (sym->st_shndx != SHN_ABS
				&& (type == R_ARM_ABS32 || type == R_ARM_TARGET1))
			{
				if (dstScn->content == NULL) {
					res = loadScn(fp, dstScn,
						strtab + dstScn->shdr.sh_name);
					if (res)
						return res;
				}

				cur->r_addend = *(Elf32_Word *)((uintptr_t)dstScn->content
					+ cur->r_offset - dstScn->shdr.sh_addr);
			} else
				cur->r_addend = sym->st_value;

			cur->r_addend += scns[sym->st_shndx].addrDiff;

			rel++;
			cur++;
		}

		free(scn->content);

		scn->shdr.sh_type = SHT_RELA;
		scn->content = buf;

cont:
		relScns++;
		relShnum--;
	}

	return 0;
}

int convRelaToPsp2Rela(scn_t *scns, seg_t *segs, const Elf32_Sym *symtab,
	scn_t **relaScns, Elf32_Half relaShnum)
{
	Psp2_Rela *buf, *cur;
	scn_t *scn, *dstScn;
	const Elf32_Rela *rela;
	const Elf32_Sym *sym;
	Elf32_Addr addend;
	Elf32_Word i, type;
	Elf32_Half symseg;

	if (scns == NULL || symtab == NULL || relaScns == NULL)
		return EINVAL;

	while (relaShnum) {
		scn = *relaScns;

		if (scn->shdr.sh_type != SHT_RELA)
			goto cont;

		rela = scn->content;

		buf = malloc(scn->shdr.sh_size);
		cur = buf;

		dstScn = scns + scn->shdr.sh_info;

		for (i = 0; i < scn->shdr.sh_size; i += sizeof(*rela)) {
			type = ELF32_R_TYPE(rela->r_info);
			sym = symtab + ELF32_R_SYM(rela->r_info);

			PSP2_R_SET_SHORT(cur, 0);
			PSP2_R_SET_TYPE(cur, type);
			PSP2_R_SET_DATSEG(cur, dstScn->phndx);
			PSP2_R_SET_OFFSET(cur, rela->r_offset
				- segs[dstScn->phndx].phdr.p_vaddr);

			addend = rela->r_addend;
			if (type == R_ARM_CALL || type == R_ARM_JUMP24)
				addend -= 8;

			if (sym->st_shndx == SHN_ABS)
				symseg = 15;
			else {
				symseg = scns[sym->st_shndx].phndx;
				addend -= segs[symseg].phdr.p_vaddr;
			}

			PSP2_R_SET_SYMSEG(cur, symseg);
			PSP2_R_SET_ADDEND(cur, addend);

			rela++;
			cur++;
		}

		free(scn->content);

		scn->shdr.sh_type = SHT_PSP2_RELA;
		scn->content = buf;

cont:
		relaScns++;
		relaShnum--;
	}

	return 0;
}
