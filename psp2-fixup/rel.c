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

/* Referred to vita-toolchain
https://github.com/vitasdk/vita-toolchain/blob/cc8dfeb87751e75ac40c54ac0d9586068d363672/src/vita-elf.c#L116
*/
static int thumbShuffle(Elf32_Word *w)
{
	if (w == NULL)
		return EINVAL;

	*w = ((*w & 0xFFFF0000) >> 16) | ((*w & 0xFFFF) << 16);

	return 0;
}

Elf32_Word getAddend(const scn_t *scn, const Elf32_Rel *rel)
{
	Elf32_Word w, r, hi, lo, sign, type;

	if (scn == NULL || scn->content == NULL || rel == NULL) {
		errno = EINVAL;
		return 0;
	}

	w = *(Elf32_Word *)((uintptr_t)scn->content + rel->r_offset - scn->shdr.sh_addr);
	type = ELF32_R_TYPE(rel->r_info);
	switch (type) {
		case R_ARM_NONE:
		case R_ARM_V4BX:
			return 0;

		case R_ARM_ABS32:
		case R_ARM_TARGET1:
			return w;

		case R_ARM_REL32:
		case R_ARM_TARGET2:
		case R_ARM_PREL31:
			return w + rel->r_offset;

		case R_ARM_THM_PC22:
		case R_ARM_THM_JUMP24:
			thumbShuffle(&w);
			hi = w >> 16;
			lo = w & 0xFFFF;
			sign = (hi >> 10) & 1;
			return rel->r_offset +
				((((lo & 0x7ff) | ((hi & 0x3ff) << 11)
				| (!(((lo >> 11) & 1) ^ sign) << 21)
				| (!(((lo >> 13) & 1) ^ sign) << 22)
				| (sign << 23)) << 1) | (sign ? 0xff000000 : 0));

		case R_ARM_CALL:
		case R_ARM_JUMP24:
			// return ((w << 2) + rel->r_offset) & 0xFFFFFF;
			return ((((w & 0x00ffffff) << 2) + rel->r_offset) << 8) >> 8;

		case R_ARM_MOVW_ABS_NC:
			r = ((w & 0xF0000) >> 4) | (w & 0xFFF);
			if (ELF32_R_TYPE(rel[1].r_info) == R_ARM_MOVT_ABS) {
				w = *(Elf32_Word *)((uintptr_t)scn->content
					+ rel[1].r_offset - scn->shdr.sh_addr);
				r |= (((w & 0xF0000) >> 4) | (w & 0xFFF)) << 16;
			} else
				fprintf(stderr, "warning: R_ARM_MOVT_ABS corresponding to R_ARM_MOVW_ABS_NC not found\n");

			return r;

		case R_ARM_MOVT_ABS:
			r = (((w & 0xF0000) >> 4) | (w & 0xFFF)) << 16;
			if (ELF32_R_TYPE(rel[-1].r_info) == R_ARM_MOVW_ABS_NC) {
				w = *(Elf32_Word *)((uintptr_t)scn->content
					+ rel[-1].r_offset - scn->shdr.sh_addr);
				r |= ((w & 0xF0000) >> 4) | (w & 0xFFF);
			} else
				fprintf(stderr, "warning: R_ARM_MOVW_ABS_NC corresponding to R_ARM_MOVT_ABS not found\n");

			return r;

		case R_ARM_THM_MOVW_ABS_NC:
			thumbShuffle(&w);
			return (((w >> 16) & 0xf) << 12)
				| (((w >> 26) & 0x1) << 11)
				| (((w >> 12) & 0x7) << 8)
				| (w & 0xff);

		case R_ARM_THM_MOVT_ABS:
			thumbShuffle(&w);
			return (((w >> 16) & 0xf) << 28)
				| (((w >> 26) & 0x1) << 27)
				| (((w >> 12) & 0x7) << 24)
				| ((w & 0xff) << 16);

		default:
			fprintf(stderr, "warning: unsupported relocation: %d\n",
				type);
			return 0;
	}
}

int relocate(FILE *fp, scn_t *scns,
	const char *strtab, const Elf32_Sym *symtab,
	scn_t **relScns, Elf32_Half relShnum)
{
	Elf32_Rela *buf, *cur;
	Elf32_Rel *rel;
	scn_t *scn, *dstScn;
	Elf32_Section st_shndx;
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

		dstScn = scns + scn->shdr.sh_info;

		rel = scn->content;
		for (i = 0; i < scn->orgSize; i += sizeof(*rel)) {
			rel->r_offset += dstScn->addrDiff;
			rel++;
		}

		buf = malloc(scn->shdr.sh_size);
		if (buf == NULL) {
			perror(strtab + scn->shdr.sh_name);
			return errno;
		}

		cur = buf;
		rel = scn->content;
		for (i = 0; i < scn->orgSize; i += sizeof(*rel)) {
			st_shndx = symtab[ELF32_R_SYM(rel->r_info)].st_shndx;
			type = ELF32_R_TYPE(rel->r_info);

			if (dstScn->content == NULL) {
				res = loadScn(fp, dstScn, strtab + dstScn->shdr.sh_name);
				if (res)
					return res;
			}

			cur->r_offset = rel->r_offset;
			cur->r_info = rel->r_info;
			cur->r_addend = getAddend(dstScn, rel);
			if (st_shndx < SHN_LORESERVE &&
				(type == R_ARM_ABS32 || type == R_ARM_TARGET1
				|| type == R_ARM_MOVW_ABS_NC || type == R_ARM_MOVT_ABS
				|| type == R_ARM_THM_MOVW_ABS_NC || type == R_ARM_THM_MOVT_ABS))
			{
				cur->r_addend += scns[st_shndx].addrDiff;
			}

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
