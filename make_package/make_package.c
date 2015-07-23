/*
 * Copyright (C) 2015 PSP2SDK Project
 *
 * This Source Code Form is subject to the terms of the Mozilla Public
 * License, v. 2.0. If a copy of the MPL was not distributed with this
 * file, You can obtain one at http://mozilla.org/MPL/2.0/.
 */

#include <openssl/err.h>
#include <openssl/sha.h>
#include <sys/types.h>
#include <dirent.h>
#include <stddef.h>
#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <errno.h>

enum {
	MAGIC_PKG = 0x7F504B47,
	MAGIC_SCE = 0x00454353
};

enum {
	SIG_SCE_TYPE_SELF = 1
};

enum {
	PKG_ENT_TYPE_SELF = 0,
	PKG_ENT_TYPE_ANY = 2,
	PKG_ENT_TYPE_DIR = 3
};

enum {
	PKG_STAT_FINALIZED = 0,
	PKG_STAT_UNFINALIZED = 0x8000
};

typedef struct {
	uint32_t magic;
	uint32_t ver;
	uint16_t key;
	uint16_t type;
	uint32_t metaOff;
	uint64_t hdrSize;
	uint64_t dataSize;
} sigSceHdr_t;

typedef struct {
	uint64_t type;
	uint64_t appInfoOff;
	uint64_t ehdrOff;
	uint64_t phdrOff;
	uint64_t secInfoOff;
	uint64_t sceVerOff;
	uint64_t ctrlInfoOff;
	uint64_t ctrlInfoSize;
	uint64_t pad;
} selfHdr_t;

#define PKG_HDR_MAX_CID_LEN 47

typedef struct {
	uint32_t magic;
	uint16_t stat;
	uint16_t type;
	uint32_t infoOff;
	uint32_t infoCnt;
	uint32_t hdrSize;
	uint32_t itemCnt;
	uint64_t totalSize;
	uint64_t bodyOff;
	uint64_t bodySize;
	char cid[PKG_HDR_MAX_CID_LEN + 1];
	uint8_t pad[12];
	uint8_t qa[16];
	uint8_t dataRiv[16];
	uint8_t hdrCmac[16];
	uint8_t hdrSig[40];
	uint8_t hdrSha1[8];
} pkgHdr_t;

typedef struct {
	uint32_t nameOff;
	uint32_t nameSize;
	uint64_t dataOff;
	uint64_t dataSize;
	uint32_t type;
	uint32_t pad;
} pkgEnt_t;

typedef struct {
	pkgHdr_t hdr;
	char names[4096];
	uint64_t namesSize;
	pkgEnt_t ents[16];
} pkg_t;

typedef struct {
	const char *key;
	uint16_t type;
} pkgContentTypeKey_t;

static const pkgContentTypeKey_t pkgContentTypeKeys[] = {
	{ "GameData", 4 },
	{ "Game_Exec", 5 },
	{ "1P", 6 },
	{ "Theme", 9 },
	{ "Widget", 10 },
	{ "License", 11 },
	{ "WT", 19 },
};

#define CONF_MAX_KEY_LEN 14

#define _STROF(s) #s
#define STROF(s) _STROF(s)

#define PKG_EXT ".PKG"

static int buildPkgHdr(pkgHdr_t *hdr, const char *conf)
{
	FILE *fp;
	char key[CONF_MAX_KEY_LEN + 1];
	int i, res;

	if (hdr == NULL || conf == NULL)
		return EINVAL;

	hdr->magic = MAGIC_PKG;
	hdr->stat = PKG_STAT_UNFINALIZED;
	hdr->hdrSize = sizeof(pkgHdr_t);
	memset(hdr->pad, 0, sizeof(hdr->pad));

	fp = fopen(conf, "r");
	if (fp == NULL) {
		perror(conf);
		return errno;
	}

	while ((res = fscanf(fp, "%" STROF(CONF_MAX_KEY_LEN) "s%*[ ]=%*[ ]", key)) != EOF)
	{
		if (res == 0) {
			fprintf(stderr, "%s: syntax error\n", conf);
			fclose(fp);
			return EILSEQ;
		}

		if (!strcmp(key, "ContentType")) {
			res = fscanf(fp, "%9s", key);
			if (res == 0) {
				fprintf(stderr, "%s: invalid ContentType\n",
					conf);
				res = EILSEQ;
				fclose(fp);
				return res;
			}

			for (i = 0; ; i++) {
				if (i >= sizeof(pkgContentTypeKeys) / sizeof(pkgContentTypeKey_t)) {
					hdr->type = strtol(key, NULL, 0);
					break;
				}

				if (!strcmp(pkgContentTypeKeys[i].key, key)) {
					hdr->type = pkgContentTypeKeys[i].type;
					break;
				}
			}
		} else if (!strcmp(key, "ContentID")) {
			res = fscanf(fp, "%" STROF(PKG_HDR_MAX_CID_LEN) "s", hdr->cid);
			if (res == 0) {
				fprintf(stderr, "%s: invalid ContentID\n",
					conf);
				res = EILSEQ;
				goto parseFail;
			} else if (res == EOF)
				goto readFail;
		} else if (!strcmp(key, "Klicensee")) {
			if (fread(key, 2, 1, fp) <= 0) {
				perror(conf);
				fclose(fp);
				return res;
			}

			if (memcmp(key, "0x", 2)) {
				fclose(fp);
				fprintf(stderr, "%s: Klicensee should be a hexadecimal value which start with \"0x\"\n",
					conf);
				return EILSEQ;
			}

			for (i = 0; i < sizeof(hdr->dataRiv); i++) {
				res = fscanf(fp, "%2hhx", hdr->dataRiv + i);
				if (res == 0) {
						fprintf(stderr, "%s: invalid hexadecimal for Klicensee\n",
							conf);
						res = EILSEQ;
				} else if (res == EOF)
					goto readFail;
			}
		}
	}

	if (fclose(fp)) {
		perror(conf);
		return errno;
	}

	return 0;

readFail:
	if (feof(fp)) {
		fprintf(stderr, "%s: unexpected EOF\n", conf);
		res = EOF;
	} else {
		perror(conf);
		res = errno;
	}

parseFail:
	fclose(fp);
	return res;
}

static int resolveDirEnts(pkg_t *pkg, SHA_CTX *c,
	const char *dirName, uint32_t dirLen)
{
	const uint32_t align = 16;

	union {
		sigSceHdr_t sigSce;
		selfHdr_t self;
	} entHdr;

	DIR *dirp;
	FILE *fp;
	struct dirent *ent;
	size_t read;
	int res;
	char *src;
	long size;
	pkgEnt_t *pkgEnt;

	if (pkg == NULL)
		return EINVAL;

	dirp = opendir(dirName);
	if (dirp == NULL) {
		perror(dirName);
		return errno;
	}

	while ((ent = readdir(dirp)) != NULL) {
		if (ent->d_name[0] == '.')
			continue;

		if (pkg->hdr.itemCnt >= sizeof(pkg->ents) / sizeof(pkgEnt_t)) {
			fputs("error: too many entries\n", stderr);
			res = EINVAL;
			goto fail;
		}

		pkgEnt = pkg->ents + pkg->hdr.itemCnt;

		if (pkg->namesSize + dirLen >= sizeof(pkg->names))
			goto namesOverflow;

		for (pkgEnt->nameSize = 0; pkgEnt->nameSize < dirLen; pkgEnt->nameSize++)
			pkg->names[pkg->namesSize + pkgEnt->nameSize]
				= dirName[pkgEnt->nameSize];

		pkg->names[pkg->namesSize + pkgEnt->nameSize] = '/';
		pkgEnt->nameSize++;

		for (src = ent->d_name; *src != 0; src++) {
			if (pkg->namesSize + pkgEnt->nameSize >= sizeof(pkg->names))
				goto namesOverflow;

			pkg->names[pkg->namesSize + pkgEnt->nameSize] = *src;
			pkgEnt->nameSize++;
		}

		pkgEnt->nameOff = pkg->namesSize;

		for (pkg->namesSize += pkgEnt->nameSize; ; pkg->namesSize++) {
			if (pkg->namesSize + dirLen >= sizeof(pkg->names))
				goto namesOverflow;

			pkg->names[pkg->namesSize] = 0;

			if (!(pkg->namesSize & (align - 1)))
				break;
		}

		if (ent->d_type == DT_DIR) {
			pkgEnt->dataOff = 0;
			pkgEnt->dataSize = 0;
			pkgEnt->type = PKG_ENT_TYPE_DIR;

			pkg->hdr.itemCnt++;

			res = resolveDirEnts(pkg, c,
				pkg->names + pkgEnt->nameOff, pkgEnt->nameSize);
			if (res) {
				closedir(dirp);
				return res;
			}
		} else {
			pkg->ents[pkg->hdr.itemCnt].dataOff = pkg->hdr.bodySize;

			fp = fopen(pkg->names + pkgEnt->nameOff, "rb");
			if (fp == NULL)
				goto stdFail;

			read = fread(&entHdr, 1, sizeof(entHdr), fp);
			pkgEnt->type = read >= offsetof(sigSceHdr_t, magic)
				&& read >= offsetof(sigSceHdr_t, type)
				&& entHdr.sigSce.magic == MAGIC_SCE
				&& entHdr.sigSce.type == SIG_SCE_TYPE_SELF ?
					PKG_ENT_TYPE_SELF : PKG_ENT_TYPE_ANY;

			do {
				if (SHA1_Update(c, &entHdr, read) != 1) {
					fclose(fp);
					ERR_print_errors_fp(stderr);
					res = ERR_get_error();
					goto fail;
				}
			} while ((read = fread(&entHdr, sizeof(entHdr), 1, fp)) > 0);

			size = ftell(fp);
			if (size < 0) {
				fclose(fp);
				goto stdFail;
			}

			if (fclose(fp))
				goto stdFail;

			pkgEnt->dataSize = size;

			pkg->hdr.bodySize += size;
			if (pkg->hdr.bodySize & (align - 1))
				pkg->hdr.bodySize = (pkg->hdr.bodySize & ~(align - 1)) + align;

			pkg->hdr.itemCnt++;
		}
	}

	if (closedir(dirp)) {
		perror(NULL);
		return errno;
	}

	return 0;

namesOverflow:
	closedir(dirp);
	fputs("error: name table overflows\n", stderr);
	return ENAMETOOLONG;

stdFail:
	perror(pkg->names + pkgEnt->nameOff);
	res = errno;
fail:
	closedir(dirp);
	return res;
}

static int resolveAllEnts(pkg_t *pkg, const char *path)
{
	int res;
	SHA_CTX c;

	if (pkg == NULL || path == NULL)
		return EINVAL;

	pkg->hdr.itemCnt = 0;
	pkg->hdr.bodySize = 0;
	pkg->namesSize = 0;

	if (SHA1_Init(&c) != 1) {
		ERR_print_errors_fp(stderr);
		return ERR_get_error();
	}

	res = resolveDirEnts(pkg, &c, path, strlen(path));
	if (res)
		return res;

	if (SHA1_Final(pkg->hdr.qa, &c) != 1) {
		ERR_print_errors_fp(stderr);
		return ERR_get_error();
	}

	pkg->hdr.infoOff = 0;
	pkg->hdr.infoCnt = 0;
	pkg->hdr.bodySize += pkg->hdr.itemCnt * sizeof(pkgEnt_t) + pkg->namesSize;
	pkg->hdr.totalSize = sizeof(pkg->hdr) + pkg->hdr.bodySize + SHA_DIGEST_LENGTH;
	pkg->hdr.bodyOff = sizeof(pkg->hdr);

	return 0;
}

static int finalizePkg(pkg_t *pkg)
{
	unsigned char *md;
	uint32_t i;
	uint32_t namesOff;
	uint64_t dataOff;

	if (pkg == NULL)
		return EINVAL;

	namesOff = pkg->hdr.itemCnt * sizeof(pkgEnt_t);
	dataOff = namesOff + pkg->namesSize;

	for (i = 0; i < pkg->hdr.itemCnt; i++) {
		pkg->ents[i].nameOff = htobe32(namesOff + pkg->ents[i].nameOff);
		pkg->ents[i].nameSize = htobe32(pkg->ents[i].nameSize);
		pkg->ents[i].dataOff = htobe64(dataOff + pkg->ents[i].dataOff);
		pkg->ents[i].dataSize = htobe64(pkg->ents[i].dataSize);
		pkg->ents[i].type = htobe32(pkg->ents[i].type);
	}

	pkg->hdr.magic = htobe32(pkg->hdr.magic);
	pkg->hdr.stat = htobe16(pkg->hdr.stat);
	pkg->hdr.type = htobe16(pkg->hdr.type);
	pkg->hdr.infoOff = htobe32(pkg->hdr.infoOff);
	pkg->hdr.infoCnt = htobe32(pkg->hdr.infoCnt);
	pkg->hdr.hdrSize = htobe32(pkg->hdr.hdrSize);
	pkg->hdr.itemCnt = htobe32(pkg->hdr.itemCnt);
	pkg->hdr.totalSize = htobe64(pkg->hdr.totalSize);
	pkg->hdr.bodyOff = htobe64(pkg->hdr.bodyOff);
	pkg->hdr.bodySize = htobe64(pkg->hdr.bodySize);

	memset(pkg->hdr.hdrCmac, 0, sizeof(pkg->hdr.hdrCmac));
	memset(pkg->hdr.hdrSig, 0, sizeof(pkg->hdr.hdrSig));

	md = SHA1((void *)&pkg->hdr, 128, NULL);
	if (md == NULL) {
		ERR_print_errors_fp(stderr);
		return ERR_get_error();
	}

	memcpy(pkg->hdr.hdrSha1, md, sizeof(pkg->hdr.hdrSha1));

	return 0;
}

#define PKG_KEY_SIZE 64

static int encrypt(void *dst, const void *src, size_t size, unsigned char *ikey)
{
	unsigned int i, j;
	unsigned char *cur, *md;

	if (dst == NULL || src == NULL || ikey == NULL)
		return EINVAL;

	i = 0;
	while (i < size) {
		md = SHA1(ikey, PKG_KEY_SIZE, NULL);
		if (md == NULL) {
			ERR_print_errors_fp(stderr);
			return ERR_get_error();
		}

		for (j = 0; j < 16; j += sizeof(int)) {
			*(int *)((uintptr_t)dst + i)
				= *(int *)((uintptr_t)src + i) ^ *(int *)((uintptr_t)md + j);
			i += sizeof(int);
			j += sizeof(int);
		}

		for (cur = ikey; *cur == 255; cur++)
			*cur = 0;

		(*cur)++;
	}

	return 0;
}

static size_t fwriteUpdateSha1(
	const void *p, size_t size, size_t nmemb, FILE *fp, SHA_CTX *c)
{
	if (p == NULL || c == NULL)
		return 0;

	if (SHA1_Update(c, p, size * nmemb) != 1)
		return 0;

	return fwrite(p, size, nmemb, fp);
}

static int writePkg(pkg_t *pkg)
{
	char path[PKG_HDR_MAX_CID_LEN + sizeof(PKG_EXT)];
	char ch, *srcPath, *srcPathEnd;
	unsigned char ikey[PKG_KEY_SIZE];
	unsigned char md[SHA_DIGEST_LENGTH];
	uint32_t i, itemCnt;
	uint64_t bufSize, entSize, offset, gap;
	size_t read;
	void *buf;
	FILE *dst, *src;
	SHA_CTX c;

	sprintf(path, "%s" PKG_EXT, pkg->hdr.cid);

	dst = fopen(path, "wb");
	if (dst == NULL)
		goto fileFail;

	if (SHA1_Init(&c) != 1)
		goto cryptoFail;

	if (fwriteUpdateSha1(&pkg->hdr, sizeof(pkg->hdr), 1, dst, &c) != 1)
		goto writeFail;

	((uint64_t *)ikey)[0] = pkg->hdr.qa[0];
	((uint64_t *)ikey)[1] = pkg->hdr.qa[0];
	((uint64_t *)ikey)[2] = pkg->hdr.qa[1];
	((uint64_t *)ikey)[3] = pkg->hdr.qa[1];
	((uint64_t *)ikey)[4] = 0;
	((uint64_t *)ikey)[5] = 0;
	((uint64_t *)ikey)[6] = 0;
	((uint64_t *)ikey)[7] = 0;

	itemCnt = be32toh(pkg->hdr.itemCnt);
	entSize = itemCnt * sizeof(pkgEnt_t);
	bufSize = entSize + pkg->namesSize;
	buf = malloc(bufSize);
	if (buf == NULL)
		goto writeFail;

	encrypt(buf, pkg->ents, entSize, ikey);
	encrypt((void *)(uintptr_t)buf + entSize, pkg->names, pkg->namesSize, ikey);

	if (fwriteUpdateSha1(buf, bufSize, 1, dst, &c) != 1)
		goto writeFail;

	offset = bufSize;
	for (i = 0; i < itemCnt; i++) {
		if (be32toh(pkg->ents[i].type) == PKG_ENT_TYPE_DIR)
			continue;

		srcPath = pkg->names + be32toh(pkg->ents[i].nameOff) - entSize;
		srcPathEnd = srcPath + be32toh(pkg->ents[i].nameSize);
		ch = *srcPathEnd;
		*srcPathEnd = 0;

		gap = be64toh(pkg->ents[i].dataOff) - offset;
		if (gap) {
			memset(buf, 0, gap);
			encrypt(buf, buf, gap, ikey);

			if (fwriteUpdateSha1(buf, gap, 1, dst, &c) != 1)
				goto writeFail;
		}

		src = fopen(srcPath, "rb");
		if (src == NULL)
			goto srcFail;

		while ((read = fread(buf, 1, bufSize, src)) != 0) {
			encrypt(buf, buf, read, ikey);

			if (fwriteUpdateSha1(buf, read, 1, dst, &c) != 1)
				goto writeFail;
		}

		if (fclose(src))
			goto srcFail;

		offset += gap + be64toh(pkg->ents[i].dataSize);
		*srcPathEnd = ch;
	}

	gap = be64toh(pkg->hdr.bodySize) - offset;
	if (gap) {
		memset(buf, 0, gap);
		encrypt(buf, buf, gap, ikey);
		if (fwriteUpdateSha1(buf, gap, 1, dst, &c) != 1)
			goto writeFail;
	}

	free(buf);

	SHA1_Final(md, &c);
	if (fwrite(md, sizeof(md), 1, dst) != 1)
		goto writeFail;

	if (fclose(dst))
		goto fileFail;

	return 0;

writeFail:
	fclose(dst);
fileFail:
	perror(path);
	return errno;

srcFail:
	perror(srcPath);
	fclose(dst);
	return errno;

cryptoFail:
	fclose(dst);
	ERR_print_errors_fp(stderr);
	return ERR_get_error();
}

int main(int argc, char *argv[])
{
	pkg_t pkg;
	int res;

	if (argc != 3) {
		fprintf(stderr, "Usage: %s <CONFIG> <DIRECTORY>\n\n"

"make_package (" PACKAGE_NAME ") " PACKAGE_VERSION "\n"
"Copyright (C) 2015  PSP2SDK Project\n"
"This Program is subject to the terms of the Mozilla Public\n"
"License, v. 2.0. If a copy of the MPL was not distributed with this\n"
"file, You can obtain one at http://mozilla.org/MPL/2.0/.\n", argv[0]);

		return EINVAL;
	}

	res = buildPkgHdr(&pkg.hdr, argv[1]);
	if (res)
		return res;

	res = resolveAllEnts(&pkg, argv[2]);
	if (res)
		return res;

	res = finalizePkg(&pkg);
	if (res)
		return res;

	res = writePkg(&pkg);
	if (res)
		return res;

	return 0;
}
