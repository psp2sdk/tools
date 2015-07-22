/*
 * Copyright (C) 2015 PSP2SDK Project
 *
 * This Source Code Form is subject to the terms of the Mozilla Public
 * License, v. 2.0. If a copy of the MPL was not distributed with this
 * file, You can obtain one at http://mozilla.org/MPL/2.0/.
 */

#include <libxml/xmlreader.h>
#include <errno.h>
#include <stdint.h>
#include <stdio.h>
#include <string.h>

enum {
	PARAM_FMT_UTF8 = 2,
	PARAM_FMT_INT32 = 4
};

typedef struct {
	uint32_t magic;
	uint32_t ver;
	uint32_t keyTblOff;
	uint32_t valTblOff;
	uint32_t cnt;
} sfoHdr_t;

typedef struct {
	uint16_t keyOff;
	uint8_t align;
	uint8_t fmt;
	uint32_t len;
	uint32_t maxLen;
	uint32_t valOff;
} param_t;

#define MAX_PARAMS 16

typedef struct {
	xmlChar tbl[256];
	uint32_t size;
} xmlTbl_t;

typedef struct {
	sfoHdr_t hdr;
	param_t params[MAX_PARAMS];
	xmlTbl_t keyTbl;
	xmlTbl_t valTbl;
} sfo_t;

static int xmlTextReaderReadUnexpectEof(xmlTextReaderPtr reader)
{
	const xmlChar *uri;
	xmlErrorPtr error;
	int res;

	if (reader == NULL)
		return EINVAL;

	res = xmlTextReaderRead(reader);
	if (res == 0) {
		uri = xmlTextReaderConstBaseUri(reader);
		if (uri != NULL)
			fprintf(stderr, "%s: ", uri);
		fputs("unexpected EOF\n", stderr);

		res = EOF;
	} else if (res < 0) {
		error = xmlGetLastError();
		res = error == NULL ? error->code : EILSEQ;
	}

	return res;
}

static int xmlAddStrToTbl(xmlTbl_t *tbl, const xmlChar *s,
	uint32_t *len, uint32_t maxLen)
{
	uint32_t i;

	if (tbl == NULL || s == NULL || tbl->size + maxLen >= sizeof(tbl->tbl))
		return EINVAL;

	i = 0;
	do {
		if (maxLen == 0) {
			if (tbl->size >= sizeof(tbl->tbl))
				return EILSEQ;
		} else if (i >= maxLen)
			return EILSEQ;

		tbl->tbl[tbl->size] = *s;
		tbl->size++;
		i++;
	} while (*s++ != 0);

	if (len != NULL)
		*len = i;

	if (maxLen) {
		for (maxLen -= i; maxLen != 0; maxLen--) {
			tbl->tbl[tbl->size] = 0;
			tbl->size++;
		}
	}

	return 0;
}

static int buildSfo(sfo_t *sfo, const char *path)
{
	xmlTextReaderPtr reader;
	xmlErrorPtr error;
	const xmlChar *value;
	xmlChar *s;
	int res, paramsfoDepth, paramDepth;

	if (sfo == NULL || path == NULL)
		return EINVAL;

	reader = xmlNewTextReaderFilename(path);
	if (reader == NULL)
		goto libxmlFail;

	do {
		res = xmlTextReaderReadUnexpectEof(reader);
		if (res != 1)
			goto fail;

		s = xmlTextReaderName(reader);
		if (s == NULL)
			goto libxmlFail;

		res = strcmp((char *)s, "paramsfo");
		xmlFree(s);
	} while (res);

	paramsfoDepth = xmlTextReaderDepth(reader);
	sfo->keyTbl.size = 0;
	sfo->valTbl.size = 0;
	sfo->hdr.cnt = 0;

	do {
		do {
			res = xmlTextReaderReadUnexpectEof(reader);
			if (res != 1)
				goto fail;

			paramDepth = xmlTextReaderDepth(reader);
			if (paramDepth <= paramsfoDepth)
				goto paramsfoBreak;
		} while (xmlTextReaderNodeType(reader) != XML_READER_TYPE_ELEMENT);

		if (sfo->hdr.cnt >= MAX_PARAMS) {
			fprintf(stderr, "%s: too many paramaters\n", path);
			res = EILSEQ;
			goto fail;
		}

		s = xmlTextReaderGetAttribute(reader, (xmlChar *)"max_len");
		if (s == NULL)
			goto libxmlFail;

		sfo->params[sfo->hdr.cnt].maxLen = strtol((char *)s, NULL, 0);

		xmlFree(s);

		s = xmlTextReaderGetAttribute(reader, (xmlChar *)"key");
		if (s == NULL)
			goto libxmlFail;

		sfo->params[sfo->hdr.cnt].keyOff = sfo->keyTbl.size;
		res = xmlAddStrToTbl(&sfo->keyTbl, s, NULL, 0);
		if (res) {
			fprintf(stderr, "%s: too many and long keys\n", path);
			goto fail;
		}

		xmlFree(s);

		s = xmlTextReaderGetAttribute(reader, (xmlChar *)"fmt");
		if (s == NULL)
			goto libxmlFail;

		if (!strcmp((char *)s, "utf8"))
			sfo->params[sfo->hdr.cnt].fmt = PARAM_FMT_UTF8;
		else if (!strcmp((char *)s, "int32"))
			sfo->params[sfo->hdr.cnt].fmt = PARAM_FMT_INT32;
		else {
			fprintf(stderr, "%s: unknown fmt \"%s\"", path, (char *)s);
			res = EILSEQ;
			goto fail;
		}

		xmlFree(s);

		res = xmlTextReaderReadUnexpectEof(reader);
		if (res != 1)
			goto fail;

		value = xmlTextReaderConstValue(reader);
		if (value == NULL)
			goto libxmlFail;

		sfo->params[sfo->hdr.cnt].valOff = sizeof(sfo->valTbl.tbl);

		if (sfo->params[sfo->hdr.cnt].fmt == PARAM_FMT_UTF8) {
			res = xmlAddStrToTbl(&sfo->valTbl, value,
				&sfo->params[sfo->hdr.cnt].len,
				sfo->params[sfo->hdr.cnt].maxLen);
			if (res) {
				fprintf(stderr, "%s: too many and long values\n",
					path);
				goto fail;
			}

			sfo->params[sfo->hdr.cnt].len = res;
		} else {
			*(int32_t *)(sfo->valTbl.tbl + sfo->valTbl.size) = strtol((char *)value, NULL, 0);
			sfo->valTbl.size += sizeof(int32_t);
			sfo->params[sfo->hdr.cnt].len = sizeof(int32_t);
		}

		sfo->params[sfo->hdr.cnt].align = 4;

		sfo->hdr.cnt++;
	} while(1);
paramsfoBreak:
	xmlFreeTextReader(reader);

	sfo->hdr.magic = 0x46535000;
	sfo->hdr.ver = 0x00010001;
	sfo->hdr.keyTblOff = sizeof(sfo->hdr) + sfo->hdr.cnt * sizeof(param_t);
	sfo->hdr.valTblOff = sfo->hdr.keyTblOff + sfo->keyTbl.size;

	return 0;

libxmlFail:
	error = xmlGetLastError();
	res = error == NULL ? EILSEQ : error->code;
fail:
	xmlFreeTextReader(reader);
	return res;
}

static int writeSfo(const sfo_t *sfo, const char *path)
{
	FILE *fp;

	if (sfo == NULL || path == NULL)
		return EINVAL;

	fp = fopen(path, "wb");
	if (fp == NULL)
		goto fail;

	if (fwrite(&sfo->hdr, sizeof(sfo->hdr), 1, fp) != 1) {
		fclose(fp);
		goto fail;
	}

	if (fwrite(sfo->params, sizeof(param_t), sfo->hdr.cnt, fp) != sfo->hdr.cnt) {
		fclose(fp);
		goto fail;
	}

	if (fwrite(sfo->keyTbl.tbl, sfo->keyTbl.size, 1, fp) != 1) {
		fclose(fp);
		goto fail;
	}

	if (fwrite(sfo->valTbl.tbl, sfo->valTbl.size, 1, fp) != 1) {
		fclose(fp);
		goto fail;
	}

	if (fclose(fp))
		goto fail;

	return 0;

fail:
	perror(path);
	return errno;
}

int main(int argc, char *argv[])
{
	sfo_t sfo;
	int res;

	if (argc != 3)
		fprintf(stderr, "Usage: %s <SFX> <SFO>\n"

"sfx2sfo (" PACKAGE_NAME ") " PACKAGE_VERSION "\n"
"Copyright (C) 2015  PSP2SDK Project\n"
"This Program is subject to the terms of the Mozilla Public\n"
"License, v. 2.0. If a copy of the MPL was not distributed with this\n"
"file, You can obtain one at http://mozilla.org/MPL/2.0/.\n", argv[0]);

	res = buildSfo(&sfo, argv[1]);
	if (res)
		return res;

	return writeSfo(&sfo, argv[2]);
}
