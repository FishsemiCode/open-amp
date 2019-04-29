/****************************************************************************
 *
 *   Copyright (C) 2019 FishSemi Inc. All rights reserved.
 *   Author: Bo Zhang <zhangbo@fishsemi.com>
 *
 * Redistribution and use in source and binary forms, with or without
 * modification, are permitted provided that the following conditions
 * are met:
 *
 * 1. Redistributions of source code must retain the above copyright
 *    notice, this list of conditions and the following disclaimer.
 * 2. Redistributions in binary form must reproduce the above copyright
 *    notice, this list of conditions and the following disclaimer in
 *    the documentation and/or other materials provided with the
 *    distribution.
 * 3. Neither the name NuttX nor the names of its contributors may be
 *    used to endorse or promote products derived from this software
 *    without specific prior written permission.
 *
 * THIS SOFTWARE IS PROVIDED BY THE COPYRIGHT HOLDERS AND CONTRIBUTORS
 * "AS IS" AND ANY EXPRESS OR IMPLIED WARRANTIES, INCLUDING, BUT NOT
 * LIMITED TO, THE IMPLIED WARRANTIES OF MERCHANTABILITY AND FITNESS
 * FOR A PARTICULAR PURPOSE ARE DISCLAIMED. IN NO EVENT SHALL THE
 * COPYRIGHT OWNER OR CONTRIBUTORS BE LIABLE FOR ANY DIRECT, INDIRECT,
 * INCIDENTAL, SPECIAL, EXEMPLARY, OR CONSEQUENTIAL DAMAGES (INCLUDING,
 * BUT NOT LIMITED TO, PROCUREMENT OF SUBSTITUTE GOODS OR SERVICES; LOSS
 * OF USE, DATA, OR PROFITS; OR BUSINESS INTERRUPTION) HOWEVER CAUSED
 * AND ON ANY THEORY OF LIABILITY, WHETHER IN CONTRACT, STRICT
 * LIABILITY, OR TORT (INCLUDING NEGLIGENCE OR OTHERWISE) ARISING IN
 * ANY WAY OUT OF THE USE OF THIS SOFTWARE, EVEN IF ADVISED OF THE
 * POSSIBILITY OF SUCH DAMAGE.
 *
 ****************************************************************************/

#include <string.h>
#include <metal/alloc.h>
#include <metal/log.h>
#include <openamp/ceva_loader.h>
#include <openamp/remoteproc.h>

static int *ceva_load_state(void *coff_info)
{
	struct ceva_info *cinfo = coff_info;
	return &cinfo->load_state;
}

static COFF_FILHDR *ceva_fileheader_ptr(void *coff_info)
{
	struct ceva_info *cinfo = coff_info;
	return &cinfo->fhdr;
}

static void **ceva_shtable_ptr(void *coff_info)
{
	struct ceva_info *cinfo = coff_info;
	return (void **)&cinfo->shdrs;
}

static void **ceva_shstrtab_ptr(void *coff_info)
{
	struct ceva_info *cinfo = coff_info;
	return (void *)&cinfo->shstrtab;
}

static void *ceva_get_section_from_name(void *coff_info, const char *find_name)
{
	struct ceva_info *cinfo = coff_info;
	COFF_SCNHDR *scnhdr = cinfo->shdrs;
	const char *name_table = (const char *)cinfo->shstrtab;
	COFF_FILHDR *fhdr = ceva_fileheader_ptr(cinfo);
	int nscns = COFF_SHORT(fhdr->f_nscns);
	int i;

	if (scnhdr == NULL || name_table == NULL)
		return NULL;
	for (i = 0; i < nscns; i++, scnhdr++) {
		unsigned long zero = COFF_LONG(scnhdr->s_name);
		unsigned long name = COFF_LONG((scnhdr->s_name + 4));
		unsigned long flags = COFF_LONG(scnhdr->s_flags);

		if (flags & CEVA_CODE)
			continue;
		if (flags & CEVA_BLOCK)
			continue;
		if (flags & CEVA_NOLOAD_DATA)
			continue;
		if (zero)
			continue;
		if (name_table + name != strstr(name_table + name, find_name))
			continue;

		metal_log(METAL_LOG_DEBUG, "######### find section %s ###########\n", find_name);
		return scnhdr;
	}

	return NULL;
}

static void ceva_parse_section(void *coff_info, const void *coff_shdr,
		unsigned long *sh_flags,
		metal_phys_addr_t *sh_addr,
		size_t *sh_offset,
		size_t *sh_size)
{
	COFF_SCNHDR *scnhdr = (COFF_SCNHDR *)coff_shdr;
	unsigned long flags = COFF_LONG(scnhdr->s_flags);
	unsigned long paddr = COFF_LONG(scnhdr->s_paddr);
	unsigned long vaddr = COFF_LONG(scnhdr->s_vaddr);
	unsigned long scnptr = COFF_LONG(scnhdr->s_scnptr);
	unsigned long size = COFF_LONG(scnhdr->s_size);

	struct ceva_info *cinfo = coff_info;
	const char *strptr = cinfo->shstrtab;
	const char *name;
	bool need_load = false;

	if (sh_flags != NULL)
		*sh_flags = flags;
	if (flags & CEVA_BLOCK) {
		*sh_flags = CEVA_BLOCK;
	}
	else if (flags & CEVA_INCODE) {
		need_load = true;
		*sh_addr = paddr;
	} else if (flags & CEVA_INDATA) {
		need_load = true;
		*sh_addr = vaddr;
	} else if (flags & CEVA_UNIFIED) {
		need_load = true;
		*sh_addr = vaddr;
	} else {
		*sh_flags = CEVA_NOLOAD_CODE | CEVA_NOLOAD_DATA;
	}
	if (sh_offset != NULL)
		*sh_offset = scnptr;
	if (sh_size != NULL)
		*sh_size = size;

	if (sh_flags != NULL && need_load && size != 0) {
		if (COFF_LONG(scnhdr->s_name))
			name = scnhdr->s_name;
		else
			name = strptr + COFF_LONG((scnhdr->s_name + 4));
		metal_log(METAL_LOG_DEBUG, "name %s paddr 0x%lx vaddr 0x%lx size 0x%lx scnptr 0x%lx flags 0x%lx\n",
			name, paddr, vaddr, size, scnptr, flags);
	}
}

static const void *ceva_get_section_from_index(void *coff_info, int index)
{
	struct ceva_info *cinfo = coff_info;
	COFF_FILHDR *fhdr = ceva_fileheader_ptr(cinfo);
	COFF_SCNHDR *shdrs = cinfo->shdrs;

	if (shdrs == NULL) {
		metal_log(METAL_LOG_ERROR, "shdr is NULL!\n");
		return NULL;
	}
	if (index < 0 || index >= COFF_SHORT(fhdr->f_nscns)) {
		metal_log(METAL_LOG_DEBUG, "index is out of range, index = %d!\n", index);
		return NULL;
	}

	return &shdrs[index];
}

static const void *ceva_next_load_section(void *coff_info, int *nseg,
		metal_phys_addr_t *da,
		size_t *noffset, size_t *nsize)
{
	const void *shdr;
	unsigned long flags;
	bool need_load = false;


	if (coff_info == NULL || nseg == NULL)
		return NULL;

	while (need_load != true) {
		shdr = ceva_get_section_from_index(coff_info, *nseg);
		if (shdr == NULL) {
			metal_log(METAL_LOG_DEBUG, "Failed to get section from index %d\n", *nseg);
			return NULL;
		}
		ceva_parse_section(coff_info, shdr, &flags, da, noffset, nsize);
		if ((flags & CEVA_NOLOAD_CODE) || (flags & CEVA_NOLOAD_DATA) ||
				(flags & CEVA_BLOCK) || (*nsize == 0)) {
			need_load = false;
		} else {
			need_load = true;
		}
		*nseg = *nseg + 1;
	}

	return shdr;
}

int ceva_identify(const void *img_data, size_t len)
{
	struct COFF_filehdr *filhdr = (struct COFF_filehdr *)img_data;

	if (COFF_SHORT(filhdr->f_opthdr) == COFF_AOUTSZ)
		return 0;
	else
		return -RPROC_EINVAL;
}

int ceva_load_header(const void *img_data, size_t offset, size_t len,
		void **img_info, int last_load_state,
		size_t *noffset, size_t *nlen)
{
	int *load_state;

	metal_assert(noffset != NULL);
	metal_assert(nlen != NULL);
	/* Get CEVA header */
	if (last_load_state == CEVA_STATE_INIT) {
		size_t tmpsize;
		metal_log(METAL_LOG_DEBUG, "Loading CEVA headering.\n");
		tmpsize = COFF_FILHSZ + COFF_AOUTSZ;
		if (len < tmpsize) {
			*noffset = 0;
			*nlen = tmpsize;
			return CEVA_STATE_INIT;
		} else {
			size_t infosize = sizeof(struct ceva_info);
			if (*img_info == NULL) {
				*img_info = metal_allocate_memory(infosize);
				if (*img_info == NULL)
					return -RPROC_ENOMEM;
				memset(*img_info, 0x0, infosize);
			}
			memcpy(*img_info, img_data, tmpsize);
			load_state = ceva_load_state(*img_info);
			*load_state = CEVA_STATE_WAIT_FOR_SHDRS;
			last_load_state = CEVA_STATE_WAIT_FOR_SHDRS;
		}
	}
	metal_assert(*img_info != NULL);
	load_state = ceva_load_state(*img_info);
	if (last_load_state != *load_state)
		return -RPROC_EINVAL;

	if (*load_state == CEVA_STATE_WAIT_FOR_SHDRS) {
		size_t shdrs_size;
		size_t shdrs_offset;
		void **shdrs;
		const void *img_shdrs;
		COFF_FILHDR *fhdr = ceva_fileheader_ptr(*img_info);

		metal_log(METAL_LOG_DEBUG, "Loading CEVA section headering!\n");

		shdrs_offset = COFF_FILHSZ + COFF_AOUTSZ;
		shdrs_size = COFF_SHORT(fhdr->f_nscns) * sizeof(COFF_SCNHDR);
		metal_log(METAL_LOG_DEBUG, "offset = %d, len = %d, shdrs_offset = %d, shdrs_size = %d\n",
				(int)offset, (int)len, (int)shdrs_offset, (int)shdrs_size);
		if (offset > shdrs_offset ||
				offset + len < shdrs_offset + shdrs_size) {
			*noffset = shdrs_offset;
			*nlen = shdrs_size;
			return *load_state;
		}
		shdrs_offset -= offset;
		img_shdrs = (const char*)img_data + shdrs_offset;
		shdrs = ceva_shtable_ptr(*img_info);
		*shdrs = metal_allocate_memory(shdrs_size);
		if (*shdrs == NULL) {
			metal_log(METAL_LOG_ERROR, "Failed to alloc shdrs!\n");
			return -RPROC_ENOMEM;
		}
		memcpy(*shdrs, img_shdrs, shdrs_size);
		*load_state = CEVA_STATE_WAIT_FOR_STRTAB | RPROC_LOADER_READY_TO_LOAD;
	}

	if ((*load_state & CEVA_STATE_WAIT_FOR_STRTAB) != 0) {
		size_t strtab_size;
		size_t strtab_offset;
		void **strtab;
		const char *img;
		COFF_FILHDR *fhdr = ceva_fileheader_ptr(*img_info);

		metal_log(METAL_LOG_DEBUG, "Loading CEVA section string table!\n");

		strtab_offset = COFF_LONG(fhdr->f_symptr) + COFF_SYMESZ * COFF_LONG(fhdr->f_nsyms);
		if (offset > strtab_offset ||
				offset + len < strtab_offset + 4) {
			*noffset = strtab_offset;
			*nlen = 4;
			metal_log(METAL_LOG_DEBUG, "Start to read strtab length!\n");
			return *load_state;
		}
		strtab_offset -= offset;
		img = (const char*)img_data + strtab_offset;
		strtab_size = COFF_LONG(img);
		metal_log(METAL_LOG_DEBUG, "strtab_size = %d\n", (int)strtab_size);
		strtab_offset = COFF_LONG(fhdr->f_symptr) + COFF_SYMESZ * COFF_LONG(fhdr->f_nsyms);
		if (offset > strtab_offset ||
				offset + len < strtab_offset + strtab_size) {
			*noffset = strtab_offset;
			*nlen = strtab_size;
			metal_log(METAL_LOG_DEBUG, "Start to read strtab content!\n");
			return *load_state;
		}

		strtab_offset -= offset;
		strtab = ceva_shstrtab_ptr(*img_info);
		*strtab = metal_allocate_memory(strtab_size);
		if (*strtab == NULL) {
			metal_log(METAL_LOG_ERROR, "Failed to alloc strtab!\n");
			return -RPROC_ENOMEM;
		}
		memcpy(*strtab, (const char *)img_data + strtab_offset, strtab_size);
		*load_state = CEVA_STATE_HDRS_COMPLETE | RPROC_LOADER_READY_TO_LOAD;
		*nlen = 0;
		return *load_state;
	}

	return last_load_state;
}

int ceva_load(struct remoteproc *rproc, const void *img_data,
		size_t offset, size_t len,
		void **img_info, int last_load_state,
		metal_phys_addr_t *da,
		size_t *noffset, size_t *nlen,
		unsigned char *padding, size_t *nmemsize)
{
	int *load_state;
	const void *shdr;

	(void)rproc;
	metal_assert(da != NULL);
	metal_assert(noffset != NULL);
	metal_assert(nlen != NULL);
	if ((last_load_state & RPROC_LOADER_MASK) == RPROC_LOADER_NOT_READY) {
		metal_log(METAL_LOG_DEBUG, "needs to load header first!\n");
		last_load_state = ceva_load_header(img_data, offset, len,
				img_info, last_load_state,
				noffset, nlen);
		if ((last_load_state & RPROC_LOADER_MASK) ==
				RPROC_LOADER_NOT_READY) {
			*da = RPROC_LOAD_ANYADDR;
			return last_load_state;
		}
	}

	metal_assert(img_info != NULL && *img_info != NULL);
	load_state = ceva_load_state(*img_info);
	/* For CEVA, segment padding value is 0 */
	if (padding != NULL)
		*padding = 0;
	if ((*load_state & RPROC_LOADER_READY_TO_LOAD) != 0) {
		int nsection;
		size_t nsectionsize = 0;
		int shnums = 0;
		COFF_FILHDR *fhdr = ceva_fileheader_ptr(*img_info);

		nsection = *load_state & CEVA_NEXT_SECTION_MASK;
		shdr = ceva_next_load_section(*img_info, &nsection, da,
				noffset, &nsectionsize);
		if (shdr == NULL) {
			metal_log(METAL_LOG_DEBUG, "Can't find more section!\n");
			*load_state = (*load_state & (~CEVA_NEXT_SECTION_MASK)) |
				(nsection & CEVA_NEXT_SECTION_MASK);
			return *load_state;
		}
		*nlen = nsectionsize;
		*nmemsize = nsectionsize;

		shnums = COFF_SHORT(fhdr->f_nscns);
		metal_log(METAL_LOG_DEBUG, "section: %d, total sections: %d\n", (int)nsection, (int)shnums);
		if (nsection == shnums) {
			*load_state = (*load_state & (~RPROC_LOADER_MASK)) |
				RPROC_LOADER_POST_DATA_LOAD;
		}
		*load_state = (*load_state & (~CEVA_NEXT_SECTION_MASK)) |
			(nsection & CEVA_NEXT_SECTION_MASK);
	} else if ((*load_state & RPROC_LOADER_POST_DATA_LOAD) != 0) {
		if ((*load_state & CEVA_STATE_HDRS_COMPLETE) == 0) {
			last_load_state = ceva_load_header(img_data, offset, len,
					img_info, last_load_state,
					noffset, nlen);
			if (last_load_state < 0)
				return last_load_state;
			if ((last_load_state & CEVA_STATE_HDRS_COMPLETE) != 0) {
				*load_state = (*load_state & (~RPROC_LOADER_MASK)) |
					RPROC_LOADER_LOAD_COMPLETE;
				*nlen = 0;
			}
			*da = RPROC_LOAD_ANYADDR;
		} else {
			*nlen = 0;
			*load_state = (*load_state & (~RPROC_LOADER_MASK)) |
				RPROC_LOADER_LOAD_COMPLETE;
		}
	}

	return *load_state;
}

int ceva_locate_rsc_table(void *img_info, metal_phys_addr_t *da,
		size_t *offset, size_t *size)
{
	char *sect_name = "resource_table@";
	void *shdr;
	int *load_state;

	if (img_info == NULL) {
		metal_log(METAL_LOG_ERROR, "coff info is NULL!\n");
		return -RPROC_EINVAL;
	}

	load_state = ceva_load_state(img_info);
	if ((*load_state & CEVA_STATE_HDRS_COMPLETE) == 0) {
		metal_log(METAL_LOG_ERROR, "coff state error!\n");
		return -RPROC_ERR_LOADER_STATE;
	}
	shdr = ceva_get_section_from_name(img_info, sect_name);
	if (shdr == NULL) {
		metal_log(METAL_LOG_ERROR, "No shdr!\n");
		*size = 0;
		return 0;
	}

	ceva_parse_section(img_info, shdr, NULL, da, offset, size);

	return 0;
}

void ceva_release(void *img_info)
{
	struct ceva_info *cinfo = img_info;

	if (img_info == NULL)
		return;

	if (cinfo->shdrs != NULL)
		metal_free_memory(cinfo->shdrs);
	if (cinfo->shstrtab != NULL)
		metal_free_memory(cinfo->shstrtab);
	metal_free_memory(img_info);
}

metal_phys_addr_t ceva_get_entry(void *img_info)
{
	struct ceva_info *cinfo = img_info;
	COFF_AOUTHDR *ahdr = &cinfo->ahdr;

	return COFF_LONG(ahdr->entry);
}

int ceva_get_load_state(void *img_info)
{
	int *load_state;

	if (img_info == NULL)
		return -RPROC_EINVAL;

	load_state = ceva_load_state(img_info);
	return *load_state;
}

struct loader_ops ceva_ops = {
	.load_header = ceva_load_header,
	.load_data = ceva_load,
	.locate_rsc_table = ceva_locate_rsc_table,
	.release = ceva_release,
	.get_entry = ceva_get_entry,
	.get_load_state = ceva_get_load_state,
};
