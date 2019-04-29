/****************************************************************************
 *
 *   Copyright (C) 2020 FishSemi Inc. All rights reserved.
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

#ifndef CEVA_LOADER_H_
#define CEVA_LOADER_H_

#include <openamp/remoteproc.h>
#include <openamp/remoteproc_loader.h>

#if defined __cplusplus
extern "C" {
#endif

/*
 * These defines are byte order independent. There is no alignment of fields
 * permitted in the structures. Therefore they are declared as characters
 * and the values loaded from the character positions. It also makes it
 * nice to have it "endian" independent.
 */

/* Load a short int from the following tables with little-endian formats */
#define COFF_SHORT_L(ps) ((short)(((unsigned short)((unsigned char)ps[1])<<8)|\
			((unsigned short)((unsigned char)ps[0]))))

/* Load a long int from the following tables with little-endian formats */
#define COFF_LONG_L(ps) (((long)(((unsigned long)((unsigned char)ps[3])<<24) |\
				((unsigned long)((unsigned char)ps[2])<<16) |\
				((unsigned long)((unsigned char)ps[1])<<8)  |\
				((unsigned long)((unsigned char)ps[0])))))

/* Load a short int from the following tables with big-endian formats */
#define COFF_SHORT_H(ps) ((short)(((unsigned short)((unsigned char)ps[0])<<8)|\
			((unsigned short)((unsigned char)ps[1]))))

/* Load a long int from the following tables with big-endian formats */
#define COFF_LONG_H(ps) (((long)(((unsigned long)((unsigned char)ps[0])<<24) |\
				((unsigned long)((unsigned char)ps[1])<<16) |\
				((unsigned long)((unsigned char)ps[2])<<8)  |\
				((unsigned long)((unsigned char)ps[3])))))

/* These may be overridden later by brain dead implementations which generate
   a big-endian header with little-endian data. In that case, generate a
   replacement macro which tests a flag and uses either of the two above
   as appropriate. */

#define COFF_LONG(v)   COFF_LONG_L(v)
#define COFF_SHORT(v)  COFF_SHORT_L(v)

/********************** FILE HEADER **********************/

struct COFF_filehdr {
	char f_magic[2];    /* magic number         */
	char f_nscns[2];    /* number of sections       */
	char f_timdat[4];   /* time & date stamp        */
	char f_symptr[4];   /* file pointer to symtab   */
	char f_nsyms[4];    /* number of symtab entries */
	char f_opthdr[2];   /* sizeof(optional hdr)     */
	char f_flags[2];    /* flags            */
};

#define COFF_FILHDR struct COFF_filehdr
#define COFF_FILHSZ sizeof(COFF_FILHDR)

typedef struct
{
	char  magic[2];       /* type of file              */
	char  vstamp[2];      /* version stamp             */
	char  tsize[4];       /* text size in bytes, padded to FW bdry */
	char  dsize[4];       /* initialized   data "   "      */
	char  bsize[4];       /* uninitialized data "   "      */
	char  entry[4];       /* entry pt.                 */
	char  text_start[4];      /* base of text used for this file       */
	char  data_start[4];      /* base of data used for this file       */
}
COFF_AOUTHDR;

#define COFF_AOUTSZ (sizeof(COFF_AOUTHDR))

/*********************** SECTION HEADER **********************/

struct COFF_scnhdr {
	char      s_name[8];  /* section name             */
	char      s_paddr[4]; /* physical address, aliased s_nlib */
	char      s_vaddr[4]; /* virtual address          */
	char      s_size[4];  /* section size             */
	char      s_scnptr[4];    /* file ptr to raw data for section */
	char      s_relptr[4];    /* file ptr to relocation       */
	char      s_lnnoptr[4];   /* file ptr to line numbers     */
	char      s_nreloc[2];    /* number of relocation entries     */
	char      s_nlnno[2]; /* number of line number entries    */
	char      s_flags[4]; /* flags                */
};

#define COFF_SCNHDR struct COFF_scnhdr
#define COFF_SCNHSZ sizeof(COFF_SCNHDR)
#define COFF_SYMESZ 18

#define CEVA_CODE                    0x001
#define CEVA_INCODE                  0x008
#define CEVA_INDATA                  0x010
#define CEVA_NOLOAD_CODE             0x020
#define CEVA_NOLOAD_DATA             0x040
#define CEVA_BLOCK                   0x080
#define CEVA_UNIFIED                 0x800

#define CEVA_STATE_INIT              0x000UL
#define CEVA_STATE_WAIT_FOR_SHDRS    0x100UL
#define CEVA_STATE_WAIT_FOR_STRTAB   0x200UL
#define CEVA_STATE_HDRS_COMPLETE     0x400UL
#define CEVA_NEXT_SECTION_MASK       0x00FFUL

struct ceva_info {
	COFF_FILHDR fhdr;
	COFF_AOUTHDR ahdr;
	int load_state;
	COFF_SCNHDR *shdrs;
	void *shstrtab;
};

extern struct loader_ops ceva_ops;

/**
 * ceva_identify - check if it is an CEVA file
 *
 * It will check if the input image header is an ceva header.
 *
 * @img_data: firmware private data which will be passed to user defined loader
 *            operations
 * @len: firmware header length
 *
 * return 0 for success or negative value for failure.
 */
int ceva_identify(const void *img_data, size_t len);

/**
 * ceva_load_header - Load CEVA headers
 *
 * It will get the CEVA header, the program header, and the section header.
 *
 * @img_data: image data
 * @offset: input image data offset to the start of image file
 * @len: input image data length
 * @img_info: pointer to store image information data
 * @last_load_state: last state return by this function
 * @noffset: pointer to next offset required by loading CEVA header
 * @nlen: pointer to next data length required by loading CEVA header
 *
 * return CEVA loading header state, or negative value for failure
 */
int ceva_load_header(const void *img_data, size_t offset, size_t len,
		void **img_info, int last_load_state,
		size_t *noffset, size_t *nlen);

/**
 * ceva_load - load CEVA data
 *
 * It will parse the CEVA image and return the target device address,
 * offset to the start of the CEVA image of the data to load and the
 * length of the data to load.
 *
 * @rproc: pointer to remoteproc instance
 * @img_data: image data which will passed to the function.
 *            it can be NULL, if image data doesn't need to be handled
 *            by the load function. E.g. binary data which was
 *            loaded to the target memory.
 * @offset: last loaded image data offset to the start of image file
 * @len: last loaded image data length
 * @img_info: pointer to store image information data
 * @last_load_state: the returned state of the last function call.
 * @da: target device address, if the data to load is not for target memory
 *      the da will be set to ANY.
 * @noffset: pointer to next offset required by loading CEVA header
 * @nlen: pointer to next data length required by loading CEVA header
 * @padding: value to pad it is possible that a size of a segment in memory
 *           is larger than what it is in the CEVA image. e.g. a segment
 *           can have stack section .bss. It doesn't need to copy image file
 *           space, in this case, it will be packed with 0.
 * @nmemsize: pointer to next data target memory size. The size of a segment
 *            in the target memory can be larger than the its size in the
 *            image file.
 *
 * return 0 for success, otherwise negative value for failure
 */
int ceva_load(struct remoteproc *rproc, const void *img_data,
		size_t offset, size_t len,
		void **img_info, int last_load_state,
		metal_phys_addr_t *da,
		size_t *noffset, size_t *nlen,
		unsigned char *padding, size_t *nmemsize);

/**
 * ceva_release - Release CEVA image information
 *
 * It will release CEVA image information data.
 *
 * @img_info: pointer to CEVA image information
 */
void ceva_release(void *img_info);

/**
 * ceva_get_entry - Get entry point
 *
 * It will return entry point specified in the CEVA file.
 *
 * @img_info: pointer to CEVA image information
 *
 * return entry address
 */
metal_phys_addr_t ceva_get_entry(void *img_info);

/**
 * ceva_locate_rsc_table - locate the resource table information
 *
 * It will return the length of the resource table, and the device address of
 * the resource table.
 *
 * @img_info: pointer to CEVA image information
 * @da: pointer to the device address
 * @offset: pointer to the offset to in the CEVA image of the resource
 *          table section.
 * @size: pointer to the size of the resource table section.
 *
 * return 0 if successfully locate the resource table, negative value for
 * failure.
 */
int ceva_locate_rsc_table(void *img_info, metal_phys_addr_t *da,
		size_t *offset, size_t *size);

#if defined __cplusplus
}
#endif

#endif /* CEVA_LOADER_H_ */
