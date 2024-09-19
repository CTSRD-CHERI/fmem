// Copyright (c) 2013-2018 Bluespec, Inc. All Rights Reserved

// This program reads an ELF file and outputs a Verilog hex memory
// image file (suitable for reading using $readmemh).

// Modifications for CHERI as well as compiling on APPLE devices:

	/*-
	 * Copyright (c) 2024 Jonathan Woodruff
	 * Copyright (c) 2022-2024 Franz Fuchs
	 * All rights reserved.
	 *
	 * This software was developed by the University of  Cambridge
	 * Department of Computer Science and Technology under the
	 * SIPP (Secure IoT Processor Platform with Remote Attestation)
	 * project funded by EPSRC: EP/S030868/1
	 *
	 * @BERI_LICENSE_HEADER_START@
	 *
	 * Licensed to BERI Open Systems C.I.C. (BERI) under one or more contributor
	 * license agreements.  See the NOTICE file distributed with this work for
	 * additional information regarding copyright ownership.  BERI licenses this
	 * file to you under the BERI Hardware-Software License, Version 1.0 (the
	 * "License"); you may not use this file except in compliance with the
	 * License.  You may obtain a copy of the License at:
	 *
	 *   http://www.beri-open-systems.org/legal/license-1-0.txt
	 *
	 * Unless required by applicable law or agreed to in writing, Work distributed
	 * under the License is distributed on an "AS IS" BASIS, WITHOUT WARRANTIES OR
	 * CONDITIONS OF ANY KIND, either express or implied.  See the License for the
	 * specific language governing permissions and limitations under the License.
	 *
	 * @BERI_LICENSE_HEADER_END@
	 */

// ================================================================
// Standard C includes

#include <stdio.h>
#include <stdlib.h>
#include <stdint.h>
#include <inttypes.h>
#include <string.h>
#include <fcntl.h>

#include <sys/types.h>
#include <sys/ioctl.h>

#ifdef __APPLE__
#include <libelf/gelf.h>
#include <vector>
#else
#include <gelf.h>
#endif

#include "fmem_utils.c"

// ================================================================
// Memory buffer into which we load the ELF file before
// writing it back out to the output file.

// 1 Gigabyte size
// #define MAX_MEM_SIZE (((uint64_t) 0x400) * ((uint64_t) 0x400) * ((uint64_t) 0x400))
#define MAX_MEM_SIZE ((uint64_t) 0xFFFFFFFFF0000000)

#define BASE_ADDR_B  0x80000000lu

// For 16 MB memory at 0x_8000_0000
#define MIN_MEM_ADDR_16MB  BASE_ADDR_B
#define MAX_MEM_ADDR_16MB  (BASE_ADDR_B + 0x1000000lu)

// For 1 GB memory at 0x_8000_0000
#define MIN_MEM_ADDR_1GB  BASE_ADDR_B
#define MAX_MEM_ADDR_1GB  (BASE_ADDR_B + 0x40000000lu)

#define MEM_MASK_1GB 0x3FFFFFFF

uint8_t *mem_buf;

// Features of the ELF binary
int       bitwidth;
uint64_t  min_addr;
uint64_t  max_addr;

uint64_t  pc_start;       // Addr of label  '_start'
uint64_t  pc_exit;        // Addr of label  'exit'
uint64_t  tohost_addr;    // Addr of label  'tohost'

static int h2f_fd;
static int address_selector_fd;
uint64_t last_offset;

typedef struct {
    uint64_t virtStart;
    uint64_t virtEnd;
    uint64_t phys;
} Trans_Table;
int transtblSz;

void fmem_memcpy(uint64_t dest,
                 void *src,
                 size_t n)
{
    //printf("fmem_memcpy called; dest == 0x%x, src == 0x%x, n = 0x%x", dest, (int)src, (int)n);
    void *end = src + n;
    for (; src < end; src += 4, dest += 4) {
        uint64_t offset = dest & (~MEM_MASK_1GB);
        if (offset != last_offset) {
	    printf("writing address selector (write) 0x0 == 0x%" PRIx64 "\n",
	               offset);
            int error = fmem_write(0, 4, (uint32_t)offset, address_selector_fd);
            if (error != 0) {
	        printf("error with address selector (write) 0x0 == 0x%" PRIx64 "\n",
	               offset);
	        break;
	    }
	    //error = fmem_write(4, 4, (uint32_t)(offset>>32), address_selector_fd);
            last_offset = offset;
        }
        uint32_t write_val = ((uint32_t *)src)[0];
        int error = fmem_write(dest & MEM_MASK_1GB, 4, write_val, h2f_fd);
	if (error != 0) {
	    printf("error with h2f bridge (write) 0x%" PRIx64 " == 0x%x\n", dest,
		    write_val);
	    break;
	}
    }
}

void fmem_memset(uint64_t dest,
		 uint32_t fill_value,
		 size_t n)
{
    uint32_t end = dest + n;
    for (; dest < end; dest += 4) {
	uint64_t offset = dest & (~MEM_MASK_1GB);
        if (offset != last_offset) {
            printf("writing address selector (write) 0x0 == 0x%" PRIx64 "\n",
	               offset);
	    int error = fmem_write(0, 4, (uint32_t)offset, address_selector_fd);
	    if (error != 0) {
	        printf("error with address selector (write) 0x0 == 0x%" PRIx64 "\n",
	               offset);
	        break;
	    }
	    //error = fmem_write(4, 4, (uint32_t)(offset>>32), address_selector_fd);
            last_offset = offset;
        }
        int error = fmem_write(dest & MEM_MASK_1GB, 4, fill_value, h2f_fd);
	if (error != 0) {
	    printf("error with h2f bridge (write) 0x%" PRIx64 " == 0x%x\n", dest,
		    fill_value);
	    break;
	}
    }
}

// ================================================================
// Load an ELF file.

void c_mem_load_elf (char *elf_filename,
		     const char *start_symbol,
		     const char *exit_symbol,
		     const char *tohost_symbol)
{
    int fd;
    // int n_initialized = 0;
    Elf *e;

    // Default start, exit and tohost symbols
    if (start_symbol == NULL)
	start_symbol = "_start";
    if (exit_symbol == NULL)
	exit_symbol = "exit";
    if (tohost_symbol == NULL)
	tohost_symbol = "tohost";
    
    // Verify the elf library version
    if (elf_version (EV_CURRENT) == EV_NONE) {
        fprintf (stderr, "ERROR: c_mem_load_elf: Failed to initialize the libelfg library!\n");
	exit (1);
    }

    // Open the file for reading
    fd = open (elf_filename, O_RDONLY, 0);
    if (fd < 0) {
        fprintf (stderr, "ERROR: c_mem_load_elf: could not open elf input file: %s\n", elf_filename);
	exit (1);
    }

    // Initialize the Elf pointer with the open file
    e = elf_begin (fd, ELF_C_READ, NULL);
    if (e == NULL) {
        fprintf (stderr, "ERROR: c_mem_load_elf: elf_begin() initialization failed!\n");
	exit (1);
    }

    // Verify that the file is an ELF file
    if (elf_kind (e) != ELF_K_ELF) {
        elf_end (e);
        fprintf (stderr, "ERROR: c_mem_load_elf: specified file '%s' is not an ELF file!\n", elf_filename);
	exit (1);
    }

    // Get the ELF header
    GElf_Ehdr ehdr;
    if (gelf_getehdr (e, & ehdr) == NULL) {
        elf_end (e);
        fprintf (stderr, "ERROR: c_mem_load_elf: get_getehdr() failed: %s\n", elf_errmsg(-1));
	exit (1);
    }

    // Is this a 32b or 64b ELF?
    if (gelf_getclass (e) == ELFCLASS32) {
	fprintf (stdout, "c_mem_load_elf: %s is a 32-bit ELF file\n", elf_filename);
	bitwidth = 32;
    }
    else if (gelf_getclass (e) == ELFCLASS64) {
	fprintf (stdout, "c_mem_load_elf: %s is a 64-bit ELF file\n", elf_filename);
	bitwidth = 64;
    }
    else {
        fprintf (stderr, "ERROR: c_mem_load_elf: ELF file '%s' is not 32b or 64b\n", elf_filename);
	elf_end (e);
	exit (1);
    }

    // Verify we are dealing with a RISC-V ELF
    if (ehdr.e_machine != 243) { // EM_RISCV is not defined, but this returns 243 when used with a valid elf file.
        elf_end (e);
        fprintf (stderr, "ERROR: c_mem_load_elf: %s is not a RISC-V ELF file\n", elf_filename);
	exit (1);
    }

    // Verify we are dealing with a little endian ELF
    if (ehdr.e_ident[EI_DATA] != ELFDATA2LSB) {
        elf_end (e);
        fprintf (stderr,
		 "ERROR: c_mem_load_elf: %s is a big-endian 64-bit RISC-V executable which is not supported\n",
		 elf_filename);
	exit (1);
    }

    transtblSz = ehdr.e_phnum;
    Trans_Table *transtbl = malloc(sizeof(Trans_Table) * transtblSz);
    GElf_Phdr *phdr = malloc(sizeof(GElf_Phdr));
    fprintf (stdout, "Physical Table Allocation: Table Size %d\n", transtblSz);
    for (int i = 0; i < transtblSz; i++) {
        phdr = gelf_getphdr(e, i, phdr);
        fprintf (stdout, "Physical Table Entry: Virtual Address 0x%" PRIx64 " Size: 0x%" PRIx64 " Physical Address 0x%" PRIx64 "\n",
			phdr->p_vaddr, phdr->p_memsz, phdr->p_paddr);
	transtbl[i].virtStart = (uint64_t)phdr->p_vaddr;
	transtbl[i].virtEnd   = (uint64_t)(phdr->p_vaddr + phdr->p_memsz);
	transtbl[i].phys = (uint64_t)phdr->p_paddr;
    }

    // Grab the string section index
    size_t shstrndx;
    shstrndx = ehdr.e_shstrndx;

    // Iterate through each of the sections looking for code that should be loaded
    Elf_Scn  *scn   = 0;
    GElf_Shdr shdr;

    min_addr    = 0xFFFFFFFFFFFFFFFFllu;
    max_addr    = 0x0000000000000000llu;
    pc_start    = 0xFFFFFFFFFFFFFFFFllu;
    pc_exit     = 0xFFFFFFFFFFFFFFFFllu;
    tohost_addr = 0xFFFFFFFFFFFFFFFFllu;

    while ((scn = elf_nextscn (e,scn)) != NULL) {
        // get the header information for this section
        gelf_getshdr (scn, & shdr);

	char *sec_name = elf_strptr (e, shstrndx, shdr.sh_name);
	fprintf (stdout, "Section %-16s: ", sec_name);

	Elf_Data *data = 0;
	// If we find a code/data section, load it into the model
	if  (shdr.sh_flags == SHF_ALLOC) {
	    data = elf_getdata (scn, data);

	    // n_initialized += data->d_size;
	    if (shdr.sh_addr < min_addr)
		min_addr = shdr.sh_addr;
	    if (max_addr < (shdr.sh_addr + data->d_size - 1))   // shdr.sh_size + 4))
		max_addr = shdr.sh_addr + data->d_size - 1;    // shdr.sh_size + 4;

	    if (max_addr >= MAX_MEM_SIZE) {
		fprintf (stdout, "INTERNAL ERROR: max_addr (0x%0" PRIx64 ") > buffer size (0x%0" PRIx64 ")\n",
			 max_addr, MAX_MEM_SIZE);
		fprintf (stdout, "    Please increase the #define in this program, recompile, and run again\n");
		fprintf (stdout, "    Abandoning this run\n");
		exit (1);
	    }

	    if (shdr.sh_addr!=0) {
		uint64_t phys_addr = 0;
		for (int i=0; i<transtblSz; i++) {
		    if (shdr.sh_addr >= transtbl[i].virtStart && shdr.sh_addr <  transtbl[i].virtEnd)
	                phys_addr = transtbl[i].phys + (shdr.sh_addr - transtbl[i].virtStart);
		}
		if (phys_addr == 0) phys_addr = shdr.sh_addr;
		fprintf (stdout, " writing physical address 0x%16" PRIx64"; ", phys_addr);
		if (shdr.sh_type == SHT_NOBITS)
		    fmem_memset(phys_addr, 0, data->d_size);
		else fmem_memcpy (phys_addr, data->d_buf, data->d_size);
	    }
	    fprintf (stdout, "addr %16" PRIx64 " to addr %16" PRIx64 "; size 0x%8lx (= %0ld) bytes\n",
		     shdr.sh_addr, shdr.sh_addr + data->d_size, data->d_size, data->d_size);

	}

	// If we find the symbol table, search for symbols of interest
	else if (shdr.sh_type == SHT_SYMTAB) {
	    fprintf (stdout, "Searching for addresses of '%s', '%s' and '%s' symbols\n",
		     start_symbol, exit_symbol, tohost_symbol);

 	    // Get the section data
	    data = elf_getdata (scn, data);

	    // Get the number of symbols in this section
	    int symbols = shdr.sh_size / shdr.sh_entsize;

	    // search for the uart_default symbols we need to potentially modify.
	    GElf_Sym sym;
	    int i;
	    for (i = 0; i < symbols; ++i) {
	        // get the symbol data
	        gelf_getsym (data, i, &sym);

		// get the name of the symbol
		char *name = elf_strptr (e, shdr.sh_link, sym.st_name);

		// Look for, and remember PC of the start symbol
		if (strcmp (name, start_symbol) == 0) {
		    pc_start = sym.st_value;
		}
		// Look for, and remember PC of the exit symbol
		else if (strcmp (name, exit_symbol) == 0) {
		    pc_exit = sym.st_value;
		}
		// Look for, and remember addr of 'tohost' symbol
		else if (strcmp (name, tohost_symbol) == 0) {
		    tohost_addr = sym.st_value;
		}
	    }

	    FILE *fp_symbol_table = fopen ("symbol_table.txt", "w");
	    if (fp_symbol_table != NULL) {
		fprintf (stdout, "Writing symbols to:    symbol_table.txt\n");
		if (pc_start == -1)
		    fprintf (stdout, "    No '_start' label found\n");
		else
		    fprintf (fp_symbol_table, "_start    0x%0" PRIx64 "\n", pc_start);

		if (pc_exit == -1)
		    fprintf (stdout, "    No 'exit' label found\n");
		else
		    fprintf (fp_symbol_table, "exit      0x%0" PRIx64 "\n", pc_exit);

		if (tohost_addr == -1)
		    fprintf (stdout, "    No 'tohost' symbol found\n");
		else
		    fprintf (fp_symbol_table, "tohost    0x%0" PRIx64 "\n", tohost_addr);

		fclose (fp_symbol_table);
	    }
	}
	else {
	    fprintf (stdout, "Ignored\n");
	}
    }

    elf_end (e);

    fprintf (stdout, "Min addr:            %16" PRIx64 " (hex)\n", min_addr);
    fprintf (stdout, "Max addr:            %16" PRIx64 " (hex)\n", max_addr);
}

// ================================================================

void print_usage (FILE *fp, int argc, char *argv [])
{
    fprintf (fp, "Usage:\n");
    fprintf (fp, "    %s  --help\n", argv [0]);
    fprintf (fp, "    %s  <ELF filename>\n", argv [0]);
    fprintf (fp, "Reads ELF file and writes to shared memory using fmem driver\n");
    fprintf (fp, "of FreeBSD Toooba CHERI-RISC-V Terasic DE10 FPGA platform.\n");
    //fprintf (fp, "ELF file should have addresses within this range:\n");
    //fprintf (fp, "<  Max: 0x%8" PRIx64 "\n", MAX_MEM_ADDR_1GB);
    //fprintf (fp, ">= Min: 0x%8" PRIx64 "\n", MIN_MEM_ADDR_1GB);
}

// ================================================================

// For getting null-terminated strings from environment variables,
// or falling back to a default string.
void get_string_from_env (
	const char* __restrict__ env_var,
	const char* __restrict__ default_val,
	char* __restrict__ destination,
	size_t max_length
) {
	const char* env_val = getenv(env_var);
	if (env_val) {
		strncpy(destination, env_val, max_length);
	} else {
		strncpy(destination, default_val, max_length);
	}
	// Always null-terminate
	destination[max_length - 1] = '\0';
}

// ================================================================

int main (int argc, char *argv [])
{
    if ((argc == 2) && (strcmp (argv [1], "--help") == 0)) {
	print_usage (stdout, argc, argv);
	return 0;
    }
    else if (argc != 2) {
	print_usage (stderr, argc, argv);
	return 1;
    }
    
    char h2f_dev_path[256] = {0}; // Zero-initialized string
	get_string_from_env(
		// Use this envvar if it's set
		"RISCV_DMA_FMEM_DEV",
		// or this value if not
		"/dev/fmem_h2f_dflt_1G",
		h2f_dev_path,
		256
	);
    h2f_fd = open(h2f_dev_path, O_RDWR);
    if (h2f_fd < 0) {
		fprintf(stderr, "could not open fmem_h2f_dflt_1G device '%s'\n", h2f_dev_path);
		exit(1);
    }

    char address_selector_dev_path[256] = {0}; // Zero-initialized string
	get_string_from_env(
		// Use this envvar if it's set
		"RISCV_ADDRESS_SELECTOR_FMEM_DEV",
		// or this value if not
		"/dev/fmem_sys0_address_selector",
		address_selector_dev_path,
		256
	);
    address_selector_fd = open(address_selector_dev_path, O_RDWR);
    if (address_selector_fd < 0) {
		fprintf(stderr, "could not open fmem_sys0_address_selector device '%s'\n", address_selector_dev_path);
		exit(1);
    }

    c_mem_load_elf (argv [1], "_start", "exit", "tohost");

    if ((min_addr < BASE_ADDR_B) || (MAX_MEM_ADDR_1GB <= max_addr)) {
	print_usage (stderr, argc, argv);
	exit (1);
    }
}
