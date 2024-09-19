// Copyright (c) 2013-2018 Bluespec, Inc. All Rights Reserved

// This program dumps data from a DE10-platform device using fmem.

// Modifications for CHERI as well as compiling on APPLE devices:

	/*-
	 * Copyright (c) 2024 Samuel Stark
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

#include "fmem_utils.c"
#include <errno.h>

// ================================================================

// We access memory by fmem-ing the address selector fd, then fmem-ing the h2f_fd.
// Accesses to the h2f_fd will have their address OR-d with the value written to the address selector fd.
#define MEM_MASK_1GB 0x3FFFFFFF
// Track what the selector currently is, so we know when to change it.#
// It can never have the value MEM_MASK_1GB, so use that as the "uninitialized" state.
static uint64_t current_selector = MEM_MASK_1GB;

static int h2f_fd;
static int address_selector_fd;
static FILE* dump_file;

void dump_access(uint64_t addr, uint32_t access_width) {
	uint64_t new_selector = addr & (~MEM_MASK_1GB);
	if (new_selector != current_selector) {
		// Write the low half of the selector to the address selector fd
		fmem_write(
			0x0,
			4,
			(uint32_t)new_selector,
			address_selector_fd
		);
		// Then write the high half
		fmem_write(
			0x4,
			4,
			(uint32_t)(new_selector >> 32),
			address_selector_fd
		);
		current_selector = new_selector;
	}
	uint64_t addr_without_selector = addr & MEM_MASK_1GB;
	// This will always fit in a uint32_t ^
	// but don't demote it immediately, I don't trust C

	// Do the actual read
	uint32_t data = 0;
	fmem_read(
		(uint32_t)addr_without_selector,
		access_width,
		&data,
		h2f_fd
	);

	// Dump that into the file
	// (interpreting `data` as a block of bytes may be UB? but this should be fiiiiiiiine)
	fwrite(
		&data, access_width, 1, dump_file
	);
}

// ================================================================

void print_usage (FILE *fp, int argc, char *argv [])
{
    fprintf (fp, "Usage:\n");
    fprintf (fp, "    %s --help\n", argv [0]);
    fprintf (fp, "    %s <start_addr (hex) (inclusive)> <end_addr (hex) (exclusive)> <dump unit (b/h/w)> <dump filename>\n", argv [0]);
    fprintf (fp, "Dump areas of memory into a binary file\n");
    fprintf (fp, "of FreeBSD Toooba CHERI-RISC-V Terasic DE10 FPGA platform.\n");
    fprintf (fp, "dump unit = [b]yte, [h]alfword, [w]ord\n");
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
    else if (argc != 5) {
		print_usage (stderr, argc, argv);
		return 1;
    }

	uint64_t start_addr = strtoull(argv[1], NULL, 16);
	if (errno) {
		fprintf(stderr, "Error parsing start_addr '%s': %s", argv[1], strerror(errno));
		return 1;
	}
	uint64_t end_addr = strtoull(argv[2], NULL, 16);
	if (errno) {
		fprintf(stderr, "Error parsing end_addr '%s': %s", argv[2], strerror(errno));
		return 1;
	}
	if (end_addr <= start_addr) {
		fprintf(stderr, "end_addr 0x%016lx cannot be <= start_addr 0x%016lx\n", end_addr, start_addr);
		return 1;
	}
	uint32_t access_width = 0;
	if (argv[3][0] == 'b') {
		access_width = 1;
	} else if (argv[3][0] == 'h') {
		access_width = 2;
	} else if (argv[3][0] == 'w') {
		access_width = 4;
	} else {
		fprintf(stderr, "dump_unit must be one of [b]yte, [h]alfword, [w]ord, got '%s'\n", argv[3]);
		return 1;
	}
	const char* dump_filename = argv[4];

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
		fprintf(stderr, "could not open fmem_h2f_dflt_1G device '%s': %s\n", h2f_dev_path, strerror(errno));
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
		fprintf(stderr, "could not open fmem_sys0_address_selector device '%s': %s\n", address_selector_dev_path, strerror(errno));
		exit(1);
    }

	fprintf(stderr, "Dumping range [0x%016lx, 0x%016lx) to file '%s' in lumps of %d bytes\n", start_addr, end_addr, dump_filename, access_width);

	dump_file = fopen(dump_filename, "wb");
	for (uint64_t addr = start_addr; addr < end_addr; addr += access_width) {
		dump_access(addr, access_width);
	}
	fclose(dump_file);

	return 0;
}
