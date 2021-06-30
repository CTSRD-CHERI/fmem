/*-
 * SPDX-License-Identifier: BSD-2-Clause
 *
 * Copyright (c) 2021 Ruslan Bukin <br@bsdpad.com>
 *
 * This work was supported by Innovate UK project 105694, "Digital Security
 * by Design (DSbD) Technology Platform Prototype".
 *
 * Redistribution and use in source and binary forms, with or without
 * modification, are permitted provided that the following conditions
 * are met:
 * 1. Redistributions of source code must retain the above copyright
 *    notice, this list of conditions and the following disclaimer.
 * 2. Redistributions in binary form must reproduce the above copyright
 *    notice, this list of conditions and the following disclaimer in the
 *    documentation and/or other materials provided with the distribution.
 *
 * THIS SOFTWARE IS PROVIDED BY THE AUTHOR AND CONTRIBUTORS ``AS IS'' AND
 * ANY EXPRESS OR IMPLIED WARRANTIES, INCLUDING, BUT NOT LIMITED TO, THE
 * IMPLIED WARRANTIES OF MERCHANTABILITY AND FITNESS FOR A PARTICULAR PURPOSE
 * ARE DISCLAIMED.  IN NO EVENT SHALL THE AUTHOR OR CONTRIBUTORS BE LIABLE
 * FOR ANY DIRECT, INDIRECT, INCIDENTAL, SPECIAL, EXEMPLARY, OR CONSEQUENTIAL
 * DAMAGES (INCLUDING, BUT NOT LIMITED TO, PROCUREMENT OF SUBSTITUTE GOODS
 * OR SERVICES; LOSS OF USE, DATA, OR PROFITS; OR BUSINESS INTERRUPTION)
 * HOWEVER CAUSED AND ON ANY THEORY OF LIABILITY, WHETHER IN CONTRACT, STRICT
 * LIABILITY, OR TORT (INCLUDING NEGLIGENCE OR OTHERWISE) ARISING IN ANY WAY
 * OUT OF THE USE OF THIS SOFTWARE, EVEN IF ADVISED OF THE POSSIBILITY OF
 * SUCH DAMAGE.
 */

#include <sys/types.h>
#include <sys/ioctl.h>

#include <ctype.h>
#include <stdlib.h>
#include <stdio.h>
#include <unistd.h>
#include <fcntl.h>

struct fmem_request {
	uint32_t offset;
	uint32_t data;
	uint32_t access_width;
};

#define	FMEM_READ	_IOWR('X', 1, struct fmem_request)
#define	FMEM_WRITE	_IOWR('X', 2, struct fmem_request)

static int fd;

static int
fmem_read(uint32_t offset, uint32_t access_width, uint32_t *data)
{
	struct fmem_request req;
	int error;

	req.offset = offset;
	req.access_width = access_width;

	error = ioctl(fd, FMEM_READ, &req);
	if (error == 0)
		*data = req.data;

	return (error);
}

static int
fmem_write(uint32_t offset, uint32_t access_width, uint32_t data)
{
	struct fmem_request req;
	int error;

	req.offset = offset;
	req.data = data;
	req.access_width = access_width;

	error = ioctl(fd, FMEM_WRITE, &req);

	return (error);
}

int
main(int argc, char **argv)
{
	uint32_t access_width;
	uint32_t write_val;
	uint32_t offset;
	uint32_t data;
	int access_type;
	char *path;
	int error;

	/* Default access type is word. */
	access_type = 'w';

	if (argc < 3) {
		fprintf(stderr,
			"\nUsage:\t%s { device } { offset } [ type [ data ] ]\n"
			"\tdevice : fmem device to act against\n"
			"\toffset : offset to read / write\n"
			"\ttype   : access width : [b]yte, [h]alfword, [w]ord\n"
			"\tdata   : data to be written\n\n", argv[0]);
		exit(1);
	}

	fd = open(argv[1], O_RDWR);
	if (fd < 0) {
		fprintf(stderr, "could not open fmem device\n");
		exit(1);
	}

	offset = strtol(argv[2], 0, 0);

	if (argc > 3)
		access_type = tolower(argv[3][0]);

	switch (access_type) {
	case 'w':
		access_width = 4;
		break;
	case 'h':
		access_width = 2;
		break;
	case 'b':
		access_width = 1;
		break;
	default:
		fprintf(stderr, "Unknown access type\n");
		exit(1);
	}

	if (argc > 4) {
		/* Write */
		write_val = strtoul(argv[4], 0, 0);
		error = fmem_write(offset, access_width, write_val);
		if (error == 0)
			printf("(write%c) 0x%x == 0x%x\n", access_type, offset,
			    write_val);
	} else {
		/* Read */
		error = fmem_read(offset, access_width, &data);
		if (error == 0)
			printf("(read%c)  0x%x == 0x%x\n", access_type, offset,
			    data);
	}

	close(fd);
}
