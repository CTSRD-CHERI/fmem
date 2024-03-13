struct fmem_request {
	uint32_t offset;
	uint32_t data;
	uint32_t access_width;
};

#define	FMEM_READ	_IOWR('X', 1, struct fmem_request)
#define	FMEM_WRITE	_IOWR('X', 2, struct fmem_request)

static int
fmem_read(uint32_t offset, uint32_t access_width, uint32_t *data, int fd)
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
fmem_write(uint32_t offset, uint32_t access_width, uint32_t data, int fd)
{
	struct fmem_request req;
	int error;

	req.offset = offset;
	req.data = data;
	req.access_width = access_width;

	error = ioctl(fd, FMEM_WRITE, &req);

	return (error);
}
