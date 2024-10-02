all:
	clang fmem.c -o fmem
	clang -g fmem_load_elf.c -o fmem_load_elf -lelf
	clang -g fmem_dump.c -o fmem_dump
	clang -g fmem_uart.c -o fmem_uart

clean:
	rm -f fmem
	rm -f fmem_load_elf
	rm -f fmem_dump
	rm -f fmem_uart
