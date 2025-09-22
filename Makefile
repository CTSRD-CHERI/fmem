all:
	clang fmem.c -Wall -o fmem
	clang -g fmem_load_elf.c -Wall -Wextra -o fmem_load_elf -lelf
	clang -g fmem_dump.c -Wall -o fmem_dump
	clang -g fmem_uart.c -Wall -o fmem_uart

clean:
	rm -f fmem
	rm -f fmem_load_elf
	rm -f fmem_dump
	rm -f fmem_uart
