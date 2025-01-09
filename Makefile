all:
	clang fmem.c -o fmem
	clang -g fmem_load_elf.c -o fmem_load_elf -lelf

clean:
	rm -f fmem
	rm -f fmem_load_elf
