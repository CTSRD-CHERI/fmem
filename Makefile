all:
	clang fmem.c -o fmem
	clang -g fmem_load_elf.c -o fmem_load_elf -lelf
	clang -g fmem_dump.c -o fmem_dump

clean:
	rm -f fmem
	rm -f fmem_load_elf
	rm -f fmem_dump
