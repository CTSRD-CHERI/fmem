all:
	clang fmem.c -o fmem
	clang -I /opt/homebrew/include -I /opt/homebrew/include/libelf -L /opt/homebrew/lib -g fmem_load_elf.c -o fmem_load_elf -lelf

clean:
	rm -f fmem
	rm -f fmem_load_elf
