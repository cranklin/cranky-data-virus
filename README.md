Cranky's Data Virus
========================================
(for educational purpose only!)

This application is used as my demonstration for:
<a href="https://cranklin.wordpress.com/2016/12/26/how-to-create-a-virus-using-the-assembly-language">How to Create a Virus Using the Assembly Language</a>


Description:
------------
This is an educational virus meant for infecting 32-bit ELF executables on Linux.
This virus uses the data segment infection method
This virus only infects ELF executables in the same directory

To assemble:
-----------
```
> nasm -f elf -F dwarf -g cranky_data_virus.asm
> ld -m elf_i386 -e v_start -o cranky_data_virus cranky_data_virus.o
```

