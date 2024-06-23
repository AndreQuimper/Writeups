# A-Byte
![image](https://github.com/AndreQuimper/Writeups/assets/96965806/ac4d412e-349c-4407-9905-c611e9bcd84a)  

Let's look at the binary in ghidra  
```c

undefined8 main(int argc,char **argv)

{
  long lVar1;
  int iVar2;
  undefined8 uVar3;
  size_t input_len;
  long in_FS_OFFSET;
  int i;
  char cmp [35];
  char *input;
  
  lVar1 = *(long *)(in_FS_OFFSET + 0x28);
  if (argc == 2) {
    input = argv[1];
    input_len = strlen(input);
    if ((int)input_len == 0x23) {
      for (i = 0; i < 0x23; i = i + 1) {
        input[i] = input[i] ^ 1;
      }
      cmp[0] = 'i';
      cmp[1] = 'r';
      cmp[2] = 'b';
      cmp[3] = 'u';
      cmp[4] = 'g';
      cmp[5] = 'z';
      cmp[6] = 'v';
      cmp[7] = '1';
      cmp[8] = 'v';
      cmp[9] = '^';
      cmp[10] = 'x';
      cmp[11] = '1';
      cmp[12] = 't';
      cmp[13] = '^';
      cmp[14] = 'j';
      cmp[15] = 'o';
      cmp[16] = '1';
      cmp[17] = 'v';
      cmp[18] = '^';
      cmp[19] = 'e';
      cmp[20] = '5';
      cmp[21] = '^';
      cmp[22] = 'v';
      cmp[23] = '@';
      cmp[24] = '2';
      cmp[25] = '^';
      cmp[26] = '9';
      cmp[27] = 'i';
      cmp[28] = '3';
      cmp[29] = 'c';
      cmp[30] = '@';
      cmp[31] = '1';
      cmp[32] = '3';
      cmp[33] = '8';
      cmp[34] = '|';
      iVar2 = strcmp(cmp,input);
      if (iVar2 == 0) {
        puts("Oof, ur too good");
        uVar3 = 0;
        goto LAB_00100891;
      }
    }
  }
  puts("u do not know da wae");
  uVar3 = 0xffffffff;
LAB_00100891:
  if (lVar1 == *(long *)(in_FS_OFFSET + 0x28)) {
    return uVar3;
  }
                    /* WARNING: Subroutine does not return */
  __stack_chk_fail();
}
```

We can see that a bunch of operations are being done on our input, and then the result is compared to another string. It seems that if they match we win.  
We could:
1. Manually calculate every single one since it does not seem complicated... >:(
2. Use Z3 to find a satisfying input :/
3. Ask angr pretty please so that it gives us the answer :D

So the plan is to run angr, a symbolic execution tool, until it reaches our desired state, which is when we print `Oof, ur too good`.  

```python
import angr
import sys
import claripy

def main():
    binary_path = "./a-byte"
    p = angr.Project(binary_path)
    argv = claripy.BVS('argv',0x24*8)

    initial_state = p.factory.entry_state(args=[binary_path,argv])
    sim = p.factory.simgr(initial_state)
    sim.explore(find=is_good)

    if sim.found:
        solve_state = sim.found[0]
        print(solve_state.solver.eval(argv, cast_to=bytes))


def is_good(state):
    output = state.posix.dumps(sys.stdout.fileno())
    if b'Oof, ur too good' in output:
        return True
    return False


if __name__ == '__main__':
    main()
```

![image](https://github.com/AndreQuimper/Writeups/assets/96965806/bf058a53-c995-4bac-9d63-1d3392fbde66)

