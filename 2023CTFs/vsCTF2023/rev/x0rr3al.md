We are given an executable:  
![image](https://github.com/AndreQuimper/Writeups/assets/96965806/80de6a2d-13e6-431f-876d-e5557e152661)

So if we open it in ghidra and go to the main function we will see this:  
```c

undefined8 main(void)

{
  char cVar1;
  int iVar2;
  int iVar3;
  long lVar4;
  size_t len;
  long in_FS_OFFSET;
  int i;
  char input [56];
  long local_10;
  
  local_10 = *(long *)(in_FS_OFFSET + 0x28);
  iVar2 = no_debug();
  if (iVar2 != 0) {
    start_reversing();
                    /* WARNING: Subroutine does not return */
    exit(1);
  }
  lVar4 = ptrace(PTRACE_TRACEME,0,1,0);
  if (lVar4 == -1) {
    start_reversing();
                    /* WARNING: Subroutine does not return */
    exit(1);
  }
  iVar2 = anti_debug(main,0x200);
  FUN_00101355();
  FUN_001013f8();
  iVar3 = anti_debug(main,0x200);
  if (iVar2 != iVar3) {
    start_reversing();
                    /* WARNING: Subroutine does not return */
    exit(1);
  }
  printf("p4ss m3 th3 fl4g: ");
  __isoc99_scanf(&DAT_0010205d,input);
  len = strlen(input);
  if (len == 0x35) {
    for (i = 0; i < 0x35; i = i + 1) {
      cVar1 = FUN_0010150a((int)input[i],0);
      iVar3 = FUN_001014f7((int)cVar1);
      if (iVar3 != *(int *)(&BYTE_001040a0 + (long)i * 4)) {
        c0m3_b4ck();
        goto LAB_00101b6c;
      }
      iVar3 = anti_debug(main,0x200);
      if (iVar2 != iVar3) {
        start_reversing();
                    /* WARNING: Subroutine does not return */
        exit(1);
      }
    }
    win();
  }
  else {
    c0m3_b4ck();
  }
LAB_00101b6c:
  if (local_10 != *(long *)(in_FS_OFFSET + 0x28)) {
                    /* WARNING: Subroutine does not return */
    __stack_chk_fail();
  }
  return 0;
}
```

We can see that there are different anti-debugging measures, however, it is possible to patch the binary by changing the `JNZ` comparizons to `JZ` and then use GDB to inspect the binary by jumping into functions by using  
`vmmap` to find the start of the program and then doing `jump *(start + func_offset)`. By doing this I was able to label the function that indicates you've won, and some functions that indicate you've lost.  
Finally we can see that to reach the win function we need to pass a string that will go through multiple functions that will XOR it. We could figure the correct string manually, but we can also just use `angr` to find the correct string.  

Solve Script:  
```python3
import logging
from IPython import embed
import angr
from pwn import log
logging.getLogger('angr').setLevel('INFO')
project = angr.Project('./x0rr3al', main_opts={'base_addr':0},load_options={"auto_load_libs": False})

initial_state = project.factory.entry_state()
log.info(initial_state)

sm = project.factory.simgr(initial_state)

win = 0x1618
lose = [0x16b1, 0x156e]

sm.explore(find=win,avoid=lose)
print(sm.found[0].posix.dumps(0))
```

![image](https://github.com/AndreQuimper/Writeups/assets/96965806/a3d2e04e-8874-4092-a925-8d5cfaf47ec5)
