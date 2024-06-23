# Rev Rev Rev
Pretty much the same as [a-byte](https://github.com/AndreQuimper/Writeups/blob/main/Nightmare/6.SymEx_Sat/hs19_abyte.md). No point in giving detail tbh

```python
import angr
import claripy
import sys

p = angr.Project('./rev_rev_rev')
init = p.factory.entry_state()
simgr = p.factory.simgr(init)

simgr.explore(find=0x08048681)
if simgr.found:
    print(simgr.found[0].posix.dumps(0))
```

![image](https://github.com/AndreQuimper/Writeups/assets/96965806/8b361aba-915d-4f25-9149-05dea3339696)
