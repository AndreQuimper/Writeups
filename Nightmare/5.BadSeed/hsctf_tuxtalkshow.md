# TuxTalkShow

```c

undefined8 main(void)

{
  int iVar1;
  time_t tVar2;
  basic_ostream *pbVar3;
  long in_FS_OFFSET;
  int input;
  int i;
  int acc;
  int j;
  undefined4 local_280;
  undefined4 local_27c;
  undefined4 local_278;
  undefined4 local_274;
  undefined4 local_270;
  undefined4 local_26c;
  int nums [8];
  basic_string flag_contents [32];
  basic_istream flag.txt [520];
  long local_20;
  
  local_20 = *(long *)(in_FS_OFFSET + 0x28);
  std::basic_ifstream<>::basic_ifstream((char *)flag.txt,0x1020b0);
  tVar2 = time((time_t *)0x0);
  srand((uint)tVar2);
                    /* try { // try from 0010127e to 001012c0 has its CatchHandler @ 00101493 */
  pbVar3 = std::operator<<((basic_ostream *)std::cout,"Welcome to Tux Talk Show 2019!!!");
  std::basic_ostream<>::operator<<((basic_ostream<> *)pbVar3,std::endl<>);
  std::operator<<((basic_ostream *)std::cout,"Enter your lucky number: ");
  std::basic_istream<>::operator>>((basic_istream<> *)std::cin,&input);
  local_280 = 0x79;
  local_27c = 0x12c97f;
  local_278 = 0x135f0f8;
  local_274 = 0x74acbc6;
  local_270 = 0x56c614e;
  local_26c = 0xffffffe2;
  nums[0] = 0x79;
  nums[1] = 0x12c97f;
  nums[2] = 0x135f0f8;
  nums[3] = 0x74acbc6;
  nums[4] = 0x56c614e;
  nums[5] = 0xffffffe2;
  for (i = 0; i < 6; i = i + 1) {
    iVar1 = rand();
    nums[i] = nums[i] - (iVar1 % 10 + -1);
  }
  acc = 0;
  for (j = 0; j < 6; j = j + 1) {
    acc = acc + nums[j];
  }
  if (acc == input) {
    std::__cxx11::basic_string<>::basic_string();
                    /* try { // try from 00101419 to 00101448 has its CatchHandler @ 0010147f */
    std::operator>>(flag.txt,flag_contents);
    pbVar3 = std::operator<<((basic_ostream *)std::cout,flag_contents);
    std::basic_ostream<>::operator<<((basic_ostream<> *)pbVar3,std::endl<>);
    std::__cxx11::basic_string<>::~basic_string((basic_string<> *)flag_contents);
  }
  std::basic_ifstream<>::~basic_ifstream((basic_ifstream<> *)flag.txt);
  if (local_20 != *(long *)(in_FS_OFFSET + 0x28)) {
                    /* WARNING: Subroutine does not return */
    __stack_chk_fail();
  }
  return 0;
}
```
Similar to [time](https://github.com/AndreQuimper/Writeups/blob/main/Nightmare/5.BadSeed/h3_time.md) we are using the `time()` function to seed our randomness and then generate a magic value.  
We can see that we are reading `flag.txt` and if the input is the same as the one provided by the user we print the flag.  
This can be solved the same way as in `time`. Run another program at the same time so that we can have the same seed.  

```c
#include <stdio.h>
#include <stdlib.h>
#include <time.h>

int gen_magic(){
    int nums[6];
    nums[0] = 0x79;
    nums[1] = 0x12c97f;
    nums[2] = 0x135f0f8;
    nums[3] = 0x74acbc6;
    nums[4] = 0x56c614e;
    nums[5] = 0xffffffe2;
    for (int i = 0; i < 6; i = i + 1) {
        int iVar1 = rand();
        nums[i] = nums[i] - (iVar1 % 10 + -1);
    }
    int acc = 0;
    for (int j = 0; j < 6; j = j + 1) {
        acc = acc + nums[j];
    }
    return acc;
}

int main(){
        FILE* file = popen("./tuxtalkshow","w");
        time_t t = time(0);
        srand(t);
        int sol = gen_magic();
        fprintf(file,"%i",sol);
        pclose(file);
}
```
![image](https://github.com/AndreQuimper/Writeups/assets/96965806/fa696ba3-320d-44cf-87e5-463ac62c94e3)

