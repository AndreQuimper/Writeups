# Time
```c
undefined8 main(void)

{
  time_t time_rn;
  long in_FS_OFFSET;
  uint input;
  uint random;
  long local_10;
  
  local_10 = *(long *)(in_FS_OFFSET + 0x28);
  time_rn = time((time_t *)0x0);
  srand((uint)time_rn);
  random = rand();
  puts("Welcome to the number guessing game!");
  puts("I\'m thinking of a number. Can you guess it?");
  puts("Guess right and you get a flag!");
  printf("Enter your number: ");
  fflush(stdout);
  __isoc99_scanf(&%u,&input);
  printf("Your guess was %u.\n",(ulong)input);
  printf("Looking for %u.\n",(ulong)random);
  fflush(stdout);
  if (random == input) {
    puts("You won. Guess was right! Here\'s your flag:");
    giveFlag();
  }
  else {
    puts("Sorry. Try again, wrong guess!");
  }
  fflush(stdout);
  if (local_10 != *(long *)(in_FS_OFFSET + 0x28)) {
                    /* WARNING: Subroutine does not return */
    __stack_chk_fail();
  }
  return 0;
}
```
This is pretty straightforward. If we guess the *random* number, we win!  
Of course randomness does not exists (kinda). So we can see that the time is being used to seed our randomness.  
Therefore if we run another program at the same time, we can use the same seed and generate the same random number.  

Here's the solution:  
```c
#include <stdio.h>
#include <stdlib.h>
#include <time.h>

int main(){
        FILE* file = popen("./time","w");
        time_t t = time(0);
        srand(t);
        uint random = rand();
        fprintf(file,"%i",random);
        pclose(file);
}
```
![image](https://github.com/AndreQuimper/Writeups/assets/96965806/188ac37d-ce0e-41a7-bd56-43d19a6d023a)


