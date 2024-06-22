# Alternate Solution
![image](https://github.com/AndreQuimper/Writeups/assets/96965806/6c5295ea-b5e2-453d-a0ec-442615db96bc)

Let's take a look at the binary in Ghidra  
```c
undefined8 main(void)

{
  FILE *__stream;
  char *pcVar1;
  long in_FS_OFFSET;
  double input_double;
  char buf [10];
  char local_48 [56];
  long local_10;
  
  local_10 = *(long *)(in_FS_OFFSET + 0x28);
  fgets(buf,10,stdin);
  input_double = atof(buf);
  if ((float)input_double < 37.35929) {
    puts("Too low just like you\'re chances of reaching the bottom.");
                    /* WARNING: Subroutine does not return */
    exit(0);
  }
  if (37.35929 < (float)input_double) {
    puts("Too high just like your hopes of reaching the bottom.");
                    /* WARNING: Subroutine does not return */
    exit(0);
  }
  __stream = fopen("flag.txt","r");
  while( true ) {
    pcVar1 = fgets(local_48,0x32,__stream);
    if (pcVar1 == (char *)0x0) break;
    printf("%s",local_48);
  }
  if (local_10 != *(long *)(in_FS_OFFSET + 0x28)) {
                    /* WARNING: Subroutine does not return */
    __stack_chk_fail();
  }
  return 0;
}
```
Seems pretty simple, but the use of `atof()` and float casts makes me believe we might be dealing with some floating point shenanigans.  
It would seem that we can just input `37.35929` and since that number is not bigger or smaller than itself, we would pass all checks and print the flag.  
![image](https://github.com/AndreQuimper/Writeups/assets/96965806/a13ff904-15f1-4980-afb6-eac9880fdf1b)  
But it doesn't work.  
Looking a bit into it, seems that `37.35929` is not a number that can be represented due to floating point precision.  
![image](https://github.com/AndreQuimper/Writeups/assets/96965806/518478f3-2002-4dfc-a71c-6fd39f1fa0d0)  

So we take a look at what is actually being compared in our registers.  
![image](https://github.com/AndreQuimper/Writeups/assets/96965806/461202e4-87d6-414a-828e-ea8a85e665da)  
Translating `0x4042adfd11f97cae` into decimal from floating point representation gives `37.3592855899999989333082339726`, but when we try that value we get the following:  
![image](https://github.com/AndreQuimper/Writeups/assets/96965806/f2dfbfa6-40f0-4d21-9984-a491da9f6602)  
Due to our input being static cast into a float, we loose the precision necessary to pass the checks.  

Now that we know that passing this checks "fairly" is impossible, there's a little gimmick. There is a special value for floating point numbers: `NaN`, which stands for "Not a Number".  
This means that it is not bigger or smaller than other floats, since it is not a number. So we can just input NaN and pass both checks to print the flag.  
![image](https://github.com/AndreQuimper/Writeups/assets/96965806/cf212cfc-6744-46ab-a81a-79c281745659)























