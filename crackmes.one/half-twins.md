![image](https://github.com/AndreQuimper/Writeups/assets/96965806/066574cf-7b11-48ec-8088-f337175ae656)


Just running the binary gives no indication of what to do so we can put the binary in ghidra and see what we can figure out.  
![image](https://github.com/AndreQuimper/Writeups/assets/96965806/c5504611-f7f5-41bd-aa52-5b8a9f355f19)  

I've relabeled some variables for more clarity.  
The binary is not stripped, so the decompiler shows us the following:  

```C
undefined8 main(int argc,char **argv)

{
  size_t len;
  size_t another_len;
  int i;
  char *input1;
  char *input2;
  
  if (argc == 3) {
    input1 = argv[1];
    input2 = argv[2];
    len = strlen(input1);
    if (len < 7) {
      puts("Abby: i\'m older than that :(");
      puts("good luck next time");
    }
    else {
      len = strlen(input2);
      if (len < 7) {
        puts("Gabby: i\'m older than that :(");
        puts("good luck next time");
      }
      else {
        len = strlen(input1);
        another_len = strlen(input2);
        if (len == another_len) {
          len = strlen(input1);
          if ((len & 1) == 0) {
            len = strlen(input1);
            for (i = 0; i < (int)(len >> 1); i = i + 1) {
              if (input1[i] != input2[i]) {
                puts("Abby & Gabby: we\'re half twins you know...");
                puts("good luck next time");
                return 0;
              }
            }
            len = strlen(input1);
            for (; i < (int)len; i = i + 1) {
              if (input1[i] == input2[i]) {
                puts("Abby & Gabby: we are only HALF twins... :3 ");
                puts("good luck next time");
                return 0;
              }
            }
            puts("Abby & Gabby: yaayy!! nice job! :D");
          }
          else {
            puts("Abby & Gabby: we are not \"odd\" years old :(");
            puts("good luck next time");
          }
        }
        else {
          puts("Abby & Gabby: for god\'s sake we are TWINS! we were born the same night!!");
          puts("good luck next time");
        }
      }
    }
  }
  else {
    puts("hmm... i\'m not sure you know what the word \"twins\" mean :/");
    puts("good luck next time");
  }
  return 0;
}
```

It seems the objective is to provide input that will get us to the "Abby & Gabby: yaayy!! nice job! :D" output.  
To achieve this we will have to pass multiple `if` statements.

Lets list the conditions our input must fulfill to achieve the desired output:
1. ` if (argc == 3)`. We must have 2 inputs. (argc also counts the binary being called as an argument)
2. ```c
    len = strlen(input1); if (len < 7)
   ```
  and
   ```c
   len = strlen(input2);
      if (len < 7) {
        puts("Gabby: i\'m older than that :(");
        puts("good luck next time");
```
Therefore both our inputs must be at least 8 characters long.  

3. ```c
   if (len == another_len) {
          len = strlen(input1);
          if ((len & 1) == 0) {
   ```
   This means our inputs must be of the same length and also of even length.

4. ```c
   for (i = 0; i < (int)(len >> 1); i = i + 1) {
              if (input1[i] != input2[i]) {
   ```
   The right shift operator is basically dividing our length by 2. Therefore the first half of our inputs must be the same.

5. ```c
   len = strlen(input1);
            for (; i < (int)len; i = i + 1) {
              if (input1[i] == input2[i]) {
   ```
   Now the rest of the inputs must be different.

   Now with all that we know we can construct the strings 22221111 22222222 to obtain the desired output.
   ![image](https://github.com/AndreQuimper/Writeups/assets/96965806/c566980a-255c-4987-aa01-f687743c94f7)
