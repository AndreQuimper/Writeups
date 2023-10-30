![image](https://github.com/AndreQuimper/Writeups/assets/96965806/95d3ca62-c618-482b-b5a5-c473c248cc2b)  

We first run the binary to see what happens.  
![image](https://github.com/AndreQuimper/Writeups/assets/96965806/2c434916-f2d2-4eb9-8b76-b6bd830948ab)  

We can then put the binary in ghidra to try and reverse it.   
The binary has been stripped, however there is an `entry()` function.   
![image](https://github.com/AndreQuimper/Writeups/assets/96965806/5571c35a-877b-4ce9-8e83-9425a61259cf)  

Since the first argument to the `__libc_start_main` is a pointer to main, we can label that function as main and take a look at it.  

![image](https://github.com/AndreQuimper/Writeups/assets/96965806/d41d33bd-d420-48ed-aeac-243236ad50b8)  

First thing to notice is the function signature; we can take advantage of ghidra to change the parameters to argc and argv.  
![image](https://github.com/AndreQuimper/Writeups/assets/96965806/f23dc704-bfac-42a5-ab67-96844181473c)  

It is a little bit clearer what is happening, however it is easy to notice that we cannot trust the decompiler for this task, so we will use purely the dissassembler from now on.  
![image](https://github.com/AndreQuimper/Writeups/assets/96965806/534cb945-be4c-4eb2-8572-698d0763cafc)    

   
Notice that there is a lot of use of the function `FUN_00101169`  
![image](https://github.com/AndreQuimper/Writeups/assets/96965806/2fe7d007-ad1e-4995-b9bb-4060185c1c4a)    

This function is just a bitwise NOT. It seems like a simple way to obfuscate hardcoded values.   

Looking back at main, we can notice that there are a couple of conditions we need to fulfill to avoid ending execution before we call `FUN_00101177(argv[1])`  
![image](https://github.com/AndreQuimper/Writeups/assets/96965806/65d0f0a0-3f4d-4887-8bf3-0822b9453d7b)  

![image](https://github.com/AndreQuimper/Writeups/assets/96965806/44c52ddb-3221-43cf-898c-141eca69647b)  


Theese two checks amount to `argc==2` and the return value of `ptrace()` to `1337`. We know however that this comparison will never be true, this is because ptrace returns 0 or -1. We need to patch the binary then.
![image](https://github.com/AndreQuimper/Writeups/assets/96965806/183ad977-00d6-4f34-a443-e41dc0efbffc)  

We can patch this instruction to do `not 0xffffffff` so that we compare the return value of `ptrace()` to `0`, which will be true. We can use the SavePatch.py Ghidra script to patch the binary.  
Finally we can look at the function call `FUN_00101177(argv[1])`
![image](https://github.com/AndreQuimper/Writeups/assets/96965806/8f89ba15-ffd1-47c2-ae59-ff790176738e)  

We see that we want our parameter (argv[1]) to be equal to `__gmon_start__`.

![image](https://github.com/AndreQuimper/Writeups/assets/96965806/7c50ca72-c80c-45b2-b6d4-29848a89589a)  







