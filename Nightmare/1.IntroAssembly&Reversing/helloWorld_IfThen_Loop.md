There  are three binaries that we need to reverse. They are all really simple, so I thought they didnt deserve a document for each of them.  

##### Hello World  

We can use objdump to look at the assembly of this binary. `objdump hello_world -D -M intel`.  
We can easily spot the main function and analyze what is does:  
![image](https://github.com/AndreQuimper/Writeups/assets/96965806/7758df6d-9495-40e4-8631-86e83d8bc93f)  
We can see that a pointer is being passed to the puts function. If we follow the pointer we see the following:  
![image](https://github.com/AndreQuimper/Writeups/assets/96965806/d80c2e5e-2957-43b3-8aaf-4d55f6673593)  
This very much looks like a null terminated string, and it is!  
![image](https://github.com/AndreQuimper/Writeups/assets/96965806/5de15eb6-4ea9-4b89-9cb4-c801e2469c7c)  
Thats basically the first one.  


##### If_then  

This binary is pretty much the same as the last one, the only difference is that there is a conditional jump that is never executed and the printed string is different.  

##### Loop  
This one is a little different.  
![image](https://github.com/AndreQuimper/Writeups/assets/96965806/ce0cec41-a8e6-42bf-af83-d28663e87cc9)  
We see that there is a loop executed until our counter is greater than 0x13. The two parameters to printf are the counter, and a pointer to the string '%d'.  
This is kind of the same as  
```c
for (int i = 0; i<=13; i++){
  printf('%d',i);
}
```






