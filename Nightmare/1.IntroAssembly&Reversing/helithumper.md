The objective is to "Find the Flag"  
![image](https://github.com/AndreQuimper/Writeups/assets/96965806/81c11c70-2b2b-42b9-babd-6546604a0eb2)  
We'll use gdb to disassemble and rev this binary.  

![image](https://github.com/AndreQuimper/Writeups/assets/96965806/735e5973-2535-40c9-8e85-36c57f48d298)  
We can see nothing special is happening here, we just print output, get input from the user and then pass it to a `validate()` function.  

![image](https://github.com/AndreQuimper/Writeups/assets/96965806/005a3e5c-bebc-471a-9936-f46583e51d05)  
The main gist of the validate function is to compare user input to the "flag", which is constructed manually in the code.  
We could just get the flag manually from the bytes, or we could place a breakpoint in the code and then examine the memory using the debugger.  
I'll do the latter.  
![image](https://github.com/AndreQuimper/Writeups/assets/96965806/15158a43-0475-4b3a-9424-814d7fb867a2)  
Due to the way that they are organized in memory it is a little inconvenient, however we can use the gdb command `x /{number}c {memory address}` to inspect the bytes as characters.  
![image](https://github.com/AndreQuimper/Writeups/assets/96965806/d278343f-048c-47d2-9dde-b0942f97f67b)  

We get the flag `flag{HuCf_lAb}`



