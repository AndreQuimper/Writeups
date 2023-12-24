![image](https://github.com/AndreQuimper/Writeups/assets/96965806/b3359a0a-a9bc-4c5a-8fc6-2f2092d0e862)  
This is another one of the challenges where we need to make our input pass a series of checks to obtain the flag.  
Lets look at the binary in ghidra:  
![image](https://github.com/AndreQuimper/Writeups/assets/96965806/28aaff39-286f-460c-94f7-65978844bedb)  
![image](https://github.com/AndreQuimper/Writeups/assets/96965806/f90cfc37-e147-41aa-b9f8-c89536519f21)  

First the `convert()` function looks at which index our character is in a character array, which looks like this (in this case w is 0, f is 1, etc.):  
![image](https://github.com/AndreQuimper/Writeups/assets/96965806/c4335d31-a9cb-48c7-9569-9d49486bd466)  
The function returns the 'index' corresponding the each of our characters in our input. Then, the `main()` function compares each of those integers to the desired integers. Therefore we just need to map the desired integers to their respective characters in our lookup structure to convert them to a string and obtain the FLAG.  

I did the work manually, but wrote a little program to help me along the way:
```python
indexes = [0x1,0x9,0x11,0x27,0x02,0x0,0x12,0x03,0x08,0x012,0x09,0x12,0x11,0x1,0x3,0x13,0x4,0x3,0x5,0x15,0x2e,0xa,0x3,0xa,0x12,0x3,0x1,0x2e,0x16,0x2e,0xa,0x12,0x6]
setin = set(indexes)
for i in setin:
    print(f'{i}: {hex(0x00301020+4*i)}')
letters = {}
letters[0] = 'w'
letters[1] = 'f'
letters[2] = '{'
letters[3] = '_'
letters[4] = 'n'
letters[5] = 'y'
letters[6] = '}'
letters[39] = 'g'
letters[8] = 'b'
letters[9] = 'l'
letters[10] = 'r'
letters[46] = 'u'
letters[17] = 'a'
letters[18] = 'e'
letters[19] = 'i'
letters[21] = 'o'
letters[22] = 't'

for i in indexes:
    print(letters[i],end='')
print()
```

It gives the following output:  
![image](https://github.com/AndreQuimper/Writeups/assets/96965806/2071054f-8f78-47cf-86ae-a9cebdaafa9c)

  



