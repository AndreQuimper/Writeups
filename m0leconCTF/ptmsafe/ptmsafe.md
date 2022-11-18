For this challenge we are given a binary called `ptmsafe`. Running the file gives the following:
![image](https://user-images.githubusercontent.com/96965806/202808443-9c07cd79-bb71-41af-93ca-6a2910abd86b.png)

so we can assume that the we have to obtain some password to solve this challenge and obtain the flag.
Let's run the binary through ghidra and see what we can find out.
If we run the binary through ghidra we will find it has two interesting functions: `main` and `checkPassword`
Opening main shows us the following:
![image](https://user-images.githubusercontent.com/96965806/202808836-cde19c7c-1d73-4edb-8fad-7ac291794c6d.png)
Note that I've renamed some of the variables to enhance readability.

Apparently the binary takes your input and runs it through some if statements to see if the password is correct.

```
  len = strlen(&input);
  if ((int)len == 0x10) {
    if ((((input == 'p') && (local_27 == 't')) && (local_26 == 'm')) &&
       ((local_25 == '{' && (local_19 == '}'))))
```
These lines in particular give us a lot of information regarding what the password should be.
First we know that the length of the password is `0x10` or 16 in decimal.
Then we also know that the first 4 characters are `ptm{` and that the last character is `}`.
This already looks like the format of a flag, so we can assume that if we can figure that the password IS the flag.

Then the binary runs the input through the `checkPassword` function and if the value returned is 0 then it means that we have the correct password.
Knowing that our objective is to make the `checkPassword` function return 0 lets take a look at it in ghidra.

![image](https://user-images.githubusercontent.com/96965806/202809964-5de4e6f8-afd8-433d-97e9-bb99569cdb57.png)
![image](https://user-images.githubusercontent.com/96965806/202810052-5146e9d0-aa5d-4b50-afdb-64188f7f8ba9.png)

So we see that in order for our function to return `0` it needs to pass through all the `switch` cases without causing them to return 1.
Most of the `if` statements reference the values of different indexes of `password`.
So we can use those if statements to figure out the values of the different indexes of password.
 
### Case 4 ###
![image](https://user-images.githubusercontent.com/96965806/202810936-6e91e6b6-8ee5-4966-be03-d6a381aca39a.png)\

Take notice that in all of the cases we **DON'T** want to trigger the if statement
In this case (no pun intended) we want the dereferenced pointer to our input XORed (`^`) with our 5th character to be equal to `0x1e`
A unique characteristic about XOR is that if you XOR the result with one of the two arguments you get the other argument back.
This means that `password[4] = 'p'^0x1e`. This comes out to be `0x6e` or `n` in ascii.

### Case 5 ###
![image](https://user-images.githubusercontent.com/96965806/202812053-732bdc46-678f-4621-9ade-f156bbfcdcd6.png)\
This one is really simple.
We just know that our 6th character is equal to `0x30` or `0` in ascii.

### Case 6 ###
![image](https://user-images.githubusercontent.com/96965806/202812281-27337cd7-24d5-48a3-b447-18c127c3f551.png)\
This case is a little bit more complex because it references `password[4]`. Since we already solved for that value we can also solve case 6.
Knowing the fact I mentioned before about XOR we can set up the following equation:
```
password[6] = 0x13e ^ 3*0x6e
```
This turns out to be `74` or `t` in ascii.\

### Case 7 ###
![image](https://user-images.githubusercontent.com/96965806/202812810-8797aec6-1f94-4457-b8dc-55647907c0f3.png)\
This is similar to case 5 in that it just tells us that `password[7] = 0x5f`\
\
Since case 8 references case 12 we'll deal with it later.

### Case 9 ###
![image](https://user-images.githubusercontent.com/96965806/202813055-414016d7-176e-4be7-98b2-471995ed4fcc.png)\
This one tells us that `password[9]` is equal to the cube root of `0x1b000`.
This is `0x30` or `0`, same as case 5\
\
Case 10 references case 11 and case 11 references case 8 so we can't deal with them right now.

### Case 12 ###
![image](https://user-images.githubusercontent.com/96965806/202813591-a1d1ccb0-a8ff-4671-9aa4-29ef377f45ec.png)\
A new operator is introduced: `&`. This is the AND operator. 
This compares every bit in the two arguments and transforms them into a 1 if both of the bits are a 1 or a 0 if at least one of the bits is a 0.
However, if we look at the binary value of ` 0x3fffffff` we can tell that its only `1`s. Because of this we can conclude that `password[12] = 0x34`. 
This happens to be `4` in ascii.\
\
Now that we know the value of `password[12]` we can go back to case 8.

### Case 8 ###
![image](https://user-images.githubusercontent.com/96965806/202814092-182c971c-4596-427d-abb5-3e8e0b04eeca.png)\
Now that we have solved case 12 we can set up the equation:
```
password[8] = 0x34^0x47
```
That is `0x73` or `s`\
\
Now that we have solved case 8 we can go to case 11 and solve it

### Case 11 ###
![image](https://user-images.githubusercontent.com/96965806/202814588-3982bebf-cc69-405f-b29f-b674ff4a4c95.png)\
Now we need to solve the equation:
```
password[11] > (4+0x33a9)/0x73
```
this gives us that `password[11]` is also equal to `0x73` = `s`\
\
Let's go back one more time to solve case 10 now that we've solved case 11

### Case 10 ###
![image](https://user-images.githubusercontent.com/96965806/202815066-3a97c0a3-c0db-45cc-a6f1-0eb0f57e4936.png)\
Since we solved case 11 we can say that `password[10] = 0x6e + 100 - 0x73`
This turns out to be `0x5f` or `_`\

### Case 13 ###
![image](https://user-images.githubusercontent.com/96965806/202815410-6219305b-1012-46fe-93e3-f132aa512396.png)\
Case 13 is another gift for us giving us that `password[13] = 0x66`

### Case 14 ###
![image](https://user-images.githubusercontent.com/96965806/202815571-e1ac6f22-827e-4b00-86bc-69add277157f.png)\
Case 14 is our last and most complicated case. What this case does is set a variable to 0 and iterate through every character in `password`, XORing the variable with them.
in the end the value of the variable should be `0x14`. We can also do this step by step to find out that `password[14] = 0x33`

Now that we have solved all the cases we can put all of our information together to figure out that the password is
```
ptm{n0t_s0_s4f3}
```
And there is our flag!
















