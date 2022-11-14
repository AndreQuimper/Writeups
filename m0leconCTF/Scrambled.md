So we are given this python script called `chall.py` and a hint that says `Oh No! My keyboard keys are all mixed up!`

The script looks like this:
```
from flag import flag
from random import randint

assert(len(flag) <= 50)
shift = randint(1, len(set(flag)) - 1)

def encrypt(data):
    charsf = {}
    for c in data:
        if c not in charsf.keys():
            charsf[c] = 1
        else:
            charsf[c] += 1

    chars = list(charsf.keys())
    chars.sort(reverse=True, key=lambda e: charsf[e])

    charsn = list(chars)
    for _ in range(shift):
        i = charsn.pop(0)
        charsn.append(i)

    enc = "".join(list(map(lambda c: charsn[chars.index(c)], data)))
    return enc

if __name__ == "__main__":
    print("Welcome to our custom encrypting system!")
    print("1) Encrypt something")
    print("2) Get flag")
    print("3) Exit")

    opt = input("> ")
    while opt != "3":
        if opt == "1":
            data = input("What is your string?\n")
            print(encrypt(data))
        elif opt == "2":
            print(encrypt(flag))
        opt = input("> ")
```

When running it on the server it gives us 3 options: Give it an input for it to encrypt, get an encrypted flag, or quit. 
Note that since it generates a Random integer on each initialization of the script, the encrypted flag output is also randomized for each session.
Here are what some of them look like:
```
db}_eDstrua1nqc0yu4q10uyoDqpyqambq{ggf3
0ugd}y_es3bDtfraq3nfDa3qcyf4qfboufp11m{
s0trngc4oad}pDm_1a{D}_a1fgD31Ddq0Dueeyb
```

So, lets take a look at the encryption algorithm and see what it does step by step.

```
assert(len(flag) <= 50)
shift = randint(1, len(set(flag)) - 1)
```
This makes sure that the flag is no longer than 50 characters and generates a random number smaller than the length of the flag to scramble the characters.
This is important to know because when determining the shift later we have to make sure that our input is at least 50 characters long.

Now let's take a look at the `encrypt` function:

```
charsf = {}
    for c in data:
        if c not in charsf.keys():
            charsf[c] = 1
        else:
            charsf[c] += 1
```
This creates a dictionary where each key is a character that appears in the flag and the value is the amount of times that character appears on the flag. Note that we won't have any duplicate characters in the dictionary.

```
chars = list(charsf.keys())
    chars.sort(reverse=True, key=lambda e: charsf[e])
```
This two lines of code make an array with the keys of the dictionary (the characters that appear in the flag) and sorts them by the values of the dictionary (the amount of times each character appears) from most repetitions to least.

```
charsn = list(chars)
    for _ in range(shift):
        i = charsn.pop(0)
        charsn.append(i)
```
Now we are copying the sorted list and shifting it to the left an amount of times equal to the random integer determined at the beginning.


```
enc = "".join(list(map(lambda c: charsn[chars.index(c)], data)))
    return enc
```
Now this line is a little bit more complex.
What it's doing is taking every character in the input (data) and getting its index in the sorted but not shifted array and replacing it with the character in that index from the shifted array. 
Since same characters always map out to the same index they will be replaced by the same character.
Ex: aabc --> ccab

So now that we know how the encryption algorithm works we can write a script that decrypts the encrypted flag.
```

def main():
    flag = input("input the flag you got\n")
    for shift in range(len(flag)):
        # this makes the dictionary of the shifted flag
        # which we will unshift later on in an array
        uniquechars = {}
        for c in flag:
            if c not in uniquechars.keys():
                uniquechars[c] = 1
            else:
                uniquechars[c] += 1

        flagsort = list(uniquechars.keys())
        flagsort.sort(reverse=True, key=lambda e: uniquechars[e])

        flagunshift = list(flagsort)
        for _ in range(shift):
            i = flagunshift.pop(len(flagunshift) - 1)
            flagunshift.insert(0, i)
        
        
        dec = "".join(list(map(lambda c: flagunshift[flagsort.index(c)], flag)))
        if dec[0:3] == "ptm":
            print(dec)

main()
```
Ok so how does our decryption algorithm work?
Since 50 is not a very significant number we can just do a for loop for all the possible cases, we could've written a function that automatically determined the shift but for this challenge it was not necessary.
```
for shift in range(len(flag)):
```

Then we generate the same lists that the original had by sorting the same way the encryption algorithm did (by most used character to least) and then shifting it the same amount but to the RIGHT. This will give us both the shifted and unshifted lists they used to encrypt our flag.
```
uniquechars = {}
        for c in flag:
            if c not in uniquechars.keys():
                uniquechars[c] = 1
            else:
                uniquechars[c] += 1

        flagsort = list(uniquechars.keys())
        flagsort.sort(reverse=True, key=lambda e: uniquechars[e])

        flagunshift = list(flagsort)
        for _ in range(shift):
            i = flagunshift.pop(len(flagunshift) - 1)
            flagunshift.insert(0, i)
```

In the case of our code `flagsort` is the shifted list and `flagunshift` is the sorted list.

Finally
```
dec = "".join(list(map(lambda c: flagunshift[flagsort.index(c)], flag)))
```
This reverses what the encryption algorithm did by getting the shifted letter and replacing it by what it would be in the unshifted version.

Running the script and providing an encrypted flag gives us our flag!
```
ptm{fr3quency_b4seD_c4esar_1s_n0t_good}
```

Feel free to try all three of the example encrypted flags I provided earlier and you'll see that they all return the flag!








        
        
        
        
