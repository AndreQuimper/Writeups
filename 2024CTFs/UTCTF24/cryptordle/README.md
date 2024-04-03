# Cryptordle (crypto)  

we have a server running the following script
```python
#!/usr/bin/env python3
import random
wordlist = open('./wordlist.txt', 'r').read().split('\n')
#wordlist = open('/srv/app/wordlist.txt', 'r').read().split('\n')

for word in wordlist:
    assert len(word) == 5
    for letter in word:
        assert letter in 'abcdefghijklmnopqrstuvwxyz'

for attempt in range(3):
    answer = random.choice(wordlist)
    num_guesses = 0
    while True:
        num_guesses += 1

        print("What's your guess?")
        guess = input().lower()

        assert len(guess) == 5
        for letter in guess:
            assert letter in 'abcdefghijklmnopqrstuvwxyz'

        if guess == answer:
            break

        response = 1
        for x in range(5):
            a = ord(guess[x]) - ord('a')
            b = ord(answer[x]) - ord('a')
            response = (response * (a-b)) % 31
        print(response)
    if num_guesses > 6:
        print("Sorry, you took more than 6 tries. No flag for you :(")
        exit()
    else:
        print("Good job! Onward...")

if num_guesses <= 6:
    print('Nice! You got it :) Have a flag:')
    flag = open('./flag.txt', 'r').read()
    print(flag)
else:
    print("Sorry, you took more than 6 tries. No flag for you :(")
```

I found the wordlist that wordle uses, so we can just precompute the answers for every word and use a hash map (python dictionary) to look for the answers to the questions.  

```python
from pwn import *

#io = remote("betta.utctf.live", 7496)

io = process(['python3','main.py'])
vals = []
guesses = [b'abcde',b'bcdef',b'cdefg',b'defgh',b'efghi']

answer_map = {}

wordlist = open('./wordlist.txt','r')
words = [s.strip() for s in wordlist.readlines()]

for word in words:
    ans = []
    for guess1 in guesses:
        response = 1
        guess = guess1.decode()
        for x in range(5):
            a = ord(guess[x]) - ord('a')
            b = ord(word[x]) - ord('a')
            response = (response * (a-b)) % 31
        ans.append(response)
    answer_map[str(ans)] = word

for i in range(3):
    answers = []
    for j in range(5):
        io.recvuntil(b'guess?\n')
        io.sendline(guesses[j])
        answers.append(int(io.recvline()[:-1]))
    lookup = answer_map[str(answers)]
    io.sendline(lookup)
    io.recvline()
io.interactive()
```
![image](https://github.com/AndreQuimper/Writeups/assets/96965806/3bb09373-d980-42e3-890d-2ba09484f303)  



