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




