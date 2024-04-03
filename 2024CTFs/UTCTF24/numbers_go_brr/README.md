# Numbers go brrr
We have a server running the following script

```python
#!/usr/bin/env python3
from Crypto.Cipher import AES
from Crypto.Util.Padding import pad
from Crypto.Random import random

seed = random.randint(0, 10 ** 6)
def get_random_number():
    global seed 
    seed = int(str(seed * seed).zfill(12)[3:9])
    return seed

def encrypt(message):
    key = b''
    for i in range(8):
        key += (get_random_number() % (2 ** 16)).to_bytes(2, 'big')
    cipher = AES.new(key, AES.MODE_ECB)
    ciphertext = cipher.encrypt(pad(message, AES.block_size))
    return ciphertext.hex()

print("Thanks for using our encryption service! To get the encrypted flag, type 1. To encrypt a message, type 2.")
while True:
    print("What would you like to do (1 - get encrypted flag, 2 - encrypt a message)?")
    user_input = int(input())
    if(user_input == 1):
        break

    print("What is your message?")
    message = input()
    print("Here is your encrypted message:", encrypt(message.encode()))


flag = open('/src/flag.txt', 'r').read();
print("Here is the encrypted flag:", encrypt(flag.encode()))
```

there are some issues with this.  
First the `get_random_number` function is not random at all. If we know the seed we can determine what the next random number will be.  
Next, our seed is a number between 0 and a million,small enough that a computer could brute force it.

The plan is to do a known plaintext attack where we know what we are encrypting and we bruteforce the seed.
Then we will use the seed to decrypt the encrypted flag

```python
from pwn import *
from Crypto.Cipher import AES
from Crypto.Util.Padding import pad
from Crypto.Random import random

io = remote('betta.utctf.live', 7356)
io.sendline(b'2')

# Step 1: obtain ciphertext from known plaintext (2 samples) and ciphertext for flag
# Step 2: bruteforce seed
# Step 3: decrypt flag

known = b'1'*16
io.sendline(known)
io.recvuntil(b'Here is your encrypted message: ')
encrypted = io.recvline()[:-1]
log.info(f'Encrypted plaintext: {encrypted}')

io.sendline(b'2')
io.sendline(known)
io.recvuntil(b'Here is your encrypted message: ')
encrypted2 = io.recvline()[:-1]
log.info(f'Encrypted plaintext: {encrypted2}')

encrypted_val = hex(int(encrypted,16))

io.sendline(b'1')
io.recvuntil(b'flag: ')
flag_en = io.recvline()[:-1]
log.info(f"Encrypted flag: {flag_en}")
assert len(flag_en) == len('6f460ef0a03a7fd56de32928266bc11c6b6840f46cc78a9e34a70b2f426a5f29f9f87775028f1950638b58b84a25601d')

# now we will bruteforce to determine what seed was used to encrypt our known plaintext
seed = 0
def get_random_number():
    global seed 
    seed = int(str(seed * seed).zfill(12)[3:9])
    return seed

def encrypt(message):
    key = b''
    for i in range(8):
        key += (get_random_number() % (2 ** 16)).to_bytes(2, 'big')
    cipher = AES.new(key, AES.MODE_ECB)
    ciphertext = cipher.encrypt(pad(message, AES.block_size))
    return ciphertext.hex()

# start the bruteforce
for i in range(10 ** 6):
    attempt = i
    seed = i
    attempt_en = encrypt(known)
    #print(attempt_en, encrypted_val)
    if int(attempt_en,16) == int(encrypted_val,16):
        break

log.success(f"Found seed: {attempt}")
#since we know the starting seed, decrypt the flag
seed = attempt
log.info(f'Match 1: {int(encrypted,16) == int(encrypt(known),16)}')
log.info(f'Match 2: {int(encrypted2,16) == int(encrypt(known),16)}')

# now flag
key = b''
for i in range(8):
    key += (get_random_number() % (2 ** 16)).to_bytes(2, 'big')
cipher = AES.new(key, AES.MODE_ECB)
flag_en = int(flag_en,16)
flag_en = flag_en.to_bytes(48, byteorder='big')
flag = cipher.decrypt(flag_en)
print(flag)
```

Thats it!
utflag{deep_seated_and_recurring_self-doubts}
