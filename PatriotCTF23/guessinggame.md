The only function of interest in this binary is check()

![image](https://github.com/AndreQuimper/Writeups/assets/96965806/8e61489a-0826-424e-9b40-5ff16ef3e28f)

Here we can see that they use the unsafe function gets()
We can leverage this by overflowing `local_c` to get the binary to execute the OutputFlag() function

solve script:
```bash
python -c 'print(b"a"*301)' | ./guessinggame
```
