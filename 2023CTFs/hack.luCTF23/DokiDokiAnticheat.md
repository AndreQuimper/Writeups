# Doki Doki Anticheat

We have the following task:  
![image](https://github.com/AndreQuimper/Writeups/assets/96965806/d104d115-4a16-4da8-b34e-462bdae7c413)


So the first thing I tried is just loading the files into the game  
![image](https://github.com/AndreQuimper/Writeups/assets/96965806/c5ae4c42-efe4-47ae-a850-6594b88ee368)

I did some research and found out that this game apparently has a security measure to prevent players from loading savefiles from an act that is different of the one in their 'persistent' save.  
The saves both have an 'anticheat' parameter, and if they don't match you get detected by the anticheat. My objective is to find that data in both savefiles and change it so that it is the same in both saves.  
  
I used binwalk to look at the savefile and the persistent file.  
![image](https://github.com/AndreQuimper/Writeups/assets/96965806/5bd7f97c-76e5-4785-81b7-d79de64ebdf5)  
![image](https://github.com/AndreQuimper/Writeups/assets/96965806/3dbfe89b-2e39-4893-8b71-7458a6e2ab40)  

We can use `binwalk` to extract the files and `zlib-flate` to uncompress data. I then explored the raw hexdumps to try to identify where the anticheat byte was in both saves.  
After some testing I was able to identify the 'anticheat' bytes in both files.  
![image](https://github.com/AndreQuimper/Writeups/assets/96965806/708927d1-5d87-47b5-8a57-e611b46d4ee4)  
![image](https://github.com/AndreQuimper/Writeups/assets/96965806/01b0e51f-0d68-41fb-b89d-44add080cfed)  

Since it doesn't really matter which one we modify I decided to change the persistent file to match the anticheat bytes in the savefile.
```python
f = open('persistent.test', 'rb+')
f.seek(f.find(b'\x39\x05'))
f.write(b'\xa4\x01)
```

We can then compress the persistent file using `zlib-flate` again, and load both the original savefile and the modified persistent file into the game.
![image](https://github.com/AndreQuimper/Writeups/assets/96965806/96014c2d-d86b-493c-8f57-a708d04b261b)  

And just like that we have avoided Anticheat.







