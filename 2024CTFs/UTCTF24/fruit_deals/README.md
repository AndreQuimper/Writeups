# Fruit Deals (REV)  

the challenge has the following description
```
I found a excel sheet with some great deals thanks to some random guy on the internet! Who doesn't trust random people off the internet, especially from email

The flag is the file name that was attempted to be downloaded, wrapped in utflag{} Note: the file imitates malicious behavior. its not malicious, but it will be flagged by AV. you probably shouldn't just run it though.
```

Ok, so we see that we are given an excel file `deals.xlsm` which is acting maliciously.  
We can try to use `anyrun.com` to analyze this as if it was malware.

I looked up the hash of the file and it looked like other peple had already submitted `malware` samples:  
![image](https://github.com/AndreQuimper/Writeups/assets/96965806/a9404af6-ec8a-441b-a0e7-d70763384e03)  

I tried the version that said that it had detected malicious activity and analyzed its behavior.  
![image](https://github.com/AndreQuimper/Writeups/assets/96965806/23ce4309-2087-4215-8cbf-4fc8904cbe8e)  

I saw there was a powershell script running so I tried to analyze that closer.  
![image](https://github.com/AndreQuimper/Writeups/assets/96965806/2c5ab452-5db9-4c92-a69c-58dcf7111a83)  

from this command we can get that we are trying to donwload the file `banANA-Hakrz09182afd4.exe`.  

Thus the flag is utflag{banANA-Hakrz09182afd4.exe}!
