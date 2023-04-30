We have an executable

![image](https://user-images.githubusercontent.com/96965806/235337198-321816e5-7451-4c8f-b339-606d5e7b715e.png)

Playing with the binary shows us that by "winning the race", we open flag.txt

![image](https://user-images.githubusercontent.com/96965806/235337222-3cc23ffe-6c35-4b49-ac68-f50cd242ffc0.png)

I made a sample flag.txt containing 'AAAABBBBCCCC'

Analyzing the binary shows a format string vulnerability on the printf that shows up when you win the race. 
Also the contents of the flag start at the 12th parameter to printf

![image](https://user-images.githubusercontent.com/96965806/235337269-9e95fd3b-2092-4e6d-bf03-24663dfa8376.png)

We may use the exact same technique on the remote target to extract the flag
