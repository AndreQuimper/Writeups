# *NIX Philosophies (PWN)  
The description was `Let's see how much you know about linux` or something along those lines.  
Let's look at the file we were provided:  
![image](https://github.com/user-attachments/assets/89581531-ff64-49e4-9029-b8ea2b0adfbd)  

Let's see what happens when we run it:   
![image](https://github.com/user-attachments/assets/80ecdfa0-4ae0-423d-b7da-86da63dbe187)  
Ok...  
Maybe there is a vulnerability on the input handling? Or there is a specific value that we need to write?  
Let's look at the binary in Ghidra  
```c

undefined8 main(void)

{
  bool bVar1;
  char cVar2;
  int iVar3;
  allocator *paVar4;
  char *string_iter;
  ulong uVar5;
  basic_ostream *pbVar6;
  long in_FS_OFFSET;
  int sum;
  int ctr;
  undefined8 local_288;
  undefined8 local_280;
  basic_string<> *local_278;
  undefined8 *local_270;
  basic_string buf [32];
  basic_string<> local_248 [535];
  allocator local_31;
  long local_30;
  
  local_30 = *(long *)(in_FS_OFFSET + 0x28);
  std::__cxx11::basic_string<>::basic_string();
                    /* try { // try from 0010128b to 001012dc has its CatchHandler @ 001015c2 */
  std::operator<<((basic_ostream *)std::cout,"Tell me what you know about *nix philosophies: ");
  std::operator>>((basic_istream *)std::cin,buf);
  sum = 0;
  ctr = 1;
  while( true ) {
    uVar5 = std::__cxx11::basic_string<>::size();
    if (uVar5 <= (ulong)(long)ctr) break;
    paVar4 = (allocator *)std::__cxx11::basic_string<>::operator[]((ulong)buf);
    local_31 = *paVar4;
    local_270 = &local_280;
                    /* try { // try from 0010131d to 00101321 has its CatchHandler @ 00101599 */
    std::__cxx11::basic_string<>::basic_string((initializer_list)local_248,&local_31);
    std::__new_allocator<char>::~__new_allocator((__new_allocator<char> *)&local_280);
    local_278 = local_248;
    local_288 = std::__cxx11::basic_string<>::begin();
    local_280 = std::__cxx11::basic_string<>::end();
    while( true ) {
      bVar1 = __gnu_cxx::operator!=((__normal_iterator *)&local_288,(__normal_iterator *)&local_280)
      ;
      if (!bVar1) break;
      string_iter = (char *)__gnu_cxx::__normal_iterator<>::operator*
                                      ((__normal_iterator<> *)&local_288);
      sum = sum + *string_iter;
      __gnu_cxx::__normal_iterator<>::operator++((__normal_iterator<> *)&local_288);
    }
    std::__cxx11::basic_string<>::~basic_string(local_248);
    ctr = ctr + 1;
  }
                    /* try { // try from 00101417 to 00101460 has its CatchHandler @ 001015c2 */
  read(sum + -0x643,::buf,0x20);
  iVar3 = strcmp("make every program a filter\n",::buf);
  if (iVar3 == 0) {
    std::basic_ifstream<>::basic_ifstream((char *)local_248,0x102055);
                    /* try { // try from 00101471 to 00101535 has its CatchHandler @ 001015ae */
    cVar2 = std::basic_ios<>::good();
    if (cVar2 == '\0') {
      pbVar6 = (basic_ostream *)
               std::basic_ostream<>::operator<<((basic_ostream<> *)std::cout,std::endl<>);
      pbVar6 = std::operator<<(pbVar6,"flag.txt: No such file or directory");
      std::basic_ostream<>::operator<<((basic_ostream<> *)pbVar6,std::endl<>);
      pbVar6 = std::operator<<((basic_ostream *)std::cout,
                               "If you\'re running this locally, then running it on the remote serve r should give you the flag!"
                              );
      std::basic_ostream<>::operator<<((basic_ostream<> *)pbVar6,std::endl<>);
    }
    else {
      pbVar6 = (basic_ostream *)
               std::basic_ostream<>::operator<<((basic_ostream<> *)std::cout,std::endl<>);
      pbVar6 = std::operator<<(pbVar6,"Welcome to pwning ^_^");
      std::basic_ostream<>::operator<<((basic_ostream<> *)pbVar6,std::endl<>);
      system("/bin/cat flag.txt");
    }
    std::basic_ifstream<>::~basic_ifstream((basic_ifstream<> *)local_248);
  }
  else {
                    /* try { // try from 0010155b to 00101571 has its CatchHandler @ 001015c2 */
    pbVar6 = std::operator<<((basic_ostream *)std::cout,"You still lack knowledge about *nix sorry")
    ;
    std::basic_ostream<>::operator<<((basic_ostream<> *)pbVar6,std::endl<>);
  }
  std::__cxx11::basic_string<>::~basic_string((basic_string<> *)buf);
  if (local_30 != *(long *)(in_FS_OFFSET + 0x28)) {
                    /* WARNING: Subroutine does not return */
    __stack_chk_fail();
  }
  return 0;
}
```

Ok, I know what you're thinking: `Ew, c++, I don't want to look at this ever again` and I get it, but stay with me for a bit.  
So we are reading into a buffer, and then we enter a while loop. It might look complicated, but if we pay attention we might notice that all the program does is `Iterate over our input and sum up the value of all the bytes` (starting from index 1 for some reason)  
``` c
uVar5 = std::__cxx11::basic_string<>::size(); //set uVar5 = size
    if (uVar5 <= (ulong)(long)ctr) break; // if counter is smaller than size
    paVar4 = (allocator *)std::__cxx11::basic_string<>::operator[]((ulong)buf);
    local_31 = *paVar4;
    local_270 = &local_280;
                    /* try { // try from 0010131d to 00101321 has its CatchHandler @ 00101599 */
    std::__cxx11::basic_string<>::basic_string((initializer_list)local_248,&local_31);
    std::__new_allocator<char>::~__new_allocator((__new_allocator<char> *)&local_280);
    local_278 = local_248;
    local_288 = std::__cxx11::basic_string<>::begin();
    local_280 = std::__cxx11::basic_string<>::end();
    while( true ) {
      //while our start iterator not equal to our end iterator
      bVar1 = __gnu_cxx::operator!=((__normal_iterator *)&local_288,(__normal_iterator *)&local_280) 
      ;
      if (!bVar1) break;
      string_iter = (char *)__gnu_cxx::__normal_iterator<>::operator*
                                      ((__normal_iterator<> *)&local_288);
      sum = sum + *string_iter; //add value of current char to sum
     //increment iterator
      __gnu_cxx::__normal_iterator<>::operator++((__normal_iterator<> *)&local_288); 
    }
    std::__cxx11::basic_string<>::~basic_string(local_248);
    ctr = ctr + 1;
```

Ok Cool, what happens next?
```
read(sum + -0x643,::buf,0x20);
```
Uhhh `man read`
![image](https://github.com/user-attachments/assets/b6150f48-0bbc-4dca-8569-2746ba2867ba)  
Ah, so `sum + -0x643` is being used as the file descriptor from which to read into buf.  
Ideally we want this to be `0`, since that is the file descriptor for `stdin`.  
Ok so a sequence of characters that sum up to 0x643.  
I came up with `CC@@@@@@@@@@@@@@@@@@@@@@@@`  
Why? Well remember the first character is not read, then `C == 0x43` and `@ == 0x40` so it was really easy to calculate their sum.  
Ok we can now write to `::buf`.  
We can now easily notice that if 
`iVar3 = strcmp("make every program a filter\n",::buf);` returns 0, the program will print the flag.  

Done!  
![image](https://github.com/user-attachments/assets/5595f629-ad87-46a4-af4c-51f6bb72c2bd)



