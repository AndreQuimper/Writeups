# catch-me-if-you-can (rev 6 solves)
`I give you this flag generator, but it's too slow. You need to speed up to catch me =D`
## Reversing the Compiled Python

We are given compiled python in a `chal.pyc` file.  
The `file` command tells us the following.  
```bash
file chal.pyc 
chal.pyc: Byte-compiled Python module for CPython 3.10, timestamp-based, .py timestamp: Mon Apr  8 12:30:35 2024 UTC, .py size: 6257 bytes
```
If we try to run the compiled python, we will face errors if we don't have Python 3.10. We can work around that using docker.  

```bash
sudo docker run -v /home/kali/Documents/CTF/bo1lers24/catch-me:/mount python:3.10 python3 /mount/chal.pyc
You're Lucky
Here is your flag: bctf{we1rd_pyth
```

The code freezes very quickly, so we will have to find another way to execute this program.  
I found [xdis](https://github.com/rocky/python-xdis), a tool to disassemble python bytecode.

Using the tool I got Python Bytecode, which I had never seen before.  
```
# pydisasm version 6.1.0
# Python bytecode 3.10.0 (3439)
# Disassembled from Python 3.11.8 (main, Feb  7 2024, 21:52:08) [GCC 13.2.0]
# Timestamp in code: 1712579435 (2024-04-08 08:30:35)
# Source code size mod 2**32: 6257 bytes
# Method Name:       <module>
# Filename:          chal_obfuscated.py
# Argument count:    0
# Position-only argument count: 0
# Keyword-only arguments: 0
# Number of locals:  0
# Stack size:        12
# Flags:             0x00000040 (NOFREE)
# First Line:        1
# Constants:
#    0: 0
#    1: None
#    2: 8
#    3: 1
#    4: 2
#    5: b'OwO_QuQ_'
#    6: 'Oops! something went wrong, run again'
#    7: "You're Lucky"
#    8: 'Here is your flag: '
#    9: ''
#   10: ('end',)
#   11: 96
#   12: 98
#   13: 198
#   14: 31
#   15: 68
#   16: 160
#   17: 180
#   18: 165
#   19: 115
#   20: 203
#   21: 172
#   22: 177
#   23: 60
#   24: 17
#   25: 166
#   26: 20
#   27: 108
#   28: 196
#   29: 25
#   30: 255
#   31: 167
#   32: 132
#   33: 122
#   34: 127
#   35: 106
#   36: 195
#   37: 208
#   38: 19
#   39: 70
#   40: 38
#   41: 151
#   42: 55
#   43: 71
#   44: 11
#   45: 158
#   46: 63
#   47: 204
#   48: 163
#   49: 211
#   50: 27
#   51: 73
#   52: 233
#   53: 59
#   54: 50
#   55: 3
#   56: (1, 2, 3)
#   57: 1000000007
#   58: 5
# Names:
#    0: os
#    1: sys
#    2: random
#    3: urandom
#    4: print
#    5: var1
#    6: var2
#    7: var3
#    8: list_a
#    9: list_c
#   10: list_b
#   11: append
#   12: combined_list
#   13: range
#   14: i_var
#   15: var9
#   16: j_var
#   17: seed
#   18: ZeroDivisionError
#   19: var11
#   20: var12
#   21: var13
#   22: var14
#   23: var15
#   24: chr
#   25: stdout
#   26: flush
  1:           0 LOAD_CONST           (0)
               2 LOAD_CONST           (None)
               4 IMPORT_NAME          (os) ; TOS = import_module(os)
               6 STORE_NAME           (os) ; os = import_module(os)

  1:           8 LOAD_CONST           (0)
              10 LOAD_CONST           (None)
              12 IMPORT_NAME          (sys) ; TOS = import_module(sys)
              14 STORE_NAME           (sys) ; sys = import_module(sys)

  2:          16 LOAD_CONST           (0)
              18 LOAD_CONST           (None)
              20 IMPORT_NAME          (random) ; TOS = import_module(random)
              22 STORE_NAME           (random) ; random = import_module(random)

  3:          24 LOAD_NAME            (os)
              26 LOAD_METHOD          (urandom)
              28 LOAD_CONST           (8)
              30 CALL_METHOD          (1 positional argument)
              32 LOAD_CONST           (1)
              34 BUILD_TUPLE          () ; TOS = (1 positional argument, 1)

  5:          36 DUP_TOP
              38 MATCH_SEQUENCE
              40 POP_JUMP_IF_FALSE    (to 72)
              42 GET_LEN
              44 LOAD_CONST           (2)
              46 COMPARE_OP           (==) ; TOS = ... == 2
              48 POP_JUMP_IF_FALSE    (to 72)
              50 UNPACK_SEQUENCE      2
              52 LOAD_CONST           (b'OwO_QuQ_')
              54 COMPARE_OP           (==) ; TOS = ... == b'OwO_QuQ_'
              56 POP_JUMP_IF_FALSE    (to 72)
              58 POP_TOP
              60 POP_TOP

  6:          62 LOAD_NAME            (print)
              64 LOAD_CONST           ("Oops! something went wrong, run again")
              66 CALL_FUNCTION        (1 positional argument) ; TOS = print("Oops! something went wrong, run again")
              68 POP_TOP
              70 JUMP_FORWARD         (to 116)

  7:     >>   72 POP_TOP

  6:          74 MATCH_SEQUENCE
              76 POP_JUMP_IF_FALSE    (to 114)
              78 GET_LEN
              80 LOAD_CONST           (2)
              82 COMPARE_OP           (==) ; TOS = ... == 2
              84 POP_JUMP_IF_FALSE    (to 114)
              86 UNPACK_SEQUENCE      2
              88 STORE_NAME           (var1)
              90 STORE_NAME           (var2)

  8:          92 LOAD_NAME            (print)
              94 LOAD_CONST           ("You're Lucky")
              96 CALL_FUNCTION        (1 positional argument) ; TOS = print("You're Lucky")
              98 POP_TOP

  9:         100 LOAD_NAME            (print)
             102 LOAD_CONST           ("Here is your flag: ")
             104 LOAD_CONST           ("")
             106 LOAD_CONST           (('end',))
             108 CALL_FUNCTION_KW     (2 total positional and keyword args) ; TOS = print("Here is your flag: ", end="")
             110 POP_TOP
             112 JUMP_FORWARD         (to 116)

 10:     >>  114 POP_TOP

  8:     >>  116 BUILD_LIST           () ; TOS = []
             118 STORE_NAME           (var3) ; var3 = []

 12:         120 BUILD_LIST           () ; TOS = []
             122 STORE_NAME           (list_a) ; list_a = []

 14:         124 BUILD_LIST           () ; TOS = []
             126 STORE_NAME           (list_c) ; list_c = []

 15:         128 BUILD_LIST           () ; TOS = []
             130 STORE_NAME           (list_b) ; list_b = []

 16:         132 LOAD_NAME            (list_a)
             134 LOAD_METHOD          (append)
             136 LOAD_CONST           (96)
             138 CALL_METHOD          (1 positional argument)
             140 POP_TOP

 18:         142 LOAD_NAME            (list_a)
             144 LOAD_METHOD          (append)
             146 LOAD_CONST           (98)
             148 CALL_METHOD          (1 positional argument)
             150 POP_TOP

 19:         152 LOAD_NAME            (list_b)
             154 LOAD_METHOD          (append)
             156 LOAD_CONST           (198)
             158 CALL_METHOD          (1 positional argument)
             160 POP_TOP

 20:         162 LOAD_NAME            (list_b)
             164 LOAD_METHOD          (append)
             166 LOAD_CONST           (31)
             168 CALL_METHOD          (1 positional argument)
             170 POP_TOP

 21:         172 LOAD_NAME            (list_a)
             174 LOAD_METHOD          (append)
             176 LOAD_CONST           (68)
             178 CALL_METHOD          (1 positional argument)
             180 POP_TOP

 22:         182 LOAD_NAME            (list_a)
             184 LOAD_METHOD          (append)
             186 LOAD_CONST           (160)
             188 CALL_METHOD          (1 positional argument)
             190 POP_TOP

 23:         192 LOAD_NAME            (list_c)
             194 LOAD_METHOD          (append)
             196 LOAD_CONST           (180)
             198 CALL_METHOD          (1 positional argument)
             200 POP_TOP

 24:         202 LOAD_NAME            (list_c)
             204 LOAD_METHOD          (append)
             206 LOAD_CONST           (165)
             208 CALL_METHOD          (1 positional argument)
             210 POP_TOP

 25:         212 LOAD_NAME            (list_c)
             214 LOAD_METHOD          (append)
             216 LOAD_CONST           (115)
             218 CALL_METHOD          (1 positional argument)
             220 POP_TOP

 26:         222 LOAD_NAME            (list_c)
             224 LOAD_METHOD          (append)
             226 LOAD_CONST           (203)
             228 CALL_METHOD          (1 positional argument)
             230 POP_TOP

 27:         232 LOAD_NAME            (list_a)
             234 LOAD_METHOD          (append)
             236 LOAD_CONST           (172)
             238 CALL_METHOD          (1 positional argument)
             240 POP_TOP

 28:         242 LOAD_NAME            (list_c)
             244 LOAD_METHOD          (append)
             246 LOAD_CONST           (177)
             248 CALL_METHOD          (1 positional argument)
             250 POP_TOP

 29:         252 LOAD_NAME            (list_b)
             254 LOAD_METHOD          (append)
             256 LOAD_CONST           (60)
             258 CALL_METHOD          (1 positional argument)
             260 POP_TOP

 30:         262 LOAD_NAME            (list_a)
             264 LOAD_METHOD          (append)
             266 LOAD_CONST           (115)
             268 CALL_METHOD          (1 positional argument)
             270 POP_TOP

 31:         272 LOAD_NAME            (list_c)
             274 LOAD_METHOD          (append)
             276 LOAD_CONST           (17)
             278 CALL_METHOD          (1 positional argument)
             280 POP_TOP

 32:         282 LOAD_NAME            (list_c)
             284 LOAD_METHOD          (append)
             286 LOAD_CONST           (166)
             288 CALL_METHOD          (1 positional argument)
             290 POP_TOP

 33:         292 LOAD_NAME            (list_a)
             294 LOAD_METHOD          (append)
             296 LOAD_CONST           (20)
             298 CALL_METHOD          (1 positional argument)
             300 POP_TOP

 34:         302 LOAD_NAME            (list_a)
             304 LOAD_METHOD          (append)
             306 LOAD_CONST           (108)
             308 CALL_METHOD          (1 positional argument)
             310 POP_TOP

 35:         312 LOAD_NAME            (list_c)
             314 LOAD_METHOD          (append)
             316 LOAD_CONST           (196)
             318 CALL_METHOD          (1 positional argument)
             320 POP_TOP

 36:         322 LOAD_NAME            (list_a)
             324 LOAD_METHOD          (append)
             326 LOAD_CONST           (25)
             328 CALL_METHOD          (1 positional argument)
             330 POP_TOP

 37:         332 LOAD_NAME            (list_c)
             334 LOAD_METHOD          (append)
             336 LOAD_CONST           (255)
             338 CALL_METHOD          (1 positional argument)
             340 POP_TOP

 38:         342 LOAD_NAME            (list_b)
             344 LOAD_METHOD          (append)
             346 LOAD_CONST           (167)
             348 CALL_METHOD          (1 positional argument)
             350 POP_TOP

 39:         352 LOAD_NAME            (list_b)
             354 LOAD_METHOD          (append)
             356 LOAD_CONST           (17)
             358 CALL_METHOD          (1 positional argument)
             360 POP_TOP

 40:         362 LOAD_NAME            (list_b)
             364 LOAD_METHOD          (append)
             366 LOAD_CONST           (1)
             368 CALL_METHOD          (1 positional argument)
             370 POP_TOP

 41:         372 LOAD_NAME            (list_b)
             374 LOAD_METHOD          (append)
             376 LOAD_CONST           (132)
             378 CALL_METHOD          (1 positional argument)
             380 POP_TOP

 42:         382 LOAD_NAME            (list_a)
             384 LOAD_METHOD          (append)
             386 LOAD_CONST           (122)
             388 CALL_METHOD          (1 positional argument)
             390 POP_TOP

 43:         392 LOAD_NAME            (list_c)
             394 LOAD_METHOD          (append)
             396 LOAD_CONST           (127)
             398 CALL_METHOD          (1 positional argument)
             400 POP_TOP

 44:         402 LOAD_NAME            (list_b)
             404 LOAD_METHOD          (append)
             406 LOAD_CONST           (106)
             408 CALL_METHOD          (1 positional argument)
             410 POP_TOP

 45:         412 LOAD_NAME            (list_b)
             414 LOAD_METHOD          (append)
             416 LOAD_CONST           (195)
             418 CALL_METHOD          (1 positional argument)
             420 POP_TOP

 46:         422 LOAD_NAME            (list_a)
             424 LOAD_METHOD          (append)
             426 LOAD_CONST           (208)
             428 CALL_METHOD          (1 positional argument)
             430 POP_TOP

 47:         432 LOAD_NAME            (list_b)
             434 LOAD_METHOD          (append)
             436 LOAD_CONST           (19)
             438 CALL_METHOD          (1 positional argument)
             440 POP_TOP

 48:         442 LOAD_NAME            (list_c)
             444 LOAD_METHOD          (append)
             446 LOAD_CONST           (70)
             448 CALL_METHOD          (1 positional argument)
             450 POP_TOP

 49:         452 LOAD_NAME            (list_b)
             454 LOAD_METHOD          (append)
             456 LOAD_CONST           (38)
             458 CALL_METHOD          (1 positional argument)
             460 POP_TOP

 50:         462 LOAD_NAME            (list_b)
             464 LOAD_METHOD          (append)
             466 LOAD_CONST           (151)
             468 CALL_METHOD          (1 positional argument)
             470 POP_TOP

 51:         472 LOAD_NAME            (list_c)
             474 LOAD_METHOD          (append)
             476 LOAD_CONST           (172)
             478 CALL_METHOD          (1 positional argument)
             480 POP_TOP

 52:         482 LOAD_NAME            (list_c)
             484 LOAD_METHOD          (append)
             486 LOAD_CONST           (55)
             488 CALL_METHOD          (1 positional argument)
             490 POP_TOP

 53:         492 LOAD_NAME            (list_a)
             494 LOAD_METHOD          (append)
             496 LOAD_CONST           (71)
             498 CALL_METHOD          (1 positional argument)
             500 POP_TOP

 54:         502 LOAD_NAME            (list_c)
             504 LOAD_METHOD          (append)
             506 LOAD_CONST           (11)
             508 CALL_METHOD          (1 positional argument)
             510 POP_TOP

 55:         512 LOAD_NAME            (list_a)
             514 LOAD_METHOD          (append)
             516 LOAD_CONST           (158)
             518 CALL_METHOD          (1 positional argument)
             520 POP_TOP

 56:         522 LOAD_NAME            (list_a)
             524 LOAD_METHOD          (append)
             526 LOAD_CONST           (63)
             528 CALL_METHOD          (1 positional argument)
             530 POP_TOP

 57:         532 LOAD_NAME            (list_c)
             534 LOAD_METHOD          (append)
             536 LOAD_CONST           (204)
             538 CALL_METHOD          (1 positional argument)
             540 POP_TOP

 58:         542 LOAD_NAME            (list_c)
             544 LOAD_METHOD          (append)
             546 LOAD_CONST           (20)
             548 CALL_METHOD          (1 positional argument)
             550 POP_TOP

 59:         552 LOAD_NAME            (list_b)
             554 LOAD_METHOD          (append)
             556 LOAD_CONST           (203)
             558 CALL_METHOD          (1 positional argument)
             560 POP_TOP

 60:         562 LOAD_NAME            (list_b)
             564 LOAD_METHOD          (append)
             566 LOAD_CONST           (163)
             568 CALL_METHOD          (1 positional argument)
             570 POP_TOP

 61:         572 LOAD_NAME            (list_b)
             574 LOAD_METHOD          (append)
             576 LOAD_CONST           (211)
             578 CALL_METHOD          (1 positional argument)
             580 POP_TOP

 62:         582 LOAD_NAME            (list_b)
             584 LOAD_METHOD          (append)
             586 LOAD_CONST           (27)
             588 CALL_METHOD          (1 positional argument)
             590 POP_TOP

 63:         592 LOAD_NAME            (list_b)
             594 LOAD_METHOD          (append)
             596 LOAD_CONST           (73)
             598 CALL_METHOD          (1 positional argument)
             600 POP_TOP

 64:         602 LOAD_NAME            (list_a)
             604 LOAD_METHOD          (append)
             606 LOAD_CONST           (233)
             608 CALL_METHOD          (1 positional argument)
             610 POP_TOP

 65:         612 LOAD_NAME            (list_b)
             614 LOAD_METHOD          (append)
             616 LOAD_CONST           (98)
             618 CALL_METHOD          (1 positional argument)
             620 POP_TOP

 66:         622 LOAD_NAME            (list_a)
             624 LOAD_METHOD          (append)
             626 LOAD_CONST           (59)
             628 CALL_METHOD          (1 positional argument)
             630 POP_TOP

 67:         632 LOAD_NAME            (list_a)
             634 LOAD_NAME            (list_c)
             636 BINARY_ADD           TOS = list_a + list_c
             638 LOAD_NAME            (list_b)
             640 BINARY_ADD           TOS = list_a + list_c + list_b
             642 STORE_NAME           (combined_list) ; combined_list = list_a + list_c + list_b

 69:         644 LOAD_NAME            (range)
             646 LOAD_CONST           (0)
             648 LOAD_CONST           (50)
             650 CALL_FUNCTION        (2 positional arguments) ; TOS = range(0, 50)
             652 GET_ITER
         >>  654 EXTENDED_ARG         (256)
             656 FOR_ITER             (to 1424)
             658 STORE_NAME           (i_var)

 72:         660 LOAD_CONST           (3)
             662 STORE_NAME           (var9) ; var9 = 3

 73:         664 SETUP_FINALLY        (to 1086)
             666 SETUP_FINALLY        (to 716)

 74:         668 LOAD_NAME            (range)
             670 LOAD_CONST           (25)
             672 LOAD_CONST           (50)
             674 CALL_FUNCTION        (2 positional arguments) ; TOS = range(25, 50)
             676 GET_ITER
         >>  678 FOR_ITER             (to 704)
             680 STORE_NAME           (j_var)

 75:         682 LOAD_NAME            (random)
             684 LOAD_METHOD          (seed)
             686 LOAD_NAME            (j_var)
             688 LOAD_NAME            (j_var)
             690 LOAD_NAME            (i_var)
             692 BINARY_SUBTRACT      TOS = j_var - i_var
             694 BINARY_TRUE_DIVIDE   TOS = j_var / (j_var - i_var)
             696 CALL_METHOD          (1 positional argument)
             698 POP_TOP
             700 EXTENDED_ARG         (256)
             702 JUMP_ABSOLUTE        (to 678)

 76:     >>  704 LOAD_NAME            (var9)
             706 LOAD_NAME            (i_var)
             708 BINARY_POWER         TOS = var9 ** i_var
             710 STORE_NAME           (var2) ; var2 = var9 ** i_var
             712 POP_BLOCK
             714 JUMP_FORWARD         (to 744)

 77:     >>  716 DUP_TOP
             718 LOAD_NAME            (ZeroDivisionError)
             720 EXTENDED_ARG         (256)
             722 JUMP_IF_NOT_EXC_MATCH (to 742)
             724 POP_TOP
             726 POP_TOP
             728 POP_TOP

 78:         730 LOAD_NAME            (var2)
             732 LOAD_NAME            (var9)
             734 BINARY_POWER         TOS = var2 ** var9
             736 STORE_NAME           (var2) ; var2 = var2 ** var9
             738 POP_EXCEPT
             740 JUMP_FORWARD         (to 744)

 79:     >>  742 RERAISE              0

 78:     >>  744 POP_BLOCK

-50:         746 LOAD_NAME            (var9)
             748 LOAD_NAME            (i_var)
             750 BINARY_POWER         TOS = var9 ** i_var
             752 STORE_NAME           (var2) ; var2 = var9 ** i_var

-47:         754 LOAD_CONST           ((1, 2, 3))
             756 UNPACK_SEQUENCE      3
             758 STORE_NAME           (var11)
             760 STORE_NAME           (var12)
             762 STORE_NAME           (var13)

-46:         764 LOAD_CONST           (1000000007)
             766 STORE_NAME           (var14) ; var14 = 1000000007

-45:         768 LOAD_NAME            (range)
             770 LOAD_NAME            (var2)
             772 CALL_FUNCTION        (1 positional argument) ; TOS = range(var2)
             774 GET_ITER
         >>  776 FOR_ITER             (to 1040)
             778 STORE_NAME           (j_var)

-43:         780 LOAD_NAME            (j_var)
             782 LOAD_CONST           (3)
             784 BINARY_MODULO        TOS = j_var %% 3
             786 LOAD_NAME            (j_var)
             788 LOAD_CONST           (5)
             790 BINARY_MODULO        TOS = j_var %% 5
             792 BUILD_TUPLE          () ; TOS = (j_var %% 3, j_var %% 5)

-42:         794 DUP_TOP
             796 MATCH_SEQUENCE
             798 EXTENDED_ARG         (256)
             800 POP_JUMP_IF_FALSE    (to 854)
             802 GET_LEN
             804 LOAD_CONST           (2)
             806 COMPARE_OP           (==) ; TOS = ... == 2
             808 EXTENDED_ARG         (256)
             810 POP_JUMP_IF_FALSE    (to 854)
             812 UNPACK_SEQUENCE      2
             814 LOAD_CONST           (0)
             816 COMPARE_OP           (==) ; TOS = ... == 0
             818 EXTENDED_ARG         (256)
             820 POP_JUMP_IF_FALSE    (to 854)
             822 LOAD_CONST           (0)
             824 COMPARE_OP           (==) ; TOS = ... == 0
             826 EXTENDED_ARG         (256)
             828 POP_JUMP_IF_FALSE    (to 856)
             830 POP_TOP

-41:         832 LOAD_NAME            (var12)
             834 LOAD_NAME            (var13)
             836 LOAD_NAME            (var11)
             838 LOAD_NAME            (var14)
             840 BINARY_MODULO        TOS = var11 %% var14
             842 ROT_THREE
             844 ROT_TWO
             846 STORE_NAME           (var11)
             848 STORE_NAME           (var12)
             850 STORE_NAME           (var13)
             852 JUMP_FORWARD         (to 1036)

-40:     >>  854 POP_TOP

-41:     >>  856 DUP_TOP
             858 MATCH_SEQUENCE
             860 EXTENDED_ARG         (256)
             862 POP_JUMP_IF_FALSE    (to 918)
             864 GET_LEN
             866 LOAD_CONST           (2)
             868 COMPARE_OP           (==) ; TOS = ... == 2
             870 EXTENDED_ARG         (256)
             872 POP_JUMP_IF_FALSE    (to 918)
             874 UNPACK_SEQUENCE      2
             876 LOAD_CONST           (0)
             878 COMPARE_OP           (==) ; TOS = ... == 0
             880 EXTENDED_ARG         (256)
             882 POP_JUMP_IF_FALSE    (to 918)
             884 POP_TOP
             886 POP_TOP

-39:         888 LOAD_NAME            (var12)
             890 LOAD_NAME            (var13)
             892 LOAD_NAME            (var11)
             894 LOAD_NAME            (var12)
             896 BINARY_ADD           TOS = var11 + var12
             898 LOAD_NAME            (var13)
             900 BINARY_ADD           TOS = var11 + var12 + var13
             902 LOAD_NAME            (var14)
             904 BINARY_MODULO        TOS = var11 + var12 + var13 %% var14
             906 ROT_THREE
             908 ROT_TWO
             910 STORE_NAME           (var11)
             912 STORE_NAME           (var12)
             914 STORE_NAME           (var13)
             916 JUMP_FORWARD         (to 1036)

-38:     >>  918 POP_TOP

-39:         920 DUP_TOP
             922 MATCH_SEQUENCE
             924 EXTENDED_ARG         (256)
             926 POP_JUMP_IF_FALSE    (to 978)
             928 GET_LEN
             930 LOAD_CONST           (2)
             932 COMPARE_OP           (==) ; TOS = ... == 2
             934 EXTENDED_ARG         (256)
             936 POP_JUMP_IF_FALSE    (to 978)
             938 UNPACK_SEQUENCE      2
             940 LOAD_CONST           (1)
             942 COMPARE_OP           (==) ; TOS = ... == 1
             944 EXTENDED_ARG         (256)
             946 POP_JUMP_IF_FALSE    (to 978)
             948 POP_TOP
             950 POP_TOP

-37:         952 LOAD_NAME            (var12)
             954 LOAD_NAME            (var13)
             956 LOAD_NAME            (var11)
             958 LOAD_NAME            (var12)
             960 BINARY_ADD           TOS = var11 + var12
             962 LOAD_NAME            (var14)
             964 BINARY_MODULO        TOS = var11 + var12 %% var14
             966 ROT_THREE
             968 ROT_TWO
             970 STORE_NAME           (var11)
             972 STORE_NAME           (var12)
             974 STORE_NAME           (var13)
             976 JUMP_FORWARD         (to 1036)

-36:     >>  978 POP_TOP

-37:         980 MATCH_SEQUENCE
             982 EXTENDED_ARG         (512)
             984 POP_JUMP_IF_FALSE    (to 1034)
             986 GET_LEN
             988 LOAD_CONST           (2)
             990 COMPARE_OP           (==) ; TOS = ... == 2
             992 EXTENDED_ARG         (512)
             994 POP_JUMP_IF_FALSE    (to 1034)
             996 UNPACK_SEQUENCE      2
             998 LOAD_CONST           (2)
            1000 COMPARE_OP           (==) ; TOS = ... == 2
            1002 EXTENDED_ARG         (512)
            1004 POP_JUMP_IF_FALSE    (to 1034)
            1006 POP_TOP

-35:        1008 LOAD_NAME            (var12)
            1010 LOAD_NAME            (var13)
            1012 LOAD_NAME            (var11)
            1014 LOAD_NAME            (var13)
            1016 BINARY_ADD           TOS = var11 + var13
            1018 LOAD_NAME            (var14)
            1020 BINARY_MODULO        TOS = var11 + var13 %% var14
            1022 ROT_THREE
            1024 ROT_TWO
            1026 STORE_NAME           (var11)
            1028 STORE_NAME           (var12)
            1030 STORE_NAME           (var13)
            1032 JUMP_FORWARD         (to 1036)

-34:     >> 1034 POP_TOP

-35:     >> 1036 EXTENDED_ARG         (256)
            1038 JUMP_ABSOLUTE        (to 776)

-163:     >> 1040 LOAD_NAME            (combined_list)
            1042 LOAD_NAME            (i_var)
            1044 BINARY_SUBSCR        TOS = combined_list[i_var]
            1046 LOAD_NAME            (var11)
            1048 LOAD_CONST           (255)
            1050 BINARY_AND           TOS = var11 & 255
            1052 BINARY_XOR           TOS = combined_list[i_var] ^ (var11 & 255)
            1054 STORE_NAME           (var15) ; var15 = combined_list[i_var] ^ (var11 & 255)

-160:        1056 LOAD_NAME            (print)
            1058 LOAD_NAME            (chr)
            1060 LOAD_NAME            (var15)
            1062 CALL_FUNCTION        (1 positional argument) ; TOS = chr(var15)
            1064 LOAD_CONST           ("")
            1066 LOAD_CONST           (('end',))
            1068 CALL_FUNCTION_KW     (2 total positional and keyword args) ; TOS = print(chr(OwO_uwu_UVU_uVu_UWU_0W0...)
            1070 POP_TOP

-159:        1072 LOAD_NAME            (sys)
            1074 LOAD_ATTR            (stdout) ; TOS = stdout.sys
            1076 LOAD_METHOD          (flush)
            1078 CALL_METHOD          (0 positional arguments)
            1080 POP_TOP
            1082 EXTENDED_ARG         (256)
            1084 JUMP_ABSOLUTE        (to 654)

-158:     >> 1086 LOAD_NAME            (var9)
            1088 LOAD_NAME            (i_var)
            1090 BINARY_POWER         TOS = var9 ** i_var
            1092 STORE_NAME           (var2) ; var2 = var9 ** i_var

-175:        1094 LOAD_CONST           ((1, 2, 3))
            1096 UNPACK_SEQUENCE      3
            1098 STORE_NAME           (var11)
            1100 STORE_NAME           (var12)
            1102 STORE_NAME           (var13)

-174:        1104 LOAD_CONST           (1000000007)
            1106 STORE_NAME           (var14) ; var14 = 1000000007

-173:        1108 LOAD_NAME            (range)
            1110 LOAD_NAME            (var2)
            1112 CALL_FUNCTION        (1 positional argument) ; TOS = range(var2)
            1114 GET_ITER
         >> 1116 FOR_ITER             (to 1380)
            1118 STORE_NAME           (j_var)

-171:        1120 LOAD_NAME            (j_var)
            1122 LOAD_CONST           (3)
            1124 BINARY_MODULO        TOS = j_var %% 3
            1126 LOAD_NAME            (j_var)
            1128 LOAD_CONST           (5)
            1130 BINARY_MODULO        TOS = j_var %% 5
            1132 BUILD_TUPLE          () ; TOS = (j_var %% 3, j_var %% 5)

-170:        1134 DUP_TOP
            1136 MATCH_SEQUENCE
            1138 EXTENDED_ARG         (512)
            1140 POP_JUMP_IF_FALSE    (to 1194)
            1142 GET_LEN
            1144 LOAD_CONST           (2)
            1146 COMPARE_OP           (==) ; TOS = ... == 2
            1148 EXTENDED_ARG         (512)
            1150 POP_JUMP_IF_FALSE    (to 1194)
            1152 UNPACK_SEQUENCE      2
            1154 LOAD_CONST           (0)
            1156 COMPARE_OP           (==) ; TOS = ... == 0
            1158 EXTENDED_ARG         (512)
            1160 POP_JUMP_IF_FALSE    (to 1194)
            1162 LOAD_CONST           (0)
            1164 COMPARE_OP           (==) ; TOS = ... == 0
            1166 EXTENDED_ARG         (512)
            1168 POP_JUMP_IF_FALSE    (to 1196)
            1170 POP_TOP

-169:        1172 LOAD_NAME            (var12)
            1174 LOAD_NAME            (var13)
            1176 LOAD_NAME            (var11)
            1178 LOAD_NAME            (var14)
            1180 BINARY_MODULO        TOS = var11 %% var14
            1182 ROT_THREE
            1184 ROT_TWO
            1186 STORE_NAME           (var11)
            1188 STORE_NAME           (var12)
            1190 STORE_NAME           (var13)
            1192 JUMP_FORWARD         (to 1376)

-168:     >> 1194 POP_TOP

-169:     >> 1196 DUP_TOP
            1198 MATCH_SEQUENCE
            1200 EXTENDED_ARG         (512)
            1202 POP_JUMP_IF_FALSE    (to 1258)
            1204 GET_LEN
            1206 LOAD_CONST           (2)
            1208 COMPARE_OP           (==) ; TOS = ... == 2
            1210 EXTENDED_ARG         (512)
            1212 POP_JUMP_IF_FALSE    (to 1258)
            1214 UNPACK_SEQUENCE      2
            1216 LOAD_CONST           (0)
            1218 COMPARE_OP           (==) ; TOS = ... == 0
            1220 EXTENDED_ARG         (512)
            1222 POP_JUMP_IF_FALSE    (to 1258)
            1224 POP_TOP
            1226 POP_TOP

-167:        1228 LOAD_NAME            (var12)
            1230 LOAD_NAME            (var13)
            1232 LOAD_NAME            (var11)
            1234 LOAD_NAME            (var12)
            1236 BINARY_ADD           TOS = var11 + var12
            1238 LOAD_NAME            (var13)
            1240 BINARY_ADD           TOS = var11 + var12 + var13
            1242 LOAD_NAME            (var14)
            1244 BINARY_MODULO        TOS = var11 + var12 + var13 %% var14
            1246 ROT_THREE
            1248 ROT_TWO
            1250 STORE_NAME           (var11)
            1252 STORE_NAME           (var12)
            1254 STORE_NAME           (var13)
            1256 JUMP_FORWARD         (to 1376)

-166:     >> 1258 POP_TOP

-167:        1260 DUP_TOP
            1262 MATCH_SEQUENCE
            1264 EXTENDED_ARG         (512)
            1266 POP_JUMP_IF_FALSE    (to 1318)
            1268 GET_LEN
            1270 LOAD_CONST           (2)
            1272 COMPARE_OP           (==) ; TOS = ... == 2
            1274 EXTENDED_ARG         (512)
            1276 POP_JUMP_IF_FALSE    (to 1318)
            1278 UNPACK_SEQUENCE      2
            1280 LOAD_CONST           (1)
            1282 COMPARE_OP           (==) ; TOS = ... == 1
            1284 EXTENDED_ARG         (512)
            1286 POP_JUMP_IF_FALSE    (to 1318)
            1288 POP_TOP
            1290 POP_TOP

-165:        1292 LOAD_NAME            (var12)
            1294 LOAD_NAME            (var13)
            1296 LOAD_NAME            (var11)
            1298 LOAD_NAME            (var12)
            1300 BINARY_ADD           TOS = var11 + var12
            1302 LOAD_NAME            (var14)
            1304 BINARY_MODULO        TOS = var11 + var12 %% var14
            1306 ROT_THREE
            1308 ROT_TWO
            1310 STORE_NAME           (var11)
            1312 STORE_NAME           (var12)
            1314 STORE_NAME           (var13)
            1316 JUMP_FORWARD         (to 1376)

-164:     >> 1318 POP_TOP

-165:        1320 MATCH_SEQUENCE
            1322 EXTENDED_ARG         (512)
            1324 POP_JUMP_IF_FALSE    (to 1374)
            1326 GET_LEN
            1328 LOAD_CONST           (2)
            1330 COMPARE_OP           (==) ; TOS = ... == 2
            1332 EXTENDED_ARG         (512)
            1334 POP_JUMP_IF_FALSE    (to 1374)
            1336 UNPACK_SEQUENCE      2
            1338 LOAD_CONST           (2)
            1340 COMPARE_OP           (==) ; TOS = ... == 2
            1342 EXTENDED_ARG         (512)
            1344 POP_JUMP_IF_FALSE    (to 1374)
            1346 POP_TOP

-163:        1348 LOAD_NAME            (var12)
            1350 LOAD_NAME            (var13)
            1352 LOAD_NAME            (var11)
            1354 LOAD_NAME            (var13)
            1356 BINARY_ADD           TOS = var11 + var13
            1358 LOAD_NAME            (var14)
            1360 BINARY_MODULO        TOS = var11 + var13 %% var14
            1362 ROT_THREE
            1364 ROT_TWO
            1366 STORE_NAME           (var11)
            1368 STORE_NAME           (var12)
            1370 STORE_NAME           (var13)
            1372 JUMP_FORWARD         (to 1376)

-162:     >> 1374 POP_TOP

-163:     >> 1376 EXTENDED_ARG         (512)
            1378 JUMP_ABSOLUTE        (to 1116)

-291:     >> 1380 LOAD_NAME            (combined_list)
            1382 LOAD_NAME            (i_var)
            1384 BINARY_SUBSCR        TOS = combined_list[i_var]
            1386 LOAD_NAME            (var11)
            1388 LOAD_CONST           (255)
            1390 BINARY_AND           TOS = var11 & 255
            1392 BINARY_XOR           TOS = combined_list[i_var] ^ (var11 & 255)
            1394 STORE_NAME           (var15) ; var15 = combined_list[i_var] ^ (var11 & 255)

-288:        1396 LOAD_NAME            (print)
            1398 LOAD_NAME            (chr)
            1400 LOAD_NAME            (var15)
            1402 CALL_FUNCTION        (1 positional argument) ; TOS = chr(var15)
            1404 LOAD_CONST           ("")
            1406 LOAD_CONST           (('end',))
            1408 CALL_FUNCTION_KW     (2 total positional and keyword args) ; TOS = print(chr(var15)...
            1410 POP_TOP

-287:        1412 LOAD_NAME            (sys)
            1414 LOAD_ATTR            (stdout) ; TOS = stdout.sys
            1416 LOAD_METHOD          (flush)
            1418 CALL_METHOD          (0 positional arguments)
            1420 POP_TOP
            1422 RERAISE              0

-286:     >> 1424 LOAD_CONST           (None)
            1426 RETURN_VALUE         return None
```
*Note*: This is not the raw output I obtained, it has been modified for readability.  

From here began an extensive reverse engineering process in which I first reverse engineered the bytecode and then manually translated the bytecode into Python to be able to run the program and modify it as needed.  

CPython uses a 3 stack system:
- Call Stack: the same as a call stack in ISAs such as x86
- Data Stack: LOAD_NAME is used to push data into the stack, STORE_NAME is used to pop/write from the stack, and functions such as ROT3 manipulate data in the stack.
- Block Stack: This is how CPython keeps track of `Try/Except` and `With` blocks.

Reading up on how CPython bytecode works and studying the "assembly" allowed me to translate this back into python:  
##### revd_chal.py
```python
import os
import sys
import random

def obfuscated():
    random.seed(os.urandom(8))
    if random.randint(0, 1) == 0:
        print("Oops! something went wrong, run again")
        return

    var1, var2 = random.randint(0, 1), random.randint(0, 1)
    if var1 == 0 and var2 == 1:
        print("You're Lucky")
        print("Here is your flag: ", end="")

    var3 = []
    list_a = [96, 98, 68, 160, 172, 115, 20, 108, 25, 122, 208, 71, 158, 63, 233, 59]
    list_b = [198, 31, 60, 167, 17, 1, 132, 106, 195, 19, 38, 151, 203, 163, 211, 27, 73, 98]
    list_c = [180, 165, 115, 203, 177, 17, 166, 20, 196, 255, 127, 70, 172, 55, 11, 204, 20]
    combined_list = list_a + list_c + list_b

    for i_var in range(50):
        var9 = 3
        try:
            for j_var in range(25, 50):
                random.seed(j_var / (j_var - i_var))
            var2 = var9 ** i_var
        except ZeroDivisionError:
            var2 = var2 ** var9

        var2 = var9 ** i_var
        var11, var12, var13 = 1, 2, 3
        var14 = 1000000007

        for j_var in range(var2):
            modulus_3, modulus_5 = j_var % 3, j_var % 5
            if modulus_3 == 0 and modulus_5 == 0:
                var13, var12, var11 = (var11) % var14, var13, var12
            elif modulus_3 == 0:
                var13, var12, var11 = (var11 + var12 + var13) % var14, var13, var12
            elif modulus_3 == 1:
                var13, var12, var11 = (var11 + var12) % var14, var13, var12
            else:
                var13, var12, var11 = (var11 + var13) % var14, var13, var12

        var15 = combined_list[i_var] ^ (var11 & 0xFF)
        print(chr(var15), end="")
        sys.stdout.flush()

obfuscated()
```
This code has the exact functionality as the bytecode, but as the challenge description suggests, it is way too slow...  

## Optimizing the Code
First thing I realized was that in the `for j` loop, we have a cycle of 15 operations (due to modulus 5 and 3).
I imagined a vector (v11,v12,v13) and did some pen and paper math to get the following  
| cycle | v11 | v12 | v13 |
|-------|-----|-----|-----|
|-1|(1,0,0)|(0,1,0)|(0,0,1)|
|0|(0,1,0)|(0,0,1)|(0,1,1)|
|1|(0,0,1)|(0,1,1)|(0,1,2)|
|2|(0,1,1)|(0,1,2)|(1,2,3)|
|3|(0,1,2)|(1,2,3)|(0,2,3)|
|...|...|...|...|
|14|(1,54,87)|(0,34,55)|(0,55,89)|

Now we can do LEAPS of 15 iterations and then compute the remaining iterations manually  
##### Optimization1
```python
import os
import sys
import random


def obfuscated():

    list_a = [96, 98, 68, 160, 172, 115, 20, 108, 25, 122, 208, 71, 158, 63, 233, 59]
    list_b = [198, 31, 60, 167, 17, 1, 132, 106, 195, 19, 38, 151, 203, 163, 211, 27, 73, 98]
    list_c = [180, 165, 115, 203, 177, 17, 166, 20, 196, 255, 127, 70, 172, 55, 11, 204, 20]
    combined_list = list_a + list_c + list_b
    

    
    mod = 1000000007

    for i_var in range(50):

        if(i_var >= 25):
            iter = iter**3
        else:
            iter = 3**i_var

        var11, var12, var13 = 1, 2, 3

        for leap in range(iter//15):
            var11, var12, var13 = (
                (1*var11 + 54*var12 + 87*var13) % mod,
                (0*var11 + 34*var12 + 55*var13) % mod,
                (0*var11 + 55*var12 + 89*var13) % mod
            )

        for step in range(iter % 15):
            modulus_3, modulus_5 = step % 3, step % 5
            if modulus_3 == 0 and modulus_5 == 0:
                var13, var12, var11 = (var11) % mod, var13, var12
            elif modulus_3 == 0:
                var13, var12, var11 = (var11 + var12 + var13) % mod, var13, var12
            elif modulus_3 == 1:
                var13, var12, var11 = (var11 + var12) % mod, var13, var12
            else: #modulus_3 == 2
                var13, var12, var11 = (var11 + var13) % mod, var13, var12
        
        var15 = combined_list[i_var] ^ (var11 & 0xFF)
        print(chr(var15), end="")
        sys.stdout.flush()

obfuscated()
```
This happens to still be too slow. However I noticed that if we consider a vector x = (a,b,c), then doing a Leap is equal to   
doing Ax for a matrix A given by  
| 1 54 87 |  
| 0 34 55 |  
| 0 55 89 |  

Applying this Leap multiple times in a row, is the same as applying the Matrix to our vector many times in a row, so we can replace iteration with Matrix Exponentiation.  

##### Optimization2
```python
import os
import sys
import random
from sage.all import *

def obfuscated():

    list_a = [96, 98, 68, 160, 172, 115, 20, 108, 25, 122, 208, 71, 158, 63, 233, 59]
    list_b = [198, 31, 60, 167, 17, 1, 132, 106, 195, 19, 38, 151, 203, 163, 211, 27, 73, 98]
    list_c = [180, 165, 115, 203, 177, 17, 166, 196, 255, 127, 70, 172, 55, 11, 204, 20]
    combined_list = list_a + list_c + list_b

    mod = 1000000007
    
    # think of (var11,var12,var13) as a vector x
    # then the leap is equal to Ax for a matrix A
    #     | 1 54 87 |
    # A = | 0 34 55 |
    #     | 0 55 89 |
    # every leap will apply the same matrix
    # so we can say that n leaps are equal to A^n*x

    A = matrix(GF(mod), [[1,54,87],[0,34,55],[0,55,89]])


    for i_var in range(50):

        if(i_var >= 25):
            iterations = iterations**3
        else:
            iterations = 3**i_var

        leaps = iterations//15
        var11, var12, var13 = A**leaps * vector([1,2,3])

        for step in range(iterations % 15):
            modulus_3, modulus_5 = step % 3, step % 5
            if modulus_3 == 0 and modulus_5 == 0:
                var13, var12, var11 = (var11) % mod, var13, var12
            elif modulus_3 == 0:
                var13, var12, var11 = (var11 + var12 + var13) % mod, var13, var12
            elif modulus_3 == 1:
                var13, var12, var11 = (var11 + var12) % mod, var13, var12
            else: #modulus_3 == 2
                var13, var12, var11 = (var11 + var13) % mod, var13, var12
        
        var15 = combined_list[i_var] ^ (int(var11) & 0xFF)
        print(chr(var15), end="")
        sys.stdout.flush()

obfuscated()
```

As impressive as I thought this was, it was still too slow... 

**Note**: This is as far as I got during the CTF, the next was added after doing some reading when the CTF ended  
Due to our use of Galois Fields on our Matrix, we actually don't need to exponentiate our matrix to iterations, we can do   
`A**(leaps % (mod+1))`.  
However, we now face the problem of modular division, so we can find the modular inverse of leaps to get the correct values.

##### final
```python
from sage.all import *

def obfuscated():

    list_a = [96, 98, 68, 160, 172, 115, 20, 108, 25, 122, 208, 71, 158, 63, 233, 59]
    list_b = [198, 31, 60, 167, 17, 1, 132, 106, 195, 19, 38, 151, 203, 163, 211, 27, 73, 98]
    list_c = [180, 165, 115, 203, 177, 17, 166, 196, 255, 127, 70, 172, 55, 11, 204, 20]
    combined_list = list_a + list_c + list_b

    mod = 1000000007
    
    # think of (var11,var12,var13) as a vector x
    # then the leap is equal to Ax for a matrix A
    #     | 1 54 87 |
    # A = | 0 34 55 |
    #     | 0 55 89 |
    # every leap will apply the same matrix
    # so we can say that n leaps are equal to A^n*x

    A = matrix(GF(mod), [[1,54,87],[0,34,55],[0,55,89]])


    for i_var in range(50):

        if(i_var >= 25):
            t = pow(3, (24*(3**(i_var-24)) - 1), mod+1)
            leaps = ((t-2) * pow(5, -1, mod+1)) % (mod+1)
            iterations = pow(3, (24*(3**(i_var-24))), 15)
        else:
            iterations = 3**i_var
            leaps = iterations//15
            iterations = iterations % 15

        
        var11, var12, var13 = A**(leaps % (mod+1)) * vector([1,2,3])

        for step in range(iterations):
            modulus_3, modulus_5 = step % 3, step % 5
            if modulus_3 == 0 and modulus_5 == 0:
                var13, var12, var11 = (var11) % mod, var13, var12
            elif modulus_3 == 0:
                var13, var12, var11 = (var11 + var12 + var13) % mod, var13, var12
            elif modulus_3 == 1:
                var13, var12, var11 = (var11 + var12) % mod, var13, var12
            else: #modulus_3 == 2
                var13, var12, var11 = (var11 + var13) % mod, var13, var12
        
        var15 = combined_list[i_var] ^ (int(var11) & 0xFF)
        print(chr(var15), end="")

obfuscated()
print()
#bctf{we1rd_pyth0nc0d3_so1v3_w1th_f4s7_M47r1x_Mu1t}
```
![image](https://github.com/AndreQuimper/Writeups/assets/96965806/7be30c6e-09bc-49a0-a508-320209dee8b0)  

Done! :D  
This was a very fun/hard challenge and I am both happy and a little sad that I got so close to the solution.   


