More from [[Boffin]]
Set a breakpoint and looking at beginning of main:
```
┌──(kali㉿kali)-[~/Desktop/4-Week]
└─$ gdb ./boffin
(gdb) break main
Breakpoint 1 at 0x4006da
(gdb) r
Breakpoint 1, 0x00000000004006da in main ()
(gdb) disas main
Dump of assembler code for function main:
   0x00000000004006d6 <+0>:     push   %rbp
   0x00000000004006d7 <+1>:     mov    %rsp,%rbp
=> 0x00000000004006da <+4>:     sub    $0x20,%rsp
   ...omitted for brevity...
   0x00000000004006f2 <+28>:    lea    -0x20(%rbp),%rax
   0x00000000004006f6 <+32>:    mov    %rax,%rdi
   0x00000000004006f9 <+35>:    call   0x400590 <gets@plt>
   0x00000000004006fe <+40>:    lea    -0x20(%rbp),%rax
   ...omitted for brevity...
(gdb) info registers
rax            0x4006d6            4196054
rbx            0x7fffffffdf08      140737488346888
rcx            0x7ffff7f9e840      140737353738304
rdx            0x7fffffffdf18      140737488346904
rsi            0x7fffffffdf08      140737488346888
rdi            0x1                 1
rbp            0x7fffffffddf0      0x7fffffffddf0
rsp            0x7fffffffddf0      0x7fffffffddf0
...omitted for brevity...
rip            0x4006da            0x4006da <main+4>
```
The stack:
```
(gdb) x/5x $sp
0x7fffffffddf0: 0x00000001      0x00000000      0xf7df26ca      0x00007fff
0x7fffffffde00: 0x00000000
```

After I enter 32 As
```
Breakpoint 1, 0x00000000004006da in main ()
(gdb) break *0x00000000004006fe
Breakpoint 2 at 0x4006fe
(gdb) c
Continuing.
Hey! What's your name?
AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA
```
After the call
Line
```
Breakpoint 2, 0x00000000004006fe in main ()
(gdb) disas main
Dump of assembler code for function main:
...omitted for brevity...
   0x00000000004006f9 <+35>:    call   0x400590 <gets@plt>
=> 0x00000000004006fe <+40>:    lea    -0x20(%rbp),%rax
   0x0000000000400702 <+44>:    mov    %rax,%rsi
```
Registers
```
(gdb) info registers
rax            0x7fffffffddd0      140737488346576
rbx            0x7fffffffdf08      140737488346888
rcx            0x7ffff7f9eaa0      140737353738912
rdx            0x0                 0
rsi            0x6022a1            6300321
rdi            0x7ffff7fa0a40      140737353747008
rbp            0x7fffffffddf0      0x7fffffffddf0
rsp            0x7fffffffddd0      0x7fffffffddd0
...omitted for brevity...
rip            0x4006fe            0x4006fe <main+40>
```
Stack
```
(gdb) x/20x $sp
quit
0x7fffffffddd0: 0x41414141      0x41414141      0x41414141      0x41414141
0x7fffffffdde0: 0x41414141      0x41414141      0x41414141      0x41414141
0x7fffffffddf0: 0x00000000      0x00000000      0xf7df26ca      0x00007fff
0x7fffffffde00: 0x00000000      0x00000000      0x004006d6      0x00000000
0x7fffffffde10: 0x00000000      0x00000001      0xffffdf08      0x00007fff
```
