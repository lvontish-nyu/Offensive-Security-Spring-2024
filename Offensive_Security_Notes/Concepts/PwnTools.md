# Install and Usage
```
$ apt-get update  
$ apt-get install python3 python3-pip python3-dev git libssl-dev libffi-dev build-essential  
$ python3 -m pip install — upgrade pip  
$ python3 -m pip install — upgrade pwntools
$ pip install pwntools
```

Add to path:
`export PATH="/home/kali/.local/bin"`
Actually, this one: 
`export PATH="/home/kali/.local/bin:/usr/local/sbin:/usr/local/bin:/usr/sbin:/usr/bin:/sbin:/bin:/usr/local/games:/usr/games"`
### Connecting
`p=remote($IP,$Port)`

## Cool Script for Buffer Overflows
```python
def ripOffset():
	p = process('./lockbox')
	d = p.recvuntil(">")
	p.sendline(cyclic(500))
	p.wait()
	cf = p.corefile
	stack = cf.rsp
	info("rsp = %#x", stack)
	pattern = cf.read(stack, 4)
	rip_offset = cyclic_find(pattern)

	info("rip offset = %d", rip_offset)
```
```
┌──(kali㉿kali)-[~/Desktop/4-Week]
└─$ python3 newdbg.py
[+] Starting local process './lockbox': pid 40543
/home/kali/Desktop/4-Week/newdbg.py:88: BytesWarning: Text is not bytes; assuming ASCII, no guarantees. See https://docs.pwntools.com/#bytes
  d = p.recvuntil(">")
[*] Process './lockbox' stopped with exit code -11 (SIGSEGV) (pid 40543)
[+] Parsing corefile...: Done
[*] '/home/kali/Desktop/4-Week/core.40543'
    Arch:      amd64-64-little
    RIP:       0x4012a4
    RSP:       0x7ffd68ab1df0
    Exe:       '/home/kali/Desktop/4-Week/lockbox' (0x400000)
[*] rsp = 0x7ffd68ab1df0
[*] rip offset = 0