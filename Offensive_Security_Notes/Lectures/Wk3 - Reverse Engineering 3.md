## Stripped Binaries and Serialized Protocols
## Recognizing Stripped Binaries
#### Different ways to compile:
Debug Flag
	`-g` in Gcc
* provides an interface for gdb ti recognize code-level debug information
* Not common in targets
Normal Compilation
* This is what the challenges so far have been
* Neither debug nor stripped
Stripped Compilation
	`-s` flag in Gcc
* Smaller file size
* No function names in main binary
	* Ads layer of obfuscation
### Stripped and Static
Stripped *dynamic* binaries are not terrible
Stripped *static* binaries are not as fun
### Value of Strings
* `debug` functions leak error conditions, function names, ...etc
* Expected strings in `strcmp`, `strstr`, ...etc
	Eg: HTTP header info
* `flag.txt`
![[Pasted image 20240219132411.png]]
#### Locate `syscall` numbers
* Can isolate certian `libc` functions using syscalls
* Useful for user space functions that wrap around syscalls
* Not as useful for string ops
![[Pasted image 20240219132505.png]]
### Serialization
#### Serialized Protocols
* Serialization is a common practice
	* JSON
	* Java serialization/Python pickle
	* Internet protocols
	* Google protobugs
* Serialization is (mostly) easy
* Deserialization is hard
	* Length checks
	* Pointer Arithmatic
	* Infinite recursion
#### Serialized Data
Typically a mix between:
* Fixed length with known locations and interpretation
* Key-value pairs
Ex:
```
len seq keylen    |-- ‘hello’ --| vallen   |-- ‘world’ --|
0c    01    05    68 65 6c 6c 6f    05_     77 6f 72 6c 64
|-header-|--------------------- len —--------------------|
```
#### Example:
| Client | Server |
| ---- | ---- |
| * Prepends header of packet length<br>* Sends two data of the same type<br>       If array, must be same length<br>* Waits to receive response | * Receives data<br>* Checks packet length and sequence number for integrity<br>* Parses data types and validates type congruence<br>* Computes response (and serializes) |
### Define Packet Structure
* Header length: `5 bytes`
	* `len: u8`
	* `seq: u32, starting at 0`
* Packet length: variable (len)
* Types of data allowed (`u8`):
	* `int: 0`
	* `char: 1`
	* `u8arr: 2`
* Type lengths
	* `int: u32`
	* `char: u8`
	* `arr:` length prepended to array
#### Packet Structure Code
```c
int send_result (uint32_t result) {
 return 0;
 // implement serialization and sending logic here!
}
int get_data (uint8_t* buf, uint32_t buflen) {
 // realistically this would read on a socket waiting for
input
 // use a local file for simplicity and testing
 int fd = open("./input" , O_RDONLY );
 return read(fd, buf, buflen);
}
int main() {
 uint8_t buf[BUFSIZE];
 memset(buf, 0, BUFSIZE);
 while (1) {
 int b = get_data (buf, sizeof(buf));
 if (b <= 0) { continue ; }
 uint8_t* packet = malloc(b);
 memset(packet, 0, b);
 memcpy(packet, buf, b);
 int result = handle_packet (packet, b);
 free(packet);
 if (result == -1) { continue ; }
 send_response (result);
 }
```
### Code:
```c
#include <stdio.h>
#include <stdlib.h>
#include <fcntl.h>
#include <stdint.h>
#include <unistd.h>
#include <string.h>
// pack to make 5 bytes
struct __attribute__((__packed__)) header {
 uint8_t len;
 uint32_t seq;
};
const uint32_t BUFSIZE = 1024;
// compile with CFLAGS=-fshort-enums to get uint8_t
sized enum vals
enum data_type {
 INTEGER,
 CHARACTER,
 U8ARRAY,
};
```
### Handle Packet
#### Header info
```c
int handle_packet(uint8_t* packet, int len) {
 uint8_t* end = packet + len;
 if (len < 5) { return -1; }
 struct header* h = (struct header*)packet;
 packet += sizeof(struct header);
 if (h->len > len) { /*handle fragmented packet*/ }
 	...
```
#### Packet Length and Types of Data Allowed:
```c
int handle_packet(uint8_t* packet, int len) {
...
 enum data_type t;
 if (packet <= end) {
 t = *(enum data_type*)packet;
 packet++;
 } else {
 return -1;
 }
 switch (t) {
 case INTEGER:
 return handle_int(packet, end);
 case CHARACTER:
 return handle_char(packet, end);
 case U8ARRAY:;
 return handle_arr(packet, end);
 default:
 return -1;
 }
```
### Handle Characters
```c
int handle_char (uint8_t* start, uint8_t* end) {
 uint8_t i1, i2;
 int ret = 0;
 if (start + sizeof(uint8_t) * 2 != end) {
 return -1;
 }
 i1 = *start;
 start += sizeof(uint8_t);
 i2 = *start;
 start += sizeof(uint8_t);
 ret = i1 * i2;
 return ret;
}
```
#### Handle Ints
```c
int handle_int(uint8_t* start, uint8_t* end) {
	int i1, i2;
	int ret = 0;
	if (start + sizeof(uint32_t) * 2 != end) {
		return -1;
	}
	i1 = *(int*)start;
	start += sizeof(uint32_t);
	i2 = *(int*)start;
	start += sizeof(uint32_t);
	ret = i1 * i2;
	return ret;
}
```
#### Handle an Array
```c
int handle_array (uint8_t* start, uint8_t* end) {
	uint8_t* arr1;
	uint8_t* arr2;
	uint8_t len;

	len = *start;
	start++;
	if (start + len <= end) {
		arr1 = malloc(len);
		memcpy(arr1, start, len);
		start += len;
	} else { return -1; }
	if (start + len <= end) {
		arr2 = malloc(len);
		memcpy(arr2, start, len);
		start += len;
	}
	// check that entire packet was consumed
	if (start != end) { return -1; }
		int ret = 0;
		for (int i = 0; i < len; i++) {
		ret += (arr1[i] * arr2[i]);
	}
		return ret;
}
```
#### Full Code
```c
#include <stdio.h>
#include <stdlib.h>
#include <fcntl.h>
#include <stdint.h>
#include <unistd.h>
#include <string.h>

// pack to make 5 bytes
struct __attribute__((__packed__)) header {
	uint8_t len;
	uint32_t seq;
};

const uint32_t BUFSIZE = 1024;

// compile with CFLAGS=-fshort-enums to get uint8_t sized enum vals
enum data_type {
	INTEGER,
	CHARACTER,
	U8ARRAY,
};

int handle_array(uint8_t* start, uint8_t* end) {
	uint8_t* arr1;
	uint8_t* arr2;
	uint8_t len;

	len = *start;
	start++;

	if (start + len <= end) {
		arr1 = malloc(len);
		memcpy(arr1, start, len);
		start += len;
	} else { return -1; }
	if (start + len <= end) {
		arr2 = malloc(len);
		memcpy(arr2, start, len);
		start += len;
	}

	// check that entire packet was consumed
	if (start != end) { return -1; }
	int ret = 0;
	for (int i = 0; i < len; i++) {
		ret += (arr1[i] * arr2[i]);
	}
	return ret;
}

int handle_int(uint8_t* start, uint8_t* end) {
	int i1, i2;
	int ret = 0;
	if (start + sizeof(uint32_t) * 2 != end) {
		return -1;
	}
	i1 = *(int*)start;
	start += sizeof(uint32_t);
	i2 = *(int*)start;
	start += sizeof(uint32_t);
	ret = i1 * i2;
	return ret;
}

int handle_char(uint8_t* start, uint8_t* end) {
	uint8_t i1, i2;
	int ret = 0;
	if (start + sizeof(uint8_t) * 2 != end) {
		return -1;
	}
	i1 = *start;
	start += sizeof(uint8_t);
	i2 = *start;
	start += sizeof(uint8_t);
	ret = i1 * i2;
	return ret;
}

int handle_packet(uint8_t* packet, int len) {
	// get header
	uint8_t* end = packet + len;
	if (len < sizeof(struct header)) { return -1; }
	struct header* h = (struct header*)packet;
	packet += sizeof(struct header);
	if (h->len != len) {
		printf("Fragmented packet, got len %d, expected len %d\n", h->len, len);
		return -1;
	}
	uint32_t seq = h->seq; /* handle sequence number logic here */
	printf("sequence: %d\n", seq);

	enum data_type t;
	if (packet <= end) {
		t = *(enum data_type*)packet;
		packet++;
	} else {
		return -1;
	}

	printf("type: %d\n", (int)t);
	printf("type: %d\n", (int)INTEGER);

	switch (t) {
		case INTEGER:
			return handle_int(packet, end);
		case CHARACTER:
			return handle_char(packet, end);
		case U8ARRAY:;
			return handle_array(packet, end);
		default:
			return -1;
	}
}

int send_response(uint32_t result) {
	// implement serialization and sending logic here!
	return 0;
}

int get_data(uint8_t* buf, uint32_t buflen) {
	// realistically this would read on a socket waiting for input
	// use a local file for simplicity and testing
	int fd = open("./input", O_RDONLY);
	return read(fd, buf, buflen);
}

int main() {
	uint8_t* buf = malloc(BUFSIZE);
	memset(buf, 0, BUFSIZE);
	while (1) {
		int b = read(0, buf, BUFSIZE);
		if (b <= 0) { continue; }
		int result = handle_packet(buf, b);
		break; /* break for the sake of testing */
		if (result == -1) { continue; }
		send_response(result);
	}
	return 0;
}
```
### Nova Message: `nv::message`
Typed key-value mapping
	`u32, u64, book, string, bytes, IP address, nv::message`
2 Flavors:
Pseudo-JSON (deprecated)
```json
{
	s1: 'hello',
	u2: 1234,
	U3: [4, 5, 6].
	b4: true
}
```
Serialized Binary "M2"
![[Pasted image 20240219135118.png]]

# Documentation:
This module covers analyzing stripped binaries and serialized protocols 
## Stripped Binaries
- [x86, x86_64 syscall numbers](https://chromium.googlesource.com/chromiumos/docs/+/master/constants/syscalls.md#x86_64-64_bit)
- [x86-64 syscall calling convention](https://stackoverflow.com/questions/22444526/x86-64-linux-syscall-arguments)
- [Linux unistd_64.h defining syscall numbers](https://elixir.bootlin.com/linux/v3.0/source/arch/x86/include/asm/unistd_64.h)
- [Interactive glibc source code](https://elixir.bootlin.com/glibc/latest/source)
## Serialized Protocol Examples  
- [Formats](https://en.wikipedia.org/wiki/Comparison_of_data-serialization_formats)
- [Protobufs](https://protobuf.dev/)
- [Protobuf analyzer](https://github.com/mildsunrise/protobuf-inspector)
- [Reversing MikroTik message protocol (22:45 - 26:45)](https://youtu.be/ItclhUF6MnA?t=1363)
- [MikroTik message protocol (PDF slide 27)](https://margin.re/pulling-mikrotik-into-the-limelight-2/)
## Deserialization Vulnerabilities
- [y so serial](https://github.com/frohoff/ysoserial)
- [Java deserialization cheat sheet](https://github.com/GrrrDog/Java-Deserialization-Cheat-Sheet)
- [SnakeYaml deserialization CVE](https://snyk.io/blog/unsafe-deserialization-snakeyaml-java-cve-2022-1471/)
- [MikroTik JSON Recursion DoS](https://seclists.org/fulldisclosure/2019/Jul/20)
- [Collection of deserialization vulns](https://www.acunetix.com/vulnerabilities/web/tag/insecure-deserialization/)[](https://www.tenable.com/security/research/tra-2018-21)


# Challenges:
[[Hand Rolled Cryptex]]
[[Heterograms]]

# More Documentation
[[Syscalls]]
