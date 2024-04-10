# Understanding GlibC Malloc
From [Sploitfun Malloc](https://sploitfun.wordpress.com/2015/02/10/understanding-glibc-malloc/)
# Intro
This blog will answer the following questions:
* How heap memory is obtained from kernel?  
* How efficiently memory is managed?  
* Is it managed by kernel or by library or by application itself?  
* Can heap memory be exploited?
### There are many cool memory allocators
`dlmalloc` - General-purpose allocator
`ptmalloc2` - GlibC
`jemalloc` - FreeBSD and Firefox
`Libumem` - Solaris

Every memory allocator claims to be fast, scalable, and memory efficient. However, not all allocators are well-suited for all applications. Memory hungry apps' performance largely depends on memory allocator performance.
This blog will cover `glibc malloc` .
### Some `malloc` history
`ptmalloc3` was forked from `dlmalloc` and released in 2006. It was then integrated into glibc source code after the official release. Since then, code changes are made directly to the `glibc malloc` source code itself. Therefore, there are a lot of changes between `ptmalloc3`  and the  `glibc malloc` of today.
## System Calls
This is actually another blog post from [the same blog](https://sploitfun.wordpress.com/2015/02/11/syscalls-used-by-malloc/)
Syscalls used by Malloc

Malloc uses syscalls to get memory from the OS.
It invokes `brk` or `mmap`
![[Pasted image 20240322142217.png]]
### `brk`
Brk obtains (non zero initialized) memory from the kernel by increasing the program break location (`brk`).
Initially, the start (`start_brk`) and end of the heap (`brk`) point to the same location
###### `ASLR`
* When ASLR is **off**, `start_brk` and `brk` point to the end of the data/bss segment (`end_data`)
* When ASLR is **on**. `start_brk` and `brk` are equal to the end of the data/bss segment (`end_data`) **plus** the random brk offset
###### Process Virtual Memory Layout
![[Pasted image 20240322144224.png]]
`start_brk` is the beginning of the heap segment
`brk` (program break) is at the end of the heap segment
#### Example:
###### Code:
```c
/* sbrk and brk example */
#include <stdio.h>
#include <unistd.h>
#include <sys/types.h>

int main()
{
	void *curr_brk, *tmp_brk = NULL;

	printf("Welcome to sbrk example:%d\n", getpid());

	/* sbrk(0) gives current program break location */
	tmp_brk = curr_brk = sbrk(0);
	printf("Program Break Location1:%p\n", curr_brk);
	getchar();

	/* brk(addr) increments/decrements program break location */
	brk(curr_brk+4096);

	curr_brk = sbrk(0);
	printf("Program break Location2:%p\n", curr_brk);
	getchar();

	brk(tmp_brk);

	curr_brk = sbrk(0);
	printf("Program Break Location3:%p\n", curr_brk);
	getchar();

	return 0;
}
```

##### Before increasing the program break, we can see that there is **NO** heap segment
`start_brk` = `brk` = `end_data` = `0x804b000`
###### Output:
```
sploitfun@sploitfun-VirtualBox:~/ptmalloc.ppt/syscalls$ ./sbrk 
Welcome to sbrk example:6141
Program Break Location1:0x804b000
...
sploitfun@sploitfun-VirtualBox:~/ptmalloc.ppt/syscalls$ cat /proc/6141/maps
...
0804a000-0804b000 rw-p 00001000 08:01 539624     /home/sploitfun/ptmalloc.ppt/syscalls/sbrk
b7e21000-b7e22000 rw-p 00000000 00:00 0 
...
sploitfun@sploitfun-VirtualBox:~/ptmalloc.ppt/syscalls$
```
###### After increasing program break location, we can see the heap segment
`start_brk` = `brk` = `end_data` = `0x804b000`
`brk` = `0x804c000`
###### Output:
```
sploitfun@sploitfun-VirtualBox:~/ptmalloc.ppt/syscalls$ ./sbrk 
Welcome to sbrk example:6141
Program Break Location1:0x804b000
Program Break Location2:**0x804c000**
...
sploitfun@sploitfun-VirtualBox:~/ptmalloc.ppt/syscalls$ cat /proc/6141/maps
...
0804a000-0804b000 rw-p 00001000 08:01 539624     /home/sploitfun/ptmalloc.ppt/syscalls/sbrk
**0804b000-0804c000 rw-p 00000000 00:00 0          [heap]**
b7e21000-b7e22000 rw-p 00000000 00:00 0 
...
sploitfun@sploitfun-VirtualBox:~/ptmalloc.ppt/syscalls$
```
Where:
	`0804b000-0804c000` = Virtual address for this segment
	`rw-p` = Flags(Read, Write, NoeXecute, Private)
	`00000000` = File Offset
		It's `0` because it isn't mapped from any file
	`00:00` = Major/Minor Device Number
		It's `0` because it isn't mapped from any file
	`0` = Inode Number
		It's `0` because it isn't mapped from any file
	`[heap]` = The heap segment

### `mmap`
Malloc uses `mmap` to create private anonymous mapping segments.
* Primary purpose of *private anonymous mapping*  is to allocate new (0-filled) memory to be used by the calling process
#### Example
###### Code:
```c
/* Private anonymous mapping example using mmap syscall */
#include <stdio.h>
#include <sys/mman.h>
#include <sys/types.h>
#include <sys/stat.h>
#include <fcntl.h>
#include <unistd.h>
#include <stdlib.h>

void static inline errExit(const char* msg)
{
	printf("%s failed. Exiting the process\n", msg);
	exit(-1);
}

int main()
{
	int ret = -1;
	printf("Welcome to private anonymous mapping example::PID:%d\n", getpid());
	printf("Before mmap\n");
	getchar();
	char* addr = NULL;
	addr = mmap(NULL, (size_t)132*1024, PROT_READ|PROT_WRITE, MAP_PRIVATE | MAP_ANONYMOUS, -1, 0);
	if (addr == MAP_FAILED)
			errExit("mmap");
	printf("After mmap\n");
	getchar();

	/* Unmap mapped region. */
	ret = munmap(addr, (size_t)132*1024);
	if(ret == -1)
			errExit("munmap");
	printf("After munmap\n");
	getchar();
	return 0;
}
```
##### Before mmap
In the below output, we can only see memory mapping segments that belog to shared libraries `libc.so` and `ld-linux.so`
###### Output:
```
sploitfun@sploitfun-VirtualBox:~/ptmalloc.ppt/syscalls$ cat /proc/6067/maps
08048000-08049000 r-xp 00000000 08:01 539691     /home/sploitfun/ptmalloc.ppt/syscalls/mmap
08049000-0804a000 r--p 00000000 08:01 539691     /home/sploitfun/ptmalloc.ppt/syscalls/mmap
0804a000-0804b000 rw-p 00001000 08:01 539691     /home/sploitfun/ptmalloc.ppt/syscalls/mmap
b7e21000-b7e22000 rw-p 00000000 00:00 0 
```
##### After mmap
We can see that our memory mapping segment:
	From `b7e00000` - `b7e21000`
	Size: `132 KB`
That segment has been combined with an existing segment
	From: `b7e21000` - `b7e22000`
###### Output
```
sploitfun@sploitfun-VirtualBox:~/ptmalloc.ppt/syscalls$ cat /proc/6067/maps
08048000-08049000 r-xp 00000000 08:01 539691     /home/sploitfun/ptmalloc.ppt/syscalls/mmap
08049000-0804a000 r--p 00000000 08:01 539691     /home/sploitfun/ptmalloc.ppt/syscalls/mmap
0804a000-0804b000 rw-p 00001000 08:01 539691     /home/sploitfun/ptmalloc.ppt/syscalls/mmap
**b7e00000-b7e22000 rw-p 00000000 00:00 0**
```
Where:
	`b7e00000-b7e22000` = Virtual address range for this segment
	`rw-p` = Flags(Read, Write, NoeXecute, Private)
	`00000000` = File Offset
		It's `0` because it isn't mapped from any file
	`00:00` = Major/Minor Device Number
		It's `0` because it isn't mapped from any file
	`0` = Inode Number
		It's `0` because it isn't mapped from any file
	`[heap]` = The heap segment
##### After munmap
Now we can see that the memory map segment is unmapped
	It's memory has been released to the operating system
```
sploitfun@sploitfun-VirtualBox:~/ptmalloc.ppt/syscalls$ cat /proc/6067/maps
08048000-08049000 r-xp 00000000 08:01 539691     /home/sploitfun/ptmalloc.ppt/syscalls/mmap
08049000-0804a000 r--p 00000000 08:01 539691     /home/sploitfun/ptmalloc.ppt/syscalls/mmap
0804a000-0804b000 rw-p 00001000 08:01 539691     /home/sploitfun/ptmalloc.ppt/syscalls/mmap
**b7e21000-b7e22000 rw-p 00000000 00:00 0**
```

## Threading
In the early days of Linux, `dlmalloc` was the default memory allocator
	Later, `ptmalloc2`'s threading support made it the default
**Threading Support** helps improve memory allocator performance (and therefore application performance)
###### `dlmalloc`
When two threads call malloc at the same time, only one thread can enter the critical section
* The freelist data structure is shared among all of the available threads
* This causes memory allocation to take longer in multi-threaded applications
###### `ptmalloc2`
When two threads call malloc at the same time, memory is allocated immediately
* each thread maintains a separate heap segment
	* Therefore each thread has its own freelist data structures to maintain those heaps
	* This is called **per thread arena**
### Example
###### Code:
```c
/* Per thread arena example. */
#include <stdio.h>
#include <stdlib.h>
#include <pthread.h>
#include <unistd.h>
#include <sys/types.h>

void* threadFunc(void* arg) {
	printf("Before malloc in thread 1\n");
	getchar();
	char* addr = (char*) malloc(1000);
	printf("After malloc and before free in thread 1\n");
	getchar();
	free(addr);
	printf("After free in thread 1\n");
	getchar();
}

int main() {
	pthread_t t1;
	void* s;
	int ret;
	char* addr;

	printf("Welcome to per thread arena example::%d\n",getpid());
	printf("Before malloc in main thread\n");
	getchar();
	addr = (char*) malloc(1000);
	printf("After malloc and before free in main thread\n");
	getchar();
	free(addr);
	printf("After free in main thread\n");
	getchar();
	ret = pthread_create(&t1, NULL, threadFunc, NULL);
	if(ret)
	{
			printf("Thread creation error\n");
			return -1;
	}
	ret = pthread_join(t1, &s);
	if(ret)
	{
			printf("Thread join error\n");
			return -1;
	}
	return 0;
}
```
##### Before malloc in main thread
There is no heap segment yet
No per thread stack either as `thread1` has not yet been created
###### Output:
```
sploitfun@sploitfun-VirtualBox:~/ptmalloc.ppt/mthread$ ./mthread 
Welcome to per thread arena example::6501
Before malloc in main thread
...
sploitfun@sploitfun-VirtualBox:~/ptmalloc.ppt/mthread$ cat /proc/6501/maps
08048000-08049000 r-xp 00000000 08:01 539625     /home/sploitfun/ptmalloc.ppt/mthread/mthread
08049000-0804a000 r--p 00000000 08:01 539625     /home/sploitfun/ptmalloc.ppt/mthread/mthread
0804a000-0804b000 rw-p 00001000 08:01 539625     /home/sploitfun/ptmalloc.ppt/mthread/mthread
b7e05000-b7e07000 rw-p 00000000 00:00 0
```
##### After Malloc in Main Thread
The below output shows that the heap segment has been created
###### Output:
```
sploitfun@sploitfun-VirtualBox:~/ptmalloc.ppt/mthread$ ./mthread 
Welcome to per thread arena example::6501
Before malloc in main thread
After malloc and before free in main thread
...
sploitfun@sploitfun-VirtualBox:~/lsploits/hof/ptmalloc.ppt/mthread$ cat /proc/6501/maps
08048000-08049000 r-xp 00000000 08:01 539625     /home/sploitfun/ptmalloc.ppt/mthread/mthread
08049000-0804a000 r--p 00000000 08:01 539625     /home/sploitfun/ptmalloc.ppt/mthread/mthread
0804a000-0804b000 rw-p 00001000 08:01 539625     /home/sploitfun/ptmalloc.ppt/mthread/mthread
0804b000-0806c000 rw-p 00000000 00:00 0          [heap]
b7e05000-b7e07000 rw-p 00000000 00:00 0 
```

After the heap segment is created, it lies at `0804b000-0806c000`, just above the data segment.
* This shows that the heap memory *was indeed* created by increasing the program break location using a `brk` syscall
Even though the user only requested `1000 bytes` of space, a heap memory of size `132 kb` was created.
* This contiguous reigon of heap memory is called an *arena*
	* This one is created by the `main` thread, so it's the `main arena`
* Further allocation requests will use this arena until it runs out of space
	* After that, it can grow by increasing the program break location
##### After free in main thread
In the below output, we can see when the allocated memory region is freed, the memory behind it isn't immediately released to the OS
###### Output:
```
sploitfun@sploitfun-VirtualBox:~/ptmalloc.ppt/mthread$ ./mthread 
Welcome to per thread arena example::6501
Before malloc in main thread
After malloc and before free in main thread
After free in main thread
...
sploitfun@sploitfun-VirtualBox:~/lsploits/hof/ptmalloc.ppt/mthread$ cat /proc/6501/maps
08048000-08049000 r-xp 00000000 08:01 539625     /home/sploitfun/ptmalloc.ppt/mthread/mthread
08049000-0804a000 r--p 00000000 08:01 539625     /home/sploitfun/ptmalloc.ppt/mthread/mthread
0804a000-0804b000 rw-p 00001000 08:01 539625     /home/sploitfun/ptmalloc.ppt/mthread/mthread
0804b000-0806c000 rw-p 00000000 00:00 0          [heap]
b7e05000-b7e07000 rw-p 00000000 00:00 0 
```

The allocated memory region (of size `1000 bytes`) is released only to the `glibc malloc` library
* `glibc malloc` adds the freed block to the *main arena*'s *bin*
	* In `glibc malloc`, freelist data structures are referred to as *bin*s
* Later, when the user requests memory
	* `glibc malloc` doesn't get new heap memory from the kernel
	* It tries to find a free block in *bin* first
		* Only gets memory from the kernel when no free blocks exist
##### Before Malloc in `thread1`
In the below output, we can see that there is no `thread1` heap segment, but now `thread1`'s per thread stack has been created/
###### Output:
```
sploitfun@sploitfun-VirtualBox:~/ptmalloc.ppt/mthread$ ./mthread 
Welcome to per thread arena example::6501
Before malloc in main thread
After malloc and before free in main thread
After free in main thread
Before malloc in thread 1
...
sploitfun@sploitfun-VirtualBox:~/ptmalloc.ppt/mthread$ cat /proc/6501/maps
08048000-08049000 r-xp 00000000 08:01 539625     /home/sploitfun/ptmalloc.ppt/mthread/mthread
08049000-0804a000 r--p 00000000 08:01 539625     /home/sploitfun/ptmalloc.ppt/mthread/mthread
0804a000-0804b000 rw-p 00001000 08:01 539625     /home/sploitfun/ptmalloc.ppt/mthread/mthread
0804b000-0806c000 rw-p 00000000 00:00 0          [heap]
b7604000-b7605000 ---p 00000000 00:00 0 
b7605000-b7e07000 rw-p 00000000 00:00 0          [stack:6594]
```
##### After malloc in `thread1`
We can see that `thread1`'s heap segment is created
```
sploitfun@sploitfun-VirtualBox:~/ptmalloc.ppt/mthread$ ./mthread 
Welcome to per thread arena example::6501
Before malloc in main thread
After malloc and before free in main thread
After free in main thread
Before malloc in thread 1
After malloc and before free in thread 1
...
sploitfun@sploitfun-VirtualBox:~/ptmalloc.ppt/mthread$ cat /proc/6501/maps
08048000-08049000 r-xp 00000000 08:01 539625     /home/sploitfun/ptmalloc.ppt/mthread/mthread
08049000-0804a000 r--p 00000000 08:01 539625     /home/sploitfun/ptmalloc.ppt/mthread/mthread
0804a000-0804b000 rw-p 00001000 08:01 539625     /home/sploitfun/ptmalloc.ppt/mthread/mthread
0804b000-0806c000 rw-p 00000000 00:00 0          [heap]
b7500000-b7521000 rw-p 00000000 00:00 0 
b7521000-b7600000 ---p 00000000 00:00 0 
b7604000-b7605000 ---p 00000000 00:00 0 
b7605000-b7e07000 rw-p 00000000 00:00 0          [stack:6594]
```

`Thread1` Heap Segment:
	Region: `b7500000` - `b7521000`
	Size: `132 KB`

We can tell that this heap segment was created using a `mmap` syscall
* the `main` thread uses `sbrk`
Even though the user requested only `1000  bytes`, `malloc` map a process address space of size `1 MB` out
* Out of that `1 MB`, only a `132 KB` region gets read-write permission
	* This `132 KB` is the heap memory for the thread
		* Called the *thread arena*