Info from [Geeks for Geeks Syscall Page](https://www.geeksforgeeks.org/introduction-of-system-call/)
# Introduction
A Syscall is how the computer requests a service from the kernel of the OS it's operating on
* They allow user-level programs to request OS services
* Syscalls are the only entry point into the kernel system
	* All programs that need resources must use them
User program uses syscalls to request services from the OS such as accessing hardware resources or performing privileged operations
* Program requests services
* OS responds by launching system calls to fulfil requests
Syscalls are written in high-level languages (ex: C or Pascal) or Assembly
* If a high-level language is used, the OS may directly invoke the syscalls as they'll be predefined function

Syscalls are initiated when the program executes a specific instruction
* Triggers a switch to **kernel mode**
		Kernel mode allows the program to request a service from the OS
	* OS handles request
		* Performs whatever necessary operations
		* Returns the result to the program
System Calls are Essential
* Provide standardized way for programs to access system resources

# System Calls
## Provided Services
* Process creation and management
* Main memory management
* File Access, Directory, and File system management
* Device handling(I/O)
* Protection
* Networking, etc.
	* Process control: end, abort, create, terminate, allocate, and free memory.
	* File management: create, open, close, delete, read files,s, etc.
	* Device management
	* Information maintenance
	* Communication
## Features
Interface
* System calls provide a well-defined interface between user programs and the operating system.
* Programs make requests by calling specific functions, and the operating system responds by executing the requested service and returning a result.
Protection
*  System calls are used to access privileged operations that are not available to normal user programs.
* The operating system uses this privilege to protect the system from malicious or unauthorized access.
Kernel Mode
* When a system call is made, the program is temporarily switched from user mode to kernel mode.
* In kernel mode, the program has access to all system resources, including hardware, memory, and other processes.
Context Switching
* A system call requires a context switch, which involves saving the state of the current process and switching to the kernel mode to execute the requested service.
* This can introduce overhead, which can impact system performance.
Error Handling
* System calls can return error codes to indicate problems with the requested service.
* Programs must check for these errors and handle them appropriately.
Synchronization
- System calls can be used to synchronize access to shared resources, such as files or network connections.
- The operating system provides synchronization mechanisms, such as locks or semaphores, to ensure that multiple programs can access these resources safely.
## Advantages
Access to Hardware Resources
* System calls allow programs to access hardware resources such as disk drives, printers, and network devices.
Memory Management
* System calls provide a way for programs to allocate and deallocate memory, as well as access memory-mapped hardware devices
Process Management
* System calls allow programs to create and terminate processes, as well as manage inter-process communication.
Security
* System calls provide a way for programs to access privileged resources, such as the ability to modify system settings or perform operations that require administrative permissions.
Standardization
* System calls provide a standardized interface for programs to interact with the operating system, ensuring consistency and compatibility across different hardware platforms and operating system versions.
## How do they work?
* The user needs special resources
	* Sometimes programs need to do some special things which can’t be done without the permission of OS like reading from a file, writing to a file , getting any information from the hardware or requesting a space in memory.
* The program makes a system call request
	* There are special predefined instruction to make a request to the operating system. These instruction are nothing but just a “system call”. The program uses these system calls in its code when needed.
* The OS sees the system call
	* When the OS sees the system call then it recognizes that the program need help at this time so it temporarily stop the program execution and give all the control to special part of itself called ‘Kernel’ . Now ‘Kernel’ solve the need of program.
* OS performs the operations
	* Now the operating system perform the operation which is requested by program . Example : reading content from a file etc.
* The OS gives control back to the program
	* After performing the special operation, OS give control back to the program for further execution of program .

# Syscall Examples
|Process|Windows|Linux|
|---|---|---|
|Process Control|CreateProcess()|Fork()|
||ExitProcess()|Exit()|
||WaitForSingleObject()|Wait()|
|File manipulation|CreateFile()|Open()|
||ReadFile()|Read()|
||WriteFile()|Write()|
|||Close()|
|Device Management|SetConsoleMode()|Ioctl()|
||ReadConsole()|Read()|
||WriteConsole()|Write()|
|Information Maintenance|GetCurrentProcessID()|Getpid()|
||SetTimer()|Alarm()|
||Sleep()|Sleep()|
|Communication|CreatePipe()|Pipe()|
||CreateFileMapping()|Shmget()|
||MapViewOfFile()|Mmap()|
|Protection|SetFileSecurity()|Chmod()|
||InitializeSecurityDescriptor()|Umask()|
||SetSecurityDescriptorgroup()|Chown()|
### Calls
#### `open()`
Accessing a file on a file system is possible with the open() system call. It gives the file resources it needs and a handle the process can use. A file can be opened by multiple processes simultaneously or just one process. Everything is based on the structure and file system.
#### `read()`
Data from a file on the file system is retrieved using it. In general, it accepts three arguments:
1) A description of a file.
2) A buffer for read data storage.
3) How many bytes should be read from the file
Before reading, the file to be read could be identified by its file descriptor and `opened` using the `open()` function.
#### `wait()`
In some systems, a process might need to hold off until another process has finished running before continuing. When a parent process creates a child process, the execution of the parent process is halted until the child process is complete. The parent process is stopped using the `wait()` system call. The parent process regains control once the child process has finished running.
#### `write()`
 Data from a user buffer is written using it to a device like a file. A program can produce data in one way by using this system call. generally, there are three arguments:
1) A description of a file.
2) A reference to the buffer where data is stored.
3) The amount of data that will be written from the buffer in bytes.
#### `fork()`
The `fork()` system call is used by processes to create copies of themselves. It is one of the methods used the most frequently in operating systems to create processes. When a parent process creates a child process, the parent process’s execution is suspended until the child process is finished. The parent process regains control once the child process has finished running.
#### `exit()`
A system call called `exit()` is used to terminate a program. In environments with multiple threads, this call indicates that the thread execution is finished. After using the `exit()` system function, the operating system recovers the resources used by the process.
## Syntax and Parameters
We need to pass parameters to the kernal.
### Ex: `open()`
```c
#include <fcntl.h>
int open(const char *pathname, int flags, mode_t mode);
```
**Parameters:** `pathname`, `flags`, `mode`
A couple things:
* Can't pass parameters directly like an ordinary function
* Different way to perform a function call in kernal mode
We can't perform the syscall in the normal address space created by the process.
* Stack isn't available to the kernel so we can't place the parameters there
**Ways to pass parameters**
1) Pass in registers
2) Pass the block address in a register
3) Push onto the stack (I thought we couldn't do that)

### Passing parameters in registers
* The simplest method
* Directly pass the params into the registers
* Number of parameters is limited by the number of registers
C code:
```c
// Passing parameters in registers. 
#include <fcntl.h>
#include <stdio.h>
int main()
{
    const char* pathname = "example.txt";
    int flags = O_RDONLY;
    mode_t mode = 0644;
 
    int fd = open(pathname, flags, mode);
  // in function call open(), we passed the parameters pathanme,flags,mode to the kernal directly
    if (fd == -1) {
        perror("Error opening file");
        return 1;
    }
    // File operations here...
    close(fd);
    return 0;
}
```
### Address of Block Passed as Parameter
* Useful when the # of parameters is greater than the # of registers
* Parameters are stored in an array or table
* This method is most commonly used in Linux
C Code:
```c
//Address of the block is passed as parameters
#include <stdio.h>
#include <fcntl.h>
int main() {
    const char *pathname = "example.txt";
    int flags = O_RDONLY;
    mode_t mode = 0644;
    int params[3];
          // Block of data(parameters) in array
    params[0] = (int)pathname;
    params[1] = flags;
    params[2] = mode;
    int fd = syscall(SYS_open, params);
          // system call
    if (fd == -1) {
        perror("Error opening file");
        return 1;
    }
    // File operations here...
    close(fd);
    return 0;
}
```
## Pushing Parameters in a Stack
I still don't understand if this works
* In this method parameters can be pushed in using the program and popped out using the operating system
* So the Kernal can easily access the data by retrieving information from the top of the stack.
C Code:
```c
//parameters are pushed into the stack
#include <stdio.h>
#include <fcntl.h>
#include <unistd.h>
int main() {
    const char *pathname = "example.txt";
    int flags = O_RDONLY;
    mode_t mode = 0644;
    int fd;
    asm volatile(
        "mov %1, %%rdi\n"
        "mov %2, %%rsi\n"
        "mov %3, %%rdx\n"
        "mov $2, %%rax\n"
        "syscall"
        : "=a" (fd)
        : "r" (pathname), "r" (flags), "r" (mode)
        : "%rdi", "%rsi", "%rdx"
    );
    if (fd == -1) {
        perror("Error opening file");
        return 1;
    }
    // File operations here...
    close(fd);
    return 0;
}
```
