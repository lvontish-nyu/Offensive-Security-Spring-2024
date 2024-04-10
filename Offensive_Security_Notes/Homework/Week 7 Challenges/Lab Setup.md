
VM: `ubuntu20.04`]\
![[Pasted image 20240323154936.png]]
Looks like I have the right GLIBC version

## My version:
```
jnu@Offsec-Ubuntu-20:~/Desktop/7-Week/uaf/challenge$ /lib/x86_64-linux-gnu/libc.so.6
GNU C Library (Ubuntu GLIBC 2.31-0ubuntu9.14) stable release version 2.31.
Copyright (C) 2020 Free Software Foundation, Inc.
This is free software; see the source for copying conditions.
There is NO warranty; not even for MERCHANTABILITY or FITNESS FOR A
PARTICULAR PURPOSE.
Compiled by GNU CC version 9.4.0.
libc ABIs: UNIQUE IFUNC ABSOLUTE
For bug reporting instructions, please see:
<https://bugs.launchpad.net/ubuntu/+source/glibc/+bugs>.

jnu@Offsec-Ubuntu-20:~/Desktop/7-Week/uaf$ md5sum /usr/lib/x86_64-linux-gnu/libc-2.31.so
8f59e8ce960275f3d8bfc286ce41e934  /usr/lib/x86_64-linux-gnu/libc-2.31.so
```
## Downloaded Version:
```
jnu@Offsec-Ubuntu-20:~/Desktop/7-Week/uaf$ ./libc-2.31.so 
GNU C Library (Ubuntu GLIBC 2.31-0ubuntu9.14) stable release version 2.31.
Copyright (C) 2020 Free Software Foundation, Inc.
This is free software; see the source for copying conditions.
There is NO warranty; not even for MERCHANTABILITY or FITNESS FOR A
PARTICULAR PURPOSE.
Compiled by GNU CC version 9.4.0.
libc ABIs: UNIQUE IFUNC ABSOLUTE
For bug reporting instructions, please see:
<https://bugs.launchpad.net/ubuntu/+source/glibc/+bugs>.

jnu@Offsec-Ubuntu-20:~/Desktop/7-Week/uaf$ md5sum libc-2.31.so 
8f59e8ce960275f3d8bfc286ce41e934  libc-2.31.so
```

Even the hashes are the same!