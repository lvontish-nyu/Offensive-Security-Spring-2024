![[Pasted image 20240202181030.png]]
Flag: `flag{gl4d_you_d1dnt_n33d_to_p4rs3_w3ird_f0rmats_huh}`
# Step one, lets be basic and use "strings"
```
$ strings numerix
/lib64/ld-linux-x86-64.so.2
mgUa
__cxa_finalize
fgets
__libc_start_main
fopen
strtol
setvbuf
stdout
puts
stdin
__stack_chk_fail
printf
libc.so.6
GLIBC_2.4
GLIBC_2.2.5
GLIBC_2.34
_ITM_deregisterTMCloneTable
__gmon_start__
_ITM_registerTMCloneTable
PTE1
u+UH
flag.txt
Here's your flag, friend: %s
ERROR: no flag found. If you're getting this error on the remote system, please message the admins. If you're seeing this locally, run it on the remote system! You solved the challenge, and need to get the flag from there!
HEY!! I forgot my favorite numbers...
Can you get them from my diary?
What's my favoritest number?
No! No! No! That's not right!
What's my second most favorite number?
What? NO! Try again!!
Ok, you're pretty smart! What's the next one?
Ugh, ok, listen, you really need to hit the books...
YEAAAAAAAAAH you're doing GREAT! One more!
Darn, so close too...
Awwwwww yeah! You did it!
:*3$"
GCC: (Ubuntu 11.4.0-1ubuntu1~22.04) 11.4.0
Scrt1.o
__abi_tag
crtstuff.c
deregister_tm_clones
__do_global_dtors_aux
completed.0
__do_global_dtors_aux_fini_array_entry
frame_dummy
__frame_dummy_init_array_entry
numerix.c
__FRAME_END__
_DYNAMIC
__GNU_EH_FRAME_HDR
_GLOBAL_OFFSET_TABLE_
__libc_start_main@GLIBC_2.34
_ITM_deregisterTMCloneTable
stdout@GLIBC_2.2.5
puts@GLIBC_2.2.5
stdin@GLIBC_2.2.5
_edata
_fini
__stack_chk_fail@GLIBC_2.4
printf@GLIBC_2.2.5
fgets@GLIBC_2.2.5
get_number
__data_start
__gmon_start__
strtol@GLIBC_2.2.5
__dso_handle
_IO_stdin_used
_end
__bss_start
main
setvbuf@GLIBC_2.2.5
fopen@GLIBC_2.2.5
print_flag
__TMC_END__
_ITM_registerTMCloneTable
__cxa_finalize@GLIBC_2.2.5
_init
.symtab
.strtab
.shstrtab
.interp
.note.gnu.property
.note.gnu.build-id
.note.ABI-tag
.gnu.hash
.dynsym
.dynstr
.gnu.version
.gnu.version_r
.rela.dyn
.rela.plt
.init
.plt.got
.plt.sec
.text
.fini
.rodata
.eh_frame_hdr
.eh_frame
.init_array
.fini_array
.dynamic
.data
.bss
.comment

```

When that didn't get me anything good I opened it up in Ghidra
Yay, the answers are here!

Full, unedited Main method:
```
undefined8 main(EVP_PKEY_CTX *param_1)

{
  int iVar1;
  uint uVar2;
  long lVar3;
  undefined8 uVar4;
  
  init(param_1);
  puts("HEY!! I forgot my favorite numbers...");
  puts("Can you get them from my diary?");
  puts("What\'s my favoritest number?");
  lVar3 = get_number();
  if (lVar3 == 0xdeadbeef) {
    puts("What\'s my second most favorite number?");
    iVar1 = get_number();
    if (iVar1 == 0x539) {
      puts("Ok, you\'re pretty smart! What\'s the next one?");
      lVar3 = get_number();
      if (lVar3 == 0xc0def001337beef) {
        puts("YEAAAAAAAAAH you\'re doing GREAT! One more!");
        uVar2 = get_number();
        if ((uVar2 & 0xf0f0f0f0) == 0xd0d0f0c0) {
          puts("Awwwwww yeah! You did it!");
          print_flag();
          uVar4 = 0;
        }
        else {
          puts("Darn, so close too...");
          uVar4 = 1;
        }
      }
      else {
        puts("Ugh, ok, listen, you really need to hit the books...");
        uVar4 = 1;
      }
    }
    else {
      puts("What? NO! Try again!!");
      uVar4 = 1;
    }
  }
  else {
    puts("No! No! No! That\'s not right!");
    uVar4 = 1;
  }
  return uVar4;
}
```

So we need to enter their favorite number:

Interesting....
```
$ ./numerix
HEY!! I forgot my favorite numbers...
Can you get them from my diary?
What's my favoritest number?
0xdeadbeef
No! No! No! That's not right!
```

So it calls get_number: Original function code here:
```
void get_number(void)

{
  long in_FS_OFFSET;
  char local_98 [136];
  long local_10;
  
  local_10 = *(long *)(in_FS_OFFSET + 0x28);
  fgets(local_98,0x80,stdin);
  strtol(local_98,(char **)0x0,10);
  if (local_10 != *(long *)(in_FS_OFFSET + 0x28)) {
                    /* WARNING: Subroutine does not return */
    __stack_chk_fail();
  }
  return;
}
```

which...does not return anything....okay so maybe the value is the memory pointer...boy I fuckign hope not

Oh thank god, I just had to input DEADBEEF in decimal

So the numbers are:
`0xdeadbeef` = `3735928559`
`0x539` = `1337`
`0xc0def001337beef` = `868613086753832687`
And the last one is a binary and:
	`if ((uVar2 & 0xf0f0f0f0) == 0xd0d0f0c0)`
	`0xf0f0f0f0`= `4042322160`
	`0xd0d0f0c0` = `3503354048`

so in binary, we have our guess and 0xf0f0f0f0
The & operation compares each bit and returns 1 if they're both 1s and 0's otherwise I think

1111 0000 1111 0000 1111 0000 1111 0000
1101 1111 1101 1111 1111 1111 1100 1111

1101 0000 1101 0000 1111 0000 1100 0000


so 1101 1111 1101 1111 1111 1111 1100 1111 should work
0xDFDFFFCF
3755999183



11011111110111111111111111001111
11110000111100001111000011110000



Trying again 
```
1101 0000 1101 0000 1111 0000 1100 0000
1111 0000 1111 0000 1111 0000 1111 0000 = 0xf0f0f0f0
ANDED TOGETHER MAKE
1101 0000 1101 0000 1111 0000 1100 0000 = 0xd0d0f0c0
```

Answer could also be `1101 0000 1101 0000 1111 0000 1100 0000`
This = 0xD0D0F0C0 and 3503354048


Local Run:
```
$ ./numerix
HEY!! I forgot my favorite numbers...
Can you get them from my diary?
What's my favoritest number?
3735928559
What's my second most favorite number?
1337
Ok, you're pretty smart! What's the next one?
868613086753832687
YEAAAAAAAAAH you're doing GREAT! One more!
3503354048
Awwwwww yeah! You did it!
ERROR: no flag found. If you're getting this error on the remote system, please message the admins. If you're seeing this locally, run it on the remote system! You solved the challenge, and need to get the flag from there!
```


Now remote:
```
$ nc offsec-chalbroker.osiris.cyber.nyu.edu 1246
HEY!! I forgot my favorite numbers...
Can you get them from my diary?
What's my favoritest number?
3735928559
What's my second most favorite number?
1337
Ok, you're pretty smart! What's the next one?
868613086753832687
YEAAAAAAAAAH you're doing GREAT! One more!
3503354048
Awwwwww yeah! You did it!
Here's your flag, friend: flag{gl4d_you_d1dnt_n33d_to_p4rs3_w3ird_f0rmats_huh}

```

Yay!


Functions:
![[Pasted image 20240202185619.png]]

Renamed `main` function:
```
 undefined8 main(EVP_PKEY_CTX *param_1)

{
  int Guess2;
  uint Guess3;
  long Guess1;
  undefined8 Success;
  
  init(param_1);
  puts("HEY!! I forgot my favorite numbers...");
  puts("Can you get them from my diary?");
  puts("What\'s my favoritest number?");
  Guess1 = get_number();
  if (Guess1 == 0xdeadbeef) {
    puts("What\'s my second most favorite number?");
    Guess2 = get_number();
    if (Guess2 == 0x539) {
      puts("Ok, you\'re pretty smart! What\'s the next one?");
      Guess1 = get_number();
      if (Guess1 == 0xc0def001337beef) {
        puts("YEAAAAAAAAAH you\'re doing GREAT! One more!");
        Guess3 = get_number();
        if ((Guess3 & 0xf0f0f0f0) == 0xd0d0f0c0) {
          puts("Awwwwww yeah! You did it!");
          print_flag();
          Success = 0;
        }
        else {
          puts("Darn, so close too...");
          Success = 1;
        }
      }
      else {
        puts("Ugh, ok, listen, you really need to hit the books...");
        Success = 1;
      }
    }
    else {
      puts("What? NO! Try again!!");
      Success = 1;
    }
  }
  else {
    puts("No! No! No! That\'s not right!");
    Success = 1;
  }
  return Success;
}
```

Print flag:
```
 __stream = fopen("flag.txt","r")
  if (__stream == (FILE *)0x0) {
    puts(
        "ERROR: no flag found. If you\'re getting this error on the remote system, please message th e admins. If you\'re seeing this locally, run it on the remote system! You solved the challe nge, and need to get the flag from there!"
        );
  }
  else {
    fgets(local_98,0x80,__stream);
    printf("Here\'s your flag, friend: %s\n",local_98);
  }
```