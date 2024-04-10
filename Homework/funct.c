undefined8 question3(void)

{
  long lVar1;
  uint uVar2;
  uint uVar3;
  undefined8 uVar4;
  long in_FS_OFFSET;
  int local_a4;
  
  lVar1 = *(long *)(in_FS_OFFSET + 0x28);
  local_a4 = 1;
  do {
    if (9 < local_a4) {
      uVar4 = 0;
LAB_0010159d:
      if (lVar1 != *(long *)(in_FS_OFFSET + 0x28)) {
                    /* WARNING: Subroutine does not return */
        __stack_chk_fail();
      }
      return uVar4;
    }
    uVar2 = get_number();
    uVar3 = get_number();
    if ((0xff < uVar2) || (0xff < uVar3)) {
      uVar4 = 1;
      goto LAB_0010159d;
    }
    if (local_a4 != (char)forestOfEwing[(ulong)uVar3 + (ulong)uVar2 * 0x100]) {
      uVar4 = 1;
      goto LAB_0010159d;
    }
    local_a4 = local_a4 + 1;
  } while( true );
}