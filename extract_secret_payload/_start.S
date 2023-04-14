
.extern main

_start:

  // copy binary to the correct position
  mov r0, pc
  mvn r1, #0xff
  and r0, r1
  ldr r1, =_start
  cmp r0, r1
  beq _bss_zero
  ldr r1, =_start
  ldr r2, =_BSS_LOW
_copy_loop:
  ldr r3, [r0], #4
  str r3, [r1], #4
  cmp r1, r2
  blt _copy_loop
  ldr r0, =_bss_zero
  bx r0

  // zero bss section
_bss_zero:
  mov r0, #0
  mov r1, #0
  ldr r2, =_BSS_LOW
  ldr r3, =_BSS_HIGH
_bss_zero_loop:
  strd r0, r1, [r2], #8
  cmp r3, r4
  blt _bss_zero_loop
  
  // setup stack
  ldr sp, =_STACK_HIGH

  // call main
  blx main

_end:
  b _end


