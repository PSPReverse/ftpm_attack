
SECTIONS
{
  . = 0x100;
  .text ALIGN(0x10): { *(.text) }
  .data ALIGN(0x20) : { *(.data) }

  _BSS_LOW = .;
  .bss ALIGN(0x10) : { *(.bss) }
  _BSS_HIGH = .;

  . = 0x8000;
  _STACK_LOW = .;
  . += 0x8000;
  _STACK_HIGH = .;

}
