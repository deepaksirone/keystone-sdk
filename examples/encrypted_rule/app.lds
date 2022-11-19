OUTPUT_ARCH( "riscv" )

SECTIONS 
{
  . = 0x00001000;
  .text : {
    *(.text._start)
    *(.text)
  }
  . = ALIGN(0x1000);
  .secure_code : {
    *(.secure_code)
    . = ALIGN(0x1000);
  }
  . = ALIGN(0x1000);
  .secure_data : {
    *(.secure_data)
    . = ALIGN(0x1000);
  }
  . = ALIGN(0x1000);
  .rodata : 
  { 
    *(.rdata)
    *(.rodata)
  }
  .data : { *(.data) }
  .bss : { *(.bss) }
  .debug : { *(.debug) }
  
  . = ALIGN(0x1000);
  .malloc_region : {
    __malloc_start = .;
    . = . + 4096*500;
    __malloc_zone_stop = .;
    . = ALIGN(0x1000);
    PROVIDE(__decrypt_buffer_start = .);
    . = . + MAX(SIZEOF(.secure_code), SIZEOF(.secure_data));
    PROVIDE(__decrypt_buffer_end = .);
  }

  _end = .;
}
