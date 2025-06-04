	cseg

  module FIZZBUZZ

DO: ld b,89
	ret
	jp DO

  endmod



print: macro xxx
    if 0
    push af
    push bc
    push de
    push hl
    push ix
    push iy
    ld e,"&xxx"
    ld c,2
    call 5
    pop iy
    pop ix
    pop hl
    pop de
    pop bc
    pop af
    endif
    endm
