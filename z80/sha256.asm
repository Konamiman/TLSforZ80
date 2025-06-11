    title	TLS for Z80 by Konamiman
	subttl	SHA256 hashing

    name('SHA256')

.COMMENT \

This module implements the SHA256 hash.
Algorithm specification: https://datatracker.ietf.org/doc/html/rfc6234

See the comment for the RUN routine.

\

    public SHA256.RUN
    public SHA256.HASH_OF_EMPTY
    public SHA256.SAVE_STATE
    public SHA256.RESTORE_STATE

    .relab

    module SHA256

;--- SHA256 hashing engine for Z80
;
;    To hash a short message in one single step, call SHA256 with these parameters:
;    A  = 3
;    HL = Address of message to hash
;    BC = Length of message in bytes
;    DE = Address for the generated 32-byte hash
;
;    To hash a message in blocks (because it does not fit in the available memory,
;    or because you don't have the whole message available in advance):
;
;    1. Call SHA256 with A=0 to initialize the hashing procedure.
;    2. For each message block call the routine with these parameters:
;       A  = 1
;       HL = Address of the block
;       BC = Length of the block (may be anything, even zero)
;    3. After all the blocks are processed, retrieve the hash by calling
;       SHA256 with these parameters:
;       A  = 2
;       DE = Address for the generated 32-byte hash
;
;    See also SAVE_STATE and RESTORE STATE.

RUN:
    or	a
    jr	z,INIT

    dec	a
    jp	z,CONTINUE

    dec	a
    jr	z,FINALIZE


    ;--- Single step hashing

SINGLESTEP:
    push de
    push hl
    push bc
    call INIT
    pop bc
    pop hl
    call CONTINUE
    pop de
    jp FINALIZE


    ;--- Hashing initialization

INIT:
    ld hl,INITIAL_H
    ld de,H0
    ld bc,INITIAL_H_END-INITIAL_H
    ldir

    ld hl,STATE_START
    ld de,STATE_START+1
    ld bc,STATE_END-STATE_START-1
    ld (hl),0
    ldir

    ld hl,BUFFER
    ld (BUFFER_PNT),hl

    ret


    ;--- Hashing finalization,
    ;    copies the computed hash to DE

FINALIZE:
    push	de  ;Destination address for the generated 32-byte hash

    ;* Calculate how much padding must be added

    ld	a,(TOTAL_LEN)
    and	3Fh
    sub	56
    neg
    and	3Fh	
    or	a
    jr	nz,FINALIZE_OKPAD
    ld	a,64
FINALIZE_OKPAD:
	;Here A = number of padding bytes to add

    ;* Hash any remaining buffered data and the padding (not including the length)

    ld	c,a
    ld	b,0
    ld	hl,ZERO_PAD
    call	CONTINUE_2

    ;* Convert total length in bytes to length in bits

    ld ix,TOTAL_LEN
    ld	b,3
FINALIZE_LENBITS:
    sla	(ix)
    rl	(ix+1)
    rl	(ix+2)
    rl	(ix+3)
    djnz	FINALIZE_LENBITS

    ;* Convert total length to big endian

    ld ix,TOTAL_LEN
    ld	d,(ix)
    ld	e,(ix+1)
    ld	(ix+7),d
    ld	(ix+6),e
    ld	d,(ix+2)
    ld	e,(ix+3)
    ld	(ix+5),d
    ld	(ix+4),e
    ld	(ix),0
    ld	(ix+1),0
    ld	(ix+2),0
    ld	(ix+3),0

    ;* Hash any remaining buffered data and the length

    ld hl,TOTAL_LEN
    ld	bc,8
    call CONTINUE_2

    ;* Copy the final hash to its destination (H0 - H7)

    ld hl,H0
    pop de
    ld bc,8*4
    ldir

    ret


    ;--- Continue hashing, buffers or processes a block of data.
    ;    Input: HL = Address of data block, BC = Block length

CONTINUE:
    ;* Update total length (increase by BC)

	push	hl
    ld hl,(TOTAL_LEN)
	add	hl,bc
    ld (TOTAL_LEN),hl
    ld hl,(TOTAL_LEN+2)
	ld	de,0
	adc	hl,de
    ld (TOTAL_LEN+2),hl
    pop	hl

CONTINUE_2:
	ld	(DATA_PNT),hl
	ld	(DATA_LEN),bc

	;* If buffered block length plus current block length
	;  is less than one full block (64 bytes), we don't have enough
    ;  bytes to proces, then simply copy the current block to the temporary block buffer

CONTINUE_LOOP:
	ld	bc,(DATA_LEN)

	ld	a,b	;No more data left?
	or	c
	ret	z

	ld	hl,(BUFFER_LEN)
	add	hl,bc   ;HL = Length of total available data (buffered + current)
    ld a,h
    or a
    jr nz,CONTINUE_LOOP_2
    ld a,l
    cp 64
	jr	nc,CONTINUE_LOOP_2

	ld	(BUFFER_LEN),a
	ld	hl,(DATA_PNT)
    ld de,(BUFFER_PNT)
	ldir
    ld (BUFFER_PNT),de
    ret

    ;* We have enough data to process.
    ;  If there's data in the temporary buffer,
    ;  fill it with current data up to 64 bytes
    ;  and process it; otherwise jump straight
    ;  to processing the current data.

CONTINUE_LOOP_2:
    ld a,(BUFFER_LEN)
    or a
    jr z,PROCESS_DATA_BLOCK

    ld	hl,64
	ld	de,(BUFFER_LEN)
	or	a
	sbc	hl,de	
	push	hl
	pop	bc	;Now BC = Space remaining in block buffer

    ld	hl,(DATA_PNT)
	ld	de,(BUFFER_PNT)
    push bc
	ldir
    pop bc
	ld	(DATA_PNT),hl
    ld hl,(DATA_LEN)
    or a
    sbc hl,bc
    ld (DATA_LEN),hl

    ld hl,BUFFER
    call PROCESS_BLOCK

    xor a
    ld	(BUFFER_LEN),a
    ld hl,BUFFER
    ld (BUFFER_PNT),hl
    jr CONTINUE_LOOP

PROCESS_DATA_BLOCK:
    ld hl,(DATA_PNT)
    push hl
    call PROCESS_BLOCK
    pop hl
    ld bc,64
    or a
    add hl,bc
    ld (DATA_PNT),hl
    ld hl,(DATA_LEN)
    or a
    sbc hl,bc
    ld (DATA_LEN),hl
    jr CONTINUE_LOOP


    ;--- Process the 64 byte block pointed by HL

PROCESS_BLOCK:

    ; * For t = 0 to 15 - Wt = M(i)t

    ld de,W
    ld bc,16*4
    ldir

_PROCESS_BLOCK_AFTER_INIT_W0_15:

    ; * For t = 16 to 63
    ;     Wt = SSIG1(W(t-2)) + W(t-7) + SSIG0(w(t-15)) + W(t-16)
    ;     SSIG0(x) = ROTR^7(x) XOR ROTR^18(x) XOR SHR^3(x)
    ;     SSIG1(x) = ROTR^17(x) XOR ROTR^19(x) XOR SHR^10(x)

    ld ix,W+16*4
    ld iy,T1
    ld b,64-16
PROCESS_INITW_LOOP:

    ;>>> Calculate SSIG0(w(t-15))

    ; HLDE = W(t-15)

    ld h,(ix-15*4)
    ld l,(ix-15*4+1)
    ld d,(ix-15*4+2)
    ld e,(ix-15*4+3)
   
_PROCESS_BLOCK_BEFORE_ROTR7:

    ; T1 = ROTR^7(HLDE) = ROTL^1(HLDE), save as EHLD:
    ; .......0 .......1 .......2 .......3    HLDE
    ; ......0. ......1. ......2. ......3.    ROTL^1(HLDE)
    ; ......3. ......0. ......1. ......2.    EHLD

    push hl
    push de

    sla	e
	rl	d
	rl	l
	rl	h
	jr	nc,$+4
	set	0,e

    ld (iy),e
    ld (iy+1),h
    ld (iy+2),l
    ld (iy+3),d

    pop de
    pop hl

_PROCESS_BLOCK_AFTER_ROTR7:

    ; T2 = ROTR^18(HLDE) = ROTR^2(HLDE), save as DEHL:
    ; .......0 .......1 .......2 .......3    HLDE
    ; .3...... .0...... .1...... .2......    ROTR^2(HLDE)
    ; .1...... .2...... .3...... .0......    DEHL

    push hl
    push de

    srl	h
	rr	l
	rr	d
	rr	e
    jr	nc,$+4
	set	7,h
    srl	h
	rr	l
	rr	d
	rr	e
    jr	nc,$+4
	set	7,h

    ld (iy+4),d
    ld (iy+4+1),e
    ld (iy+4+2),h
    ld (iy+4+3),l

_PROCESS_BLOCK_AFTER_ROTR18:

    pop de
    pop hl

    ; HLDE = SHR^3(HLDE)

    srl	h
	rr	l
	rr	d
	rr	e
    srl	h
	rr	l
	rr	d
	rr	e
    srl	h
	rr	l
	rr	d
	rr	e

_PROCESS_BLOCK_AFTER_SHR3:

    ; HLDE = HLDE XOR T1 XOR T2

    ld a,h
    xor (iy)
    xor (iy+4)
    ld h,a
    ld a,l
    xor (iy+1)
    xor (iy+4+1)
    ld l,a
    ld a,d
    xor (iy+2)
    xor (iy+4+2)
    ld d,a
    ld a,e
    xor (iy+3)
    xor (iy+4+3)
    ld e,a

    ; Wt = HLDE, which is the result of SSIG0(w(t-15))

    ld (ix),h
    ld (ix+1),l
    ld (ix+2),d
    ld (ix+3),e

_PROCESS_BLOCK_AFTER_SSIG0:

    ;>>> Calculate SSIG1(w(t-2))

    ; HLDE = W(t-2)

    ld h,(ix-2*4)
    ld l,(ix-2*4+1)
    ld d,(ix-2*4+2)
    ld e,(ix-2*4+3)

_PROCESS_BLOCK_BEFORE_ROTR17:

    ; T1 = ROTR^17(HLDE) = ROTR^1(HLDE), save as DEHL:
    ; .......0 .......1 .......2 .......3    HLDE
    ; 3....... 0....... 1....... 2.......    ROTR^1(HLDE)
    ; 1....... 2....... 3....... 0.......    DEHL

    push hl
    push de

    srl	h
	rr	l
	rr	d
	rr	e
    jr	nc,$+4
    set	7,h

    ld (iy),d
    ld (iy+1),e
    ld (iy+2),h
    ld (iy+3),l

    pop de
    pop hl

_PROCESS_BLOCK_AFTER_ROTR17:

    ; T2 = ROTR^19(HLDE) = ROTR^3(HLDE), save as DEHL:
    ; .......0 .......1 .......2 .......3    HLDE
    ; ..3..... ..0..... ..1..... ..2.....    ROTR^3(HLDE)
    ; ..1..... ..2..... ..3..... ..0.....    DEHL

    push hl
    push de

    srl	h
	rr	l
	rr	d
	rr	e
    jr	nc,$+4
    set 7,h
    srl	h
	rr	l
	rr	d
	rr	e
    jr	nc,$+4
    set 7,h
    srl	h
	rr	l
	rr	d
	rr	e
    jr	nc,$+4
    set 7,h

    ld (iy+4),d
    ld (iy+4+1),e
    ld (iy+4+2),h
    ld (iy+4+3),l

    pop de
    pop hl

_PROCESS_BLOCK_AFTER_ROTR19:

    ; HLDE = SHR^10(HLDE) = SHR^2(HLDE), save as 0HLD:
    ; 4......0 .......1 .......2 .......3    HLDE
    ; ..4..... ..0..... ..1..... ..2.....    SHR^2(HLDE)
    ; ........ ..4..... ..0..... ..1.....    0HLD

    srl	h
	rr	l
	rr	d
	rr	e
    srl	h
	rr	l
	rr	d
	rr	e

    ld e,d
    ld d,l
    ld l,h
    ld h,0

_PROCESS_BLOCK_AFTER_SHR10:

    ; HLDE = HLDE XOR T1 XOR T2

    ld a,h
    xor (iy)
    xor (iy+4)
    ld h,a
    ld a,l
    xor (iy+1)
    xor (iy+4+1)
    ld l,a
    ld a,d
    xor (iy+2)
    xor (iy+4+2)
    ld d,a
    ld a,e
    xor (iy+3)
    xor (iy+4+3)
    ld e,a

_PROCESS_BLOCK_AFTER_SSIG1:

    ; Wt = Wt + HLDE, which is the result of SSIG1(w(t-2))

    push hl

    ld h,(ix+2)
    ld l,(ix+3)
    add hl,de
    ld (ix+2),h
    ld (ix+3),l

    pop hl

    ld d,(ix)
    ld e,(ix+1)
    adc hl,de
    ld (ix),h
    ld (ix+1),l

    ; Wt = Wt + W(t-7)

    push hl ;High 16 bits of current Wt

    ld h,(ix+2)
    ld l,(ix+3)
    ld d,(ix-7*4+2)
    ld e,(ix-7*4+3)
    add hl,de
    ld (ix+2),h
    ld (ix+3),l

    pop de

    ld h,(ix-7*4)
    ld l,(ix-7*4+1)
    adc hl,de
    ld (ix),h
    ld (ix+1),l

    ; Wt = Wt + W(t-16)

    push hl ;High 16 bits of current Wt

    ld h,(ix+2)
    ld l,(ix+3)
    ld d,(ix-16*4+2)
    ld e,(ix-16*4+3)
    add hl,de
    ld (ix+2),h
    ld (ix+3),l

    pop de

    ld h,(ix-16*4)
    ld l,(ix-16*4+1)
    adc hl,de
    ld (ix),h
    ld (ix+1),l

_PROCESS_BLOCK_AFTER_W:

    ;>>> Current Wt done, go to the next one

    inc ix
    inc ix
    inc ix
    inc ix

    dec b
    jp nz,PROCESS_INITW_LOOP

    ;* a-h = H0-H7

    ld hl,H0
    ld de,:SHA256.A
    ld bc,8*4
    ldir

_PROCESS_BLOCK_AFTER_INIT_A_H:

    ; * For t = 0 to 63
    ;     T1 = h + BSIG1(e) + CH(e,f,g) + Kt + Wt
    ;     BSIG1(x) = ROTR^6(x) XOR ROTR^11(x) XOR ROTR^25(x)
    ;     CH( x, y, z) = (x AND y) XOR ( (NOT x) AND z)

    ld b,64
    ld ix,W
    ld iy,K

PROCESS_HASH_COMP_LOOP:
    push iy
    ld iy,T1

    ;>>> Calculate T1 = BSIG1(e)

    ; HLDE = e

    ld hl,(E)
    ld a,h
    ld h,l
    ld l,a
    ld de,(E+2)
    ld a,e
    ld e,d
    ld d,a

    ; T1 = ROTR^6(HLDE) = ROTL^2(HLDE), save as EHLD:
    ; .......0 .......1 .......2 .......3    HLDE
    ; .....0.. .....1.. .....2.. .....3..    ROTL^2(HLDE)
    ; .....3.. .....0.. .....1.. .....2..    EHLD

    push hl
    push de

    sla	e
	rl	d
	rl	l
	rl	h
	jr	nc,$+4
	set	0,e
    sla	e
	rl	d
	rl	l
	rl	h
	jr	nc,$+4
	set	0,e

    ld (iy),e
    ld (iy+1),h
    ld (iy+2),l
    ld (iy+3),d

    pop de
    pop hl

_PROCESS_BLOCK_AFTER_ROTR6:

    ; T2 = ROTR^11(HLDE) = ROTR^3(HLDE), save as EHLD:
    ; .......0 .......1 .......2 .......3    HLDE
    ; ..3..... ..0..... ..1..... ..2.....    ROTR^1(HLDE)
    ; ..2..... ..3..... ..0..... ..1.....    EHLD

    push hl
    push de

    srl	h
	rr	l
	rr	d
	rr	e
    jr	nc,$+4
    set 7,h
    srl	h
	rr	l
	rr	d
	rr	e
    jr	nc,$+4
    set 7,h  
    srl	h
	rr	l
	rr	d
	rr	e
    jr	nc,$+4
    set 7,h

    ld (iy+4),e
    ld (iy+4+1),h
    ld (iy+4+2),l
    ld (iy+4+3),d

    pop de
    pop hl

_PROCESS_BLOCK_AFTER_ROTR11:

    ; HLDE = ROTR^25(HLDE) = ROTR^1(HLDE), save as LDEH:
    ; .......0 .......1 .......2 .......3    HLDE
    ; 3....... 0....... 1....... 2.......    ROTR^1(HLDE)
    ; 0....... 1....... 2....... 3.......    LDEH

    srl	h
	rr	l
	rr	d
	rr	e
    jr	nc,$+4
    set 7,h

    ld a,l
    ld l,d
    ld d,e
    ld e,h
    ld h,a

_PROCESS_BLOCK_AFTER_ROTR25:

    ; HLDE = HLDE XOR T1 XOR T2 = BSIG1(e)

    ld a,h
    xor (iy)
    xor (iy+4)
    ld h,a
    ld a,l
    xor (iy+1)
    xor (iy+4+1)
    ld l,a
    ld a,d
    xor (iy+2)
    xor (iy+4+2)
    ld d,a
    ld a,e
    xor (iy+3)
    xor (iy+4+3)
    ld e,a

_PROCESS_BLOCK_AFTER_BSIG1:

    ;>>> Add Kt, Wt and h to T1

    ; HLDE = HLDE + Wt

    push hl

    ld h,(ix+2)
    ld l,(ix+3) ;HL = Low(Wt)
    add hl,de   ;HL = Low(Wt) + Low(HLDE original)
    ex (sp),hl  ;(SP) = Low(Wt) + DE, HL = High(HLDE original)

    ld d,(ix)
    ld e,(ix+1)
    adc hl,de   ;HL = High(Wt) + High(HLDE original)

    pop de

_PROCESS_BLOCK_AFTER_PLUS_WT:

    ; HLDE = HLDE + Kt

    pop iy  ;Restore pointer to Wt

    push hl

    ld h,(iy+2)
    ld l,(iy+3)
    add hl,de
    ex (sp),hl

    ld d,(iy)
    ld e,(iy+1)
    adc hl,de

    pop de

_PROCESS_BLOCK_AFTER_PLUS_KT:

    ; HLDE = HLDE + h

    push hl

    ld hl,(H+2)
    ld a,h
    ld h,l
    ld l,a
    add hl,de
    ex (sp),hl

    ld de,(H)
    ld a,d
    ld d,e
    ld e,a
    adc hl,de

    pop de

_PROCESS_BLOCK_AFTER_PLUS_H:

    ; T1 = HLDE = BSIG1(e) + Wt + Kt

    ld a,h
    ld h,l
    ld l,a
    ld (T1),hl
    ld a,d
    ld d,e
    ld e,a
    ld (T1+2),de

_PROCESS_BLOCK_AFTER_SET_T1:

    ;>>> Calculate CH(e, f, g) = (e AND f) XOR ((NOT e) AND g)

    ; (SP) = high((NOT e) AND g)

    ld hl,(E)
    ld de,(G)
    ld a,h
    cpl
    and d
    ld c,a  ;Change to big endian while we're at it
    ld a,l
    cpl
    and e
    ld h,a
    ld l,c
    push hl

    ; HL = high(e and f)

    ld hl,(E)
    ld de,(F)
    ld a,h
    and d
    ld c,a  ;Change to big endian while we're at it
    ld a,l
    and e
    ld h,a
    ld l,c
    
    ; (SP) = high((e AND f) XOR ((NOT e) AND g))

    pop de  ; high((NOT e) AND g)
    ld a,h
    xor d
    ld h,a
    ld a,l
    xor e
    ld l,a
    push hl

    ; (SP) = low((NOT e) AND g)

    ld hl,(E+2)
    ld de,(G+2)
    ld a,h
    cpl
    and d
    ld c,a  ;Change to big endian while we're at it
    ld a,l
    cpl
    and e
    ld h,a
    ld l,c
    push hl

    ; HL = low(e and f)

    ld hl,(E+2)
    ld de,(F+2)
    ld a,h
    and d
    ld c,a  ;Change to big endian while we're at it
    ld a,l
    and e
    ld h,a
    ld l,c
    
    ; HL = low((e AND f) XOR ((NOT e) AND g))

    pop de  ; low((NOT e) AND g)
    ld a,h
    xor d
    ld h,a
    ld a,l
    xor e
    ld l,a
    
    ex de,hl
    pop hl  ;Now HLDE = CH(e, f, g)

_PROCESS_BLOCK_AFTER_CH:

    ;>>> T1 = T1 + HLDE = BSIG1(e) + Wt + Kt + CH(e,f,g) + h

    push hl

    ld hl,(T1+2)
    ld a,h
    ld h,l
    ld l,a
    add hl,de
    ld a,h
    ld h,l
    ld l,a
    ld (T1+2),hl

    pop hl

    ld de,(T1)
    ld a,d
    ld d,e
    ld e,a
    adc hl,de
    ld a,h
    ld h,l
    ld l,a
    ld (T1),hl

_PROCESS_BLOCK_AFTER_T1_COMPLETED:

    push iy
    ld iy,T1

    ;>>> Calculate T2 = BSIG0(a)

    ; HLDE = a

    ld hl,(A)
    ld a,h
    ld h,l
    ld l,a
    ld de,(A+2)
    ld a,e
    ld e,d
    ld d,a

    ; T2 = ROTR^2(HLDE)

    push hl
    push de

    srl	h
	rr	l
	rr	d
	rr	e
    jr	nc,$+4
    set 7,h
    srl	h
	rr	l
	rr	d
	rr	e
    jr	nc,$+4
    set 7,h  

    ld (iy+4),h
    ld (iy+4+1),l
    ld (iy+4+2),d
    ld (iy+4+3),e

    pop de
    pop hl

_PROCESS_BLOCK_AFTER_ROTR2:

    ; HLDE = ROTR^13(HLDE) = ROTR^5(HLDE), save as EHLD:
    ; .......0 .......1 .......2 .......3    HLDE
    ; .....3.. .....0.. .....1.. .....2..    ROTR^5(HLDE)
    ; .....2.. .....3.. .....0.. .....1..    EHLD

    push hl
    push de

    srl	h
	rr	l
	rr	d
	rr	e
    jr	nc,$+4
    set 7,h
    srl	h
	rr	l
	rr	d
	rr	e
    jr	nc,$+4
    set 7,h
    srl	h
	rr	l
	rr	d
	rr	e
    jr	nc,$+4
    set 7,h
    srl	h
	rr	l
	rr	d
	rr	e
    jr	nc,$+4
    set 7,h
    srl	h
	rr	l
	rr	d
	rr	e
    jr	nc,$+4
    set 7,h

    ;Skip rearranging since we're XORing right afterwards
    ;ld a,d
    ;ld d,l
    ;ld l,h
    ;ld h,e
    ;ld e,a

_PROCESS_BLOCK_AFTER_ROTR13:

    ; T2 = T2 XOR EHLD = ROTR^2(a) XOR ROTR^13(a)

    ld a,(iy+4)
    xor e
    ld (iy+4),a
    ld a,(iy+4+1)
    xor h
    ld (iy+4+1),a
    ld a,(iy+4+2)
    xor l
    ld (iy+4+2),a
    ld a,(iy+4+3)
    xor d
    ld (iy+4+3),a

    pop de
    pop hl

_PROCESS_BLOCK_AFTER_T2XOR:

    ; HLDE = ROTR^22(HLDE) = ROTL^2(HLDE), save as LDEH:
    ; .......0 .......1 .......2 .......3    HLDE
    ; .....0.. .....1.. .....2.. .....3..    ROTL^2(HLDE)
    ; .....1.. .....2.. .....3.. .....0..    LDEH

    sla	e
	rl	d
	rl	l
	rl	h
	jr	nc,$+4
	set	0,e
    sla	e
	rl	d
	rl	l
	rl	h
	jr	nc,$+4
	set	0,e

    ;Skip rearranging since we're XORing right afterwards
    ;ld a,h
    ;ld h,e
    ;ld e,d
    ;ld d,l
    ;ld l,a

_PROCESS_BLOCK_AFTER_ROTR22:

    ; T2 = T2 XOR LDEH = ROTR^2(a) XOR ROTR^13(a) XOR ROTR22(a) = BSIG0(a)

    ld a,(iy+4)
    xor l
    ld (iy+4),a
    ld a,(iy+4+1)
    xor d
    ld (iy+4+1),a
    ld a,(iy+4+2)
    xor e
    ld (iy+4+2),a
    ld a,(iy+4+3)
    xor h
    ld (iy+4+3),a

_PROCESS_BLOCK_AFTER_BSIG0:

    ;>>> Calculate HLDE = MAJ(a,b,c) = (a AND b) XOR (a AND c) XOR (b AND c)

    ld iy,:SHA256.A
    
    ; 1st byte

    ld a,(iy)    ;a
    and (iy+4)   ;a AND b
    ld c,a
    
    ld a,(iy)    ;a
    and (iy+4*2) ;a AND c
    xor c        ;(a AND b) XOR (a AND c)
    ld c,a

    ld a,(iy+4)  ;b
    and (iy+4*2) ;b AND c
    xor c        ;(a AND b) XOR (a AND c) XOR (b and c)

    ld h,a

    ; 2nd byte

    ld a,(iy+1)
    and (iy+4+1)
    ld c,a
    
    ld a,(iy+1)
    and (iy+4*2+1)
    xor c
    ld c,a

    ld a,(iy+4+1)
    and (iy+4*2+1)
    xor c

    ld l,a

    ; 3rd byte

    ld a,(iy+2)
    and (iy+4+2)
    ld c,a
    
    ld a,(iy+2)
    and (iy+4*2+2)
    xor c
    ld c,a

    ld a,(iy+4+2)
    and (iy+4*2+2)
    xor c

    ld d,a

    ; 4th byte

    ld a,(iy+3)
    and (iy+4+3)
    ld c,a
    
    ld a,(iy+3)
    and (iy+4*2+3)
    xor c
    ld c,a

    ld a,(iy+4+3)
    and (iy+4*2+3)
    xor c

    ld e,a

_PROCESS_BLOCK_AFTER_MAJ:

    ; >>> T2 = T2 + HLDE = BSIG0(a) + MAJ(a,b,c)

    push hl

    ld hl,(T2+2)
    ld a,h
    ld h,l
    ld l,a
    add hl,de
    ld a,h
    ld h,l
    ld l,a
    ld (T2+2),hl

    pop hl

    ld de,(T2)
    ld a,d
    ld d,e
    ld e,a
    adc hl,de
    ld a,h
    ld h,l
    ld l,a
    ld (T2),hl

_PROCESS_BLOCK_AFTER_T2_COMPLETED:

    ;>>> Update a-h

    ; h = g
    ; g = f
    ; f = e

    push bc
    ld hl,G+3
    ld de,H+3
    ld bc,4*3
    lddr
    pop bc

_PROCESS_BLOCK_AFTER_EFGH:

    ; e = d + T1

    ld hl,(D+2)
    ld a,h
    ld h,l
    ld l,a
    ld de,(T1+2)
    ld a,d
    ld d,e
    ld e,a
    add hl,de
    ld a,h
    ld h,l
    ld l,a
    ld (E+2),hl

    ld hl,(D)
    ld a,h
    ld h,l
    ld l,a
    ld de,(T1)
    ld a,d
    ld d,e
    ld e,a
    adc hl,de
    ld a,h
    ld h,l
    ld l,a
    ld (E),hl

_PROCESS_BLOCK_AFTER_E:

    ; d = c
    ; c = b
    ; b = a

    push bc
    ld hl,C+3
    ld de,D+3
    ld bc,4*3
    lddr
    pop bc

_PROCESS_BLOCK_AFTER_ABCD:

    ; a = T1 + T2

    ld hl,(T1+2)
    ld a,h
    ld h,l
    ld l,a
    ld de,(T2+2)
    ld a,d
    ld d,e
    ld e,a
    add hl,de
    ld a,h
    ld h,l
    ld l,a
    ld (A+2),hl

    ld hl,(T1)
    ld a,h
    ld h,l
    ld l,a
    ld de,(T2)
    ld a,d
    ld d,e
    ld e,a
    adc hl,de
    ld a,h
    ld h,l
    ld l,a
    ld (A),hl

_PROCESS_BLOCK_AFTER_A:

    ; >>> Main hash computation step completed

    pop iy ;Restore pointer to K
   
    inc ix  ;Next W
    inc ix
    inc ix
    inc ix
    inc iy  ;Next K
    inc iy
    inc iy
    inc iy

    dec b
    jp nz,PROCESS_HASH_COMP_LOOP

    ; >>> H(i)0 = a + H(i-1)0
    ;     ...
    ;     H(i)7 = h + H(i-1)7

    ld ix,:SHA256.A
    ld iy,H0
    ld b,8

PROCESS_H_LOOP:
    ld h,(ix+2)
    ld l,(ix+3)
    ld d,(iy+2)
    ld e,(iy+3)
    add hl,de
    ld (iy+2),h
    ld (iy+3),l

    ld h,(ix)
    ld l,(ix+1)
    ld d,(iy)
    ld e,(iy+1)
    adc hl,de
    ld (iy),h
    ld (iy+1),l

    inc ix
    inc ix
    inc ix
    inc ix
    inc iy
    inc iy
    inc iy
    inc iy

    djnz PROCESS_H_LOOP

_PROCESS_BLOCK_AFTER_END:

    ret


    ;--- Save the current hashing state.
    ;    This allows continuing a hashing process after having finished it:
    ;    1. Call SAVE_STATE
    ;    2. Call RUN with A=2
    ;    3. Call RESTORE_STATE
    ;    4. Keep calling RUN with A=1

SAVE_STATE:
    push hl
    push bc
    push de

    ld hl,STATE_START
    ld de,SAVED_STATE
    ld bc,STATE_END-STATE_START
    ldir

    ld hl,H0
    ld de,SAVED_H
    ld bc,INITIAL_H_END-INITIAL_H
    ldir
    
    ld hl,(BUFFER_PNT)
    ld (SAVED_BUFFER_PNT),hl

.POP_RET:
    pop de
    pop bc
    pop hl
    ret


    ;--- Restore the hashing state that was saved with SAVE_STATE.

RESTORE_STATE:
    push hl
    push bc
    push de

    ld hl,SAVED_STATE
    ld de,STATE_START
    ld bc,STATE_END-STATE_START
    ldir

    ld hl,SAVED_H
    ld de,H0
    ld bc,INITIAL_H_END-INITIAL_H
    ldir
    
    jr SAVE_STATE.POP_RET


;----------------------------------------
; Data area 
;----------------------------------------

; SHA256 hash of the empty string

HASH_OF_EMPTY:
    db 0e3h, 0b0h, 0c4h, 42h
    db 98h, 0fch, 1ch, 14h
    db 9ah, 0fbh, 0f4h, 0c8h
    db 99h, 6fh, 0b9h, 24h
    db 27h, 0aeh, 41h, 0e4h
    db 64h, 9bh, 93h, 4ch
    db 0a4h, 95h, 99h, 1bh
    db 78h, 52h, 0b8h, 55h

H0: ds 4
H1: ds 4
H2: ds 4
H3: ds 4
H4: ds 4
H5: ds 4
H6: ds 4
H7: ds 4

A: ds 4
B: ds 4
C: ds 4
D: ds 4
E: ds 4
F: ds 4
G: ds 4
H: ds 4

W: ds 64*4

STATE_START:

TOTAL_LEN: ds 8 ;Accumulated total message length in bytes (8 bytes)

T1: ds 4
T2: ds 4

BUFFER_LEN: dw 0 ;Number of bytes buffered in the temporary 64-bit block buffer (1 byte, dw on purpose)
BUFFER_PNT: dw 0 ;Pointer to continue filling the temporary 64-bit block buffer (2 bytes)
BUFFER: ds 64 ;Temporary 64-bit block buffer

DATA_LEN:	defw	0	;Length of block passed to CONTINUE, in bytes
DATA_PNT:	defw	0	;Pointer to the block passed to CONTINUE

STATE_END:

ZERO_PAD:	defb	80h	;Source for final padding
            defs	64-1

INITIAL_H:
    db 6ah, 09h, 0e6h, 67h
    db 0bbh, 67h, 0aeh, 85h
    db 3ch, 6eh, 0f3h, 72h
    db 0a5h, 4fh, 0f5h, 3ah
    db 51h, 0eh, 52h, 7fh
    db 9bh, 05h, 68h, 8ch
    db 1fh, 83h, 0d9h, 0abh
    db 5bh, 0e0h, 0cdh, 19h
INITIAL_H_END:

K:
    db 42h, 8ah, 2fh, 98h
    db 71h, 37h, 44h, 91h
    db 0b5h, 0c0h, 0fbh, 0cfh
    db 0e9h, 0b5h, 0dbh, 0a5h
    db 39h, 56h, 0c2h, 5bh
    db 59h, 0f1h, 11h, 0f1h
    db 92h, 3fh, 82h, 0a4h
    db 0abh, 1ch, 5eh, 0d5h
    db 0d8h, 07h, 0aah, 98h
    db 12h, 83h, 5bh, 01h
    db 24h, 31h, 85h, 0beh
    db 55h, 0ch, 7dh, 0c3h
    db 72h, 0beh, 5dh, 74h
    db 80h, 0deh, 0b1h, 0feh
    db 9bh, 0dch, 06h, 0a7h
    db 0c1h, 9bh, 0f1h, 74h
    db 0e4h, 9bh, 69h, 0c1h
    db 0efh, 0beh, 47h, 86h
    db 0fh, 0c1h, 9dh, 0c6h
    db 24h, 0ch, 0a1h, 0cch
    db 2dh, 0e9h, 2ch, 6fh
    db 4ah, 74h, 84h, 0aah
    db 5ch, 0b0h, 0a9h, 0dch
    db 76h, 0f9h, 88h, 0dah
    db 98h, 3eh, 51h, 52h
    db 0a8h, 31h, 0c6h, 6dh
    db 0b0h, 03h, 27h, 0c8h
    db 0bfh, 59h, 7fh, 0c7h
    db 0c6h, 0e0h, 0bh, 0f3h
    db 0d5h, 0a7h, 91h, 47h
    db 06h, 0cah, 63h, 51h
    db 14h, 29h, 29h, 67h
    db 27h, 0b7h, 0ah, 85h
    db 2eh, 1bh, 21h, 38h
    db 4dh, 2ch, 6dh, 0fch
    db 53h, 38h, 0dh, 13h
    db 65h, 0ah, 73h, 54h
    db 76h, 6ah, 0ah, 0bbh
    db 81h, 0c2h, 0c9h, 2eh
    db 92h, 72h, 2ch, 85h
    db 0a2h, 0bfh, 0e8h, 0a1h
    db 0a8h, 1ah, 66h, 4bh
    db 0c2h, 4bh, 8bh, 70h
    db 0c7h, 6ch, 51h, 0a3h
    db 0d1h, 92h, 0e8h, 19h
    db 0d6h, 99h, 06h, 24h
    db 0f4h, 0eh, 35h, 85h
    db 10h, 6ah, 0a0h, 70h
    db 19h, 0a4h, 0c1h, 16h
    db 1eh, 37h, 6ch, 08h
    db 27h, 48h, 77h, 4ch
    db 34h, 0b0h, 0bch, 0b5h
    db 39h, 1ch, 0ch, 0b3h
    db 4eh, 0d8h, 0aah, 4ah
    db 5bh, 9ch, 0cah, 4fh
    db 68h, 2eh, 6fh, 0f3h
    db 74h, 8fh, 82h, 0eeh
    db 78h, 0a5h, 63h, 6fh
    db 84h, 0c8h, 78h, 14h
    db 8ch, 0c7h, 02h, 08h
    db 90h, 0beh, 0ffh, 0fah
    db 0a4h, 50h, 6ch, 0ebh
    db 0beh, 0f9h, 0a3h, 0f7h
    db 0c6h, 71h, 78h, 0f2h

SAVED_STATE: ds STATE_END-STATE_START
SAVED_H: ds INITIAL_H_END-INITIAL_H
SAVED_BUFFER_PNT: dw 0

    endmod

    end
