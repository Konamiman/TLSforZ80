    title	TLS for Z80 by Konamiman
	subttl	HMAC algorithm

	name('HMAC')

.COMMENT \

This module implements the HMAC-SHA256 hashing.
Algorithm specification: https://datatracker.ietf.org/doc/html/rfc2104

See the comment for the RUN routine.

\

	public HMAC.RUN
	extrn SHA256.RUN

	.extroot

    module HMAC


;--- HMAC-SHA256 hashing routine
;    
;    To hash a short message in one single step, call the routine with these parameters:
;            A  = 3
;            IX = Address of message to digest
;            BC = Length of message in bytes
;            IY = Address of key
;            HL = Length of key
;            DE = Destination address for the hash
;    
;    To hash a message in chunks (because it does not fit in the available memory,
;    or because you don't have the whole message available in advance):
;    
;    1. Call the routine to initialize the hashing procedure with:
;       A = 0
;       IY = Address of key
;       DE = Length of key
;    2. For each message chunk call the routine with these parameters:
;       A  = 1
;       HL = Address of the chunk
;       BC = Length of the chunk (may be anything, even zero)
;    3. After all the chunks are processed, retrieve the hash by calling
;       the routine with these parameters:
;       A  = 2
;       DE = Address for the generated SHA256 32-byte hash

RUN:
	or	a
	jr	z,INIT

	cp 1
	jp	z,SHA256.RUN

	cp 2
	jr	z,FINALIZE

SINGLESTEP:
	push	de
	push	bc
    push ix
	ex	de,hl
	call	INIT
    pop hl
	pop	bc
	ld a,1
	call	SHA256.RUN
	pop	de
	jp	FINALIZE


	;--- Initialization:
	;    Hash (key xor ipad) and leave the hashing engine
	;    ready for hashing message chunks

INIT:
	push	de	;Initialize zero padding for key
	ld	hl,KEY
	ld	de,KEY+1
	ld	(hl),0
	ld	bc,64-1
	ldir
	pop	de

    ld a,d
    or a
    jr nz,LONGKEY
	ld	a,e
	cp 64+1
	jr	c,SHORTKEY

	;* The key is longer than 64 bytes: hash it first to KEY

LONGKEY:
	push	iy

	push	iy
	pop	hl
	push	de
	pop	bc
	ld	de,KEY
	ld a,3
	call	SHA256.RUN

	pop	iy
	ld	de,KEY
	jr	DO_IPAD

	;* Copy the original key or the hashed one to KEY

SHORTKEY:
	ld	a,d
	or	e
	jr	z,DO_IPAD	;Empty key?

	push	de
	pop	bc
	push	iy
	pop	hl
	ld	de,KEY
	ldir

	;* Apply ipad

DO_IPAD:
	ld	hl,KEY
	ld	b,64
IPAD_LOOP:
	ld	a,(hl)
	xor	36h
	ld	(hl),a
	inc	hl
	djnz	IPAD_LOOP
	
	;* Initialize the hashing procedure, then hash the processed key

	xor a
	call	SHA256.RUN

	ld	hl,KEY
	ld	bc,64
	ld a,1
	jp	SHA256.RUN

	
	;--- Finalization:
	;    Finish the internal hash, then hash (key xor opad) || (internal hash)

FINALIZE:
	push	de

	ld	de,INTERNAL
	ld a,2
	call	SHA256.RUN

	;* Xor the key with opad (5Ch).
	;  Since the key was already XORed with ipad (36h),
	;  we xor with (ipad xor opad) = 6Ah.

DO_OPAD:
	ld	hl,KEY
	ld	b,64
OPAD_LOOP:
	ld	a,(hl)
	xor	6Ah
	ld	(hl),a
	inc	hl
	djnz	OPAD_LOOP

	;* Initialize the hashing procedure, then hash the processed key

	xor a
	call	SHA256.RUN

	ld	a,1
	ld	hl,KEY
	ld	bc,64
	call	SHA256.RUN

	;* Finally, hash the internal hash

	ld	hl,INTERNAL
	ld	bc,32
	ld	b,0
	ld	a,1
	call	SHA256.RUN

	pop	de
	ld	a,2
	jp	SHA256.RUN
	

;----------------------------------------
; Data area 
;----------------------------------------

KEY:	defs	64
INTERNAL:	defs	32

    endmod

	end
