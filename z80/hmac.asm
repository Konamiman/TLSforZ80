    extrn SHA256.INIT
    extrn SHA256.CONTINUE
    extrn SHA256.FINALIZE
    extrn SHA256.SINGLESTEP
	extrn SHA256.RUN

    module HMAC

;--- HMAC-SHA256 hashing routine for Z80
;    Algorithm specification: https://datatracker.ietf.org/doc/html/rfc2104
;
;    Depends on sha256.asm
;
;    Usage:
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

HMAC_SINGLESTEP:
	or	a
	jr	z,HMAC_INIT

	dec a
	jp	z,:SHA256.CONTINUE

	dec a
	jr	z,HMAC_FINALIZE

HMAC_ONESTEP:
	push	de
	push	bc
    push ix
	ex	de,hl
	call	HMAC_INIT
    pop hl
	pop	bc
	call	:SHA256.CONTINUE
	pop	de
	jp	HMAC_FINALIZE


	;--- Initialization:
	;    Hash (key xor ipad) and leave the hashing engine
	;    ready for hashing message chunks

HMAC_INIT:
	push	de	;Initialize zero padding for key
	ld	hl,HMAC_KEY
	ld	de,HMAC_KEY+1
	ld	(hl),0
	ld	bc,64-1
	ldir
	pop	de

    ld a,d
    or a
    jr nz,HMAC_LONGKEY
	ld	a,e
	cp 64+1
	jr	c,HMAC_SHORTKEY

	;* The key is longer than 64 bytes: hash it first to HMAC_KEY

HMAC_LONGKEY:
	push	iy

	push	iy
	pop	hl
	push	de
	pop	bc
	ld	de,HMAC_KEY
	call	:SHA256.SINGLESTEP

	pop	iy
	ld	de,HMAC_KEY
	jr	HMAC_DO_IPAD

	;* Copy the original key or the hashed one to HMAC_KEY

HMAC_SHORTKEY:
	ld	a,d
	or	e
	jr	z,HMAC_DO_IPAD	;Empty key?

	push	de
	pop	bc
	push	iy
	pop	hl
	ld	de,HMAC_KEY
	ldir

	;* Apply ipad

HMAC_DO_IPAD:
	ld	hl,HMAC_KEY
	ld	b,64
HMAC_IPAD_LOOP:
	ld	a,(hl)
	xor	36h
	ld	(hl),a
	inc	hl
	djnz	HMAC_IPAD_LOOP
	
	;* Initialize the hashing procedure, then hash the processed key

	call	:SHA256.INIT

	ld	hl,HMAC_KEY
	ld	bc,64
	jp	:SHA256.CONTINUE

	
	;--- Finalization:
	;    Finish the internal hash, then hash (key xor opad) || (internal hash)

HMAC_FINALIZE:
	push	de

	ld	de,HMAC_INTERNAL
	call	:SHA256.FINALIZE

	;* Xor the key with opad (5Ch).
	;  Since the key was already XORed with ipad (36h),
	;  we xor with (ipad xor opad) = 6Ah.

HMAC_DO_OPAD:
	ld	hl,HMAC_KEY
	ld	b,64
HMAC_OPAD_LOOP:
	ld	a,(hl)
	xor	6Ah
	ld	(hl),a
	inc	hl
	djnz	HMAC_OPAD_LOOP

	;* Initialize the hashing procedure, then hash the processed key

	xor	a
	call	:SHA256.SINGLESTEP

	ld	a,1
	ld	hl,HMAC_KEY
	ld	bc,64
	call	:SHA256.RUN

	;* Finally, hash the internal hash

	ld	a,1
	ld	hl,HMAC_INTERNAL
	ld	bc,32
	ld	b,0
	call	:SHA256.RUN

	pop	de
	ld	a,2
	jp	:SHA256.RUN
	

;----------------------------------------
; Data area 
;----------------------------------------

HMAC_KEY:	defs	64
HMAC_INTERNAL:	defs	32

    endmod

	end
