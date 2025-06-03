        title	TLS for Z80 by Konamiman
	    subttl	AES-128-GCM algorithm implementation

.COMMENT \

Implementation of the AES-128-GCM encryption algorithm as specified in
https://nvlpubs.nist.gov/nistpubs/Legacy/SP/nistspecialpublication800-38d.pdf

Usage:

To encrypt:
  1. Call INIT passing the encryption key, IV and the additional data.
  2. Call ENCRYPT passing the data to encrypt.
     This can be called multiple times, however all times
     except for the last one the passed length must be a multiple of 16.
  3. Call FINISH to calculate and get the authentication tag.

To decrypt:
  1. Call INIT passing the encryption key, IV and the additional data.
  2. Call DECRYPT passing the data to decrypt.
     Like ENCRYPT, this can be called multiple times but with the same
     input length restrictions.

To get the auth tag of received encrypted data:
  Same as to encrypt, but call AUTHTAG instead of ENCRYPT passing the address
  of the encrypted block in IX (AUTHTAG too requires all blocks except the last one 
  to be multiples of 16 bytes).

\

    public AES_GCM.INIT
    public AES_GCM.ENCRYPT
    public AES_GCM.FINISH
    public AES_GCM.DECRYPT
    public AES_GCM.AUTHTAG
    extrn AES.INIT
    extrn AES.ENCRYPT
    extrn AES.DECRYPT

    module AES_GCM

    root AES.INIT
    root AES.ENCRYPT
    root AES.DECRIPT 


;--------------------------------------------------------------------
; Initialize the AES GCM engine.
;
; This must be invoked whenever a new set of data is to be encrypted
; or decrypted, or when starting the calculation of the auth tag
; for received encrypted data.
;
; Input:  HL = Pointer to the AES encryption key (16 bytes)
;         DE = Pointer to ICB (initialization vector) (12 bytes)
;         BC = Pointer to additional data (5 bytes)
;--------------------------------------------------------------------

INIT:
    push de
    push bc
    call AES.INIT
    
    pop bc
    pop hl
    push bc
    ld de,CB
    ld bc,12
    ldir

    ld hl,TMP
    ld de,TMP+1
    ld (hl),0
    ld bc,32-1
    ldir

    ld hl,TMP
    ld de,:AES_GCM.H
    call AES.ENCRYPT

    pop hl
    ld de,TMP
    ld bc,5
    ldir

    ld hl,0
    ld (CB+12),hl
    ld (LEN),hl
    inc h
    ld (CB+14),hl

    ;Start the GHASHing process for the auth tag with the additional data

    ld hl,TMP
    ld de,AES_GHASH_Y
    call MULT

    ret


;--------------------------------------------------------------------
; Encrypt a block of data using the AES GCM engine (GCTR function)
; and also calculate the auth tag.
;
; The routine can be called multiple times to encrypt or decrypt
; the data in chunks, but all chunks except for the last one
; need to have a length multiple of 16.
; After a non-multiple of 16 block is passed, INIT
; must be called again.
;
; Input:  HL = Pointer to the block of data to encrypt/decrypt
;         DE = Destination address for the encrypted/decrypted data
;         BC = Length of the passed data chunk
;              (the output will have the same length)
;--------------------------------------------------------------------

ENCRYPT:
    push de
    push bc

    call AES_GCTR

    pop bc
    pop ix

    ;Continue calculating GHASH for the passed data.
    ;Input: IX = Address of data block
    ;       BC = Size of data block

AUTHTAG:
    ld hl,(LEN)
    add hl,bc
    ld (LEN),hl
    jp AES_GHASH_MORE_LOOP

AES_GHASH_MORE_LOOP:
    ;If the remaining data length is zero, we're done.

    ld a,b
    or c
    ret z

    ;If the remaining data length is less than 16,
    ;copy it to the temp area with zeros appended,
    ;hash it from here and finish.

    ld a,b
    or a
    jr nz,AES_GHASH_MORE_NEXT

    ld a,c
    cp 16
    jr nc,AES_GHASH_MORE_NEXT

    push bc
    push ix
    
    ld hl,TMP
    ld de,TMP+1
    ld (hl),0
    ld bc,16-1
    ldir

    pop hl
    pop bc
    ld de,TMP
    ldir

    ld ix,TMP
    call AES_GHASH_STEP
_AES_GHASH_AFTER_LAST_STEP:
    ret

AES_GHASH_MORE_NEXT:
    push bc
    push ix
    call AES_GHASH_STEP
    pop ix

_AES_GHASH_AFTER_STEP:

    pop hl
    ld bc,16
    add ix,bc   ;Update pointer to data to hash
    or a
    sbc hl,bc   ;Update remaining length
    push hl
    pop bc

    jr AES_GHASH_MORE_LOOP


;--------------------------------------------------------------------
; Finish the encryption or auth tag calculation.
;
; Input:  HL = Destination address for the generated auth tag
;              (16 bytes)
;--------------------------------------------------------------------

FINISH:

    push hl

    ld hl,(LEN)
    add hl,hl   ;Convert to number of bits
    add hl,hl
    add hl,hl
    ld a,h
    ld h,l
    ld l,a
    ld (LEN),hl

    ld ix,ALL_LENS
    call AES_GHASH_STEP
_FINISH_AFTER_HASH_LENGTH:

    ld hl,0
    ld (CB+12),hl
    ld (CB+14),hl

    pop de
    ld hl,AES_GHASH_Y
    ld bc,16
    jp AES_GCTR


;---------------------------
; Auxiliary routines
;---------------------------

;--- GCTR algorithm, see ENCRYPT
;    for information of input size restrictions.
;    Input: HL = Address of input
;           BC = Length of input
;           DE = Address for output (16 bytes)

DECRYPT:
AES_GCTR:

    push bc

ENCRYPT_BLOCK:

    ;Increase CB and hash it

    push hl
    push de

    ld iy,CB+12
    ld h,(iy+2)
    ld l,(iy+3)
    ld de,1
    add hl,de
    ld (iy+2),h
    ld (iy+3),l
    ld h,(iy)
    ld l,(iy+1)
    dec e
    adc hl,de
    ld (iy),h
    ld (iy+1),l

    ld hl,CB
    ld de,CB_HASH
    call AES.ENCRYPT

    pop de
    pop hl

    ;Next block length is 16 unless total remaining length is less

    pop bc
    push bc
    ld a,b
    or a
    jr nz,ENCRYPT_16
    ld a,c
    cp 16+1
    jr nc,ENCRYPT_16
    ld b,c
    jr ENCRYPT_START_2
ENCRYPT_16:
    ld b,16

    ;Compose output by XORing the AES of current CB with the data

ENCRYPT_START_2:
    ld ix,CB_HASH
    ld c,b
    
ENCRYPT_LOOP:
    ld a,(hl)
    xor (ix)
    ld (de),a
    inc hl
    inc de
    inc ix
    djnz ENCRYPT_LOOP

    ;Decrease remaining length by the block size,
    ;and if it reaches zero, we're done.

    ex (sp),hl  ;Now HL = Remaining length, (SP) = Source pointer
    push de

    ld b,0  ;C is still the block length
    or a
    sbc hl,bc   ;HL = Updated remaining length

    ld a,h
    or l
    jr nz,ENCRYPT_NEXT

ENCRYPT_END:
    pop de
    pop hl
    ret

ENCRYPT_NEXT:
    pop de
    ex (sp),hl  ;Now HL = Source pointer, (SP) = Updated remaining length

    jr ENCRYPT_BLOCK


;--- AES-GCM multiplication by H, where H = AES128(16 zero bytes)
;    Input: HL = block to multiply
;           DE = Destination address

MULT:
    push de

    ld de,MULT_X
    ld bc,16
    ldir

    ld hl,:AES_GCM.H
    ld de,MULT_V
    ld bc,16
    ldir

    ld hl,MULT_Z
    ld de,MULT_Z+1
    ld (hl),0
    ld bc,16-1
    ldir

    ld c,16  ;Byte loop
    ld hl,MULT_X
    ld ix,MULT_V
    ld iy,MULT_Z
MULT_LOOP_BYTE:
    ld b,8  ;bit loop
    ld e,(hl)
MULT_LOOP_BIT:

    ;Zi+1 = Zi xor Vi, if Xi = 1

    sla e
    jp nc,MULT_NO_XOR_ZV

    ld a,(iy)
    xor (ix)
    ld (iy),a
    ld a,(iy+1)
    xor (ix+1)
    ld (iy+1),a
    ld a,(iy+2)
    xor (ix+2)
    ld (iy+2),a
    ld a,(iy+3)
    xor (ix+3)
    ld (iy+3),a    
    ld a,(iy+4)
    xor (ix+4)
    ld (iy+4),a    
    ld a,(iy+5)
    xor (ix+5)
    ld (iy+5),a    
    ld a,(iy+6)
    xor (ix+6)
    ld (iy+6),a
    ld a,(iy+7)
    xor (ix+7)
    ld (iy+7),a
    ld a,(iy+8)
    xor (ix+8)
    ld (iy+8),a
    ld a,(iy+9)
    xor (ix+9)
    ld (iy+9),a
    ld a,(iy+10)
    xor (ix+10)
    ld (iy+10),a
    ld a,(iy+11)
    xor (ix+11)
    ld (iy+11),a
    ld a,(iy+12)
    xor (ix+12)
    ld (iy+12),a
    ld a,(iy+13)
    xor (ix+13)
    ld (iy+13),a
    ld a,(iy+14)
    xor (ix+14)
    ld (iy+14),a
    ld a,(iy+15)
    xor (ix+15)
    ld (iy+15),a
MULT_NO_XOR_ZV:

    ;Vi+1 = Vi >> 1...

    srl (ix)
    rr (ix+1)
    rr (ix+2)
    rr (ix+3)
    rr (ix+4)
    rr (ix+5)
    rr (ix+6)
    rr (ix+7)
    rr (ix+8)
    rr (ix+9)
    rr (ix+10)
    rr (ix+11)
    rr (ix+12)
    rr (ix+13)
    rr (ix+14)
    rr (ix+15)

    ;...xor R if LSB(Vi) = 1

    jr nc,MULT_NO_XOR_R

    ld a,(ix)
    xor 0E1h
    ld (ix),a
MULT_NO_XOR_R:

    dec b
    jp nz,MULT_LOOP_BIT

    inc hl
    dec c
    jp nz,MULT_LOOP_BYTE

    pop de
    ld hl,MULT_Z
    ld bc,16
    ldir
    ret


;--- Perform one step of the GHASH algorithm
;    Input: IX = Address of next data block (16 bytes)

AES_GHASH_STEP:
    ld iy,AES_GHASH_Y

    ld a,(iy)
    xor (ix)
    ld (iy),a
    ld a,(iy+1)
    xor (ix+1)
    ld (iy+1),a
    ld a,(iy+2)
    xor (ix+2)
    ld (iy+2),a
    ld a,(iy+3)
    xor (ix+3)
    ld (iy+3),a    
    ld a,(iy+4)
    xor (ix+4)
    ld (iy+4),a    
    ld a,(iy+5)
    xor (ix+5)
    ld (iy+5),a    
    ld a,(iy+6)
    xor (ix+6)
    ld (iy+6),a
    ld a,(iy+7)
    xor (ix+7)
    ld (iy+7),a
    ld a,(iy+8)
    xor (ix+8)
    ld (iy+8),a
    ld a,(iy+9)
    xor (ix+9)
    ld (iy+9),a
    ld a,(iy+10)
    xor (ix+10)
    ld (iy+10),a
    ld a,(iy+11)
    xor (ix+11)
    ld (iy+11),a
    ld a,(iy+12)
    xor (ix+12)
    ld (iy+12),a
    ld a,(iy+13)
    xor (ix+13)
    ld (iy+13),a
    ld a,(iy+14)
    xor (ix+14)
    ld (iy+14),a
    ld a,(iy+15)
    xor (ix+15)
    ld (iy+15),a

    push iy
    pop hl
    ld de,AES_GHASH_Y
    jp MULT


;--------------------------------------------------------------------
; Data area
;--------------------------------------------------------------------

; Counter block for the GCTR function
CB: ds 16

; AES hash of current CB for the GCTR function
CB_HASH: ds 16

; Data and buffers for the block multiplication

MULT_X: ds 16
MULT_V: ds 16
MULT_Z: ds 16

; These need to be consecutive and in this order

TMP: ds 16
AES_GHASH_Y: ds 16

ALL_LENS:
    db 0,0,0,0,0,0,0,8*5  ;Additional data length (in bits)
    db 0,0,0,0,0,0        ;Encrypted data length
LEN: dw 0         ;Needs to be converted to bits and to big endian when finishing the GHASH calculation

H: ds 16          ;H for GCM multiplication

    endmod

    end
