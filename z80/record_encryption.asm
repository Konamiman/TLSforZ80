    public RECORD_ENCRYPTION.INIT
    public RECORD_ENCRYPTION.ENCRYPT
    public RECORD_ENCRYPTION.DECRYPT

    extrn AES_GCM.INIT
    extrn AES_GCM.ENCRYPT
    extrn AES_GCM.FINISH
    extrn AES_GCM.DECRYPT
    extrn AES_GCM.AUTHTAG

    module RECORD_ENCRYPTION

    root AES_GCM.INIT
    root AES_GCM.ENCRYPT
    root AES_GCM.FINISH
    root AES_GCM.DECRYPT
    root AES_GCM.AUTHTAG

KEY_SIZE: equ 16
IV_SIZE: equ 12
TAG_SIZE: equ 16

APP_DATA_CONTENT_TYPE: equ 23

    .relab


;--- Initialize
;
;    Input: Cy = 0 for client, 1 for server
;           HL = Pointer to key
;           DE = Pointer to IV
;    Assumes that KEY, IV, NONCE and SEQUENCE are consecutive

INIT:
    push de
    ld de,CLIENT_KEY
    jr nc,.GO
    ld de,SERVER_KEY
.GO:
    ld bc,KEY_SIZE
    ldir
    pop hl
    push hl
    ld bc,IV_SIZE
    ldir
    pop hl
    ld bc,IV_SIZE
    ldir

    push de
    pop hl
    inc de
    ld (hl),0
    ld bc,IV_SIZE-1
    ldir

    ret


;--- Encrypt record
;
;    Input:  A  = Content type
;            HL = Pointer to plaintext data
;            BC = Length of plaintext data
;            DE = Pointer to output encrypted data + auth tag
;    Output: BC = Length of output encrypted data + auth tag

ENCRYPT:
    push bc
    push de

    ; struct {
    ;   opaque content[TLSPlaintext.length];
    ;   ContentType type;
    ;   uint8 zeros[length_of_padding]; -- nope, we don't support padding
    ; } TLSInnerPlaintext;

    push hl
    push bc
    add hl,bc
    ld (hl),a   ;Content type goes right after the data to encrypt
    pop bc
    inc bc
    push bc

    ld hl,TAG_SIZE
    add hl,bc
    ld a,h
    ld (ADDITIONAL_DATA.ENCRYPTED_LENGTH),a
    ld a,l
    ld (ADDITIONAL_DATA.ENCRYPTED_LENGTH+1),a

    ld hl,CLIENT_KEY
    ld de,CLIENT_NONCE
    ld bc,ADDITIONAL_DATA
    call AES_GCM.INIT

    pop bc
    pop hl
    pop de
    push de
    push bc
    call AES_GCM.ENCRYPT

    pop bc
    pop hl
    add hl,bc
    call AES_GCM.FINISH

    pop hl  ;Length of plaintext
    ld bc,TAG_SIZE+1 ;+1 for the content type byte
    add hl,bc
    push hl
    pop bc

    ld ix,CLIENT_NONCE+IV_SIZE-1
    jp INC_SEQ


;--- Decrypt record
;
;    Input:  HL = Pointer to encrypted data + tag
;            BC = Length of encrypted data + tag
;            DE = Pointer to output plaintext data
;    Output: A  = 0: Ok
;                 1: Bad auth tag
;                 2: Payload was all zeros
;            BC = Length of output plaintext data
;            D  = Content type

DECRYPT:
    ld a,b
    ld (ADDITIONAL_DATA.ENCRYPTED_LENGTH),a
    ld a,c
    ld (ADDITIONAL_DATA.ENCRYPTED_LENGTH+1),a

    ;Compute auth tag
    ;By doing this BEFORE decrypting we can do in-place decryption

    push de
    push hl
    push bc

    ld hl,SERVER_KEY
    ld de,SERVER_NONCE
    ld bc,ADDITIONAL_DATA
    call AES_GCM.INIT

    pop hl
    ld bc,TAG_SIZE
    or a
    sbc hl,bc
    push hl
    pop bc ;BC = Length of data minus the tag
    pop ix ;Encrypted data
    push ix
    push bc
    call AES_GCM.AUTHTAG

    ld hl,COMPUTED_AUTH_TAG
    call AES_GCM.FINISH

    ;Decrypt

    ld hl,SERVER_KEY
    ld de,SERVER_NONCE
    ld bc,ADDITIONAL_DATA
    call AES_GCM.INIT

    pop bc ;BC = Length of data minus the tag
    pop hl
    pop de
    push de
    push bc
    push hl
    call AES_GCM.DECRYPT

    ;Validate auth tag

    pop hl
    pop bc
    add hl,bc   ;HL = Pointer to received auth tag
    push bc
    ld de,COMPUTED_AUTH_TAG
    ld b,16
.CHECK:
    ld a,(de)
    cpi
    jr nz,.BAD_TAG
    inc de
    djnz .CHECK

    ;Search content type by skipping zeros starting at the end

    pop bc
    pop hl  ;Destination address
    add hl,bc
    dec hl  ;Now HL points to the last byte of the decrypted data

.GET_CONTENT_TYPE:
    ld a,(hl)
    or a
    jr nz,.CONTENT_TYPE_FOUND

    dec bc
    ld a,b
    or c
    ld a,2
    ret z

    dec hl
    jr .GET_CONTENT_TYPE

.CONTENT_TYPE_FOUND:
    dec bc  ;Don't count content type byte for the decrypted content length
    ld d,a

    ld ix,SERVER_NONCE+IV_SIZE-1
    call INC_SEQ

    xor a
    ret

.BAD_TAG:
    pop bc
    pop hl
    ld a,1
    ret


;--- Increase sequence number and update nonce
;    Input: IX = Pointer to last byte of CLIENT_NONCE or SERVER_NONCE
;
;    Note: assumes that IV, NONCE and SEQUENCE are consecutive in memory

INC_SEQ:
.LOOP:
    ld a,(ix+IV_SIZE) ;Corresponding byte of sequence number
    inc a
    push af
    ld (ix+IV_SIZE),a
    xor (ix-IV_SIZE) ;Corresponding byte of IV
    ld (ix),a ;Corresponding byte of nonce
    pop af
    dec ix
    jr z,.LOOP ;Here we assume that we'll never send more than 2^IV_SIZE records in the connection

    ret


CLIENT_KEY: ds KEY_SIZE
CLIENT_IV: ds IV_SIZE
CLIENT_NONCE: ds IV_SIZE
CLIENT_SEQUENCE: ds IV_SIZE
SERVER_KEY: ds KEY_SIZE
SERVER_IV: ds IV_SIZE
SERVER_NONCE: ds IV_SIZE
SERVER_SEQUENCE: ds IV_SIZE

COMPUTED_AUTH_TAG: ds TAG_SIZE

; additional_data = 
;   TLSCiphertext.opaque_type ||
;   TLSCiphertext.legacy_record_version ||
;   TLSCiphertext.length

ADDITIONAL_DATA:
    db APP_DATA_CONTENT_TYPE
    db 3,3  ;Legacy TLS version
.ENCRYPTED_LENGTH:
    dw 0

    endmod

    end
