	title	TLS for Z80 by Konamiman
	subttl	ServerHello message parser

    name('SERVER_HELLO')

.COMMENT \

This module will parse a received ServerHello message and inform if there's something wrong with it.
It will also store a copy of the received public key for later usage.

\

    include "tls_connection_constants.asm"

    public SERVER_HELLO.PARSE
    public SERVER_HELLO.PUBLIC_KEY
    extrn CLIENT_HELLO.SESSION_ID

    .extroot
    .relab

    module SERVER_HELLO

EXT_KEY_SHARE: equ 51
EXT_SUPPORTED_VERSIONS: equ 43

GROUP_ID_P256: equ 23


    ;--- Parse a received Server Hello message.
    ;    Input:  HL = Message address
    ;            BC = Message length
    ;    Output: A = Parse result or error code. See SERVER_HELLO.ERROR_CODE in tls_connection_constants.asm
    ;            HL = Address of the received public key (64 bytes)

PARSE:
    xor a
    ld (FLAGS),a

    ;--- Process headers

    ld a,(hl)   ;Legacy version field represents TLS 1.2?
    cp 3
    ld a,ERROR_CODE.NO_TLS13
    ret nz
    inc hl
    ld a,(hl)
    cp 3
    ld a,ERROR_CODE.NO_TLS13
    ret nz
    inc hl

    ld b,32     ;Random number is NOT the one for HelloRetryRequest?
    ld de,HELLO_RETRY_RANDOM
.RANDOM_CHECK_LOOP:
    ld a,(de)
    cp (hl)
    jr nz,.NO_HELLO_RETRY
    inc hl
    inc de
    djnz .RANDOM_CHECK_LOOP
    ld a,ERROR_CODE.HELLO_RETRY
    ret
.NO_HELLO_RETRY:
    ld c,b
    ld b,0
    add hl,bc   ;Skip random bytes not checked

    ld a,(hl)
    cp 32
    ld a,ERROR_CODE.BAD_SESSIONID
    ret nz
    inc hl

    ld b,32      ;Session ID is the same we sent?
    ld de,CLIENT_HELLO.SESSION_ID
    ld c,ERROR_CODE.BAD_SESSIONID
.SESSION_ID_CHECK_LOOP:
    ld a,(de)
    cp (hl)
    ld a,c
    ret nz
    inc hl
    inc de
    djnz .SESSION_ID_CHECK_LOOP

    ld a,(hl)   ;Cipher suite is TLS_AES_128_GCM_SHA256?
    cp 13h
    ld a,ERROR_CODE.BAD_CIPHER_SUITE
    ret nz
    inc hl
    ld a,(hl)
    dec a ;cp 1
    ld a,ERROR_CODE.BAD_CIPHER_SUITE
    ret nz
    inc hl

    ld a,(hl)   ;Legacy compression method is 0?
    or a
    ld a,ERROR_CODE.BAD_COMPRESSION
    ret nz
    inc hl

    ;--- Process extensions, we only care about "SupportedVersions" and "KeyShare"

    ld b,(hl)
    inc hl
    ld c,(hl)   ;BC = Total extensions length
    inc hl

.EXTENSIONS_LOOP:
    bit 7,b
    ld a,ERROR_CODE.INVALID_FORMAT
    ret nz  ;Somehow remaining length went negative

    ld a,b
    or c
    jr z,.EXTENSIONS_END

    ld d,(hl)
    inc hl
    ld e,(hl)   ;DE = Extension type
    inc hl

    push bc
    ld b,(hl)
    inc hl
    ld c,(hl)   ;BC = Extension length
    inc hl

    ld a,d
    or a
    jr nz,.EXTENSIONS_NEXT
    ld a,e
    cp EXT_SUPPORTED_VERSIONS
    jr z,.EXTENSION_SUPPORTED_VERSIONS
    cp EXT_KEY_SHARE
    jr nz,.EXTENSIONS_NEXT

    ;* Key share extension

.EXTENSIONS_KEY_SHARE:
    ld a,(hl)
    or a
    jr nz,.EXTENSIONS_NEXT
    inc hl
    ld a,(hl)
    dec hl
    cp GROUP_ID_P256
    jr nz,.EXTENSIONS_NEXT

    push hl
    ld de,5 ;Skip extension type, extension length, and legacy "4" byte
    add hl,de
    ld de,PUBLIC_KEY
    ld bc,64
    ldir
    pop hl

    ld a,(FLAGS)
    or 2
    ld (FLAGS),a
    jr .EXTENSIONS_NEXT

    ;* Supported versions extension

.EXTENSION_SUPPORTED_VERSIONS:
    ;Expected value is 0x0304 (TLS 1.3)
    ld a,(hl)
    cp 3
    jr nz,POP_NOTLS13
    inc hl
    ld a,(hl)
    cp 4
    jr nz,POP_NOTLS13

    dec hl
    ld a,(FLAGS)
    or 1
    ld (FLAGS),a

.EXTENSIONS_NEXT:
    pop de    ;DE = Remaining extensions length
    add hl,bc ;HL = Pointer to next extension
    
    ex de,hl  ;HL = Remaining extensions length, DE = Pointer to next extension
    or a
    sbc hl,bc ;HL = Updated remaining extensions length
    ld bc,4
    or a
    sbc hl,bc ;Substract extension type and length too
    push hl
    pop bc
    ex de,hl  ;HL = Pointer to next extension

    jr .EXTENSIONS_LOOP

.EXTENSIONS_END:
    ld a,(FLAGS)
    ld b,a
    bit 0,b
    ld a,ERROR_CODE.NO_TLS13
    ret z
    bit 1,b
    ld a,ERROR_CODE.NO_KEYSHARE
    ret z

    xor a
    ld hl,PUBLIC_KEY
    ret

POP_NOTLS13:
    pop bc
NO_TLS13:
    ld a,ERROR_CODE.NO_TLS13
    ret
NO_KEYSHARE:
    ld a,ERROR_CODE.NO_KEYSHARE
    ret

HELLO_RETRY_RANDOM:
    db 0xCF, 0x21, 0xAD, 0x74, 0xE5, 0x9A, 0x61, 0x11, 0xBE, 0x1D, 0x8C, 0x02, 0x1E, 0x65, 0xB8, 0x91
    db 0xC2, 0xA2, 0x11, 0x16, 0x7A, 0xBB, 0x8C, 0x5E, 0x07, 0x9E, 0x09, 0xE2, 0xC8, 0xA8, 0x33, 0x9C

PUBLIC_KEY: ds 64

FLAGS: db 0 ;Bit 0: TLS 1.3 found, bit 1: key share found
    endmod

    end
