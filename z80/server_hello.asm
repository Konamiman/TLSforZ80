    public SERVER_HELLO.PARSE
    public SERVER_HELLO.PUBLIC_KEY

    .relab

    module SERVER_HELLO

ERR_INVALID_FORMAT: equ 1
ERR_HELLO_RETRY: equ 2
ERR_NO_TLS13: equ 3
ERR_NO_P256: equ 4
ERR_NO_KEYSHARE: equ 5
ERR_BAD_SESSIONID: equ 6
ERR_BAD_COMPRESSION: equ 7

EXT_KEY_SHARE: equ 51
EXT_SUPPORTED_VERSIONS: equ 43


    ;--- Parse a received Server Hello message
    ;    Input:  HL = Message address
    ;            BC = Message length
    ;    Output: A = 0: Ok
    ;                1: Invalid format
    ;                2: HelloRetryRequest received
    ;                3: Not TLS 1.3
    ;                4: CipherSuite is not P256
    ;                5: No KeyShare extension received
    ;                6: Mismatched session id echo
    ;                7: Bad legacy compression method
    ;            HL = Address of public key
PARSE:
    xor a
    ld (FLAGS),a

    ;--- Process headers

    ld a,(hl)   ;Legacy version field represents TLS 1.2?
    cp 3
    ld a,ERR_NO_TLS13
    ret nz
    inc hl
    ld a,(hl)
    cp 3
    ld a,ERR_NO_TLS13
    ret nz
    inc hl

    ld b,32     ;Random number is NOT the one for HelloRetryRequest?
    ld de,HELLO_RETRY_RANDOM
.RANDOM_CHECK_LOOP:
    ld a,(de)
    cpi
    jr nz,.NO_HELLO_RETRY
    inc de
    djnz .RANDOM_CHECK_LOOP
    ld a,2
    ret
.NO_HELLO_RETRY

    ld a,(hl)
    inc hl
    cp 32
    ld a,ERR_BAD_SESSIONID
    ret nz

    ld b,a      ;Session ID is the same we sent?
    ld de,CLIENT_HELLO.SESSION_ID
    ld c,ERR_BAD_SESSIONID
.SESSION_ID_CHECK_LOOP:
    ld a,(de)
    cpi
    ld c,a
    ret nz
    inc de
    djnz .SESSION_ID_CHECK_LOOP

    ld a,(hl)   ;Legacy compression method is 0?
    or a
    ld a,ERR_BAD_COMPRESSION
    ret nz

    ;---Process extensions, we only care about "SupportedVersions" and "KeyShare"

    ;WIP...

    ld a,(FLAGS)
    ld b,a
    bit 0,b
    ld a,ERR_NO_TLS13
    ret z
    bit 1,b
    ld a,ERR_NO_KEYSHARE
    ret z

    xor a
    ld hl,PUBLIC_KEY
    ret

NO_TLS13:
    ld a,ERR_NO_TLS13
    ret
NO_KEYSHARE:
    ld a,ERR_NO_KEYSHARE
    ret

HELLO_RETRY_RANDOM:
    db 0xCF, 0x21, 0xAD, 0x74, 0xE5, 0x9A, 0x61, 0x11, 0xBE, 0x1D, 0x8C, 0x02, 0x1E, 0x65, 0xB8, 0x91
    db 0xC2, 0xA2, 0x11, 0x16, 0x7A, 0xBB, 0x8C, 0x5E, 0x07, 0x9E, 0x09, 0xE2, 0xC8, 0xA8, 0x33, 0x9C

PUBLIC_KEY: ds 64

FLAGS: db 0 ;Bit 0: TLS 1.3 found, bit 1: key share found
    endmod

    end
