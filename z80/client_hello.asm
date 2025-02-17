    public CLIENT_HELLO.INIT
    public CLIENT_HELLO.MESSAGE
    public CLIENT_HELLO.SIZE
    public CLIENT_HELLO.SESSION_ID

    module CLIENT_HELLO

RANDOM_SIZE: equ 32
PUBLIC_KEY_SIZE: equ 64

;--- Init
;    Input:  HL = Address of "server name"
;            B  = Length of "server name" (max 128 bytes!)
;            DE = Address of public key
;    Output: HL = Address of CLIENT_HELLO.MESSAGE
;            BC = Value of CLIENT_HELLO.SIZE

INIT:
    push hl
    push bc

    ex de,hl
    ld de,PUBLIC_KEY
    ld bc,PUBLIC_KEY_SIZE
    ldir

    ld a,r
    ld l,a
    ld b,a
.WAIT:
    djnz .WAIT
    ld a,r
    ld h,a
    ld de,RANDOM
    ld bc,RANDOM_SIZE
    ldir
    ld de,SESSION_ID
    ld bc,RANDOM_SIZE
    ldir

    pop bc
    pop hl

    ld a,b
    or a
    jr nz,.WITH_SERVER_NAME

.NO_SERVER_NAME:
    ld bc,-(EXTENSIONS_END-SERVER_NAME_EXTENSION_START)    ;To skip the server name extension header
    jr .ADJUST_FIELDS

.WITH_SERVER_NAME:
    ld c,b
    ld b,0
    push bc
    ld de,SERVER_NAME
    ldir
    pop bc

    ;ld a,b
    ;ld (SERVER_NAME_NAME_SIZE),a
    ld a,c
    ld (SERVER_NAME_NAME_SIZE+1),a

    ld hl,3
    add hl,bc
    ;ld a,h
    ;ld (SERVER_NAME_DATA_SIZE),a    ;Server name length + 3
    ld a,l
    ld (SERVER_NAME_DATA_SIZE+1),a

    inc hl
    inc hl
    ;ld a,h
    ;ld (SERVER_NAME_EXT_SIZE),a     ;Server name length + 5
    ld a,l
    ld (SERVER_NAME_EXT_SIZE+1),a

.ADJUST_FIELDS:
    ld hl,EXTENSIONS_END-EXTENSIONS_START
    add hl,bc
    ;ld a,h
    ;ld (EXTENSIONS_LENGTH),a
    ld a,l
    ld (EXTENSIONS_LENGTH+1),a

    ld hl,EXTENSIONS_END-MESSAGE
    add hl,bc
    ld (SIZE),hl

    push hl
    pop bc
    ld hl,MESSAGE

    ret

SIZE: dw 0

    ;--- ClientHello packet bytes

    ;* Header

MESSAGE:
    db 3,3 ;legacy_version
RANDOM:
    ds 32
    db 32 ;Session id length
SESSION_ID:
    ds 32
    db 0, 2    ;Length of cipher suites
    db 13h,01h ;TLS_AES_128_GCM_SHA256
    db 1, 0    ;legacy_compression_methods
EXTENSIONS_LENGTH:
    dw 0       ;Length of extensions

    ;* Extensions

EXTENSIONS_START:
    db 0, 43   ; supported_versions
    db 0, 3    ; Extension size
    db 2       ; Data size
    db 3, 4    ; TLS 1.3

    db 0, 1    ; max_fragment_length
    db 0, 1    ; Extension size
    db 1       ; 512 bytes

    db 0, 10   ; supported_groups
    db 0, 4    ; Extension size
    db 0, 2    ; Data size
    db 0, 17h  ; SECP_256_R1

    db 0, 51   ; key_share
    db 0, PUBLIC_KEY_SIZE+7   ; Extension size
    db 0, PUBLIC_KEY_SIZE+5   ; Data size
    db 0, 17h  ; SECP_256_R1
    db 0, PUBLIC_KEY_SIZE+1   ; Key size
    db 4       ; Legacy form
PUBLIC_KEY: ds PUBLIC_KEY_SIZE

    db 0, 13   ; signature_algorithms
    db 0, 14   ; Extension size
    db 0, 12   ; Data size
    db 4, 1    ; RSA-PKCS1-SHA256
    db 5, 1    ; RSA-PKCS1-SHA384
    db 8, 4    ; RSA-PSS-RSAE-SHA256
    db 8, 5    ; RSA-PSS-RSAE-SHA384
    db 4, 3    ; ECDSA-SECP256r1-SHA256
    db 5, 3    ; ECDSA-SECP384r1-SHA384

    ;* If there's no server name the message ends here,
    ;* otherwise, here's the "server name" extension

SERVER_NAME_EXTENSION_START:
    db 0,0     ; server_name
SERVER_NAME_EXT_SIZE: dw 0
SERVER_NAME_DATA_SIZE: dw 0
    db 0       ; Name type: "DNS hostname"
SERVER_NAME_NAME_SIZE: dw 0    
EXTENSIONS_END:
SERVER_NAME: ds 128

    endmod

    end
