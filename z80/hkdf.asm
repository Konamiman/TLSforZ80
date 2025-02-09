    public HKDF.DERIVE_HS_KEYS
    public HKDF.DERIVE_AP_KEYS
    public HKDF.CLIENT_SECRET
    public HKDF.SERVER_SECRET
    public HKDF.CLIENT_KEY
    public HKDF.SERVER_KEY
    public HKDF.CLIENT_IV
    public HKDF.SERVER_IV
    extrn HMAC.RUN
    extrn SHA256.RUN
    extrn SHA256.HASH_OF_EMPTY

    module HKDF

    root HMAC.RUN
    root SHA256.RUN
    root SHA256.HASH_OF_EMPTY


;--- Z80 code for the derivation of handshake and application keys for TLS
;    Algorithm specification: https://datatracker.ietf.org/doc/html/rfc5869
;
;    Input: IX = Address of the shared secret (for DERIVE_HS_KEYS only)
;           HL = Address of hash of handshake messages (32 bytes)
;
;    DERIVE_AP_KEYS assumes that DEVK_SECRET_TMP contains handshake_secret,
;    this will be true after DERIVE_HS_KEYS is executed.
;    Therefore these two must be executed in that order: DERIVE_HS_KEYS first,
;    then DERIVE_AP_KEYS.
;
;    The generated keys will be stored starting at CLIENT_SECRET, in this order:
;
;    +0:   CLIENT_SECRET: client_handshake/application_traffic_secret (32 bytes)
;    +32:  SERVER_SECRET: server_handshake/application_traffic_secret (32 bytes)
;    +64:  CLIENT_KEY:    client_handshake/application_key (16 bytes)
;    +80:  SERVER_KEY:    server_handshake/application_key (16 bytes)
;    +96:  CLIENT_IV:     client_handshake/application_iv (12 bytes)
;    +108: SERVER_IV:     server_handshake/application_iv (12 bytes)

    ;--- Handshake keys

DERIVE_HS_KEYS:    ;Handshake keys
    ld de,"sh"
    ld (STR_CTR+2),de
    ld (STR_STR+2),de

    ; DEVK_SECRET_TMP = handshake_secret = 
    ;   HMAC(
    ;     key = derived_secret, 
    ;     msg = shared_secret)

    push hl

    ;IX is already the shared secret
    ld de,DEVK_SECRET_TMP
    ld bc,32
    ld iy,HS_DEVSEC
    ld hl,HS_DEVSEC_END-HS_DEVSEC
    
    ld a,3
    call HMAC.RUN

    jr DERIVE_KEYS_COMMON

    ;--- Application keys

DERIVE_AP_KEYS:    ;Application keys
    ld de,"pa"
    ld (STR_CTR+2),de
    ld (STR_STR+2),de

    push hl

    ;DEVK_HASH_TMP = derived_secret = 
    ;  HKDF-Expand-Label(
    ;    key = handshake_secret,
    ;    label = "derived",
    ;    context = empty_hash,
    ;    len = 32)

    ld a,32
    ld (HKDEFL_LENGTH),a

    ld ix,SHA256.HASH_OF_EMPTY ;Context
    ld iy,DEVK_SECRET_TMP
    ld bc,2020h    ;B = Key length, C = Context length, both 32

    ld hl,STR_DRV  ;Label
    ld a,STR_DRV_END-STR_DRV  ;Label length

    ld de,DEVK_HASH_TMP

    call EXPAND_LABEL

    ;DEVK_SECRET_TMP = master_secret =
    ; HKDF-Extract(
    ;   key = derived_secret,
    ;   msg = 00...)

    ld iy,DEVK_HASH_TMP
    ld hl,32
    ld ix,ZEROKEY
    ld bc,32
    ld de,DEVK_SECRET_TMP

    ld a,3
    call HMAC.RUN

    ;--- Common keys

DERIVE_KEYS_COMMON:

    ; +0 = client_handshake_traffic_secret = 
    ; HKDF-Expand-Label(
    ;   key = handshake_secret,
    ;   label = "c hs traffic",
    ;   context = hello_hash,
    ;   len = 32)

    ld a,32
    ld (HKDEFL_LENGTH),a

    pop ix  ;Context
    ld c,a  ;Context length

    ld de,CLIENT_SECRET  ;Destination address

    push de
    push ix

    ld iy,DEVK_SECRET_TMP ;Key
    ld b,a  ;Key length

    ld hl,STR_CTR  ;Label
    ld a,STR_CTR_END-STR_CTR  ;Label length

    call EXPAND_LABEL

    ; +32 = server_handshake_traffic_secret =
    ; HKDF-Expand-Label(
    ;   key = handshake_secret,
    ;   label = "s hs traffic",
    ;   context = hello_hash,
    ;   len = 32)

    pop ix  ;Context
    ld c,32 ;Context length

    pop hl      ;Address of client_handshake_traffic_secret
    push hl
    ld bc,32    ;Length of previous key
    add hl,bc
    ex de,hl    ;DE  = ;Destination address

    ld iy,DEVK_SECRET_TMP ;Key
    ld b,c  ;Key length

    ld hl,STR_STR  ;Label
    ld a,STR_STR_END-STR_STR  ;Label length

    call EXPAND_LABEL

    ; +64 = client_handshake_key = 
    ;  HKDF-Expand-Label(
    ;    key = client_handshake_traffic_secret,
    ;    label = "key",
    ;    context = "",
    ;    len = 16)

    ld a,16
    ld (HKDEFL_LENGTH),a

    pop hl      ;Address of client_handshake_traffic_secret
    push hl

    push hl
    pop iy      ;Key

    ld bc,32+32 ;Length of previous two keys
    add hl,bc
    ex de,hl    ;DE  = ;Destination address

    ld bc,2000h ;B = Length of key (32), C = Context length (0)

    ld hl,STR_KEY  ;Label
    ld a,STR_KEY_END-STR_KEY  ;Label length

    call EXPAND_LABEL

    ; +80 = server_handshake_key = 
    ; HKDF-Expand-Label(
    ;   key = server_handshake_traffic_secret,
    ;   label = "key",
    ;   context = "",
    ;   len = 16)

    pop hl      ;Address of client_handshake_traffic_secret
    push hl

    ld bc,32
    add hl,bc
    push hl
    pop iy      ;Key = address of server_handshake_traffic_secret

    ld bc,32+16 ;Length of previous two keys (we have already added length of 1st key)
    add hl,bc
    ex de,hl    ;DE  = ;Destination address

    ld bc,2000h ;B = Length of key (32), C = Context length (0)

    ld hl,STR_KEY  ;Label
    ld a,STR_KEY_END-STR_KEY  ;Label length

    call EXPAND_LABEL

    ; + 96 = client_handshake_iv =
    ; HKDF-Expand-Label(
    ;   key = client_handshake_traffic_secret,
    ;   label = "iv",
    ;   context = "",
    ;   len = 12)

    ld a,12
    ld (HKDEFL_LENGTH),a

    pop iy      ;Address of client_handshake_traffic_secret
    push iy

    ld bc,2000h ;B = Length of key (32), C = Context length (0)

    ld de,DEVK_HASH_TMP ;Destination = tmp, since we want only 12 bytes

    ld hl,STR_IV  ;Label
    ld a,STR_IV_END-STR_IV  ;Label length

    call EXPAND_LABEL

    pop hl
    push hl
    ld bc,32+32+16+16 ;Length of previous four keys
    add hl,bc
    ex de,hl    ;DE  = ;Destination address

    ld hl,DEVK_HASH_TMP
    ld bc,12
    ldir    ;Copy first 12 bytes of hash to destination

    ; +108 = server_handshake_iv = 
    ; HKDF-Expand-Label(
    ;   key = server_handshake_traffic_secret,
    ;   label = "iv",
    ;   context = "",
    ;   len = 12)

    pop hl      ;Address of client_handshake_traffic_secret
    push hl

    ld bc,32
    add hl,bc
    push hl
    pop iy      ;Key = address of server_handshake_traffic_secret

    ld bc,2000h ;B = Length of key (32), C = Context length (0)

    ld hl,STR_IV  ;Label
    ld a,STR_IV_END-STR_IV  ;Label length

    ld de,DEVK_HASH_TMP ;Destination = tmp, since we want only 12 bytes

    call EXPAND_LABEL

    pop hl
    ld bc,32+32+16+16+12 ;Length of previous five keys
    add hl,bc
    ex de,hl    ;DE  = ;Destination address
    ld hl,DEVK_HASH_TMP
    ld bc,12
    ldir    ;Copy first 12 bytes of hash to destination

    ret

STR_DRV:
    db "derived"
STR_DRV_END:

STR_CTR:
    db "c XX traffic"
STR_CTR_END:

STR_STR:
    db "s XX traffic"
STR_STR_END:

STR_KEY:
    db "key"
STR_KEY_END:

STR_IV:
    db "iv"
STR_IV_END:

ZEROKEY: ds 32
DEVK_HASH_TMP: ds 32


; Fixed derived secret for handshake keys calculation

HS_DEVSEC:
    db 6fh, 26h, 15h, 0a1h
    db 08h, 0c7h, 02h, 0c5h
    db 67h, 8fh, 54h, 0fch
    db 9dh, 0bah, 0b6h, 97h
    db 16h, 0c0h, 76h, 18h
    db 9ch, 48h, 25h, 0ch
    db 0ebh, 0eah, 0c3h, 57h
    db 6ch, 36h, 11h, 0bah
HS_DEVSEC_END:


; - DERIVE_HS_KEYS will calculate handshake_secret and put it here.
; - DERIVE_AP_KEYS will use the previously set handshake_secret
;     to calculate master_secret and will put it here too.
; - DERIVE_KEYS_COMMON will use this value as handshake_secret or as
;     master_secret as appropriate.

DEVK_SECRET_TMP: ds 32

; Generated keys will be stored here

CLIENT_SECRET: ds 32
SERVER_SECRET: ds 32
CLIENT_KEY: ds 16
SERVER_KEY: ds 16
CLIENT_IV: ds 12
SERVER_IV: ds 12


;--- HKDF-Expand-Label
;
;    Input: IY = Address of secret
;           B  = Length of secret
;           IX = Address of context
;           C  = Length of contex
;           HL = Address of label
;           A  = Length of label
;           (HKDEFL_LENGTH) = "Length" parameter
;           DE = Destination address for the hash
;                Note that 32 bytes will be generated, regardless of "Length"

; HKDF-Expand-Label(Secret, Label, Context, Length) = 
; HKDF-Expand(Secret, HkdfLabel, Length)
;
; For Length <= 32:
; HKDF-Expand(Secret, Info, Length) = HMAC-Hash(Secret, Info | 0x01), take first "Length" bytes
;
; struct {
;     uint16 length = Length;
;     opaque label<7..255> = "tls13 " + Label;
;     opaque context<0..255> = Context;
; } HkdfLabel;

EXPAND_LABEL:
    push de
    push ix
    push bc
    push hl
    push af

    ; Init HMAC with the secret

    ld e,b
    ld d,0
    xor a
    call HMAC.RUN

    ; Hash "Length" (two bytes, big endian)

    ld hl,HKDEFL_LENGTH-1
    ld bc,2
    ld a,1
    call SHA256.RUN

    ; Calculate and hash the label length (one byte)

    pop af
    push af
    add 6   ;For "tls13 "
    ld (HKDEFL_TMP),a
    ld hl,HKDEFL_TMP
    ld bc,1
    ld a,1
    call SHA256.RUN

    ; Hash "tls13 "

    ld hl,HKDEFL_TLS13
    ld bc,6
    ld a,1
    call SHA256.RUN

    ; Hash the label

    pop af
    ld c,a
    ld b,0
    pop hl
    ld a,1
    call SHA256.RUN

    ; Hash the context length (one byte)

    pop bc
    push bc
    ld a,c
    ld (HKDEFL_TMP),a
    ld hl,HKDEFL_TMP
    ld bc,1
    ld a,1
    call SHA256.RUN

    ; Hash the context

    pop bc
    pop hl  ;Passed as IX
    ld b,0
    ld a,1
    call SHA256.RUN

    ; Hash an extra "1" byte

    ld hl,HKDEFL_ONE
    ld bc,1
    ld a,1
    call SHA256.RUN

    ; Finalize

    pop de
    ld a,2
    jp HMAC.RUN

    ;--- Data area

    db 0
HKDEFL_LENGTH: db 0
HKDEFL_TMP: db 0
HKDEFL_ONE: db 1
HKDEFL_TLS13: db "tls13 "

    endmod

    end
