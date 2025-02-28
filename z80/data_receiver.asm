    public DATA_RECEIVER.INIT
    public DATA_RECEIVER.UPDATE
    public DATA_RECEIVER.TLS_RECORD_TYPE.APP_DATA

    module DATA_RECEIVER

    include "tls_record_types.asm"

;--- Initialize
;    Input: HL = Address of buffer
;           BC = Length of buffer

INIT:
    ld (BUFFER_ADDRESS),hl
    ld (BUFFER_LENGTH),bc
    ld (BUFFER_REMAINING),hl
    ld hl,0
    ld (BUFFER_USED),hl
    ld a,h
    ld (HANDSHAKE_TYPE),a
    ld (RECORD_TYPE),a
    ret


;--- Update
;    Input:  -
;    Output: A = 0: No full record available yet
;                1: Full record available
;                2: Error: buffer is full
;            If A = 1:
;            HL = Record address
;            BC = Record length
;            D  = Record type
;            E  = Handshake type (if handshake record)

UPDATE:
    xor a
    ld b,TLS_RECORD_TYPE.APP_DATA
    ret


BUFFER_POINTER: dw 0

BUFFER_USED: dw 0

BUFFER_REMAINING: dw 0

RECORD_TYPE: db 0

HANDSHAKE_TYPE: db 0

BUFFER_ADDRESS: dw 0
BUFFER_LENGTH: dw 0

    endmod

    end