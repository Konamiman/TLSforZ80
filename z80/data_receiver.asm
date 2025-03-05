    public DATA_RECEIVER.INIT
    public DATA_RECEIVER.UPDATE
    public DATA_RECEIVER.TLS_RECORD_TYPE.APP_DATA
    extrn DATA_TRANSPORT.RECEIVE
    extrn DATA_TRANSPORT.HAS_IN_DATA
    extrn DATA_TRANSPORT.IS_REMOTELY_CLOSED
    extrn RECORD_ENCRYPTION.DECRYPT
    extrn RECORD_ENCRYPTION.TAG_SIZE

    module DATA_RECEIVER

ERROR_NO_CHANGE: equ 0
ERROR_FULL_RECORD_AVAILABLE: equ 1
ERROR_CONNECTION_CLOSED: equ 2
ERROR_RECORD_TOO_LONG: equ 3
ERROR_BAD_AUTH_TAG: equ 4
ERROR_MSG_ALL_ZEROS: equ 5
ERROR_RECORD_OVER_16K: equ 6
ERROR_HANDSHAKE_MSG_TOO_LONG: equ 7

FLAG_SPLIT_HANDSHAKE_MSG: db 1

    root DATA_TRANSPORT.RECEIVE
    root DATA_TRANSPORT.HAS_IN_DATA
    root DATA_TRANSPORT.IS_REMOTELY_CLOSED
    root RECORD_ENCRYPTION.DECRYPT
    root RECORD_ENCRYPTION.TAG_SIZE

    include "tls_record_types.asm"


; Record format:
;
; Content type (1 byte)
; Legacy protocol version (2 bytes)
; Record length (2 bytes, big endian)
; Record content (record length bytes)
;
; Handshake message format:
;
; Message type (1 byte)
; Message length (3 bytes, big endian)
; Message (message length bytes)
;
; A record of handshake type can contain multiple handshake messages,
; or a long handshake message could be split in multiple records
; of handshake type.

;--- Initialize
;    Input: HL = Address of buffer
;           BC = Length of buffer

INIT:
    ld (BUFFER_ADDRESS),hl
    ld (BUFFER_TOTAL_SIZE),bc
    xor a
    ld (FLAGS),a

INIT_FOR_NEXT_RECORD:
    ld hl,(BUFFER_ADDRESS)
    ld (BUFFER_RECEIVE_POINTER),hl
    xor a
    ld (HANDSHAKE_TYPE),a
    ld (RECORD_TYPE),a
    ret


;--- Update
;    Input:  -
;    Output: A = 0: No full record available yet
;                1: Full record available
;                2: Error: underlying connection is closed
;                3: Error: message is longer than buffer size
;                4: Error decrypting record: bad auth tag
;                5: Error decrypting record: message is all zeros
;                6: Error: record is longer than 16K
;                7: Error: handshake message is too long
;                8: Part of a handshake message available
;            If A = 1 or 8:
;            HL = Record address
;            BC = Record length
;            D  = Record type (if A=1)
;            E  = Handshake type (if handshake record and A=1)

UPDATE:
    ld a,(RECORD_TYPE)
    or a
    jr z,START_RECEIVING_RECORD

    ld hl,(REMAINING_RECORD_SIZE)
    ld a,h
    or l
    jr nz,CONTINUE_RECEIVING_RECORD

    ;--- Return the next handshake message in a multi-message record

    ;QIP


    ;--- Start receiving a new record from scratch

START_RECEIVING_RECORD:
    ld bc,5 ;Length of record header
    call RECEIVE_DATA
    ret z   ;No data received (we don't care if it's error or not)
    or a
    ret nz  ;Error

    ;We assume we actually received 5 bytes (if we didn't receive zero bytes)

    ld hl,(BUFFER_ADDRESS)
    ld a,(hl)
    ld (RECORD_TYPE),a
    inc hl

    inc hl  ;Just skip and ignorelegacy protocol version
    inc hl

    ld a,(hl) ;Record size, high byte
    inc hl
    ld l,(hl)
    ld h,a
    ld (INCOMING_RECORD_SIZE),hl
    ld (REMAINING_RECORD_SIZE),hl

    ld bc,RECORD_ENCRYPTION.TAG_SIZE
    or a
    sbc hl,bc   ;Account for the tag at the end of the record to check size

    ld bc,16384+256
    or a
    sbc hl,bc
    bit 7,h
    ld a,ERROR_RECORD_OVER_16K
    ret nz

    ld bc,(BUFFER_TOTAL_SIZE)
    or a
    sbc hl,bc
    bit 7,h
    ld a,ERROR_RECORD_TOO_LONG
    ret nz

    xor a
    ret


    ;--- Continue receiving a partially received record

CONTINUE_RECEIVING_RECORD:
    ld bc,(REMAINING_RECORD_SIZE)
    call RECEIVE_DATA
    ret z   ;No data received (we don't care if it's error or not)
    or a
    ret nz  ;Error

    ld hl,(REMAINING_RECORD_SIZE)
    ld a,h
    or l
    ret z

    ; We got a full record!
    ; If it's of application data type we need to decrypt it

    ld a,(RECORD_TYPE)
    cp TLS_RECORD_TYPE.APP_DATA
    jr nz,HANDLE_FULL_RECORD

    ld hl,(BUFFER_ADDRESS)
    ld bc,(INCOMING_RECORD_SIZE)
    push hl
    pop de
    call RECORD_ENCRYPTION.DECRYPT
    or a
    jr z,.DECRYPT_OK
    add ERROR_BAD_AUTH_TAG-1    ;1 = lowest error code from RECORD_ENCRYPTION.DECRYPT
    ret

.DECRYPT_OK:
    ld (INCOMING_RECORD_SIZE),bc
    ld a,d
    ld (RECORD_TYPE),a

HANDLE_FULL_RECORD:

    ; The record is now decrypted or it wasn't decrypted to start with,
    ; we can process it now

    ld a,(RECORD_TYPE)
    cp TLS_RECORD_TYPE.HANDSHAKE
    jr z,HANDLE_HANDSHAKE_RECORD

    ; No handshake record: no further processing needed, just return it

    ld hl,(BUFFER_ADDRESS)
    ld bc,(INCOMING_RECORD_SIZE)
    ld d,a  ;Record type
    push hl
    call INIT_FOR_NEXT_RECORD
    pop hl

    ld a,ERROR_FULL_RECORD_AVAILABLE
    ret

    ; It was a handshake record

HANDLE_HANDSHAKE_RECORD:
    ld a,(FLAGS)
    and FLAG_SPLIT_HANDSHAKE_MSG
    jr nz,HANDLE_NEXT_HANDSHAKE_PART

    ; The record contains multiple entire handshake messages,
    ; or the first part of a long message

    ld hl,(BUFFER_ADDRESS)
    ld a,(hl)
    ld (HANDSHAKE_TYPE),a
    inc hl
    
    ld a,(hl)
    or a
    ld a,ERROR_HANDSHAKE_MSG_TOO_LONG
    ret nz

    inc hl
    ld a,(hl)
    inc hl
    ld l,(hl)
    ld h,a  ;HL = Handshake message size

    ;WIP!!!

    ; Return the first or the next handshake message from the record
    ;WIP!!!
    ret


; Receive a block of data from the underlying data transport layer
; Input:  BC = How much data to received (must be at most BUFFER_FREE_SIZE)
; Output: A  = Error:
;              0: Ok
;              2: Error: underlying connection is closed
;              3: Error: message is longer than buffer size
;         If A=0:
;         BC = How much data was received
;         Z set it no data received
;         BUFFER_RECEIVE_POINTER increased by BC
;         REMAINING_RECORD_SIZE decreased by BC

RECEIVE_DATA:
    push bc
    call DATA_TRANSPORT.IS_REMOTELY_CLOSED
    pop bc
    ld a,ERROR_CONNECTION_CLOSED
    ret c

    push bc
    call DATA_TRANSPORT.HAS_IN_DATA
    pop hl
    ld bc,0
    ld a,b
    ret nc
    push hl
    pop bc

    ld hl,(BUFFER_RECEIVE_POINTER)
    push hl
    call DATA_TRANSPORT.RECEIVE
    pop hl
    add hl,bc
    ld (BUFFER_RECEIVE_POINTER),hl
    ld hl,(REMAINING_RECORD_SIZE)
    or a
    sbc hl,bc
    ld (REMAINING_RECORD_SIZE),hl

    xor a
    ld a,b
    or c
    ret


RECORD_TYPE: db 0

HANDSHAKE_TYPE: db 0

BUFFER_TOTAL_SIZE: dw 0

INCOMING_RECORD_SIZE: dw 0

INCOMING_HANDSHAKE_MSG_SIZE: dw 0

BUFFER_RECEIVE_POINTER: dw 0

REMAINING_RECORD_SIZE: dw 0

BUFFER_ADDRESS: dw 0

HANDSHAKE_HEADER: ds 4

REMAINING_HANDSHAKE_MSG_SIZE: ds 2

FLAGS: db 0 ;0: a handshake message split in multiple records is being receieved

    endmod

    end