    public DATA_RECEIVER.INIT
    public DATA_RECEIVER.UPDATE
    public DATA_RECEIVER.TLS_RECORD_TYPE.APP_DATA
    public DATA_RECEIVER.HANDSHAKE_HEADER
    public DATA_RECEIVER.HANDSHAKE_MSG_SIZE
    extrn DATA_TRANSPORT.RECEIVE
    extrn DATA_TRANSPORT.HAS_IN_DATA
    extrn DATA_TRANSPORT.IS_REMOTELY_CLOSED
    extrn RECORD_ENCRYPTION.DECRYPT
    extrn RECORD_ENCRYPTION.TAG_SIZE

def_error: macro name,code
name: equ code
    public name
    endm

    module DATA_RECEIVER

def_error ERROR_NO_CHANGE, 0
def_error ERROR_CONNECTION_CLOSED, 1
def_error ERROR_RECORD_TOO_LONG, 2
def_error ERROR_BAD_AUTH_TAG, 3
def_error ERROR_MSG_ALL_ZEROS, 4
def_error ERROR_RECORD_OVER_16K, 5
def_error ERROR_HANDSHAKE_MSG_TOO_LONG, 6
def_error ERROR_NON_HANDSHAKE_RECEIVED, 7
def_error ERROR_FULL_RECORD_AVAILABLE, 128
def_error ERROR_FULL_HANDSHAKE_MESSAGE, 129
def_error ERROR_SPLIT_HANDSHAKE_FIRST, 130
def_error ERROR_SPLIT_HANDSHAKE_NEXT, 131
def_error ERROR_SPLIT_HANDSHAKE_LAST, 132

FLAG_SPLIT_HANDSHAKE_MSG: equ 1

FLAG_MULTIPLE_HANDSHAKE_MSG: equ 2

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

INIT_FOR_NEXT_RECORD:
    push af
    push hl
    ld hl,(BUFFER_ADDRESS)
    ld (BUFFER_RECEIVE_POINTER),hl
    pop hl
    xor a
    ;ld (HANDSHAKE_TYPE),a
    ld (RECORD_TYPE),a
    ld (FLAGS),a
    pop af
    ret


;--- Update
;    Input:  -
;    Output: A = 0: No full record available yet
;                1: Error: underlying connection is closed
;                2: Error: message is longer than buffer size
;                3: Error decrypting record: bad auth tag
;                4: Error decrypting record: message is all zeros
;                5: Error: record is longer than 16K
;                6: Error: handshake message is too long
;                7: Error: non-handshake record received while split handshake is being received
;                128: Full non-handshake record available
;                129: Full handshake message available
;                130: First part of a split handshake message available
;                131: Next part of a split handshake message available
;                132: Last part of a split handshake message available
;            HL = Record address (if A>=128)
;            BC = Record length (if A=128), full message length (if A=129), fragmenet length (if A>=130)
;                 If A>=130, see DATA_RECEIVER.HANDSHAKE_MSG_SIZE for the actual full message size
;            D  = Record type (if A=128)
;            E  = Handshake type (if A>=129)

UPDATE:
    ld a,(FLAGS)
    cp FLAG_MULTIPLE_HANDSHAKE_MSG
    jp z,EXTRACT_NEXT_HANDSHAKE_MESSAGE

    ld a,(RECORD_TYPE)
    or a
    jr nz,CONTINUE_RECEIVING_RECORD


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

    inc hl  ;Just skip and ignore legacy protocol version
    inc hl

    ld a,(hl) ;Record size, high byte
    inc hl
    ld l,(hl)
    ld h,a
    ld (RECORD_SIZE),hl
    ld (REMAINING_RECORD_SIZE),hl

    ;ld bc,RECORD_ENCRYPTION.TAG_SIZE
    ;or a
    ;sbc hl,bc   ;Account for the tag at the end of the record to check size

    push hl
    pop bc
    ld hl,16384+256
    or a
    sbc hl,bc
    bit 7,h
    ld a,ERROR_RECORD_OVER_16K
    jp nz,INIT_FOR_NEXT_RECORD

    ld hl,(BUFFER_TOTAL_SIZE)
    ld bc,5
    or a
    sbc hl,bc   ;Max record size is the buffer size minus the record header
    ld bc,(RECORD_SIZE)
    or a
    sbc hl,bc
    bit 7,h
    ld a,ERROR_RECORD_TOO_LONG
    jp nz,INIT_FOR_NEXT_RECORD

    jr UPDATE


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
    ld a,0
    ret nz

    ; We got a full record!
    ; If it's of application data type we need to decrypt it

GOT_FULL_RECORD:
    ld a,(RECORD_TYPE)
    cp TLS_RECORD_TYPE.APP_DATA
    jr nz,HANDLE_FULL_RECORD

    ld hl,(BUFFER_ADDRESS)
    ld bc,5
    add hl,bc   ;Skip record header
    ld bc,(RECORD_SIZE)
    push hl
    pop de
    call RECORD_ENCRYPTION.DECRYPT
    or a
    jr z,.DECRYPT_OK
    add ERROR_BAD_AUTH_TAG-1    ;1 = lowest error code from RECORD_ENCRYPTION.DECRYPT
    jp INIT_FOR_NEXT_RECORD

.DECRYPT_OK:
    ld (RECORD_SIZE),bc
    ld a,d
    ld (RECORD_TYPE),a

HANDLE_FULL_RECORD:

    ; The record is now decrypted or it wasn't decrypted to start with,
    ; we can process it now

    ld a,(RECORD_TYPE)
    cp TLS_RECORD_TYPE.HANDSHAKE
    jr z,HANDLE_HANDSHAKE_RECORD
    ld d,a

    ; No handshake record: no further processing needed, just return it

    ld a,(FLAGS)
    and FLAG_SPLIT_HANDSHAKE_MSG
    jr z,HANDLE_NON_HANDSHAKE_RECORD
    ld a,(RECORD_TYPE)
    cp TLS_RECORD_TYPE.HANDSHAKE
    ld a,ERROR_NON_HANDSHAKE_RECEIVED   ;Non-handshake record received while receiving a split handshake message
    jp z,INIT_FOR_NEXT_RECORD

HANDLE_NON_HANDSHAKE_RECORD:
    ld hl,(BUFFER_ADDRESS)
    ld bc,5
    add hl,bc ;Skip record header
    ld bc,(RECORD_SIZE)
    ld a,d

    ld a,ERROR_FULL_RECORD_AVAILABLE
    push hl
    call INIT_FOR_NEXT_RECORD
    pop hl
    ret

    ; It was a handshake record. There are some possibilities:
    ; 1. The record contains one or more full handshake messages.
    ; 2. The record contains the first (or the next/last, if FLAG_SPLIT_HANDSHAKE_MSG is set) part of a long handshake message.
    ; 3. A combination of the above (one or more full messages, then the first part of a long message.)

HANDLE_HANDSHAKE_RECORD:
    ld a,(FLAGS)
    and FLAG_SPLIT_HANDSHAKE_MSG
    jp nz,HANDLE_NEXT_HANDSHAKE_PART

    ; The record contains one or more entire handshake messages,
    ; or it's the first part of a long message

    ld hl,(RECORD_SIZE)
    ld bc,4
    or a
    sbc hl,bc   ;Don't count handshake message header
    ld (REMAINING_RECORD_SIZE),hl
    ld hl,(BUFFER_ADDRESS)
    ld bc,5
    add hl,bc   ;Skip record header
    ld (MESSAGE_EXTRACT_POINTER),hl

    ; We jump here also from UPDATE when FLAG_MULTIPLE_HANDSHAKE_MSG is set.

EXTRACT_NEXT_HANDSHAKE_MESSAGE:
    ld hl,(MESSAGE_EXTRACT_POINTER)
    ld a,(hl)
    ld (HANDSHAKE_TYPE),a
    push hl
    ld de,HANDSHAKE_HEADER
    ld bc,4
    ldir
    pop hl
    inc hl
    
    ld a,(hl)
    or a
    ld a,ERROR_HANDSHAKE_MSG_TOO_LONG
    jp nz,INIT_FOR_NEXT_RECORD

    inc hl
    ld b,(hl)
    inc hl
    ld c,(hl)
    inc hl
    ld (MESSAGE_EXTRACT_POINTER),hl
    push bc
    pop hl  ;HL = Handshake message size
    ld (HANDSHAKE_MSG_SIZE),bc

    ld bc,(REMAINING_RECORD_SIZE)
    or a
    sbc hl,bc
    ld a,h
    or l    ;If zero, it's the last message in the record
    jr z,EXTRACT_FULL_HANDSHAKE_MESSAGE

    bit 7,h
    jr z,HANDLE_FIRST_PART_OF_SPLIT_HANDHSAKE_MESSAGE
    or a   ;Force NZ

EXTRACT_FULL_HANDSHAKE_MESSAGE:
    push af
    ld hl,(MESSAGE_EXTRACT_POINTER)
    ld bc,(HANDSHAKE_MSG_SIZE)
    push hl
    add hl,bc
    ld (MESSAGE_EXTRACT_POINTER),hl
    ld hl,(REMAINING_RECORD_SIZE)
    or a
    sbc hl,bc
    dec hl
    dec hl
    dec hl
    dec hl  ;Substract current handshake message header
    ld (REMAINING_RECORD_SIZE),hl
    ld a,(HANDSHAKE_TYPE)
    ld e,a
    pop hl
    pop af
    ld a,ERROR_FULL_HANDSHAKE_MESSAGE
    jp z,INIT_FOR_NEXT_RECORD

    ld a,FLAG_MULTIPLE_HANDSHAKE_MSG
    ld (FLAGS),a
    ld a,ERROR_FULL_HANDSHAKE_MESSAGE
    ret

    ; We have received the first part of a handshake message split in multiple records.

HANDLE_FIRST_PART_OF_SPLIT_HANDHSAKE_MESSAGE:
    ld hl,(HANDSHAKE_MSG_SIZE)
    ld bc,(REMAINING_RECORD_SIZE)
    or a
    sbc hl,bc
    ld (REMAINING_MESSAGE_SIZE),hl

    ld hl,(MESSAGE_EXTRACT_POINTER)
    ld bc,(REMAINING_RECORD_SIZE)
    ld a,(HANDSHAKE_TYPE)
    ld e,a
    call INIT_FOR_NEXT_RECORD
    ld a,FLAG_SPLIT_HANDSHAKE_MSG
    ld (FLAGS),a
    ld a,ERROR_SPLIT_HANDSHAKE_FIRST
    ret

    ; We have received the next (or last) part of a handshake message split in multiple records.

HANDLE_NEXT_HANDSHAKE_PART:
    ld hl,(REMAINING_MESSAGE_SIZE)
    ld bc,(RECORD_SIZE)
    or a
    sbc hl,bc
    ld (REMAINING_MESSAGE_SIZE),hl
    ld a,h
    or l
    ld hl,(BUFFER_ADDRESS)
    ld bc,5
    add hl,bc ;Skip record header
    ld bc,(RECORD_SIZE)
    jr z,HANDLE_LAST_HANDSHAKE_PART
    call INIT_FOR_NEXT_RECORD
    ld a,FLAG_SPLIT_HANDSHAKE_MSG
    ld (FLAGS),a
    ld a,ERROR_SPLIT_HANDSHAKE_NEXT
    ret

HANDLE_LAST_HANDSHAKE_PART:
    ld a,(HANDSHAKE_TYPE)
    ld e,a
    ld a,ERROR_SPLIT_HANDSHAKE_LAST
    jp INIT_FOR_NEXT_RECORD


; Receive a block of data from the underlying data transport layer
; Input:  BC = How much data to received (must be at most BUFFER_FREE_SIZE)
; Output: A  = Error:
;              0: Ok
;              ERROR_CONNECTION_CLOSED: Error: underlying connection is closed
;         If A=0:
;         BC = How much data was received
;         Z set it no data received
;         BUFFER_RECEIVE_POINTER increased by BC
;         REMAINING_RECORD_SIZE decreased by BC

RECEIVE_DATA:
    push bc
    call DATA_TRANSPORT.HAS_IN_DATA
    jr c,DO_RECEIVE_DATA

    call DATA_TRANSPORT.IS_REMOTELY_CLOSED
    pop bc
    ld a,ERROR_CONNECTION_CLOSED
    ret c

    ld bc,0
    xor a
    ret

DO_RECEIVE_DATA:
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

    ld a,b
    or c
    ld a,0
    ret


RECORD_TYPE: db 0

HANDSHAKE_TYPE: db 0

BUFFER_TOTAL_SIZE: dw 0

MESSAGE_SIZE:    ;When FLAG_MULTIPLE_HANDSHAKE_MSG is set
RECORD_SIZE: dw 0

HANDSHAKE_MSG_SIZE: dw 0

MESSAGE_EXTRACT_POINTER:    ;When FLAG_MULTIPLE_HANDSHAKE_MSG is set
BUFFER_RECEIVE_POINTER: dw 0

REMAINING_MESSAGE_SIZE: dw 0    ;When FLAG_SPLIT_HANDSHAKE_MSG is set
REMAINING_RECORD_SIZE: dw 0

BUFFER_ADDRESS: dw 0

HANDSHAKE_HEADER: ds 4

REMAINING_HANDSHAKE_MSG_SIZE: ds 2

FLAGS: db 0 ;0: a handshake message split in multiple records is being receieved

    endmod

    end