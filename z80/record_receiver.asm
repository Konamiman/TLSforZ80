	title	TLS for Z80 by Konamiman
	subttl	Record reception state machine

.COMMENT \

This module handles the reception of a record from the server,
properly handling all the data transport/record/handshake message fragmentation
and handling all the possible cases for handshake messages:

* Record delivered in multiple fragments by the data transport layer
* Multiple handshake messages in one single record
* Handshake message split in multiple records
* Multiple handshake messages, *and then* the first part of a split
  handshake message, in one single record (unlikely but allowed by the protocol!)

The only assumption made is that the first five bytes of a record (the record header)
and the first four bytes of a handshake message (the handshake header)
will be delivered in the same fragment by the data transport layer.

Before TLS connections can be established RECORD_RECEIVER.INIT must be invoked once.
The buffer size value supplied will determine the maximum received record size supported,
ideally this should be 16K as that's the maximum record size as specified in RFC8446.

Once there's a connection, UPDATE is called repeatedly, and whenever a full record
is available then its address, length and type (and handshake type, when appropriate) 
are returned and the record can be processed.

\

    include "tls_connection_constants.asm"
    
    public RECORD_RECEIVER.INIT
    public RECORD_RECEIVER.UPDATE
    public RECORD_RECEIVER.HANDSHAKE_HEADER
    public RECORD_RECEIVER.HANDSHAKE_MSG_SIZE
    public RECORD_RECEIVER.HAS_PARTIAL_RECORD
    extrn DATA_TRANSPORT.RECEIVE
    extrn DATA_TRANSPORT.HAS_IN_DATA
    extrn DATA_TRANSPORT.IS_REMOTELY_CLOSED
    extrn RECORD_ENCRYPTION.DECRYPT
    extrn RECORD_ENCRYPTION.TAG_SIZE

    module RECORD_RECEIVER

FLAG_SPLIT_HANDSHAKE_MSG: equ 1
FLAG_MULTIPLE_HANDSHAKE_MSG: equ 2

    root DATA_TRANSPORT.RECEIVE
    root DATA_TRANSPORT.HAS_IN_DATA
    root DATA_TRANSPORT.IS_REMOTELY_CLOSED
    root RECORD_ENCRYPTION.DECRYPT
    root RECORD_ENCRYPTION.TAG_SIZE


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


;--- Initialize the engine.
;    Input: HL = Address of the buffer the for received record
;           BC = Length of buffer the for received record

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
    ld (RECORD_TYPE),a
    ld (FLAGS),a
    pop af
    ret


;--- Has a record being partially received?
;    Output: Cy=1 if yes, 0 if not

HAS_PARTIAL_RECORD:
    ld a,(RECORD_TYPE)
    or a
    ret z
    scf
    ret


;--- Update the state machine, trying to receive more record data if appropriate.
;    Input:  -
;    Output: A = Update result or error code. See RECORD_RECEIVER.UPDATE_RESULT in tls_connection_constants.asm
;            HL = Record contents address (if A>=FULL_RECORD_AVAILABLE)
;            BC = Record length (if A=FULL_RECORD_AVAILABLE), 
;                 or full message length (if A=FULL_HANDSHAKE_MESSAGE), 
;                 or fragment length (if A>=SPLIT_HANDSHAKE_FIRST).
;                 If A>=SPLIT_HANDSHAKE_FIRST, see RECORD_RECEIVER.HANDSHAKE_MSG_SIZE for the actual full message size.
;            D  = Record type (if A=FULL_RECORD_AVAILABLE)
;            E  = Handshake type (if A>=FULL_HANDSHAKE_MESSAGE)
;
;   Note that the record contents will NOT include the record nor handshake headers,
;   you can check HANDSHAKE_HEADER and HANDSHAKE_MSG_SIZE if needed.


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
    or a
    ret nz   ;Error
    ld a,b
    or c
    ret z  ;No data received

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
    ld a,UPDATE_RESULT.RECORD_OVER_16K
    jp nz,INIT_FOR_NEXT_RECORD

    ld hl,(BUFFER_TOTAL_SIZE)
    ld bc,5
    or a
    sbc hl,bc   ;Max record size is the buffer size minus the record header
    ld bc,(RECORD_SIZE)
    or a
    sbc hl,bc
    bit 7,h
    ld a,UPDATE_RESULT.RECORD_TOO_LONG
    jp nz,INIT_FOR_NEXT_RECORD

    ;jr UPDATE


    ;--- Continue receiving a partially received record

CONTINUE_RECEIVING_RECORD:
    ld bc,(REMAINING_RECORD_SIZE)
    call RECEIVE_DATA
    or a
    ret nz   ;Error
    ld a,b
    or c
    ret z  ;No data received

    ld hl,(REMAINING_RECORD_SIZE)
    ld a,h
    or l
    ld a,0
    ret nz

    ; We got a full record!
    ; If it's of application data type we need to decrypt it

GOT_FULL_RECORD:
    ld a,(RECORD_TYPE)
    cp :TLS_CONNECTION.RECORD_TYPE.APP_DATA
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
    add UPDATE_RESULT.BAD_AUTH_TAG-1    ;1 = lowest error code from RECORD_ENCRYPTION.DECRYPT
    jp INIT_FOR_NEXT_RECORD

.DECRYPT_OK:
    ld (RECORD_SIZE),bc
    ld a,d
    ld (RECORD_TYPE),a

HANDLE_FULL_RECORD:

    ; The record is now decrypted or it wasn't decrypted to start with,
    ; we can process it now

    ld a,(RECORD_TYPE)
    cp :TLS_CONNECTION.RECORD_TYPE.HANDSHAKE
    jr z,HANDLE_HANDSHAKE_RECORD
    ld d,a

    ; No handshake record: no further processing needed, just return it

    ld a,(FLAGS)
    and FLAG_SPLIT_HANDSHAKE_MSG
    jr z,HANDLE_NON_HANDSHAKE_RECORD
    ld a,d
    cp :TLS_CONNECTION.RECORD_TYPE.HANDSHAKE
    ld a,UPDATE_RESULT.NON_HANDSHAKE_RECEIVED   ;Non-handshake record received while receiving a split handshake message
    jp nz,INIT_FOR_NEXT_RECORD

HANDLE_NON_HANDSHAKE_RECORD:
    ld hl,(BUFFER_ADDRESS)
    ld bc,5
    add hl,bc ;Skip record header
    ld bc,(RECORD_SIZE)

    ld a,UPDATE_RESULT.FULL_RECORD_AVAILABLE
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
    ld a,UPDATE_RESULT.HANDSHAKE_MSG_TOO_LONG   ;TODO: Support messages >64k
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
    dec bc  ;Don't count handshake message header
    dec bc
    dec bc
    dec bc
    or a
    sbc hl,bc
    ld a,h
    or l    ;If zero, it's the last message in the record
    jr z,EXTRACT_FULL_HANDSHAKE_MESSAGE

    bit 7,h
    jr z,HANDLE_FIRST_PART_OF_SPLIT_HANDHSAKE_MESSAGE

EXTRACT_FULL_HANDSHAKE_MESSAGE:
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
    ld hl,(REMAINING_RECORD_SIZE)
    ld a,h
    or l
    pop hl
    ld a,UPDATE_RESULT.FULL_HANDSHAKE_MESSAGE
    jp z,INIT_FOR_NEXT_RECORD

    ld a,FLAG_MULTIPLE_HANDSHAKE_MSG
    ld (FLAGS),a
    ld a,UPDATE_RESULT.FULL_HANDSHAKE_MESSAGE
    ret

    ; We have received the first part of a handshake message split in multiple records.

HANDLE_FIRST_PART_OF_SPLIT_HANDHSAKE_MESSAGE:
    ld hl,(HANDSHAKE_MSG_SIZE)
    ld bc,(REMAINING_RECORD_SIZE)
    dec bc
    dec bc
    dec bc
    dec bc  ;Don't count handshake message header
    or a
    sbc hl,bc
    ld (REMAINING_MESSAGE_SIZE),hl
    ;Here BC is already the current message part size

    ld hl,(MESSAGE_EXTRACT_POINTER)
    ld a,(HANDSHAKE_TYPE)
    ld e,a
    call INIT_FOR_NEXT_RECORD
    ld a,FLAG_SPLIT_HANDSHAKE_MSG
    ld (FLAGS),a
    ld a,UPDATE_RESULT.SPLIT_HANDSHAKE_FIRST
    ret

    ; We have received the next (or last) part of a handshake message split in multiple records.

HANDLE_NEXT_HANDSHAKE_PART:
    ld hl,(REMAINING_MESSAGE_SIZE)
    ld bc,(RECORD_SIZE)
    or a
    sbc hl,bc
    ex de,hl
    ld hl,(BUFFER_ADDRESS)
    ld bc,5
    add hl,bc ;Skip record header
    bit 7,d
    jr nz,HANDLE_LAST_HANDSHAKE_PART_AND_MORE_MSGS
    ld (REMAINING_MESSAGE_SIZE),de

    ld a,d
    or e
    ld a,(HANDSHAKE_TYPE)
    ld e,a
    ld bc,(RECORD_SIZE)
    jr z,HANDLE_LAST_HANDSHAKE_PART

    call INIT_FOR_NEXT_RECORD
    ld a,FLAG_SPLIT_HANDSHAKE_MSG
    ld (FLAGS),a
    ld a,UPDATE_RESULT.SPLIT_HANDSHAKE_NEXT
    ret

HANDLE_LAST_HANDSHAKE_PART:
    ld a,UPDATE_RESULT.SPLIT_HANDSHAKE_LAST
    jp INIT_FOR_NEXT_RECORD

HANDLE_LAST_HANDSHAKE_PART_AND_MORE_MSGS:
    push hl
    ld bc,(REMAINING_MESSAGE_SIZE)
    add hl,bc
    ld (MESSAGE_EXTRACT_POINTER),hl
    ld hl,(RECORD_SIZE)
    or a
    sbc hl,bc
    ld (REMAINING_RECORD_SIZE),hl
    pop hl

    ld a,FLAG_MULTIPLE_HANDSHAKE_MSG
    ld (FLAGS),a
    ld a,(HANDSHAKE_TYPE)
    ld e,a
    ld a,UPDATE_RESULT.SPLIT_HANDSHAKE_LAST
    ret


; Receive a block of data from the underlying data transport layer
; Input:  BC = How much data to received (must be at most BUFFER_FREE_SIZE)
; Output: A  = Error:
;              0: Ok
;              UPDATE_RESULT.CONNECTION_CLOSED: Error: underlying connection is closed
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
    ld a,UPDATE_RESULT.CONNECTION_CLOSED
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

    xor a
    ret


RECORD_TYPE: db 0

HANDSHAKE_TYPE: db 0

BUFFER_TOTAL_SIZE: dw 0

MESSAGE_SIZE: dw 0   ;When FLAG_MULTIPLE_HANDSHAKE_MSG is set
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