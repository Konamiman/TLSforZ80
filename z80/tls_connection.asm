    public TLS_CONNECTION.INIT
    public TLS_CONNECTION.UPDATE
    public TLS_CONNECTION.CAN_SEND
    public TLS_CONNECTION.CAN_RECEIVE
    public TLS_CONNECTION.SEND
    public TLS_CONNECTION.RECEIVE
    public TLS_CONNECTION.ERROR_CODE
    public TLS_CONNECTION.RECORD_ERROR
    public TLS_CONNECTION.ALERT_SENT
    public TLS_CONNECTION.ALERT_RECEIVED
    extrn CLIENT_HELLO.INIT
    extrn P256.GENERATE_KEY_PAIR
    extrn P256.GENERATE_SHARED_KEY
    extrn DATA_TRANSPORT.SEND

    module TLS_CONNECTION

    root CLIENT_HELLO.INIT
    root P256.GENERATE_KEY_PAIR
    root P256.GENERATE_SHARED_KEY
    root DATA_TRANSPORT.SEND

    module STATE

INITIAL: equ 0
HANDSHAKE: equ 1
ESTABLISHED: equ 2
LOCALLY_CLOSED: equ 3
REMOTELY_CLOSED: equ 4
FULL_CLOSED: equ 5

    endmod


;--- Initialize the connection.
;    Input:  HL = Address of "server name"
;            B  = Length of "server name" (max 128 bytes!)
;
;    Assumes the following has been called already:
;    DATA_TRANSPORT.INIT
;    RECORD_RECEIVER.INIT

INIT:
    push hl
    push bc
    call P256.GENERATE_KEY_PAIR
    ex de,hl
    pop bc
    pop hl
    call CLIENT_HELLO.INIT

    ld a,1
    ld (RECORD_HEADER.LEGACY_VERSION+1),a
    ld a,1  ;ClientHello
    call SEND_HANDSHAKE
    ld a,3
    ld (RECORD_HEADER.LEGACY_VERSION+1),a

    ld a,STATE.HANDSHAKE
    ld (STATE),a
    ret


;--- Update the state machine.
;    Output: A = New state

UPDATE:
    ld a,(STATE)
    ret


;--- Can application data be sent?
;    Output: Cy=1 if yes

CAN_SEND:
    ld a,(STATE)
    cp STATE.ESTABLISHED
    scf
    ret z
    cp STATE.REMOTELY_CLOSED
    scf
    ret z
    ccf
    ret


;--- Can application data be received?
;    Output: Cy=1 if yes

CAN_RECEIVE:
    ld a,(STATE)
    cp STATE.ESTABLISHED
    scf
    ret z
    cp STATE.LOCALLY_CLOSED
    scf
    ret z
    ccf
    ret


;--- Send data
;    Input:  HL = Data
;            BC = Length (max 512 bytes)
;    Output: Cy = 1 if error

SEND:
    ret


;--- Receive data
;    Input:  HL = Data
;            BC = Length (max 512 bytes)
;    Output: BC = Actual length

RECEIVE:
    ret


;--- Send a handshake record
;    Input:  A  = Message type
;            HL = Message address
;            BC = Message length
;    Output: Cy=1 if error
SEND_HANDSHAKE:
    ;TODO: Check if remotely closed

    ld (RECORD_HEADER.HANDSHAKE_TYPE),a
    ld a,22 ;Handshake
    ld (RECORD_HEADER.CONTENT_TYPE),a
    ld a,b
    ld (RECORD_HEADER.HANDSHAKE_LENGTH+1),a
    ld a,c
    ld (RECORD_HEADER.HANDSHAKE_LENGTH+2),a
    push hl
    push bc
    inc bc
    inc bc
    inc bc
    inc bc
    ld a,b
    ld (RECORD_HEADER.LENGTH),a
    ld a,c
    ld (RECORD_HEADER.LENGTH+1),a

    ld hl,RECORD_HEADER.CONTENT_TYPE
    ld bc,5+4
    call DATA_TRANSPORT.SEND
    ret c   ;TODO: Set errors

    pop bc
    pop hl
    call DATA_TRANSPORT.SEND
    ret     ;TODO: Set errors if failed

STATE: db 0
ERROR_CODE: db 0
RECORD_ERROR: db 0
ALERT_SENT: db 0
ALERT_RECEIVED: db 0

    module RECORD_HEADER

CONTENT_TYPE: db 0
LEGACY_VERSION: db 3,3
LENGTH: dw 0

HANDSHAKE_TYPE: db 0
HANDSHAKE_LENGTH: db 0,0,0

    endmod


    endmod

    end