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
    extrn CLIENT_HELLO.MESSAGE
    extrn CLIENT_HELLO.SIZE
    extrn P256.GENERATE_KEY_PAIR
    extrn P256.GENERATE_SHARED_KEY
    extrn DATA_TRANSPORT.SEND
    extrn DATA_TRANSPORT.IS_REMOTELY_CLOSED
    extrn DATA_TRANSPORT.CLOSE
    extrn SHA256.RUN
    extrn RECORD_ENCRYPTION.ENCRYPT
    extrn RECORD_RECEIVER.UPDATE
    extrn RECORD_RECEIVER.TLS_RECORD_TYPE.APP_DATA
    extrn RECORD_RECEIVER.HANDSHAKE_HEADER
    extrn RECORD_RECEIVER.HANDSHAKE_MSG_SIZE

    module TLS_CONNECTION

    root CLIENT_HELLO.INIT
    root CLIENT_HELLO.MESSAGE
    root CLIENT_HELLO.SIZE
    root P256.GENERATE_KEY_PAIR
    root P256.GENERATE_SHARED_KEY
    root DATA_TRANSPORT.SEND
    root DATA_TRANSPORT.IS_REMOTELY_CLOSED
    root DATA_TRANSPORT.CLOSE
    root SHA256.RUN
    root RECORD_ENCRYPTION.ENCRYPT
    root RECORD_RECEIVER.UPDATE
    root RECORD_RECEIVER.TLS_RECORD_TYPE.APP_DATA
    root RECORD_RECEIVER.HANDSHAKE_HEADER
    root RECORD_RECEIVER.HANDSHAKE_MSG_SIZE

    .relab

    module STATE

INITIAL: equ 0
HANDSHAKE_PLAIN: equ 1
HANDSHAKE_ENCRYPTED: equ 2
ESTABLISHED: equ 3
LOCALLY_CLOSED: equ 4
REMOTELY_CLOSED: equ 5
FULL_CLOSED: equ 6

    endmod

    module RECORD_TYPE

CHANGE_CIHPER_SPEC: equ 20
ALERT: equ 21
HANDSHAKE: equ 22
APP_DATA: equ 23

    endmod

    module ERROR

ALERT_RECEIVED: equ 1
ALERT_SENT: equ 2
RECEIVED_RECORD_ERROR: equ 3
HELLO_RETRY_REQUEST_RECEIVED: equ 4
CONNECTION_CLOSED_IN_HANDSHAKE: equ 5

    endmod


;--- Initialize the connection.
;    Input:  HL = Address of "server name"
;            B  = Length of "server name" (max 128 bytes!)
;
;    Assumes the following has been called already:
;    DATA_TRANSPORT.INIT
;    RECORD_RECEIVER.INIT

INIT:
    xor a
    ld (STATE),a    ;STATE.INITIAL
    ld (ERROR_CODE),a
    ld (RECORD_ERROR),a
    ld (ALERT_SENT),a
    ld (ALERT_RECEIVED),a
    call SHA256.RUN ;With A=0, to initialize, for the hash of the transmitted handshake bytes

    push hl
    push bc
    call P256.GENERATE_KEY_PAIR
    ex de,hl
    pop bc
    pop hl
    call CLIENT_HELLO.INIT

    ret


;--- Update the state machine.
;    Output: A = New state

UPDATE:
    ld a,(STATE)
    cp STATE.FULL_CLOSED
    ret z   ;Nothing to do if connection is closed on both ends
    or a
    jp z,UPDATE_ON_INITIAL_STATE
    cp STATE.ESTABLISHED
    jp c,UPDATE_ON_HANDSHAKE_STATE


    ;--- Update when the connection is established
    ;    (and possibly partially closed)

UPDATE_ON_ESTABLISHED_STATE:

    ;WIP


    ;--- Update when the connection is in the initial state:
    ;    we send the ClientHello message.

UPDATE_ON_INITIAL_STATE:
    call CHECK_CLOSED_DURING_HANDSHAKE
    ret c

    ;For ClientHello the legacy version announced is 1.0 for some compatibility thing
    ld a,1
    ld (RECORD_HEADER.LEGACY_VERSION+1),a

    ld hl,(CLIENT_HELLO.MESSAGE)
    dec hl
    dec hl
    dec hl
    dec hl  ;HL = Handshake message header
    ld bc,(CLIENT_HELLO.SIZE)
    inc bc
    inc bc
    inc bc
    inc bc  ;BC = Record size including handshake message header
    call SEND_HANDSHAKE_RECORD

    ld a,3
    ld (RECORD_HEADER.LEGACY_VERSION+1),a

    ld a,STATE.HANDSHAKE_PLAIN
    ld (STATE),a
    ret


    ;--- Update when the connection is in the handshake negotiation state

UPDATE_ON_HANDSHAKE_STATE:
    call CHECK_CLOSED_DURING_HANDSHAKE
    ret c

    ;WIP

    ld a,(STATE)
    ret


    ;--- Check if the data transport connection was closed during the handshake stage

CHECK_CLOSED_DURING_HANDSHAKE:
    call DATA_TRANSPORT.IS_REMOTELY_CLOSED
    ret nc

    ld a,ERROR.CONNECTION_CLOSED_IN_HANDSHAKE
    ld (ERROR_CODE),a
    call DATA_TRANSPORT.CLOSE
    ld a,STATE.FULL_CLOSED
    ld (STATE),a
    scf
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
    ;WIP
    ret


;--- Receive data
;    Input:  HL = Data
;            BC = Length (max 512 bytes)
;    Output: BC = Actual length

RECEIVE:
    ;WIP
    ret


;--- Send a handshake record
;    Input:  HL = Message header address
;            BC = Message length

SEND_HANDSHAKE_RECORD:
    ld a,(STATE)
    cp STATE.ESTABLISHED
    jr nc,.SEND

    ; If in the initial handshake stage, 
    ; count the message towards the transmitted messages hash

    push hl
    push bc
    ld a,1
    call SHA256.RUN
    pop bc
    pop hl

.SEND:
    ld a,RECORD_TYPE.HANDSHAKE
    ;jp SEND_RECORD


;--- Send a record
;    Input:  A  = Record type
;            HL = Record address
;            BC = Record length

SEND_RECORD:
    ld d,a
    ld a,(STATE)
    push hl
    cp STATE.HANDSHAKE_ENCRYPTED
    jr c,.SEND

    ; We have encryption keys, so let's encrypt the message

    ld a,d
    push hl
    pop de  ;We overwrite the original data with the encrypted version
    call RECORD_ENCRYPTION.ENCRYPT
    ld a,RECORD_TYPE.APP_DATA

.SEND:

    ; Here the record has been encrypted, or will be sent as plaintext

    ld (RECORD_HEADER.CONTENT_TYPE),a
    ld a,b
    ld (RECORD_HEADER.LENGTH),a
    ld a,c
    ld (RECORD_HEADER.LENGTH+1),a

    push bc
    ld hl,RECORD_HEADER.CONTENT_TYPE
    ld bc,5
    call DATA_TRANSPORT.SEND    ;Send the record header...

    pop bc
    pop hl
    call DATA_TRANSPORT.SEND    ;...then send the record itself.
    ret


;--- Send an alert message and close the connection
;    Input:  A = Message code
;    Output: A = FULL_CLOSED state

SEND_ALERT_AND_CLOSE:
    ld (ALERT_RECORD.DESCRIPTION),a
    ld (ALERT_SENT),a
    ld a,RECORD_TYPE.ALERT
    ld hl,ALERT_RECORD.LEVEL
    ld bc,2
    call SEND_RECORD

    call DATA_TRANSPORT.CLOSE

    ld a,ERROR.ALERT_SENT
    ld (ERROR_CODE),a
    ld a,STATE.FULL_CLOSED
    ld (STATE),a
    ret


    ;--- Data area

STATE: db 0
ERROR_CODE: db 0
RECORD_ERROR: db 0
ALERT_SENT: db 0
ALERT_RECEIVED: db 0

    module RECORD_HEADER

CONTENT_TYPE: db 0
LEGACY_VERSION: db 3,3
LENGTH: dw 0

    endmod

    module ALERT_RECORD

LEVEL: db 2    ;Always fatal error
DESCRIPTION: db 0

    endmod

    endmod

    end