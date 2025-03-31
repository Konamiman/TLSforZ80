    public TLS_CONNECTION.INIT
    public TLS_CONNECTION.UPDATE
    public TLS_CONNECTION.CAN_SEND
    public TLS_CONNECTION.CAN_RECEIVE
    public TLS_CONNECTION.SEND
    public TLS_CONNECTION.RECEIVE
    public TLS_CONNECTION.CLOSE
    public TLS_CONNECTION.ERROR_CODE
    public TLS_CONNECTION.SUB_ERROR_CODE
    public TLS_CONNECTION.ALERT_SENT
    public TLS_CONNECTION.ALERT_RECEIVED

    ifdef DEBUGGING
    public TLS_CONNECTION.SEND_RECORD
    public TLS_CONNECTION.SEND_HANDSHAKE_RECORD
    public TLS_CONNECTION.SEND_ALERT_RECORD
    endif


    extrn CLIENT_HELLO.INIT
    extrn CLIENT_HELLO.MESSAGE
    extrn CLIENT_HELLO.SIZE
    extrn P256.GENERATE_KEY_PAIR
    extrn P256.GENERATE_SHARED_KEY
    extrn DATA_TRANSPORT.SEND
    extrn DATA_TRANSPORT.IS_REMOTELY_CLOSED
    extrn DATA_TRANSPORT.HAS_IN_DATA
    extrn DATA_TRANSPORT.CLOSE
    extrn SHA256.RUN
    extrn RECORD_ENCRYPTION.ENCRYPT
    extrn RECORD_RECEIVER.UPDATE
    extrn RECORD_RECEIVER.TLS_RECORD_TYPE.APP_DATA
    extrn RECORD_RECEIVER.HANDSHAKE_HEADER
    extrn RECORD_RECEIVER.HANDSHAKE_MSG_SIZE
    extrn SERVER_HELLO.PARSE

    module TLS_CONNECTION

    root CLIENT_HELLO.INIT
    root CLIENT_HELLO.MESSAGE
    root CLIENT_HELLO.SIZE
    root P256.GENERATE_KEY_PAIR
    root P256.GENERATE_SHARED_KEY
    root DATA_TRANSPORT.SEND
    root DATA_TRANSPORT.IS_REMOTELY_CLOSED
    root DATA_TRANSPORT.HAS_IN_DATA
    root DATA_TRANSPORT.CLOSE
    root SHA256.RUN
    root RECORD_ENCRYPTION.ENCRYPT
    root RECORD_RECEIVER.UPDATE
    root RECORD_RECEIVER.TLS_RECORD_TYPE.APP_DATA
    root RECORD_RECEIVER.HANDSHAKE_HEADER
    root RECORD_RECEIVER.HANDSHAKE_MSG_SIZE
    root SERVER_HELLO.PARSE

    .relab

    module STATE

INITIAL: equ 0
HANDSHAKE: equ 1
ESTABLISHED: equ 2
LOCALLY_CLOSED: equ 3
REMOTELY_CLOSED: equ 4
FULL_CLOSED: equ 5

    endmod

    module RECORD_TYPE

CHANGE_CIHPER_SPEC: equ 20
ALERT: equ 21
HANDSHAKE: equ 22
APP_DATA: equ 23

    endmod

    module ERROR_CODE

LOCAL_CLOSE: equ 1
ALERT_RECEIVED: equ 2
RECEIVED_RECORD_DECODE_ERROR: equ 3
CONNECTION_CLOSED_IN_HANDSHAKE: equ 4
UNEXPECTED_RECORD_TYPE_IN_HANDSHAKE: equ 5
UNEXPECTED_RECORD_TYPE_AFTER_ESTABLISHED: equ 6
UNEXPECTED_HANDSHAKE_TYPE_IN_HANDSHAKE: equ 7
UNEXPECTED_HANDSHAKE_TYPE_AFTER_HANDSHAKE: equ 8
SECOND_SERVER_HELLO_RECEIVED: equ 9
INVALID_SERVER_HELLO: equ 10
FINISHED_BEFORE_SERVER_HELLO: equ 11
FINISHED_BEFORE_CERTIFICATE: equ 12
BAD_FINISHED: equ 13
CERTIFICATE_BEFORE_SERVER_HELLO: equ 14
ENCRYPTED_EXTENSIONS_BEFORE_SERVER_HELLO: equ 15
BAD_MAX_FRAGMENT_LEGTH: equ 16
CERTIFICATE_REQUESTED_BEFORE_SERVER_HELLO: equ 17
INVALID_KEY_UPDATE: equ 18

    endmod

    module ALERT_CODE

CLOSE_NOTIFY: equ 0
USER_CANCELED: equ 90

    endmod

    module FLAGS

HAS_KEYS: equ 1
CERTIFICATE_RECEIVED: equ 2
CERTIFICATE_REQUESTED: equ 4

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
    ld (SUB_ERROR_CODE),a
    ld (ALERT_SENT),a
    ld (ALERT_RECEIVED),a
    ld (FLAGS),a
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
    call DATA_TRANSPORT.HAS_IN_DATA
    jr nz,.NO_IN_DATA

    ;WIP

.NO_IN_DATA:
    call DATA_TRANSPORT.IS_REMOTELY_CLOSED
    ld a,(STATE)
    ret nc

    cp STATE.ESTABLISHED
    ld a,STATE.REMOTELY_CLOSED
    jr z,.UPDATE_STATE
    ld a,STATE.FULL_CLOSED
.UPDATE_STATE:
    ld (STATE),a

    ret


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
    call SEND_HANDSHAKE_RECORD

    ld a,3
    ld (RECORD_HEADER.LEGACY_VERSION+1),a

    ld a,STATE.HANDSHAKE
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

    ld a,ERROR_CODE.CONNECTION_CLOSED_IN_HANDSHAKE
    jp CLOSE_CORE


;--- Can application data be sent?
;    Output: Cy=1 if yes

CAN_SEND:
    call UPDATE
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
    call UPDATE
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
    call CAN_SEND
    ccf
    ret c

    ;WIP
    ret


;--- Receive data
;    Input:  HL = Data
;            BC = Length (max 512 bytes)
;    Output: BC = Actual length

RECEIVE:
    call CAN_RECEIVE
    jr c,.DO
    ld bc,0
    ret

.DO:
    ;WIP
    ret


;--- Locally close the connection

CLOSE:
    call UPDATE
    ld a,ERROR_CODE.LOCAL_CLOSE
    ;jp CLOSE_CORE


;--- Close the connection
;    Input: A = Error code

CLOSE_CORE:
    ld (ERROR_CODE),a

    ld a,(STATE)
    ld b,a
    or a    ;cp STATE.INITIAL
    jr z,.NO_SEND_ALERT
    ld a,(ALERT_SENT)
    or a
    jr nz,.NO_SEND_ALERT

    ld a,b
    cp STATE.ESTABLISHED
    ld a,ALERT_CODE.USER_CANCELED
    jr c,.DO_SEND_ALERT
    ld a,ALERT_CODE.CLOSE_NOTIFY
.DO_SEND_ALERT:
    call SEND_ALERT_RECORD

.NO_SEND_ALERT:
    call DATA_TRANSPORT.CLOSE

    call DATA_TRANSPORT.IS_REMOTELY_CLOSED
    ld a,STATE.FULL_CLOSED
    jr c,.SET_STATE
    ld a,STATE.LOCALLY_CLOSED
.SET_STATE:
    ld (STATE),a
    ret


;--- Send a handshake record
;    Input:  HL = Message header address
;            BC = Message length

SEND_HANDSHAKE_RECORD:
    push hl
    inc hl
    inc hl
    ld b,(hl)
    inc hl
    ld c,(hl)
    pop hl
    inc bc
    inc bc
    inc bc
    inc bc  ;Include handshake message header in record data size

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
    ld a,(FLAGS)
    push hl
    and FLAGS.HAS_KEYS
    ld a,d
    jr z,.SEND

    ; We have encryption keys, so let's encrypt the message

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


;--- Send an alert message
;    Input:  A = Message code

SEND_ALERT_RECORD:
    ld (ALERT_RECORD.DESCRIPTION),a
    ld (ALERT_SENT),a
    ld a,RECORD_TYPE.ALERT
    ld hl,ALERT_RECORD.LEVEL
    ld bc,2
    call SEND_RECORD
    ret


    ;--- Data area

STATE: db 0
FLAGS: db 0
ALERT_SENT: db 0
ALERT_RECEIVED: db 0
ERROR_CODE: db 0

; What gets stored here depends on ERROR_CODE:
; RECEIVED_RECORD_DECODE_ERROR: Error returned by RECORD_RECEIVER.UPDATE
; UNEXPECTED_RECORD_TYPE_IN_HANDSHAKE: Record type
; UNEXPECTED_RECORD_TYPE_AFTER_ESTABLISHED: Record type
; UNEXPECTED_HANDSHAKE_TYPE_IN_HANDSHAKE: Message type
; UNEXPECTED_HANDSHAKE_TYPE_AFTER_HANDSHAKE: Message type
; INVALID_SERVER_HELLO: Error returned by SERVER_HELLO.PARSE
; BAD_MAX_FRAGMENT_LEGTH: Received value of max_fragment_length
; INVALID_KEY_UPDATE: Received key update request type

SUB_ERROR_CODE: db 0

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