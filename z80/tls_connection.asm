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
    public TLS_CONNECTION.ERROR_CODE.UNEXPECTED_RECORD_TYPE_IN_HANDSHAKE
    public TLS_CONNECTION.ERROR_CODE.UNALLOWED_HANDSHAKE_TYPE_BEFORE_SERVER_HELLO
    public TLS_CONNECTION.ERROR_CODE.ALERT_RECEIVED
    public TLS_CONNECTION.ERROR_CODE.UNEXPECTED_HANDSHAKE_TYPE_IN_HANDSHAKE
    public TLS_CONNECTION.ERROR_CODE.SECOND_SERVER_HELLO_RECEIVED
    public TLS_CONNECTION.ERROR_CODE.RECEIVED_RECORD_DECODE_ERROR
    public TLS_CONNECTION.ERROR_CODE.INVALID_SERVER_HELLO
    public TLS_CONNECTION.ALERT_CODE.UNEXPECTED_MESSAGE
    public TLS_CONNECTION.ERROR_CODE.UNSUPPORTED_SPLIT_HANDSHAKE_MESSAGE
    public TLS_CONNECTION.ERROR_CODE.CONNECTION_CLOSED_IN_ESTABLISHED
    
    ifdef DEBUGGING
    public TLS_CONNECTION.SEND_RECORD
    public TLS_CONNECTION.SEND_HANDSHAKE_RECORD
    public TLS_CONNECTION.SEND_ALERT_RECORD
    public TLS_CONNECTION.STATE
    public TLS_CONNECTION.FLAGS
    public TLS_CONNECTION.HANDSHAKE_HASH
    public TLS_CONNECTION.SHARED_SECRET
    public TLS_CONNECTION.FINISHED_KEY
    public TLS_CONNECTION.FINISHED_VALUE
    public TLS_CONNECTION.COMPARE_BLOCK
    endif


    extrn CLIENT_HELLO.INIT
    extrn CLIENT_HELLO.MESSAGE_HEADER
    extrn CLIENT_HELLO.SIZE
    extrn P256.GENERATE_KEY_PAIR
    extrn P256.GENERATE_SHARED_KEY
    extrn DATA_TRANSPORT.SEND
    extrn DATA_TRANSPORT.IS_REMOTELY_CLOSED
    extrn DATA_TRANSPORT.HAS_IN_DATA
    extrn DATA_TRANSPORT.CLOSE
    extrn SHA256.RUN
    extrn SHA256.SAVE_STATE
    extrn SHA256.RESTORE_STATE
    extrn RECORD_ENCRYPTION.ENCRYPT
    extrn RECORD_RECEIVER.UPDATE
    extrn RECORD_RECEIVER.TLS_RECORD_TYPE.APP_DATA
    extrn RECORD_RECEIVER.HANDSHAKE_HEADER
    extrn RECORD_RECEIVER.HANDSHAKE_MSG_SIZE
    extrn SERVER_HELLO.PARSE
    extrn RECORD_RECEIVER.ERROR_FULL_RECORD_AVAILABLE
    extrn RECORD_RECEIVER.ERROR_FULL_HANDSHAKE_MESSAGE
    extrn RECORD_RECEIVER.ERROR_SPLIT_HANDSHAKE_FIRST
    extrn SERVER_HELLO.PARSE
    extrn SERVER_HELLO.PUBLIC_KEY
    extrn HKDF.DERIVE_HS_KEYS
    extrn HKDF.DERIVE_AP_KEYS
    extrn HKDF.COMPUTE_FINISHED_KEY
    extrn HKDF.UPDATE_TRAFFIC_KEY
    extrn HKDF.CLIENT_KEY
    extrn HKDF.SERVER_KEY
    extrn HKDF.CLIENT_IV
    extrn HKDF.SERVER_IV
    extrn HMAC.RUN

    module TLS_CONNECTION

    root CLIENT_HELLO.INIT
    root CLIENT_HELLO.MESSAGE_HEADER
    root CLIENT_HELLO.SIZE
    root P256.GENERATE_KEY_PAIR
    root P256.GENERATE_SHARED_KEY
    root DATA_TRANSPORT.SEND
    root DATA_TRANSPORT.IS_REMOTELY_CLOSED
    root DATA_TRANSPORT.HAS_IN_DATA
    root DATA_TRANSPORT.CLOSE
    root SHA256.RUN
    root SHA256.SAVE_STATE
    root SHA256.RESTORE_STATE
    root RECORD_ENCRYPTION.ENCRYPT
    root RECORD_RECEIVER.UPDATE
    root RECORD_RECEIVER.TLS_RECORD_TYPE.APP_DATA
    root RECORD_RECEIVER.HANDSHAKE_HEADER
    root RECORD_RECEIVER.HANDSHAKE_MSG_SIZE
    root SERVER_HELLO.PARSE
    root RECORD_RECEIVER.ERROR_FULL_RECORD_AVAILABLE
    root RECORD_RECEIVER.ERROR_FULL_HANDSHAKE_MESSAGE
    root RECORD_RECEIVER.ERROR_SPLIT_HANDSHAKE_FIRST
    root SERVER_HELLO.PARSE
    root SERVER_HELLO.PUBLIC_KEY
    root HKDF.DERIVE_HS_KEYS
    root HKDF.DERIVE_AP_KEYS
    root HKDF.COMPUTE_FINISHED_KEY
    root HKDF.UPDATE_TRAFFIC_KEY
    root HKDF.CLIENT_KEY
    root HKDF.SERVER_KEY
    root HKDF.CLIENT_IV
    root HKDF.SERVER_IV
    root HMAC.RUN

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

    module MESSAGE_TYPE

SERVER_HELLO: equ 2
ENCRYPTED_EXTENSIONS: equ 8
CERTIFICATE: equ 11
CERTIFICATE_REQUEST: equ 13
CERTIFICATE_VERIFY: equ 15
FINISHED: equ 20

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
UNALLOWED_HANDSHAKE_TYPE_BEFORE_SERVER_HELLO: equ 11
FINISHED_BEFORE_CERTIFICATE: equ 12
BAD_FINISHED: equ 13
BAD_MAX_FRAGMENT_LEGTH: equ 14
INVALID_KEY_UPDATE: equ 15
UNSUPPORTED_SPLIT_HANDSHAKE_MESSAGE: equ 16
CONNECTION_CLOSED_IN_ESTABLISHED: equ 17

    endmod

    module ALERT_CODE

CLOSE_NOTIFY: equ 0
USER_CANCELED: equ 90
BAD_RECORD_MAC: equ 20
RECORD_OVERFLOW: equ 22
DECODE_ERROR: equ 50
DECRYPT_ERROR: equ 51
INTERNAL_ERROR: equ 80
UNEXPECTED_MESSAGE: equ 10
HANDSHAKE_FAILURE: equ 40
PROTOCOL_VERSION: equ 70
ILLEGAL_PARAMETER: equ 47

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
    ld (INCOMING_DATA_LENGTH),a
    ld (INCOMING_DATA_LENGTH+1),a

    push hl
    push bc
    call SHA256.RUN ;With A=0, to initialize, for the hash of the transmitted handshake bytes
    call P256.GENERATE_KEY_PAIR
    ex de,hl
    pop bc
    pop hl
    call CLIENT_HELLO.INIT

    ld a,2
    ld (ALERT_RECORD.LEVEL),a
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

    ; We won't do any state change if there's received data
    ; pending to be retrieved.

    ld hl,(INCOMING_DATA_LENGTH)
    ld a,h
    or a
    jp nz,RETURN_STATE

    ; Now check if there's an incoming record available.

    call DATA_TRANSPORT.HAS_IN_DATA
    jr nz,.NO_IN_DATA

    call RECORD_RECEIVER.UPDATE
    or a
    jr z,.NO_IN_DATA

    cp RECORD_RECEIVER.ERROR_FULL_RECORD_AVAILABLE
    jp c,HANDLE_RECORD_RECEIVER_ERROR
    jr z,.HANDLE_FULL_RECORD

    cp RECORD_RECEIVER.ERROR_FULL_HANDSHAKE_MESSAGE
    jr z,.HANDLE_HANDSHAKE_MESSAGE

    ; We have a split handshake message:
    ; we don't support that.

    ld a,e
    jp UPDATE_ON_HANDSHAKE_STATE.CLOSE_WITH_UNSUPPORTED_SPLIT_HANDSHAKE_MESSAGE_ERROR

    ; We have a full record that is not a handshake message.

.HANDLE_FULL_RECORD:
    ld a,d
    cp RECORD_TYPE.APP_DATA
    jp nz,UPDATE_ON_HANDSHAKE_STATE.HANDLE_NO_HANDSHAKE_NOR_APP_DATA_RECORD

    ; We have application data:
    ; just store pointer and size so that
    ; further calls to RECEIVE will retrieve them.

    ld (INCOMING_DATA_POINTER),hl
    ld (INCOMING_DATA_LENGTH),bc

    jp RETURN_STATE

    ; Handshake message received in the stablished state.

.HANDLE_HANDSHAKE_MESSAGE:
    ld a,e

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

    ld hl,CLIENT_HELLO.MESSAGE_HEADER
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

    call RECORD_RECEIVER.UPDATE
    or a    ;cp RECORD_RECEIVER.ERROR_NO_CHANGE
    jp z,RETURN_STATE

    cp RECORD_RECEIVER.ERROR_FULL_RECORD_AVAILABLE
    jp c,HANDLE_RECORD_RECEIVER_ERROR

    cp RECORD_RECEIVER.ERROR_FULL_HANDSHAKE_MESSAGE
    jr z,.HANDLE_FULL_HANDSHAKE_MESSAGE

    cp RECORD_RECEIVER.ERROR_SPLIT_HANDSHAKE_FIRST
    jp nc,.HANDLE_SPLIT_HANDSHAKE_MESSAGE

    ; We received a record that is not a handshake message:
    ; recognized types are alert and change cipher-spec,
    ; and these get the same handling before and after 
    ; the initial handshake.

.HANDLE_NO_HANDSHAKE_NOR_APP_DATA_RECORD:
    ld a,d
    cp RECORD_TYPE.CHANGE_CIHPER_SPEC
    jp z,RETURN_STATE

    cp RECORD_TYPE.ALERT
    jp z,HANDLE_ALERT_RECEIVED

    ld b,a
    ld a,ERROR_CODE.UNEXPECTED_RECORD_TYPE_IN_HANDSHAKE
    ld c,ALERT_CODE.UNEXPECTED_MESSAGE
    jp SEND_ALERT_AND_CLOSE

    ;* Full handshake message received while in handshake stage
    ;  HL = Message address
    ;  BC = Message length
    ;  E  = Handshake message type

.HANDLE_FULL_HANDSHAKE_MESSAGE:
    push de
    ld a,e
    cp MESSAGE_TYPE.FINISHED
    call nz,INCLUDE_HANDSHAKE_MESSAGE_IN_HASH
    pop de

    ld a,e
    cp MESSAGE_TYPE.SERVER_HELLO
    jr z,.HANDLE_SERVER_HELLO

    ; Any message except ServerHello is only allowed
    ; after we have generated the handshake keys.
    ld a,(FLAGS)
    and FLAGS.HAS_KEYS
    jp z,.SEND_UNALLOWED_MESSAGE_ALERT
    ld a,e

    cp MESSAGE_TYPE.ENCRYPTED_EXTENSIONS
    jr z,.HANDLE_ENCRYPTED_EXTENSIONS
    cp MESSAGE_TYPE.CERTIFICATE
    jr z,.HANDLE_CERTIFICATE
    cp MESSAGE_TYPE.CERTIFICATE_REQUEST
    jr z,.HANDLE_CERTIFICATE_REQUEST
    cp MESSAGE_TYPE.CERTIFICATE_VERIFY
    jr z,.HANDLE_CERTIFICATE_VERIFY
    cp MESSAGE_TYPE.FINISHED
    jr z,.HANDLE_FINISHED

    ld a,ERROR_CODE.UNEXPECTED_HANDSHAKE_TYPE_IN_HANDSHAKE
    jp .SEND_UNEXPECTED_MESSAGE_ALERT


    ;* ServerHello received

.HANDLE_SERVER_HELLO:
    ld a,(FLAGS)
    and FLAGS.HAS_KEYS
    jr z,.HANDLE_SERVER_HELLO_2

    ; We already have keys, thus this is a second ServerHello
    ld a,ERROR_CODE.SECOND_SERVER_HELLO_RECEIVED
    ld b,0
    ld c,ALERT_CODE.UNEXPECTED_MESSAGE
    jp SEND_ALERT_AND_CLOSE

.HANDLE_SERVER_HELLO_2:
    call SERVER_HELLO.PARSE
    or a
    jr z,.HANDLE_SERVER_HELLO_3

    ; Error parsing ServerHello
    ld hl,SERVER_HELLO_ERROR_TO_ALERT_CODE
    ld e,a
    ld d,0
    add hl,de
    dec hl     ;First error code is 1
    ld c,(hl)  ;Alert code
    ld b,a     ;Secondary error code
    ld a,ERROR_CODE.INVALID_SERVER_HELLO
    jp SEND_ALERT_AND_CLOSE

.HANDLE_SERVER_HELLO_3:

    ; All good, let's derive the handshake keys
    
    ld hl,SERVER_HELLO.PUBLIC_KEY
    ld de,SHARED_SECRET
    push de
    call P256.GENERATE_SHARED_KEY ;TODO: Handle error

    call SHA256.SAVE_STATE ;We'll need to keep on hashing for the Finished messages

    ld a,2
    ld de,HANDSHAKE_HASH
    push de
    call SHA256.RUN ;Complete the running hash of all the handshake messages transmitted

    pop hl
    pop ix
    call HKDF.DERIVE_HS_KEYS

    call SHA256.RESTORE_STATE ;Restore here (not before) because HKDF does its own hashing too

    ld a,(FLAGS)
    or FLAGS.HAS_KEYS
    ld (FLAGS),a

    jp RETURN_STATE


    ;* Any other type of message except Finished received:
    ;  We just update flags if needed and then move on.
    ;  We completely ignore server certificates, and we can
    ;  ignore EncryptedExtensions (in particular the
    ;  max fragment length extension, since we're going to send
    ;  records of at most 512 bytes anyway).
    ;  Note that at this point we have already checked if
    ;  handshake keys are available and have updated
    ;  the running handshake hash.

.HANDLE_CERTIFICATE_REQUEST:
    ld d,FLAGS.CERTIFICATE_REQUESTED
    jr .UPDATE_FLAGS

.HANDLE_CERTIFICATE:
    ld d,FLAGS.CERTIFICATE_RECEIVED

.UPDATE_FLAGS:
    ld a,(FLAGS)
    or d
    ld (FLAGS),a

.HANDLE_ENCRYPTED_EXTENSIONS:
.HANDLE_CERTIFICATE_VERIFY:
    jp RETURN_STATE


    ;* Finished message

.HANDLE_FINISHED:
    ;TODO: If server requested a certificate, send an empty Certificate message

    ld a,(FLAGS)
    and FLAGS.CERTIFICATE_RECEIVED
    ld a,ERROR_CODE.FINISHED_BEFORE_CERTIFICATE
    jp z,.SEND_UNEXPECTED_MESSAGE_ALERT

    push bc
    push hl
    call SHA256.SAVE_STATE
    ld a,2
    ld de,HANDSHAKE_HASH
    call SHA256.RUN
    call SHA256.RESTORE_STATE
    pop hl
    pop bc

    push bc
    push hl
    call SHA256.SAVE_STATE  ;We'll need to include the server Finished message itself later
    ld a,2
    ld de,FINISHED_KEY
    scf
    call HKDF.COMPUTE_FINISHED_KEY  ;Server finished HMAC key
    
    ld a,3
    ld ix,HANDSHAKE_HASH
    pop hl
    pop bc
    push bc
    push hl
    ld iy,FINISHED_KEY
    ld hl,32
    ld de,FINISHED_VALUE
    call HMAC.RUN

    call SHA256.RESTORE_STATE   ;Restore here (not before) because HKDF and HMAC do their own SHA56 hashings

    pop hl  ;Received finished value
    pop bc
    push bc
    push hl
    ld de,FINISHED_VALUE    ;Computed finished value
    call COMPARE_BLOCK
    jr z,.SERVER_FINISHED_OK

    ld a,ERROR_CODE.BAD_FINISHED
    ld b,0
    ld c,ALERT_CODE.DECRYPT_ERROR
    jp SEND_ALERT_AND_CLOSE

.SERVER_FINISHED_OK:
    pop hl
    pop bc
    ;NOW finalize the running hash by including the server's Finished message!
    call INCLUDE_HANDSHAKE_MESSAGE_IN_HASH
    ld a,2
    ld de,HANDSHAKE_HASH
    call SHA256.RUN

    ld de,FINISHED_KEY
    or a
    call HKDF.COMPUTE_FINISHED_KEY  ;Client finished HMAC key

    ld a,3
    ld ix,HANDSHAKE_HASH
    ld bc,32
    ld iy,FINISHED_KEY
    ld hl,32
    ld de,FINISHED_VALUE
    call HMAC.RUN   ;Set the value of the client Finished message

    ld a,RECORD_TYPE.CHANGE_CIHPER_SPEC
    ld hl,ONE
    ld bc,1
    call SEND_RECORD

    ld hl,FINISHED_MESSAGE
    ld bc,FINISHED_MESSAGE_END-FINISHED_MESSAGE
    call SEND_HANDSHAKE_RECORD

    ld hl,HANDSHAKE_HASH
    call HKDF.DERIVE_AP_KEYS 
    
    ;Now we have the keys for application data, the handshake has finished
    
    ld a,STATE.ESTABLISHED
    ld (STATE),a
    ret


    ; Jump here when receiving an unallowed handshake message before ServerHello.
    ; Input: E = Handhsake message type

.SEND_UNALLOWED_MESSAGE_ALERT:
    ld a,ERROR_CODE.UNALLOWED_HANDSHAKE_TYPE_BEFORE_SERVER_HELLO

    ; Here A = Error code to set, E = Handshake message type

.SEND_UNEXPECTED_MESSAGE_ALERT:
    ld b,e
    ld c,ALERT_CODE.UNEXPECTED_MESSAGE
    jp SEND_ALERT_AND_CLOSE


    ;* Split handshake message received while in handshake stage

.HANDLE_SPLIT_HANDSHAKE_MESSAGE:
    cp RECORD_RECEIVER.ERROR_SPLIT_HANDSHAKE_FIRST
    jr nz,.HANDLE_NON_FIRST_HANDSHAKE_FRAGMENT

    ; If the message is not of type "Certificate", close with an error:
    ; we only support Certificate messages to be received split.

    ld a,(RECORD_RECEIVER.HANDSHAKE_HEADER)
    cp MESSAGE_TYPE.CERTIFICATE
    jr z,.HANDLE_FIRST_SPLIT_HANDSHAKE_FRAGMENT

.CLOSE_WITH_UNSUPPORTED_SPLIT_HANDSHAKE_MESSAGE_ERROR:
    ld b,a
    ld a,ERROR_CODE.UNSUPPORTED_SPLIT_HANDSHAKE_MESSAGE
    ld c,ALERT_CODE.INTERNAL_ERROR
    jp SEND_ALERT_AND_CLOSE

.HANDLE_FIRST_SPLIT_HANDSHAKE_FRAGMENT:
    ld a,(FLAGS)
    or FLAGS.CERTIFICATE_RECEIVED
    ld (FLAGS),a

    call INCLUDE_HANDSHAKE_MESSAGE_IN_HASH
    jp RETURN_STATE

    ; Non-first message fragment:
    ; We assume it's a fragment of a "Certificate" message
    ; (otherwise we would have closed the connection when receiving the first fragment)

.HANDLE_NON_FIRST_HANDSHAKE_FRAGMENT:
    ld a,1
    call SHA256.RUN
    jp RETURN_STATE


    ; Just return the current state

RETURN_STATE:
    ld a,(STATE)
    ret

    ; Include the message in the SHA256 running hash
    ; Input: HL = Message address
    ;        BC = Message length
    ;        Message header in RECORD_RECEIVER.HANDSHAKE_HEADER
    ; Preserves HL, BC

INCLUDE_HANDSHAKE_MESSAGE_IN_HASH:
    push hl
    push bc

    ld a,1
    ld hl,RECORD_RECEIVER.HANDSHAKE_HEADER
    ld bc,4
    call SHA256.RUN

    pop bc
    pop hl
    push hl
    push bc
    ld a,1
    call SHA256.RUN
    pop bc
    pop hl

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
    ld a,(STATE)
    ld b,a
    or a    ;cp STATE.INITIAL
    ld a,ALERT_CODE.CLOSE_NOTIFY
    jp z,CLOSE_CORE

    ld a,b
    cp STATE.ESTABLISHED
    ld a,ERROR_CODE.LOCAL_CLOSE
    ld bc,ALERT_CODE.USER_CANCELED ;B = seconday error code = 0
    jr c,SEND_ALERT_AND_CLOSE
    ld c,ALERT_CODE.CLOSE_NOTIFY
    ;jp SEND_ALERT_AND_CLOSE


;--- Send an alert and close the connection
;    Input:  A = Error code
;            B = Secondary error code
;            C = Alert code to send
;    Output: A = New state

SEND_ALERT_AND_CLOSE:
    push af
    push bc
    ld a,c
    call SEND_ALERT_RECORD
    pop bc
    pop af
    ;jp CLOSE_CORE


;--- Close the connection
;    Input:  A = Error code
;            B = Secondary error code
;    Output: A = New state

CLOSE_CORE:
    ld (ERROR_CODE),a
    ld a,b
    ld (SUB_ERROR_CODE),a
   
    call DATA_TRANSPORT.CLOSE

    call DATA_TRANSPORT.IS_REMOTELY_CLOSED
    ld a,STATE.FULL_CLOSED
    jr c,.SET_STATE
    ld a,STATE.LOCALLY_CLOSED
.SET_STATE:
    ld (STATE),a
    ret


;--- Handle the reception of an alert record
;    Input: HL = Record data address

HANDLE_ALERT_RECEIVED:
    inc hl
    ld a,(hl)
    ld (ALERT_RECEIVED),a
    cp ALERT_CODE.CLOSE_NOTIFY
    jr z,.HANDLE_CLOSE_NOTIFY

    ; Error received: record it and close the connection.

    ld a,ERROR_CODE.ALERT_RECEIVED
    ld b,0
    jp CLOSE_CORE

    ; Close notification received:
    ; In established state, change to "remotely closed";
    ; othewrwise change to "fully closed".

.HANDLE_CLOSE_NOTIFY:
    ld a,ERROR_CODE.ALERT_RECEIVED
    ld (ERROR_CODE),a
    ld a,(STATE)
    cp STATE.ESTABLISHED
    ld a,STATE.REMOTELY_CLOSED
    jr z,.SET_STATE
    ld a,STATE.FULL_CLOSED
.SET_STATE:
    ld (STATE),a
    ret


;--- Handle an error received by RECORD_RECEIVER_UPDATE
;    Input: A = Error code

HANDLE_RECORD_RECEIVER_ERROR:
    ld b,a ;Secondary error code

    dec a ;First error has code 1
    ld hl,RECORD_ERROR_TO_ALERT_CODE
    ld e,a
    ld d,0
    add hl,de
    ld c,(hl) ;Alert code

    ld a,ERROR_CODE.RECEIVED_RECORD_DECODE_ERROR
    jp SEND_ALERT_AND_CLOSE

    ; Mapping of record receive errors to alert codes
    ; This depends on the values assigned to error codes in RECORD_RECEIVER !!

RECORD_ERROR_TO_ALERT_CODE:
    db ALERT_CODE.INTERNAL_ERROR  ;ERROR_CONNECTION_CLOSED
    db ALERT_CODE.INTERNAL_ERROR  ;ERROR_RECORD_TOO_LONG 
    db ALERT_CODE.BAD_RECORD_MAC  ;ERROR_BAD_AUTH_TAG
    db ALERT_CODE.DECODE_ERROR    ;ERROR_MSG_ALL_ZEROS
    db ALERT_CODE.RECORD_OVERFLOW ;ERROR_RECORD_OVER_16K
    db ALERT_CODE.INTERNAL_ERROR  ;ERROR_HANDSHAKE_MSG_TOO_LONG
    db ALERT_CODE.UNEXPECTED_MESSAGE ;ERROR_NON_HANDSHAKE_RECEIVED


    ; Mapping of ServerHello parsing errors to alert codes

SERVER_HELLO_ERROR_TO_ALERT_CODE:
    db ALERT_CODE.DECODE_ERROR      ;Invalid format
    db ALERT_CODE.HANDSHAKE_FAILURE ;HelloRetryRequest received
    db ALERT_CODE.PROTOCOL_VERSION  ;Not TLS 1.3
    db ALERT_CODE.ILLEGAL_PARAMETER ;CipherSuite is not TLS_AES_128_GCM_SHA256
    db ALERT_CODE.HANDSHAKE_FAILURE ;No KeyShare extension for the cipher suite received
    db ALERT_CODE.HANDSHAKE_FAILURE ;Mismatching session id echo (not the same as CLIENT_HELLO.SESSION_ID)
    db ALERT_CODE.HANDSHAKE_FAILURE ;Bad legacy compression method


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

    cp RECORD_TYPE.HANDSHAKE
    jr z,.ENCRYPT
    cp RECORD_TYPE.APP_DATA
    jr nz,.SEND

    ; We have encryption keys, so let's encrypt the message

.ENCRYPT:
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
    ;TODO: Warning level if userCancelled or closeNotify
    ld (ALERT_RECORD.DESCRIPTION),a
    ld (ALERT_SENT),a
    ld a,RECORD_TYPE.ALERT
    ld hl,ALERT_RECORD.LEVEL
    ld bc,2
    call SEND_RECORD
    ret


;--- Compare two blocks of memory
;    Input:  HL and DE = Blocks, BC = Size
;    Output: Z if they are equal, NZ otherwise

COMPARE_BLOCK:
    ld a,(de)
    inc de
    cpi
    ret nz  ;Not equal
    ret po  ;End of block reached
    jr COMPARE_BLOCK


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
; UNEXPECTED_HANDSHAKE_TYPE_BEFORE_SERVER_HELLO: Message type
; UNEXPECTED_HANDSHAKE_TYPE_AFTER_HANDSHAKE: Message type
; INVALID_SERVER_HELLO: Error returned by SERVER_HELLO.PARSE
; BAD_MAX_FRAGMENT_LEGTH: Received value of max_fragment_length
; INVALID_KEY_UPDATE: Received key update request type
; UNSUPPORTED_SPLIT_HANDSHAKE_MESSAGE: Message type

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

HANDSHAKE_HASH: ds 32
SHARED_SECRET: ds 32
FINISHED_KEY: ds 32

INCOMING_DATA_POINTER: dw 0
INCOMING_DATA_LENGTH: dw 0

FINISHED_MESSAGE:
    db MESSAGE_TYPE.FINISHED
    db 0,0,32
FINISHED_VALUE: 
    ds 32
FINISHED_MESSAGE_END:

ONE: db 1

    endmod

    end