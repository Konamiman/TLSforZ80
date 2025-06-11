	title	TLS for Z80 by Konamiman
	subttl	TLS connection handler

    name('TLS_CONNECTION')

.COMMENT \

This is the "main" file that handles a TLS connection.
It contains the entry points that allow user applications to establish a connection,
check its state and send and receive data.

Instructions for use in applications:

1. Call RECORD_RECEIVER.INIT (see record_receiver.asm), this needs to be done only once
2. Initialize the data transport, this will usually mean opening a TCP connection
3. Call TLS_CONNECTION.INIT
4. Call TLS_CONNECTION.UPDATE until the connection state is TLS_CONNECTION.STATE.ESTABLISHED
5. Use TLS_CONNECTION.SEND and TLS_CONNECTION.RECEIVE to send and receive data
6. Call TLS_CONNECTION.UPDATE, if the connection state is still TLS_CONNECTION.STATE.ESTABLISHED
   then goto 5, or call TLS_CONNECTION.CLOSE if you don't have anything else to send
7. If the connection is no longer established you won't be able to send more data,
   close the connection with TLS_CONNECTION.CLOSE and then optionally check
   TLS_CONNECTION.ERROR_CODE, TLS_CONNECTION.SUB_ERROR_CODE and TLS_CONNECTION.ALERT_RECEIVED

Note that you need to implement the data transport layer for your system,
see data_transport.asm which is a stub with the signature of the required methods
(or you can use msx/unapi.asm if you are developing an application for MSX).
You may also want to include tls_connection_constants.asm in your own code.

You can have only one connection open at a given time. You can start over at any time
after the connection is closed (you don't need to run RECORD_RECEIVER.INIT again, though).

NOTE! By default TLS connections will actually be insecure due to how the shared secret derivation
is implemented, see p256.asm. You may want to use external hardware for generating a proper
private and public key pair, if so go ahead and reimplement the public routines in p256.asm as appropriate.

\

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
    public TLS_CONNECTION.STATE

    ifdef DEBUGGING
    public TLS_CONNECTION.SEND_DATA
    public TLS_CONNECTION.SEND_RECORD
    public TLS_CONNECTION.SEND_HANDSHAKE_RECORD
    public TLS_CONNECTION.SEND_ALERT_RECORD
    public TLS_CONNECTION.FLAGS
    public TLS_CONNECTION.HANDSHAKE_HASH
    public TLS_CONNECTION.SHARED_SECRET
    public TLS_CONNECTION.FINISHED_KEY
    public TLS_CONNECTION.FINISHED_VALUE
    public TLS_CONNECTION.COMPARE_BLOCK
    public TLS_CONNECTION.INCOMING_DATA_LENGTH
    public TLS_CONNECTION.INCOMING_DATA_POINTER
    public TLS_CONNECTION.UPDATE_ON_INITIAL_STATE
    public TLS_CONNECTION.UPDATE_ON_HANDSHAKE_STATE
    endif


    extrn CLIENT_HELLO.INIT
    extrn CLIENT_HELLO.MESSAGE_HEADER
    extrn CLIENT_HELLO.SIZE
    extrn CLIENT_HELLO.PUBLIC_KEY
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
    extrn RECORD_ENCRYPTION.TAG_SIZE
    extrn RECORD_ENCRYPTION.INIT
    extrn RECORD_RECEIVER.UPDATE
    extrn RECORD_RECEIVER.HAS_PARTIAL_RECORD
    extrn RECORD_RECEIVER.HANDSHAKE_HEADER
    extrn RECORD_RECEIVER.HANDSHAKE_MSG_SIZE
    extrn SERVER_HELLO.PARSE
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
    extrn HKDF.UPDATE_TRAFFIC_KEY
    extrn HMAC.RUN

    .relab
    .extroot

    include "tls_connection_constants.asm"

    module TLS_CONNECTION

    root RECORD_RECEIVER.UPDATE_RESULT.FULL_RECORD_AVAILABLE
    root RECORD_RECEIVER.UPDATE_RESULT.FULL_HANDSHAKE_MESSAGE
    root RECORD_RECEIVER.UPDATE_RESULT.SPLIT_HANDSHAKE_FIRST

    ifndef TLS_CONNECTION.OUTPUT_DATA_BUFFER_LENGTH
OUTPUT_DATA_BUFFER_LENGTH: equ 128
    endif

    module FLAGS

HAS_KEYS: equ 1
CERTIFICATE_RECEIVED: equ 2
CERTIFICATE_REQUESTED: equ 4

    endmod


;--- Initialize the connection.
;    Input:  HL = Address of server name string
;            B  = Length of server name string
;                 (max length is given by CLIENT_HELLO.SERVER_NAME_MAX_LENGTH)
;
;    Assumes the following has been called already:
;    DATA_TRANSPORT.INIT
;    RECORD_RECEIVER.INIT

INIT:
    ld a,2
    ld (ALERT_RECORD.LEVEL),a ;"Fatal" by default
    xor a
    ld (STATE),a    ;STATE.INITIAL
    ld (ERROR_CODE),a
    ld (SUB_ERROR_CODE),a
    ld (FLAGS),a
    ld (INCOMING_DATA_LENGTH),a
    ld (INCOMING_DATA_LENGTH+1),a
    cpl
    ld (ALERT_SENT),a
    ld (ALERT_RECEIVED),a

    cpl
    push hl
    push bc
    call SHA256.RUN ;With A=0, to initialize, for the hash of the transmitted handshake bytes
    ld hl,CLIENT_HELLO.PUBLIC_KEY
    call P256.GENERATE_KEY_PAIR
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
    or l
    jp nz,RETURN_STATE

    ; Now check if there's an incoming record available.

    call DATA_TRANSPORT.HAS_IN_DATA
    jr nc,.NO_IN_DATA

    call RECORD_RECEIVER.UPDATE
    or a
    jr z,.NO_IN_DATA

    cp RECORD_RECEIVER.UPDATE_RESULT.FULL_RECORD_AVAILABLE
    jp c,HANDLE_RECORD_RECEIVER_ERROR
    jr z,.HANDLE_FULL_RECORD

    cp RECORD_RECEIVER.UPDATE_RESULT.FULL_HANDSHAKE_MESSAGE
    jr z,.HANDLE_HANDSHAKE_MESSAGE

    ; We have a split handshake message:
    ; we don't support that in the Established state.

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

    ; Handshake message received in the established state.

.HANDLE_HANDSHAKE_MESSAGE:
    ld a,e

    cp MESSAGE_TYPE.KEY_UPDATE
    jr z,.UPDATE_KEYS

    cp MESSAGE_TYPE.NEW_SESSION_TICKET
    jp z,RETURN_STATE ;We ignore new session ticket messages

    ; We have received an unknown/unsupported message type

    ld b,a
    ld a,ERROR_CODE.UNEXPECTED_HANDSHAKE_TYPE_IN_ESTABLISHED
    ld c,ALERT_CODE.UNEXPECTED_MESSAGE
    jp SEND_ALERT_AND_CLOSE

    ; We have received a key update request
    ; TODO: verify if message length is 1 and value is 0 or 1

.UPDATE_KEYS:
    ld a,(hl) ;1 = local update requested
    push af

    scf ;Update server keys
    call HKDF.UPDATE_TRAFFIC_KEY

    call INIT_RECORD_ENCRYPTION

    pop af
    or a
    jp z,RETURN_STATE

    ld hl,KEY_UPDATE_MESSAGE
    ld bc,KEY_UPDATE_MESSAGE_END-KEY_UPDATE_MESSAGE
    call SEND_HANDSHAKE_RECORD

    or a ;Update client keys (AFTER sending the KeyUpdate message!)
    call HKDF.UPDATE_TRAFFIC_KEY

    jp RETURN_STATE

    ; No new incoming data available

.NO_IN_DATA:
    call DATA_TRANSPORT.IS_REMOTELY_CLOSED
    ld a,(STATE)
    ret nc

    call RECORD_RECEIVER.HAS_PARTIAL_RECORD
    jp c,RETURN_STATE ;Server closed the connection, but we haven't yet received the last data it sent (the data transport layer has it waiting for us)

    ld a,(STATE)
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
    or a    ;cp RECORD_RECEIVER.UPDATE_RESULT.NO_CHANGE
    jp z,RETURN_STATE

    cp RECORD_RECEIVER.UPDATE_RESULT.FULL_RECORD_AVAILABLE
    jp c,HANDLE_RECORD_RECEIVER_ERROR

    cp RECORD_RECEIVER.UPDATE_RESULT.FULL_HANDSHAKE_MESSAGE
    jr z,.HANDLE_FULL_HANDSHAKE_MESSAGE

    cp RECORD_RECEIVER.UPDATE_RESULT.SPLIT_HANDSHAKE_FIRST
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
    ld a,(STATE)
    cp STATE.ESTABLISHED
    ld a,ERROR_CODE.UNEXPECTED_RECORD_TYPE_IN_HANDSHAKE
    jr c,.HANDLE_NO_HANDSHAKE_NOR_APP_DATA_RECORD_2
    ld a,ERROR_CODE.UNEXPECTED_RECORD_TYPE_IN_ESTABLISHED
.HANDLE_NO_HANDSHAKE_NOR_APP_DATA_RECORD_2:
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
    jp z,.HANDLE_ENCRYPTED_EXTENSIONS
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

    call INIT_RECORD_ENCRYPTION

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
    ld a,ERROR_CODE.FINISHED_RECEIVED_BEFORE_CERTIFICATE
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

    call SHA256.RESTORE_STATE   ;Restore now (not before) because HKDF and HMAC do their own SHA56 hashings

    pop hl  ;Received finished value
    pop bc
    push bc
    push hl
    ld de,FINISHED_VALUE    ;Computed finished value
    call COMPARE_BLOCK
    jr z,.SERVER_FINISHED_OK

    ld a,ERROR_CODE.INVALID_FINISHED_RECEIVED
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

    call INIT_RECORD_ENCRYPTION
    
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
    cp RECORD_RECEIVER.UPDATE_RESULT.SPLIT_HANDSHAKE_FIRST
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


    ; Initialize the record encryption engine,
    ; must be done every time that the encryption keys change.

INIT_RECORD_ENCRYPTION:
    ld hl,HKDF.CLIENT_KEY
    ld de,HKDF.CLIENT_IV
    or a
    call RECORD_ENCRYPTION.INIT
    ld hl,HKDF.SERVER_KEY
    ld de,HKDF.SERVER_IV
    scf
    call RECORD_ENCRYPTION.INIT
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
;            BC = Length
;    Output: Cy = 1 if error

SEND:
    push hl
    push bc
    call CAN_SEND
    pop bc
    pop hl
    ld a,RECORD_TYPE.APP_DATA
    jp c,SEND_DATA
    ccf
    ret


;--- Receive data
;    Input:  DE = Destination for data
;            BC = Length
;    Output: BC = Actual length

RECEIVE:
    ld hl,(INCOMING_DATA_LENGTH)
    ld a,h
    or l
    jr z,.NO_RECEIVE

    push hl ;Save available length for later
    or a
    sbc hl,bc
    jr nc,.DO_RECEIVE   ;Length requested <= length available
    ld bc,(INCOMING_DATA_LENGTH)    ;Length requested > length available
.DO_RECEIVE:
    ld hl,(INCOMING_DATA_POINTER)
    push hl ;Save data pointer for later
    push bc
    ldir
    pop bc

    pop hl  ;Data pointer
    add hl,bc
    ld (INCOMING_DATA_POINTER),hl
    pop hl  ;Data length
    or a
    sbc hl,bc
    ld (INCOMING_DATA_LENGTH),hl
    ret

.NO_RECEIVE:
    ld bc,0
    ret


;--- Locally close the connection

CLOSE:
    ld a,(STATE)
    ld b,a
    or a    ;cp STATE.INITIAL
    jr nz,.NO_INITIAL

    ld (SUB_ERROR_CODE),a
    ld a,ERROR_CODE.LOCAL_CLOSE
    ld (ERROR_CODE),a

    call DATA_TRANSPORT.CLOSE
    ld a,STATE.FULL_CLOSED
    ld (STATE),a
    ret

.NO_INITIAL:
    ld a,1
    ld (ALERT_RECORD.LEVEL),a ;Change level to "warning"
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
    ;jr SEND_DATA


;--- Send handshake or application data.
;    Input:  A  = Record type
;            HL = Data address
;            BC = Data length
;    Output: Cy = 1 if error

SEND_DATA:
    ld d,a
    ld a,(FLAGS)
    and FLAGS.HAS_KEYS
    ld a,d
    jr z,SEND_RECORD

    ; We have encryption keys, so we need to encrypt the data.
    ; We'll encrypt to OUTPUT_DATA_BUFFER, and we'll send the data
    ; in multiple records if it's larger than OUTPUT_DATA_BUFFER_LENGTH.

.LOOP:
    push bc ;Remaining data length
    push hl ;Data address
    ld hl,OUTPUT_DATA_BUFFER_LENGTH
    or a
    sbc hl,bc
    jr nc,.GO
    ld bc,OUTPUT_DATA_BUFFER_LENGTH
.GO:

    pop hl      ;Data address
    push hl
    push bc     ;Chunk size
    push af     ;Record type
    call .SEND_DATA_CHUNK_AS_ENCRYPTED_RECORD
    jr c,.ERROR
    pop af      ;Record type
    or a        ;To bypass "ret c"
.NEXT:
    pop bc      ;Chunk size
    pop de      ;Data address
    pop hl      ;Remaining data length
    ret c       ;Error sending record

    or a
    sbc hl,bc   ;Updated remaining data length
    ret z       ;No more data left to send

    ex de,hl    ;Data address to HL again, DE is remaining length
    add hl,bc   ;Updated data address

    push de
    pop bc      ;Remaining data length to BC again
    jr .LOOP

.ERROR:
    pop af
    jr .NEXT


.SEND_DATA_CHUNK_AS_ENCRYPTED_RECORD:
    ld de,OUTPUT_DATA_BUFFER
    push de
    call RECORD_ENCRYPTION.ENCRYPT
    ld a,RECORD_TYPE.APP_DATA
    pop hl
    ;jr SEND_RECORD


;--- Send a record without any extra processing,
;    encryption/splitting is assumed to have happened already if needed.
;    Call this to send a record that is neither handshake nor application data.
;
;    Input:  A  = Record type
;            HL = Data address
;            BC = Data length
;    Output: Cy = 1 if error

SEND_RECORD:
    ld (RECORD_HEADER.CONTENT_TYPE),a
    ld a,b
    ld (RECORD_HEADER.LENGTH),a
    ld a,c
    ld (RECORD_HEADER.LENGTH+1),a

    push hl
    push bc
    ld hl,RECORD_HEADER.CONTENT_TYPE
    ld bc,5
    call DATA_TRANSPORT.SEND    ;Send the record header...

    pop bc
    pop hl
    call nc,DATA_TRANSPORT.SEND    ;...then send the record itself.

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

FLAGS: db 0

; Current connection state, one of TLS_CONNECTION.STATE
STATE: db 0

; Error code indicating why the connection was closed,
; 0 if not available (the connection is still open)
ERROR_CODE: db 0

; Secondary error code, what gets stored here depends on ERROR_CODE:
;
; RECEIVED_RECORD_DECODE_ERROR: Error returned by RECORD_RECEIVER.UPDATE
; UNEXPECTED_RECORD_TYPE_IN_HANDSHAKE: Record type
; UNEXPECTED_RECORD_TYPE_AFTER_ESTABLISHED: Record type
; UNEXPECTED_HANDSHAKE_TYPE_IN_HANDSHAKE: Message type
; UNEXPECTED_HANDSHAKE_TYPE_BEFORE_SERVER_HELLO: Message type
; UNEXPECTED_HANDSHAKE_TYPE_IN_ESTABLISHED: Message type
; INVALID_SERVER_HELLO: Error returned by SERVER_HELLO.PARSE
; UNSUPPORTED_SPLIT_HANDSHAKE_MESSAGE: Message type
;
; All the error codes and message/record types are defined in tls_connection_constants.asm
SUB_ERROR_CODE: db 0

; Alert codes sent and received, FFh if no alert message was sent or received
ALERT_SENT: db 0FFh
ALERT_RECEIVED: db 0FFh


    module RECORD_HEADER

CONTENT_TYPE: db 0
LEGACY_VERSION: db 3,3
LENGTH: dw 0

    endmod

    module ALERT_RECORD

LEVEL: db 2
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

KEY_UPDATE_MESSAGE:
    db MESSAGE_TYPE.KEY_UPDATE
    db 0,0,1
    db 0    ;Don't request server key update
KEY_UPDATE_MESSAGE_END:

ONE: db 1

OUTPUT_DATA_BUFFER: ds OUTPUT_DATA_BUFFER_LENGTH + 1 + 16 ;RECORD_ENCRYPTION.TAG_SIZE - can't use in DS because it's an external symbol

    endmod

    end
    