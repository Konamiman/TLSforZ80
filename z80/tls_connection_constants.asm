	title	TLS for Z80 by Konamiman
	subttl	Public constants for the TLS connection handler

.COMMENT \

It's recommended to include this file in any program that opens a TLS connection,
at the very least for the STATE constants but also for the error codes and related information
if you want to provide detailed information about what caused a connection to close.

\


;--- Connection states returned by TLS_CONNECTION.UPDATE
;    and available for read at TLS_CONNECTION.STATE

    module TLS_CONNECTION.STATE

INITIAL: equ 0
HANDSHAKE: equ 1
ESTABLISHED: equ 2
LOCALLY_CLOSED: equ 3
REMOTELY_CLOSED: equ 4
FULL_CLOSED: equ 5

    endmod


;--- Error codes available at TLS_CONNECTION.ERROR_CODE
;    after the connection has been closed

    module TLS_CONNECTION.ERROR_CODE

STILL_OPEN: equ 0
LOCAL_CLOSE: equ 1
ALERT_RECEIVED: equ 2
RECEIVED_RECORD_DECODE_ERROR: equ 3
CONNECTION_CLOSED_IN_HANDSHAKE: equ 4
UNEXPECTED_RECORD_TYPE_IN_HANDSHAKE: equ 5
UNEXPECTED_RECORD_TYPE_IN_ESTABLISHED: equ 6
UNEXPECTED_HANDSHAKE_TYPE_IN_HANDSHAKE: equ 7
UNEXPECTED_HANDSHAKE_TYPE_IN_ESTABLISHED: equ 8
SECOND_SERVER_HELLO_RECEIVED: equ 9
INVALID_SERVER_HELLO: equ 10
UNALLOWED_HANDSHAKE_TYPE_BEFORE_SERVER_HELLO: equ 11
FINISHED_RECEIVED_BEFORE_CERTIFICATE: equ 12
INVALID_FINISHED_RECEIVED: equ 13
UNSUPPORTED_SPLIT_HANDSHAKE_MESSAGE: equ 14

    endmod


;--- Alert codes as defined in RFC8446 (only the codes sent by us,
;    see https://datatracker.ietf.org/doc/html/rfc8446#appendix-B.2 for the full list);
;    the received and sent alert codes (if any) will be available at 
;    TLS_CONNECTION.ALERT_RECEIVED and TLS_CONNECTION.ALERT_SENT, respectively,
;    after the connection is closed.

    module TLS_CONNECTION.ALERT_CODE

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


;--- Handshake message types as defined in https://datatracker.ietf.org/doc/html/rfc8446#appendix-B.3

    module TLS_CONNECTION.MESSAGE_TYPE

SERVER_HELLO: equ 2
NEW_SESSION_TICKET: equ 4
ENCRYPTED_EXTENSIONS: equ 8
CERTIFICATE: equ 11
CERTIFICATE_REQUEST: equ 13
CERTIFICATE_VERIFY: equ 15
FINISHED: equ 20
KEY_UPDATE: equ 24

    endmod


;--- Record types as defined in https://datatracker.ietf.org/doc/html/rfc8446#appendix-B.1

    module TLS_CONNECTION.RECORD_TYPE

CHANGE_CIHPER_SPEC: equ 20
ALERT: equ 21
HANDSHAKE: equ 22
APP_DATA: equ 23
HEARTBEAT: equ 24 ; RFC6520, not used by us

    endmod


;--- Status/error codes returned by RECORD_RECEIVER.UPDATE

    module RECORD_RECEIVER.UPDATE_RESULT

; Nothing changed from the previous call to UPDATE
NO_CHANGE: equ 0

; The underlying data transport connection is closed
CONNECTION_CLOSED: equ 1

; The peer sent a record that is bigger than the defined receive buffer size
RECORD_TOO_LONG: equ 2

; Error decrypting the received record: bad auth tag
BAD_AUTH_TAG: equ 3

; Error decrypting the received record: ther payload is all zero bytes
MSG_ALL_ZEROS: equ 4

; The received record is bigger than 16KBytes
RECORD_OVER_16K: equ 5

; The received record contains a handshake message that is bigger than 64KBytes
HANDSHAKE_MSG_TOO_LONG: equ 6

; Non-handshake record received while receiving a split handshake message
NON_HANDSHAKE_RECEIVED: equ 7

; Full record available, it's not a handshake message
FULL_RECORD_AVAILABLE: equ 128

; Full record available, it's a handshake message
FULL_HANDSHAKE_MESSAGE: equ 129

; Full record available, it's the first part of a handshake message split in multiple records
SPLIT_HANDSHAKE_FIRST: equ 130

; Full record available, it's the next part of a handshake message split in multiple records
SPLIT_HANDSHAKE_NEXT: equ 131

; Full record available, it's the last part of a handshake message split in multiple records
SPLIT_HANDSHAKE_LAST: equ 132

    endmod


;--- Error codes returned by SERVER_HELLO.PARSE

    module SERVER_HELLO.ERROR_CODE

; The message is valid
OK: equ 0

; Invalid message format
INVALID_FORMAT: equ 1

; HelloRetryRequest received (we don't support that)
HELLO_RETRY: equ 2

; Not a TLS 1.3 ServerHello message
NO_TLS13: equ 3

; Unsupported cipher suite (it's not TLS_AES_128_GCM_SHA256)
BAD_CIPHER_SUITE: equ 4

; No KeyShare extension for the cipher suite received
NO_KEYSHARE: equ 5

; Mismatching session id echo (not the same as CLIENT_HELLO.SESSION_ID)
BAD_SESSIONID: equ 6

; Bad legacy compression method
BAD_COMPRESSION: equ 7

    endmod

