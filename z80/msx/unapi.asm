    public DATA_TRANSPORT.INIT
    public DATA_TRANSPORT.SEND
    public DATA_TRANSPORT.RECEIVE
    public DATA_TRANSPORT.HAS_IN_DATA
    public DATA_TRANSPORT.CLOSE
    public DATA_TRANSPORT.IS_REMOTELY_CLOSED

    public DATA_TRANSPORT.HAS_IN_DATA ;!!!

    module DATA_TRANSPORT

TCPIP_TCP_CLOSE: equ 14
TCPIP_TCP_ABORT: equ 15
TCPIP_TCP_STATE: equ 16
TCPIP_TCP_SEND: equ 17
TCPIP_TCP_RCV: equ 18
TCPIP_WAIT: equ 29

CLOSE_WAIT: equ 7

ERR_BUFFER: equ 13


;--- Initialize
;    Input: A  = Connection number
;           HL = UNAPI code block

INIT:
    ld (CONNECTION_INDEX),a
    ld de,UNAPI_BLOCK
    ld bc,5
    ldir
    ret


;--- Send data
;    Input:  HL = Data address
;            BC = Data length (max 512 bytes)
;    Output: Cy = 0: Ok, 1: Error

SEND:
    push ix
    push iy

    ex de,hl
    push bc
    pop hl
    ld a,(CONNECTION_INDEX)
    ld b,a
    ld c,1  ;Push data
.TRY:
    push hl
    push de
    push bc
    ld a,TCPIP_TCP_SEND
    call UNAPI_BLOCK
    or a
    jr z,.END

    cp ERR_BUFFER
    scf
    jr z,.END

    ld a,TCPIP_WAIT
    call UNAPI_BLOCK
    pop bc
    pop de
    pop hl
    jr .TRY

.END:
    pop bc
    pop de
    pop hl

    pop iy
    pop ix
    
    ret


;--- Receive data
;    Input:  HL = Destination address
;            BC = Length
;    Output: BC = Actual length received

RECEIVE:
    push ix
    push iy
    ex de,hl
    push bc
    pop hl
    ld a,(CONNECTION_INDEX)
    ld b,a
    ld a,TCPIP_TCP_RCV
    call UNAPI_BLOCK

    pop iy
    pop ix
    or a
    ret z
    ld bc,0
    ret


;--- Is data available for reception?
;    Output: Cy = 1 if yes, 0 if not

HAS_IN_DATA:
    call GET_CONNECTION_STATUS
    or a
    scf
    ccf
    ret nz  ;If there's an error the connection doesn't exist anymore (was aborted)

    ld a,h
    or l
    scf
    ret nz
    ccf
    ret


;--- Locally close connection

CLOSE:
    ld a,(CONNECTION_INDEX)
    ld b,a
    ld a,TCPIP_TCP_CLOSE
    jp UNAPI_BLOCK


;--- Check if connection is remotely closed
;    Output: Cy = 0 if no, 1 if yes

IS_REMOTELY_CLOSED:
    call GET_CONNECTION_STATUS
    or a
    scf
    ret nz  ;If there's an error the connection doesn't exist anymore (was aborted)

    ld a,b
    cp CLOSE_WAIT
    scf
    ret z
    ccf
    ret


GET_CONNECTION_STATUS:
    ld a,(CONNECTION_INDEX)
    ld b,a
    ld hl,0
    ld a,TCPIP_TCP_STATE
    jp UNAPI_BLOCK

CONNECTION_INDEX: db 0

UNAPI_BLOCK: ds 5

    endmod

    end
