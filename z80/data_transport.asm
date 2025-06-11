	title	TLS for Z80 by Konamiman
	subttl	Underlying data transport module stub
    
    name('DATA_TRANSPORT')

.COMMENT \

Underlying data transport layer for the TLS connection,
it assumes a byte-oriented data stream that has no message boundaries
and can be closed individually by each side (closed means "I'll not send any more data").
This will typically be a TCP connection.

THIS FILE IS A STUB! You need to implement it for the target system.
To do that, go through the methods marked as public and implement them
following the documented input and output values for the Z80 registers.
You may also want to add an "init" method to actually initiate the data connection
but that's not included in this stub because the TLS code assumes that such connection
is already stablished by the time TLS_CONNECTION.INIT is invoked.

See msx/unapi.asm for a working implementation.

\
    
    public DATA_TRANSPORT.SEND
    public DATA_TRANSPORT.RECEIVE
    public DATA_TRANSPORT.HAS_IN_DATA
    public DATA_TRANSPORT.CLOSE
    public DATA_TRANSPORT.IS_REMOTELY_CLOSED

    module DATA_TRANSPORT


;--- Send data
;    Input:  HL = Data address
;            BC = Data length
;                 (will never be over 512 bytes)
;    Output: Cy = 0: Ok, 1: Error

SEND:
    ;TODO: Implement this!

    scf
    ret


;--- Receive data
;    Input:  HL = Destination address
;            BC = Requested length
;    Output: BC = Actual length received

RECEIVE:
    ;TODO: Implement this!

    ld bc,0
    ret


;--- Is there data available for reception?
;    Output: Cy = 1 if yes, 0 if not
;    Note: if this returns 0, RECEIVE should return BC=0

HAS_IN_DATA:
    ;TODO: Implement this!

    or a
    ret


;--- Locally close the connection

CLOSE:
    ;TODO: Implement this!

    ret


;--- Check if the connection is remotely closed
;    Output: Cy = 0 if no, 1 if yes

IS_REMOTELY_CLOSED:
    ;TODO: Implement this!

    scf
    ret

    endmod

    end
