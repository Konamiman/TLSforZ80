	;--- TLS console for the TCP/IP UNAPI 1.0
	;    By Konamiman, 5/2025
	;    Use: TCPCON <host name>|<IP address> <remote port> [<local port>]

	;This program opens a TCP connection to the specified host
	;on the specified port (optionally a passive connection),
	;and enters a loop in which all the received data is printed
	;on the screen, and all the data typed on the keyboard
	;is sent, until we (by pressing ESC) or the peer
	;close the connection.

	;Note that this is NOT a Telnet client, since no
	;special characters being part of the Telnet specification
	;are supported (received data is printed raw in the screen,
	;and input data is sent raw to the TCP connection).

	public UNAPI_CODE_BLOCK ;!!!
	public WAIT_TLS_OPEN ;!!!

    extrn TLS_CONNECTION.INIT
    extrn TLS_CONNECTION.UPDATE
    extrn TLS_CONNECTION.SEND
    extrn TLS_CONNECTION.RECEIVE
    extrn TLS_CONNECTION.CLOSE
    extrn TLS_CONNECTION.ERROR_CODE
    extrn TLS_CONNECTION.SUB_ERROR_CODE
    extrn TLS_CONNECTION.ALERT_RECEIVED
	extrn TLS_CONNECTION.STATE
	extrn DATA_TRANSPORT.INIT
	extrn RECORD_RECEIVER.INIT

TLS_ESTABLISHED_STATE: equ 2


;*****************************
;***                       ***
;***   MACROS, CONSTANTS   ***
;***                       ***
;*****************************

	;--- Macro for printing a $-finished string

print:	macro	@d
	ld	de,@d
	ld	c,_STROUT
	call	DO_DOS
	endm

	;--- System variables and routines

DOS:	equ	#0005	;DOS function calls entry point
ENASLT:	equ	#0024

TPASLOT1:	equ	#F342
ARG:	equ	#F847
EXTBIO:	equ	#FFCA

	;--- DOS function calls

_TERM0:	equ	#00	;Program terminate
_CONIN:	equ	#01	;Console input with echo
_CONOUT:	equ	#02	;Console output
_DIRIO:	equ	#06	;Direct console I/O
_INNOE:	equ	#08	;Console input without echo
_STROUT:	equ	#09	;String output
_BUFIN:	equ	#0A	;Buffered line input
_CONST:	equ	#0B	;Console status
_TERM:	equ	#62	;Terminate with error code
_DEFAB:	equ	#63	;Define abort exit routine
_DOSVER:	equ	#6F	;Get DOS version

	;--- TCP/IP UNAPI routines

TCPIP_GET_CAPAB:	equ	1
TCPIP_DNS_Q:	equ	6
TCPIP_DNS_S:	equ	7
TCPIP_TCP_OPEN:	equ	13
TCPIP_TCP_CLOSE:	equ	14
TCPIP_TCP_ABORT:	equ	15
TCPIP_TCP_STATE:	equ	16
TCPIP_TCP_SEND:	equ	17
TCPIP_TCP_RCV:	equ	18
TCPIP_WAIT:	equ	29

	;--- TCP/IP UNAPI error codes

ERR_OK:			equ	0
ERR_NOT_IMP:		equ	1
ERR_NO_NETWORK:		equ	2
ERR_NO_DATA:		equ	3
ERR_INV_PARAM:		equ	4
ERR_QUERY_EXISTS:	equ	5
ERR_INV_IP:		equ	6
ERR_NO_DNS:		equ	7
ERR_DNS:		equ	8
ERR_NO_FREE_CONN:	equ	9
ERR_CONN_EXISTS:	equ	10
ERR_NO_CONN:		equ	11
ERR_CONN_STATE:		equ	12
ERR_BUFFER:		equ	13
ERR_LARGE_DGRAM:	equ	14
ERR_INV_OPER:		equ	15


;************************
;***                  ***
;***   MAIN PROGRAM   ***
;***                  ***
;************************

	;------------------------
	;---  Initialization  ---
	;------------------------

	;--- Checks the DOS version and establishes variable DOS2

	ld	c,_DOSVER
	call	DO_DOS
	or	a
	jr	nz,NODOS2
	ld	a,b
	cp	2
	jr	c,NODOS2

	ld	a,#FF
	ld	(DOS2),a	;#FF for DOS 2, 0 for DOS 1
NODOS2:	;

	;--- Prints the presentation

	print	PRESENT_S

	;--- Checks if there are command line parameters.
	;    If not, prints information and finishes.

	ld	a,1
	ld	de,BUFFER
	call	EXTPAR
	jr	nc,HAYPARS

TERMINFO:	print	INFO_S
	jp	DO_TERM
HAYPARS:	;

	;--- Get mapper support routines in DOS 2 (we need GET_P1 and PUT_P1)

	ld	de,#0402
	xor	a
	call	EXTBIO
	or	a
	jr	z,NOMAPPER

	ld	bc,10*3	;Skip ALL_SEG to GET_P0
	add	hl,bc
	ld	de,PUT_P1
	ld	bc,2*3
	ldir

	call	GET_P1
	ld	(TPASEG1),a
NOMAPPER:

	;> From this point we can call TERMINATE to return to DOS.

	;--- Search a TCP/IP UNAPI implementation

	ld	hl,TCPIP_S
	ld	de,ARG
	ld	bc,15
	ldir

	xor	a
	ld	b,0
	ld	de,#2222
	call	EXTBIO
	ld	a,b
	or	a
	ld	de,NOTCPIP_S
	jp	z,PRINT_TERM

	;--- Setup the UNAPI calling code

	ld	a,1
	ld	de,#2222
	call	EXTBIO

	ld	(DO_UNAPI+1),hl
	ld	c,a
	ld	a,h
	cp	#C0
	ld	a,c
	jr	c,NO_UNAPI_P3

	ld	a,#C9
	ld	(SET_UNAPI),a
	jr	OK_SET_UNAPI
NO_UNAPI_P3:

	ld	(UNAPI_SLOT+1),a
	ld	a,b
	cp	#FF
	jr	nz,NO_UNAPI_ROM

	ld	a,#C9
	ld	(UNAPI_SEG),a
	jr	OK_SET_UNAPI
NO_UNAPI_ROM:

	ld	(UNAPI_SEG+1),a
OK_SET_UNAPI:


	;--- Obtains server name from the command line

	ld	a,1
	ld	de,HOST_NAME
	call	EXTPAR

	;--- Obtains remote port from command line

	ld	a,2
	ld	de,BUFFER
	call	EXTPAR
	jp	c,MISSPAR	;Error if the parameter is missing

	ld	hl,BUFFER
	call	EXTNUM16
	jp	c,INVPAR	;Error if not a valid number

	ld	(PORT_REMOTE),bc

	;--- If we are in DOS 2, set the abort exit routine

	ld	a,(DOS2)
	or	a
	ld	de,CLOSE_END	;From now on, pressing CTRL-C
	ld	c,_DEFAB	;has te same effect of pressing CTRL-ESC
	call	nz,DO_DOS		;(aborts the TCP connection and terminates program)


	;------------------------------------------------------------
	;---  Host name resolution and TCP connection initiation  ---
	;------------------------------------------------------------

	;>>> Resolve host name

	print	RESOLVING_S

	ld	hl,HOST_NAME
	ld	b,0
	ld	a,TCPIP_DNS_Q
	call	CALL_UNAPI	;Query the resolver...

	ld	b,a	;...and check for an error
	ld	ix,DNSQERRS_T
	or	a
	jr	nz,DNSQR_ERR

	;* Wait for the query to finish

DNSQ_WAIT:
	ld	a,TCPIP_WAIT
	call	CALL_UNAPI
	call	CHECK_KEY	;To allow process abort with CTRL-C
	ld	b,1
	ld	a,TCPIP_DNS_S
	call	CALL_UNAPI

	;* Error?

	or	a
	ld	ix,DNSRERRS_T
	jr	nz,DNSQR_ERR

	;* The request continues? Then go back to the waiting loop

	ld	a,b
	cp	2
	jr	nz,DNSQ_WAIT	;The request has not finished yet?

	;* Request finished? Store and display result, and continue

	ld	(IP_REMOTE),hl	;Stores the returned result (L.H.E.D)
	ld	(IP_REMOTE+2),de

	ld	ix,RESOLVIP_S	;Displays the result
	ld	a,"$"
	call	IP_STRING
	print	RESOLVOK_S
	print	TWO_NL_S

	jp	RESOLV_OK	;Continues

	;- Error routine for DNS_Q and DNS_S
	;  Input: B=Error code, IX=Errors table

DNSQR_ERR:	
	push ix
	push bc

	;* Prints "ERROR <code>: "

	ld	ix,RESOLVERRC_S
	ld	a,b
	call	BYTE2ASC
	ld	(ix),":"
	ld	(ix+1)," "
	ld	(ix+2),"$"
	print	RESOLVERR_S

	;* Obtains the error code, display it and finish

	pop	bc
	pop de
	call	GET_STRING
	ld	c,_STROUT
	call	DO_DOS

	jp	TERMINATE
RESOLV_OK:	;

	;>>> Close all transient TCP connections

	ld	a,TCPIP_TCP_ABORT
	ld	b,0
	call	CALL_UNAPI

	;>>> Open the TCP connection

	ld	hl,TCP_PARAMS
	ld	a,TCPIP_TCP_OPEN
	call	CALL_UNAPI
	or	a
	jr	z,OPEN_OK

	;* If error is "not implemented", show the appropriate message
	;  depending on the type of connection requested

	cp	ERR_NOT_IMP
	jr	nz,NO_NOT_IMP

	ld	a,(PASSIVE_OPEN)
	or	a
	ld	de,NOTCPA_S	;Active TCP open
	jp	z,PRINT_TERM

	ld	hl,(IP_REMOTE)
	ld	de,(IP_REMOTE+2)
	ld	a,h
	or	l
	or	d
	or	e
	ld	de,NOTCPPU_S	;Passive TCP open with socket unespecified
	jp	z,PRINT_TERM

	ld	de,NOTCPPS_S	;Passive TCP open with socket specified
	jp	PRINT_TERM

NO_NOT_IMP:

	;* If error is other, get its message from the errors table

	push	af
	print	ERROR_S
	pop	af
	ld	b,a	;Error: Show the cause and terminate
	ld	de,TCPOPERRS_T
	call	GET_STRING
	jp	PRINT_TERM

OPEN_OK:
	ld	a,b
	ld	(CON_NUM),a	;No error: saves connection handle
	print	OPENING_S

	;--- Wait until the connection is established.
	;    If ESC is pressed meanwhile, the connection is closed
	;    and the program finishes.

WAIT_OPEN:
	ld	a,TCPIP_WAIT
	call	CALL_UNAPI

	ld	a,(#FBEC)	;Bit 2 of #FBEC is 0
	bit	2,a	;when ESC is being pressed
	jp	z,CLOSE_END

	ld	a,(CON_NUM)
	ld	b,a
	ld	hl,0
	ld	a,TCPIP_TCP_STATE
	call	CALL_UNAPI
	or	a
	jr	z,WAIT_OPEN2

	push	bc
	print	ONE_NL_S
	pop	bc
	ld	de,TCPCLOSED_T	;If the connection has reverted to CLOSED,
	ld	b,c
	set	7,b
	call	GET_STRING	;show the reason and terminate
	jp	PRINT_TERM

WAIT_OPEN2:
	ld	a,b
	cp	4	;4 = code for ESTABLISHED state
	jr	nz,WAIT_OPEN

	print	OPENED_S

	;--- Initialize the TLS engine

	ld hl,8000h
	ld bc,4000h
	call RECORD_RECEIVER.INIT

	ld a,(CON_NUM)
	ld hl,UNAPI_CODE_BLOCK
	call DATA_TRANSPORT.INIT

	ld hl,SNI ;!!!
	ld b,SNI_END-SNI
	call TLS_CONNECTION.INIT

	print TLS_OPENING_S

WAIT_TLS_OPEN:
	ld	a,TCPIP_WAIT
	call	CALL_UNAPI
	call	CHECK_KEY	;To allow process abort with CTRL-C

	call TLS_CONNECTION.UPDATE
	cp TLS_ESTABLISHED_STATE
	jr c,WAIT_TLS_OPEN
	jp nz,TLS_IS_CLOSED

	print TLS_OPENED_S


	;---------------------------
	;---  Program main loop  ---
	;---------------------------

	;- Check for incoming data, if present, print it.
	;- Check for "established" state loss, if so, print
	;  "connection closed by remote side" and finish.
	;- Check for ESC pressing, if so, print "connection
	;  closed/aborted by user" and finish.
	;- Check for F1/F2/F3 pressing, if so, process it.
	;- Check for other key pressing, if so, get the character
	;  or the line (depending on current input mode)
	;  and send it.
	;- Wait for the next interrupt (WAIT_INT) and repeat the loop.

MAIN_LOOP:	;

	;--- First try to get incoming data and then print it

	ld	de,BUFFER
	ld	bc,1024
	call	TLS_CONNECTION.RECEIVE
	ld	a,b
	or	c
	jr	z,END_RCV	;No data available?
TCP_RCVOK:	;

	ld	hl,BUFFER

PRNTLOOP:
	ld	a,(#FBEC)	;If ESC is pressed, terminate
	bit	2,a
	jp	z,CLOSE_END

	push	bc	;Print out data character by character.
	ld	a,(hl)	;We can't use _STROUT function call,
	inc	hl	;since we don't know if any "$" character
	push	hl	;is contained in the string.
	ld	e,a
	ld	c,_CONOUT
	call	DO_DOS
	pop	hl
	pop bc
	dec	bc
	ld	a,b
	or	c
	jr	nz,PRNTLOOP
	jr	STATUS_OK
END_RCV:	;

	;--- Check if the connection has lost the ESTABLISHED
	;    state. If so, close the connection and terminate.

	ld	a,TCPIP_WAIT
	call	CALL_UNAPI

	call TLS_CONNECTION.UPDATE
	cp TLS_ESTABLISHED_STATE
	jr z,STATUS_OK

TLS_IS_CLOSED:
	print TLS_ERROR_S
	ld a,(TLS_CONNECTION.ERROR_CODE)
	ld ix,BUFFER
	call BYTE2ASC
	ld (ix),"$"
	print BUFFER

	print TLS_SUB_ERROR_S
	ld a,(TLS_CONNECTION.SUB_ERROR_CODE)
	ld ix,BUFFER
	call BYTE2ASC
	ld (ix),"$"
	print BUFFER

	print TLS_ALERT_RECEIVED_S
	ld a,(TLS_CONNECTION.ALERT_RECEIVED)
	ld ix,BUFFER
	call BYTE2ASC
	ld (ix),"$"
	print BUFFER

	ld	a,(CON_NUM)
	ld b,a
	ld a,TCPIP_TCP_ABORT
	call	CALL_UNAPI
	print	TWO_NL_S
	jp	TERMINATE
STATUS_OK:

	;--- Check for ESC key being pressed, if so, close/abort
	;    and finish

	ld	a,(#FBEC)
	bit	2,a
	jp	z,CLOSE_END

	;--- Check for F1/F2/F3 pressing

	ld	a,(#FBEB)	;#FBEB contains the status of
	and	%11100000	;F1, F2 and F3 keys on bits
	cp	%11100000	;5, 6 and 7 respectively
	jp	z,NO_F_KEY	;(0 when being pressed)

	;--- F1? Then print help

CHECK_F1:	bit	5,a
	jr	nz,CHECK_F2

	print	HELP_S
	jr	END_F_KEY

	;--- F2? Then toggle character/line mode

CHECK_F2:	bit	6,a
	jr	nz,CHECK_F3

	ld	a,(INPUT_MODE)
	cpl
	ld	(INPUT_MODE),a

	ld	de,INPTOG0_S
	ld	hl,LINE_S
	or	a
	jr	z,CHECK_F22
	ld	de,INPTOG1_S
	ld	hl,CHAR_S
CHECK_F22:	push	hl	;Prints change information
	ld	c,_STROUT	;and updates help text
	call	DO_DOS
	pop	hl
	ld	de,LINCHAR_S
	ld	bc,9
	ldir
	jr	END_F_KEY

	;--- F3? Then toggle local echo ON/OFF

FUN_XOR:	equ	1 xor 8	;_CONIN xor _INNOE

CHECK_F3:	ld	a,(GETCHAR_FUN)
	xor	FUN_XOR	;Toggles _CONIN <--> _INNOE
	ld	(GETCHAR_FUN),a	;(the DOS function used to get char.)

	cp	_CONIN
	ld	de,ECHOTOG0_S
	ld	hl,ON_S
	jr	z,CHECK_F32
	ld	de,ECHOTOG1_S
	ld	hl,OFF_S
CHECK_F32:	push	hl	;Prints change information
	ld	c,_STROUT	;and updates help text
	call	DO_DOS
	pop	hl
	ld	de,ECHONOFF_S
	ld	bc,3
	ldir

END_F_KEY:	ld	c,_DIRIO	;Erases keyboard buffer
	ld	e,#FF	;to avoid the Fx key contents
	call	DO_DOS	;to be accepted as data to be sent
	or	a
	jr	nz,END_F_KEY

	jp	END_KEY

NO_F_KEY:	;

	;--- Check if any other key is pressed, if so, it is
	;    assumed to be data to be sent to the TCP connection
	;    (a whole line is read or just one character, depending
	;    on the current input mode)

	ld	c,_CONST	;Any key was pressed?
	call	DO_DOS
	or	a
	jp	z,END_KEY

	ld	a,(INPUT_MODE)
	or	a
	jr	nz,GET_INPUT_C

	;* Line mode: gets one line, adds a LF at the end,
	;  and sends it

GET_INPUT_L:	ld	a,255
	ld	(BUFFER),a
	ld	c,_BUFIN	;Read characters until ENTER is pressed
	ld	de,BUFFER
	call	DO_DOS
	call	LF	;Prints a LF to change screen line

	ld	a,(BUFFER+1)	;Adds a LF at the end of the line
	ld	c,a
	ld	b,0
	inc	bc
	ld	hl,BUFFER+2
	add	hl,bc
	ld	(hl),10
	inc	bc

	push bc
	pop hl
	ld hl,BUFFER+2
	call TLS_CONNECTION.SEND
	;TODO: Failed?

	jr	END_KEY

	;* Character mode: gets the character with or without echo,
	;  and sends it to the connection

GET_INPUT_C:	ld	a,(GETCHAR_FUN)
	ld	c,a
	push	bc
	call	DOS
	ld	(BUFFER),a

	pop	hl	;If character is CR, sends also
	cp	13	;a LF
	ld	hl,1
	jr	nz,GET_INPUT_C2

	ld	a,10
	ld	(BUFFER+1),a
	ld	a,l	;If local echo is ON, the LF
	cp	_CONIN	;must be explicitly printed
	call	z,LF
	ld	hl,2

GET_INPUT_C2:
	ld	a,(CON_NUM)	;Sends the character(s)
	ld	b,a
	ld	de,BUFFER
	ld	c,1	;"PUSH" is specified
	ld	a,TCPIP_TCP_SEND
	call	CALL_UNAPI
	or	a
	jp	nz,TCP_ERROR

END_KEY:	;

	;--- End of the main loop step:
	;    Give the INL code an opportunity to excute,
	;    then repeat the loop.

	ld	a,TCPIP_WAIT
	call	CALL_UNAPI
	jp	MAIN_LOOP


	;--- Jump here in case a call to TCP_SEND or TCP_RCV return an error.
	;    Input: A=Error code

	;* If the error is "Output buffer overflow",
	;  print the error, close the connection and finish

TCP_ERROR:
	cp	ERR_NO_CONN
	jr	z,TCP_ERROR2

	;* The error is not "Connection is closed"

	ld	de,TCPERROR_T
	ld	b,a
	call	GET_STRING
	ld	c,_STROUT
	call	DO_DOS

	ld	a,(CON_NUM)
	ld	b,a
	ld	a,TCPIP_TCP_CLOSE
	call	CALL_UNAPI
	jp	TERMINATE
TCP_ERROR2:

	;* The error is "Connection is closed"
	;  (cannot be ERR_CONN_STATE, since the
	;  connection is either CLOSED, ESTABLISHED or CLOSE-WAIT;
	;  and we assume that it is not ERR_INV_PARAM nor ERR_NOT_IMP):
	;  Print the cause and finish

	print	TWO_NL_S
	ld	a,(CON_NUM)
	ld	b,a
	ld	hl,0
	ld	a,TCPIP_TCP_STATE
	call	CALL_UNAPI
	ld	b,c
	set	7,b
	ld	de,TCPCLOSED_T
	call	GET_STRING
	jp	PRINT_TERM


;******************************
;***                        ***
;***   AUXILIARY ROUTINES   ***
;***                        ***
;******************************

;--- STRCMP: Compares two strings
;    Input: HL, DE = Strings
;    Output: Z if strings are equal

STRCMP:
	ld	a,(de)
	cp	(hl)
	ret	nz
	or	a
	ret	z
	inc	hl
	inc	de
	jr	STRCMP


;--- NAME: COMP
;      Compares HL and DE (16 bits unsigned)
;    INPUT:    HL, DE = numbers to compare
;    OUTPUT:    C, NZ if HL > DE
;               C,  Z if HL = DE
;              NC, NZ if HL < DE

COMP:	call	_COMP
	ccf
	ret

_COMP:	ld	a,h
	sub	d
	ret	nz
	ld	a,l
	sub	e
	ret


;--- NAME: EXTPAR
;      Extracts a parameter from the command line
;    INPUT:   A  = Parameter to extract (the first one is 1)
;             DE = Buffer to put the extracted parameter
;    OUTPUT:  A  = Total number of parameters in the command line
;             CY = 1 -> The specified parameter does not exist
;                       B undefined, buffer unmodified
;             CY = 0 -> B = Parameter length, not including the tailing 0
;                       Parameter extracted to DE, finished with a 0 byte
;                       DE preserved

EXTPAR:	or	a	;Terminates with error if A = 0
	scf
	ret	z

	ld	b,a
	ld	a,(#80)	;Terminates with error if
	or	a	;there are no parameters
	scf
	ret	z
	ld	a,b

	push af
	push hl
	ld	a,(#80)
	ld	c,a	;Adds 0 at the end
	ld	b,0	;(required under DOS 1)
	ld	hl,#81
	add	hl,bc
	ld	(hl),0
	pop	hl
	pop af

	push hl
	push de
	push ix
	ld	ix,0	;IXl: Number of parameter
	ld	ixh,a	;IXh: Parameter to be extracted
	ld	hl,#81

	;* Scans the command line and counts parameters

PASASPC:	ld	a,(hl)	;Skips spaces until a parameter
	or	a	;is found
	jr	z,ENDPNUM
	cp	" "
	inc	hl
	jr	z,PASASPC

	inc	ix	;Increases number of parameters
PASAPAR:	ld	a,(hl)	;Walks through the parameter
	or	a
	jr	z,ENDPNUM
	cp	" "
	inc	hl
	jr	z,PASASPC
	jr	PASAPAR

	;* Here we know already how many parameters are available

ENDPNUM:	ld	a,ixl	;Error if the parameter to extract
	cp	ixh	;is greater than the total number of
	jr	c,EXTPERR	;parameters available

	ld	hl,#81
	ld	b,1	;B = current parameter
PASAP2:	ld	a,(hl)	;Skips spaces until the next
	cp	" "	;parameter is found
	inc	hl
	jr	z,PASAP2

	ld	a,ixh	;If it is the parameter we are
	cp	b	;searching for, we extract it,
	jr	z,PUTINDE0	;else...

	inc	B
PASAP3:	ld	a,(hl)	;...we skip it and return to PASAP2
	cp	" "
	inc	hl
	jr	nz,PASAP3
	jr	PASAP2

	;* Parameter is located, now copy it to the user buffer

PUTINDE0:	ld	b,0
	dec	hl
PUTINDE:	inc	b
	ld	a,(hl)
	cp	" "
	jr	z,ENDPUT
	or	a
	jr	z,ENDPUT
	ld	(de),a	;Paramete is copied to (DE)
	inc	de
	inc	hl
	jr	PUTINDE

ENDPUT:	xor	a
	ld	(de),a
	dec	b

	ld	a,ixl
	or	a
	jr	FINEXTP
EXTPERR:	scf
FINEXTP:	
	pop	ix
	pop de
	pop hl
	ret


;--- Termination due to ESC or CTRL-C pressing
;    Connection is closed, or aborted if CTRL is pressed,
;    and program finishes

CLOSE_END:	ld	a,(CON_NUM)
	cp	#FF
	jr	z,TERMINATE
	push	af
	pop	bc

	ld	a,(#FBEB)	;Checks CTRL key status
	bit	1,a	;in order to decide whether
	ld	a,TCPIP_TCP_CLOSE	;CLOSE or ABORT must be executed
	ld	de,USERCLOS_S	;(always ABORT in case of CTRL-C)
	jr	nz,CLOSE_END2	;and which message to show
	ld	a,TCPIP_TCP_ABORT	;("user closed" or "user aborted")
	ld	de,USERAB_S
CLOSE_END2:	push	de

	call	CALL_UNAPI

CLOSE_END3:	pop	de
	jp	PRINT_TERM


;--- Program terminations

	;* Print string at DE and terminate

PRINT_TERM:
	ld	c,_STROUT
	call	DO_DOS
	jr	TERMINATE

	;* Invalid parameter

INVPAR:	print	INVPAR_S
	jr	TERMINATE

	;* Missing parameter

MISSPAR:	print	MISSPAR_S
	jr	TERMINATE

	;* Generic termination routine

TERMINATE:
	ld	a,(TPASLOT1)
	ld	h,#40
	call	ENASLT

	ld	a,(TPASEG1)	;Restores TPA on page 1
	call	PUT_P1

	ld	a,(DOS2)	;Under DOS 2, the CTRL-C
	or	a	;control routine has to be cancelled first
	ld	de,0
	ld	c,_DEFAB
	call	nz,DO_DOS

DO_TERM:
	ld	bc,_TERM+0*256
	call	DO_DOS
	ld	c,_TERM0
	jp	DO_DOS


;--- Prints LF

LF:	ld	e,10
	ld	c,_CONOUT
	jp	DO_DOS


;--- Segment switching routines for page 1,
;    these are overwritten with calls to
;    mapper support routines on DOS 2

PUT_P1:	out	(#FD),a
	ret
GET_P1:	in	a,(#FD)
	ret

TPASEG1:	db	2	;TPA segment on page 1


;--- IP_STRING: Converts an IP address to a string
;    Input: L.H.E.D = IP address
;           A = Termination character
;           IX = Address for the string

IP_STRING:
	push	af
	ld	a,l
	call	BYTE2ASC
	ld	(ix),"."
	inc	ix
	ld	a,h
	call	BYTE2ASC
	ld	(ix),"."
	inc	ix
	ld	a,e
	call	BYTE2ASC
	ld	(ix),"."
	inc	ix
	ld	a,d
	call	BYTE2ASC

	pop	af
	ld	(ix),a	;Termination character
	ret


;--- NAME: NUMTOASC
;      Converts a 16 bit number into an ASCII string
;    INPUT:      DE = Number to convert
;                HL = Buffer to put the generated ASCII string
;                B  = Total number of characters of the string
;                     not including any termination character
;                C  = Padding character
;                     The generated string is right justified,
;                     and the remaining space at the left is padded
;                     with the character indicated in C.
;                     If the generated string length is greater than
;                     the value specified in B, this value is ignored
;                     and the string length is the one needed for
;                     all the digits of the number.
;                     To compute length, termination character "$" or 00
;                     is not counted.
;                 A = &B ZPRFFTTT
;                     TTT = Format of the generated string number:
;                            0: decimal
;                            1: hexadecimal
;                            2: hexadecimal, starting with "&H"
;                            3: hexadecimal, starting with "#"
;                            4: hexadecimal, finished with "H"
;                            5: binary
;                            6: binary, starting with "&B"
;                            7: binary, finishing with "B"
;                     R   = Range of the input number:
;                            0: 0..65535 (unsigned integer)
;                            1: -32768..32767 (twos complement integer)
;                               If the output format is binary,
;                               the number is assumed to be a 8 bit integer
;                               in the range 0.255 (unsigned).
;                               That is, bit R and register D are ignored.
;                     FF  = How the string must finish:
;                            0: No special finish
;                            1: Add a "$" character at the end
;                            2: Add a 00 character at the end
;                            3: Set to 1 the bit 7 of the last character
;                     P   = "+" sign:
;                            0: Do not add a "+" sign to positive numbers
;                            1: Add a "+" sign to positive numbers
;                     Z   = Left zeros:
;                            0: Remove left zeros
;                            1: Do not remove left zeros
;    OUTPUT:    String generated in (HL)
;               B = Length of the string, not including the padding
;               C = Length of the string, including the padding
;                   Tailing "$" or 00 are not counted for the length
;               All other registers are preserved

NUMTOASC:	
	push	af
	push ix
	push de
	push hl
	ld	ix,WorkNTOA
	push af
	push af
	and	%00000111
	ld	(ix+0),a	;Type
	pop	af
	and	%00011000
	rrca
	rrca
	rrca
	ld	(ix+1),a	;Finishing
	pop	af
	and	%11100000
	rlca
	rlca
	rlca
	ld	(ix+6),a	;Flags: Z(zero), P(+ sign), R(range)
	ld	(ix+2),b	;Number of final characters
	ld	(ix+3),c	;Padding character
	xor	a
	ld	(ix+4),a	;Total length
	ld	(ix+5),a	;Number length
	ld	a,10
	ld	(ix+7),a	;Divisor = 10
	ld	(ix+13),l	;User buffer
	ld	(ix+14),h
	ld	hl,BufNTOA
	ld	(ix+10),l	;Internal buffer
	ld	(ix+11),h

ChkTipo:	ld	a,(ix+0)	;Set divisor to 2 or 16,
	or	a	;or leave it to 10
	jr	z,ChkBoH
	cp	5
	jp	nc,EsBin
EsHexa:	ld	a,16
	jr	GTipo
EsBin:	ld	a,2
	ld	d,0
	res	0,(ix+6)	;If binary, range is 0-255
GTipo:	ld	(ix+7),a

ChkBoH:	ld	a,(ix+0)	;Checks if a final "H" or "B"
	cp	7	;is desired
	jp	z,PonB
	cp	4
	jr	nz,ChkTip2
PonH:	ld	a,"H"
	jr	PonHoB
PonB:	ld	a,"B"
PonHoB:	ld	(hl),a
	inc	hl
	inc	(ix+4)
	inc	(ix+5)

ChkTip2:	ld	a,d	;If the number is 0, never add sign
	or	e
	jr	z,NoSgn
	bit	0,(ix+6)	;Checks range
	jr	z,SgnPos
ChkSgn:	bit	7,d
	jr	z,SgnPos
SgnNeg:	push	hl	;Negates number
	ld	hl,0	;Sign=0:no sign; 1:+; 2:-
	xor	a
	sbc	hl,de
	ex	de,hl
	pop	hl
	ld	a,2
	jr	FinSgn
SgnPos:	bit	1,(ix+6)
	jr	z,NoSgn
	ld	a,1
	jr	FinSgn
NoSgn:	xor	a
FinSgn:	ld	(ix+12),a

ChkDoH:	ld	b,4
	xor	a
	cp	(ix+0)
	jp	z,EsDec
	ld	a,4
	cp	(ix+0)
	jp	nc,EsHexa2
EsBin2:	ld	b,8
	jr	EsHexa2
EsDec:	ld	b,5

EsHexa2:	push	de
Divide:	
	push bc
	push hl	;DE/(IX+7)=DE, remaining A
	ld	a,d
	ld	c,e
	ld	d,0
	ld	e,(ix+7)
	ld	hl,0
	ld	b,16
BucDiv:	rl	c
	rla
	adc	hl,hl
	sbc	hl,de
	jr	nc,$+3
	add	hl,de
	ccf
	djnz	BucDiv
	rl	c
	rla
	ld	d,a
	ld	e,c
	ld	a,l
	pop	hl
	pop bc

ChkRest9:	cp	10	;Converts the remaining
	jp	nc,EsMay9	;to a character
EsMen9:	add	a,"0"
	jr	PonEnBuf
EsMay9:	sub	10
	add	a,"A"

PonEnBuf:	ld	(hl),a	;Puts character in the buffer
	inc	hl
	inc	(ix+4)
	inc	(ix+5)
	djnz	Divide
	pop	de

ChkECros:	bit	2,(ix+6)	;Cchecks if zeros must be removed
	jr	nz,ChkAmp
	dec	hl
	ld	b,(ix+5)
	dec	b	;B=num. of digits to check
Chk1Cro:	ld	a,(hl)
	cp	"0"
	jr	nz,FinECeros
	dec	hl
	dec	(ix+4)
	dec	(ix+5)
	djnz	Chk1Cro
FinECeros:	inc	hl

ChkAmp:	ld	a,(ix+0)	;Puts "#", "&H" or "&B" if necessary
	cp	2
	jr	z,PonAmpH
	cp	3
	jr	z,PonAlm
	cp	6
	jr	nz,PonSgn
PonAmpB:	ld	a,"B"
	jr	PonAmpHB
PonAlm:	ld	a,"#"
	ld	(hl),a
	inc	hl
	inc	(ix+4)
	inc	(ix+5)
	jr	PonSgn
PonAmpH:	ld	a,"H"
PonAmpHB:	ld	(hl),a
	inc	hl
	ld	a,"&"
	ld	(hl),a
	inc	hl
	inc	(ix+4)
	inc	(ix+4)
	inc	(ix+5)
	inc	(ix+5)

PonSgn:	ld	a,(ix+12)	;Puts sign
	or	a
	jr	z,ChkLon
SgnTipo:	cp	1
	jr	nz,PonNeg
PonPos:	ld	a,"+"
	jr	PonPoN
	jr	ChkLon
PonNeg:	ld	a,"-"
PonPoN:	ld	(hl),a
	inc	hl
	inc	(ix+4)
	inc	(ix+5)

ChkLon:	ld	a,(ix+2)	;Puts padding if necessary
	cp	(ix+4)
	jp	c,Invert
	jr	z,Invert
PonCars:	sub	(ix+4)
	ld	b,a
	ld	a,(ix+3)
Pon1Car:	ld	(hl),a
	inc	hl
	inc	(ix+4)
	djnz	Pon1Car

Invert:	ld	l,(ix+10)
	ld	h,(ix+11)
	xor	a	;Inverts the string
	push	hl
	ld	(ix+8),a
	ld	a,(ix+4)
	dec	a
	ld	e,a
	ld	d,0
	add	hl,de
	ex	de,hl
	pop	hl	;HL=initial buffer, DE=final buffer
	ld	a,(ix+4)
	srl	a
	ld	b,a
BucInv:	push	bc
	ld	a,(de)
	ld	b,(hl)
	ex	de,hl
	ld	(de),a
	ld	(hl),b
	ex	de,hl
	inc	hl
	dec	de
	pop	bc
	ld	a,b	;*** This part was missing on the
	or	a	;*** original routine
	jr	z,ToBufUs	;***
	djnz	BucInv
ToBufUs:	ld	l,(ix+10)
	ld	h,(ix+11)
	ld	e,(ix+13)
	ld	d,(ix+14)
	ld	c,(ix+4)
	ld	b,0
	ldir
	ex	de,hl

ChkFin1:	ld	a,(ix+1)	;Checks if "$" or 00 finishing is desired
	and	%00000111
	or	a
	jr	z,Fin
	cp	1
	jr	z,PonDolar
	cp	2
	jr	z,PonChr0

PonBit7:	dec	hl
	ld	a,(hl)
	or	%10000000
	ld	(hl),a
	jr	Fin

PonChr0:	xor	a
	jr	PonDo0
PonDolar:	ld	a,"$"
PonDo0:	ld	(hl),a
	inc	(ix+4)

Fin:	ld	b,(ix+5)
	ld	c,(ix+4)
	pop	hl
	pop de
	pop ix
	pop af
	ret

WorkNTOA:	defs	16
BufNTOA:	ds	10


;--- EXTNUM16
;      Extracts a 16-bit number from a zero-finished ASCII string
;    Input:  HL = ASCII string address
;    Output: BC = Extracted number
;            Cy = 1 if error (invalid string)

EXTNUM16:	call	EXTNUM
	ret	c
	jp	c,INVPAR	;Error if >65535

	ld	a,e
	or	a	;Error if the last char is not 0
	ret	z
	scf
	ret


;--- NAME: EXTNUM
;      Extracts a 5 digits number from an ASCII string
;    INPUT:      HL = ASCII string address
;    OUTPUT:     CY-BC = 17 bits extracted number
;                D  = number of digits of the number
;                     The number is considered to be completely extracted
;                     when a non-numeric character is found,
;                     or when already five characters have been processed.
;                E  = first non-numeric character found (or 6th digit)
;                A  = error:
;                     0 => No error
;                     1 => The number has more than five digits.
;                          CY-BC contains then the number composed with
;                          only the first five digits.
;    All other registers are preserved.

EXTNUM:	
	push hl
	push ix
	ld	ix,ACA
	res	0,(ix)
	set	1,(ix)
	ld	bc,0
	ld	de,0
BUSNUM:	ld	a,(hl)	;Jumps to FINEXT if no numeric character
	ld	e,a	;IXh = last read character
	cp	"0"
	jr	c,FINEXT
	cp	"9"+1
	jr	nc,FINEXT
	ld	a,d
	cp	5
	jr	z,FINEXT
	call	POR10

SUMA:	push	hl	;BC = BC + A 
	push	bc
	pop	hl
	ld	bc,0
	ld	a,e
	sub	"0"
	ld	c,a
	add	hl,bc
	call	c,BIT17
	push	hl
	pop	bc
	pop	hl

	inc	d
	inc	hl
	jr	BUSNUM

BIT17:	set	0,(ix)
	ret
ACA:	db	0	;b0: num>65535. b1: more than 5 digits

FINEXT:	ld	a,e
	cp	"0"
	call	c,NODESB
	cp	"9"+1
	call	nc,NODESB
	ld	a,(ix)
	pop	ix
	pop hl
	srl	a
	ret

NODESB:	res	1,(ix)
	ret

POR10:	
	push	de
	push 	hl	;BC = BC * 10 
	push	bc
	push	bc
	pop	hl
	pop	de
	ld	b,3
ROTA:	sla	l
	rl	h
	djnz	ROTA
	call	c,BIT17
	add	hl,de
	call	c,BIT17
	add	hl,de
	call	c,BIT17
	push	hl
	pop	bc
	pop	hl
	pop de
	ret


;--- CHECK_KEY: Calls a DOS routine so the CTRL-C pressing
;    can be detected by DOS and the program can be aborted.
;    Also, returns A<>0 if a key has been pressed.

CHECK_KEY:	ld	e,#FF
	ld	c,_DIRIO
	jp	DO_DOS


;--- BYTE2ASC: Converts the number A into a string without termination
;    Puts the string in (IX), and modifies IX so it points after the string
;    Modifies: C

BYTE2ASC:	cp	10
	jr	c,B2A_1D
	cp	100
	jr	c,B2A_2D
	cp	200
	jr	c,B2A_1XX
	jr	B2A_2XX

	;--- One digit

B2A_1D:	add	"0"
	ld	(ix),a
	inc	ix
	ret

	;--- Two digits

B2A_2D:	ld	c,"0"
B2A_2D2:	inc	c
	sub	10
	cp	10
	jr	nc,B2A_2D2

	ld	(ix),c
	inc	ix
	jr	B2A_1D

	;--- Between 100 and 199

B2A_1XX:	ld	(ix),"1"
	sub	100
B2A_XXX:	inc	ix
	cp	10
	jr	nc,B2A_2D	;If ti is 1XY with X>0
	ld	(ix),"0"	;If it is 10Y
	inc	ix
	jr	B2A_1D

	;--- Between 200 and 255

B2A_2XX:	ld	(ix),"2"
	sub	200
	jr	B2A_XXX


;--- GET_STRING: Returns the string associated to a number, or "Unknown".
;    Input:  DE = Pointer to a table of numbers and strings, with the format:
;                 db num,"String$"
;                 db num2,"String2$"
;                 ...
;                 db 0
;            B = Associated number
;    Output: DE = Pointer to the string

GET_STRING:	ld	a,(de)
	inc	de
	or	a	;String not found: return "Unknown"
	jr	nz,LOOP_GETS2

	ld	ix,UNKCODE_S
	ld	a,b
	call	BYTE2ASC
	ld	(ix),")"
	ld	(ix+1),"$"

	ld	de,STRUNK_S
	ret

LOOP_GETS2:	cp	b	;The number matches?
	ret	z

LOOP_GETS3:	ld	a,(de)	;No: pass to the next one
	inc	de
	cp	"$"
	jr	nz,LOOP_GETS3
	jr	GET_STRING

STRUNK_S:	db	"*** Unknown error ("
UNKCODE_S:	db	"000)$"

;--- Code to switch TCP/IP implementation on page 1, if necessary

SET_UNAPI:
	ld	a,(UNAPI_IS_SET)
	or	a
	ret	nz
	dec	a
	ld	(UNAPI_IS_SET),a
UNAPI_SLOT:	ld	a,0
	ld	h,#40
	call	ENASLT
UNAPI_SEG:	ld	a,0
	jp	PUT_P1

CALL_UNAPI:	ex	af,af'
	exx
	call	SET_UNAPI
	ei
	ex	af,af'
	exx

DO_UNAPI:	jp	0

UNAPI_CODE_BLOCK: jp CALL_UNAPI

;--- Code to call a DOS function

DO_DOS:
	ex	af,af'
	xor	a
	ld	(UNAPI_IS_SET),a
	ex	af,af'
	jp	5


;***************************
;***                     ***
;***   DATA, VARIABLES   ***
;***                     ***
;***************************

;--- TCP parameters block for the connection, it is filled in with the command line parameters

TCP_PARAMS:
IP_REMOTE:	db	0,0,0,0
PORT_REMOTE:	dw	0
PORT_LOCAL:	dw	#FFFF	;Random port if none is specified
USER_TOUT:	dw	0
PASSIVE_OPEN:	db	0

;--- Variables

UNAPI_IS_SET:	db	0	;#FF when UNAPI slot/seg is switched on page 1
CON_NUM:	db	#FF	;Connection handle
INPUT_MODE:	db	0	;0 for line mode, #FF for character mode
GETCHAR_FUN:	db	_CONIN	;_CONIN for echo ON, _INNOE for echo OFF
DOS2:		db	0	;0 for DOS 1, #FF for DOS 2

;--- Text strings

PRESENT_S:
	db	"TLS Console (simplified Telnet client over TLS) for the TCP/IP UNAPI 1.0",13,10
	db	"By Konamiman, 5/2025",13,10,10,"$"

INFO_S:	db	"Usage: TLSCON <host name>|<remote IP address> <remote port> [<local port>]",13,10,10
	db	"       <local port>: if not specified, a random port will be selected",13,10,"$"

NOINS_S:	db	"*** InterNestor Lite is not installed",13,10,"$"
INVPAR_S:	db	"*** Invalid parameter(s)",13,10,"$"
MISSPAR_S:	db	"*** Missing parameter(s)",13,10,"$"
ERROR_S:	db	"*** ERROR: $"
OPENING_S:	db	"Opening connection (press ESC to cancel)... $"
RESOLVING_S:	db	"Resolving host name... $"
OPENED_S:	db	"OK!",13,10,10
	db	"*** Press F1 for help",13,10,10,"$"
HELP_S:	db	13,10,"*** F1: Show this help",13,10
	db	"*** F2: Toggle line/character mode",13,10
	db	"        Current mode is: "
LINCHAR_S:	db	"line     ",13,10
	db	"*** F3: Toggle local echo ON/OFF (only on character mode)",13,10
	db	"        Currently local echo is: "
ECHONOFF_S:	db	"ON ",13,10
	db	"*** ESC: Close connection and exit",13,10
	db	"*** CTRL+ESC: Abort connection and exit",13,10
	db	"*** Type the text to be sent to the other side.",13,10
	db	"    In line mode, the line text will be sent when pressing ENTER.",13,10
	db	"    In character mode, each typed character will be sent immediately.",13,10
	db	"    Incoming data will be printed out to the screen.",13,10,10,"$"
INPTOG0_S:	db	13,10,"*** Input mode toggled to line mode",13,10,"$"
INPTOG1_S:	db	13,10,"*** Input mode toggled to character mode",13,10,"$"
ECHOTOG0_S:	db	13,10,"*** Local echo toggled ON",13,10,"$"
ECHOTOG1_S:	db	13,10,"*** Local echo toggled OFF",13,10,"$"
USERCLOS_S:	db	13,10,"*** Connection closed by user",13,10,"$"
USERAB_S:	db	13,10,"*** Connection aborted by user",13,10,"$"
LINE_S:	db	"line     "
CHAR_S:	db	"character"
ON_S:	db	"ON "
OFF_S:	db	"OFF"
ASTERISK_S:	db	"*** $"

TLS_OPENING_S: db "Establishing TLS connection... $"
TLS_OPENED_S:  db	"OK!",13,10,10
	db	"*** Press F1 for help",13,10,10,"$"
TLS_ERROR_S: db 13,10,"--- TLS error code: $"
TLS_SUB_ERROR_S: db 13,10,"--- TLS sub error code: $"
TLS_ALERT_RECEIVED_S: db 13,10,"--- TLS alert received: $"

	;* Host name resolution

RESOLVERR_S:	db	13,10,"ERROR "
RESOLVERRC_S:	ds	6	;Leave space for "<code>: $"
RESOLVOK_S:	db	"OK: "
RESOLVIP_S:	ds	16	;Space for "xxx.xxx.xxx.xxx$"
TWO_NL_S:	db	13,10
ONE_NL_S:	db	13,10,"$"

	;* DNS_Q errors

DNSQERRS_T:	db	ERR_NO_NETWORK,"No network connection$"
	db	ERR_NO_DNS,"No DNS servers available$"
	db	ERR_NOT_IMP,"This TCP/IP UNAPI implementation does not support name resolution.",13,10
	db	"An IP address must be specified instead.$"
	db	0

	;* DNS_S errors

DNSRERRS_T:	db	1,"Query format error$"
	db	2,"Server failure$"
	db	3,"Name error (this host name does not exist)$"
	db	4,"Query type not implemented by the server$"
	db	5,"Query refused by the server$"
	db	6,"DNS error 6$"
	db	7,"DNS error 7$"
	db	8,"DNS error 8$"
	db	9,"DNS error 9$"
	db	10,"DNS error 10$"
	db	11,"DNS error 11$"
	db	12,"DNS error 12$"
	db	13,"DNS error 13$"
	db	14,"DNS error 14$"
	db	15,"DNS error 15$"
	db	16,"Server(s) not responding to queries$"
	db	17,"Total operation timeout expired$"
	db	19,"Internet connection lost$"
	db	20,"Dead-end reply (not containing answers nor redirections)$"
	db	21,"Answer is truncated$"
	db	0

	;* TCP_OPEN errors

TCPOPERRS_T:	db	ERR_NO_FREE_CONN,"Too many TCP connections opened$"
		db	ERR_NO_NETWORK,"No network connection found$"
		db	ERR_CONN_EXISTS,"Connection already exists, try another local port number$"
		db	ERR_INV_PARAM,"Unespecified remote socket is not allowed on active connections$"
		db	0

	;* TCP close reasons

TCPCLOSED_T:
	db	128+0,"*** Connection closed$"
	db	128+1,"*** Connection never used$"
PEERCLOSE_S:
	db	128+2,"*** Connection closed by peer$"	;Actually local CLOSE, but we close only when the peer closes
	db	128+3,"*** Connection locally aborted$"
	db	128+4,"*** Connection refused (RST received)$"
	db	128+5,"*** Data sending timeout expired$"
	db	128+6,"*** Connection timeout expired$"
	db	128+7,"*** Internet connection lost$"
	db	128+8,"*** Destination host is unreachable$"
	db	0

	;* TCP RCV/SEND errors

TCPERROR_T:
	db	ERR_CONN_STATE,"*** The connection state does not allow sending data$"
	db	ERR_BUFFER,"*** Output buffer overflow$"
	db	ERR_INV_PARAM,"*** Invalid parameter$"
	db	0

	;* Other errors

NOTCPIP_S:	db	"*** No TCP/IP UNAPI implementation found.",13,10,"$"
NOTCPA_S:	db	"*** This TCP/IP UNAPI implementation does not support",13,10
		db	"    opening active TCP connections.",13,10,"$"
NOTCPPS_S:	db	"*** This TCP/IP UNAPI implementation does not support",13,10
		db	"    opening passive TCP connections with remote socket specified.",13,10,"$"
NOTCPPU_S:	db	"*** This TCP/IP UNAPI implementation does not support",13,10
	db	"    opening passive TCP connections with remote socket unespecified.",13,10,"$"

;--- UNAPI related

TCPIP_S:	db	"TCP/IP",0

SNI: db "tls13.1d.pw"
SNI_END:

;--- Buffer for the remote host name

HOST_NAME:	;

;--- Generic temporary buffer for data send/receive
;    and for parameter parsing

BUFFER:	equ	HOST_NAME+256
