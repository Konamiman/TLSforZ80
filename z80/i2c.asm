; Pinout: 
; Pin 6 - SDA
; Pin 7 - SCL
;
; Pin 8 - J2C HUB Power (optional)

;
; PSG Registers 
;
PSGAD:	EQU	0A0H
PSGWR:	EQU	0A1H
PSGRD:	EQU	0A2H
;
;  PSG Register bits;
;
ASDA:	EQU	0
ASCL:	EQU	1
BSDA:	EQU	2
BSCL:	EQU	3
APWR:	EQU	4
BPWR:	EQU	5
ABSEL:	EQU	6
MSDA:	EQU	10H	; [SDA In = TRGA]


;
; Constants
;
TIMEOUT:	EQU	2000
T1MS3MHZ:	EQU	109
T1MS7MHZ:	EQU	220

	org	8000h

	ld a,#C0
	ld hl,ATECC_INFO
	ld b,ATECC_INFO_END-ATECC_INFO
	ld de,9000h
	call ATECC_CMD
	ret
ATECC_INFO: db #30,0,0,0
ATECC_INFO_END:

	ld	ix,9000h
	ld	(ix),0

	;*** Wake ATECC608, read status

	if	1

	or	a
	call	J2CINIT

	call	J2CWAKE
	call	J2CSTART

	ld	c,0C1h
	call	J2CPUTBYTE
	ret	c
	inc	(ix)
	inc	ix

	or	a
	call	J2CGETBYTE	; Data 0
	ld	(ix),c
	inc	ix
	or	a
	call	J2CGETBYTE	; Data 1
	ld	(ix),c
	inc	ix
	or	a
	call	J2CGETBYTE	; Data 2
	ld	(ix),c
	inc	ix
	scf
	call	J2CGETBYTE	; Data 3
	ld	(ix),c
	inc	ix

	call	J2CSTOP

	;Now send command!

	ld	ix,9000h
	ld	iy,9010h
	call	J2CSTART

	ld	c,0c0h
	call	J2CPUTBYTE
	ret	c
	inc	(ix)
	ld	c,03h
	call	J2CPUTBYTE
	ret	c
	inc	(ix)
	ld	c,07h
	call	J2CPUTBYTE
	ret	c
	inc	(ix)
	ld	c,30h
	call	J2CPUTBYTE
	ret	c
	inc	(ix)
	ld	c,00h
	call	J2CPUTBYTE
	ret	c
	inc	(ix)
	ld	c,00h
	call	J2CPUTBYTE
	ret	c
	inc	(ix)
	ld	c,00h
	call	J2CPUTBYTE
	ret	c
	inc	(ix)
	ld	c,03h
	call	J2CPUTBYTE
	ret	c
	inc	(ix)
	ld	c,5Dh
	call	J2CPUTBYTE
	ret	c
	inc	(ix)

	call	J2CSTOP
	call	J2CSTART

	ld	c,0C1h
	call	J2CPUTBYTE
	ret	c
	inc	(ix)

	or	a
	call	J2CGETBYTE	; Data 3
	ld	(iy),c
	inc	iy
	or	a
	call	J2CGETBYTE	; Data 3
	ld	(iy),c
	inc	iy
	or	a
	call	J2CGETBYTE	; Data 3
	ld	(iy),c
	inc	iy
	or	a
	call	J2CGETBYTE	; Data 3
	ld	(iy),c
	inc	iy
	or	a
	call	J2CGETBYTE	; Data 3
	ld	(iy),c
	inc	iy
	or	a
	call	J2CGETBYTE	; Data 3
	ld	(iy),c
	inc	iy
	or	a
	call	J2CGETBYTE	; Data 3
	ld	(iy),c
	inc	iy

	call	J2CSTOP

	or	a
	ret

	endif

	;*** Writing into EEPROM

	if	0

	or	a
	call	J2CINIT
	call	J2CSTART

	ld	c,0a0h
	call	J2CPUTBYTE
	call	J2CGETACK
	ret	c
	inc	(ix)

	ld	c,050H	;Address High Byte
	call	J2CPUTBYTE
	call	J2CGETACK
	ret	c
	inc	(ix)

	ld	c,004h	;Address Low Byte
	call	J2CPUTBYTE
	call	J2CGETACK
	ret	c
	inc	(ix)

	ld	c,0aah	;Data
	call	J2CPUTBYTE
	call	J2CGETACK
	ret	c
	inc	(ix)

	ld	c,0bbh	;Data
	call	J2CPUTBYTE
	call	J2CGETACK
	ret	c
	inc	(ix)

	ld	c,0cch	;Data
	call	J2CPUTBYTE
	call	J2CGETACK
	ret	c
	inc	(ix)

	call	J2CSTOP
	ret

	endif

	;*** Reading from EEPROM

	or	a
	call	J2CINIT
	call	J2CSTART

	ld	c,0a0h
	call	J2CPUTBYTE
	ret	c
	inc	(ix)

	ld	c,050H	;Address High Byte
	call	J2CPUTBYTE
	ret	c
	inc	(ix)

	ld	c,000h	;Address Low Byte
	call	J2CPUTBYTE
	ret	c
	inc	(ix)

	call	J2CSTART	;the so called repeate start
	ld	c,0a1h	; ( I2C address <<1 | 0x01 ) for read operation
	call	J2CPUTBYTE
	ret	c
	inc	(ix)

	inc	ix

	or	a
	call	J2CGETBYTE	; Data n
	ld	(ix),c
	or	a
	inc	ix

	or	a
	call	J2CGETBYTE	; Data n+1
	ld	(ix),c
	or	a
	inc	ix

	or	a
	call	J2CGETBYTE	; Data n+2
	ld	(ix),c
	or	a
	inc	ix

	or	a
	call	J2CGETBYTE	; Data n+3
	ld	(ix),c
	or	a
	inc	ix

	or	a
	call	J2CGETBYTE	; Data n+4
	ld	(ix),c
	or	a
	inc	ix

	or	a
	call	J2CGETBYTE	; Data n+5
	ld	(ix),c
	or	a
	inc	ix

	scf
	call	J2CGETBYTE	; Data n+6 (last)
	ld	(ix),c
	scf

	call	J2CSTOP
	or	a
	ret


; Delay 1ms
WAIT1MS:
	PUSH	HL
	PUSH	AF
	LD	HL,T1MS3MHZ
WAIT1:	DEC	HL
	LD	A,H
	OR	L
	JR	NZ,WAIT1
	POP	AF
	POP	HL
	RET

J2CWAKE:
	ld	a,%10	;SCL=1, SDA=0
	call	J2CSETPINS

	call	WAIT1MS
	call	WAIT1MS

	ld	a,%11	;SCL=1, SDA=10
	call	J2CSETPINS

	call	WAIT1MS
	call	WAIT1MS

	ld	a,%10	;SCL=1, SDA=0
	call	J2CSETPINS

	ret


; Directly set the state of the the I2C pins
; Inputs:  B = reg 15 state  PSG reg 15 selected
;          A = SDA in bit 0, SCL in bit 1
J2CSETPINS:
	BIT	6,B	; ABSEL   ; test for A/B 
	jr	nz,BSETPINS
ASETPINS:
	and	%0011
	res	0,b
	res	1,b
	jr	DOSETPINS
BSETPINS:
	rla
	rla
	and	%1100
	res	2,b
	res	3,b
DOSETPINS:
	or	b
	OUT	(PSGWR),A
	ld	b,a
	ret

	if	0

	ld	a,b
	SET	1,A	; ASCL ; SCL=1
	OUT	(PSGWR),A
	RES	0,A	; ASDA ; SDA=0
	OUT	(PSGWR),A

	;call    WAIT1MS
	call	WAIT1MS
	call	WAIT1MS

	SET	0,A	; ASDA ; SDA=1
	OUT	(PSGWR),A

	; call    WAIT1MS
	call	WAIT1MS
	call	WAIT1MS

	RES	0,A	; ASDA ; SDA=0
	OUT	(PSGWR),A

	ret

	endif


;    ___ _  _ ___ _____ 
;   |_ _| \| |_ _|_   _|
;    | || .` || |  | |  
;   |___|_|\_|___| |_|  
;                       
; Inicialize I2C on Joystick port
; Inputs: Cy flag: 0->Port A  1->Port B
; Outputs: A,B = Reg 15 State, PSG Reg 15 Selected
; Modify: AF, B
; 
; note: The value of ABSEL bit will be used along all other functions
;       to decide wheter use port A or B. 
J2CINIT:
	DI
	LD	A,15
	OUT	(PSGAD),A
	IN	A,(PSGRD)
;    LD (PSGSAV),A
	JR	C,BINIT

; Initialize I2C on Joystick port A
AINIT:
	RES	6,A	; ABSEL ; JOY A
	SET	4,A	; APWR ; Power On J2C HUB (if exists) 
	OUT	(PSGWR),A
	CALL	WAIT1MS	; Wait 1ms
	SET	0,A	; ASDA ; SDA=1
	OUT	(PSGWR),A
	RES	1,A	; ASCL  ; SCL=0
	OUT	(PSGWR),A
	jr	ABINIEXIT	; common exit


; Initialize I2C on Joystick port B
BINIT:
	SET	6,A	; ABSEL ; JOY B
	SET	5,A	; BPWR ; Power On J2C HUB (if exists)
	OUT	(PSGWR),A
	CALL	WAIT1MS	; Wait 1ms
	SET	2,A	; BSDA ; SDA=1
	OUT	(PSGWR),A
	RES	3,A	; BSCL  ; SCL=0
	OUT	(PSGWR),A
	;

ABINIEXIT:
	LD	B,A	; save a/b select (reg 15 state)
	CALL	J2CSTOP
	CALL	J2CSTOP
	CALL	J2CSTOP
	RET




;    ___ _____ ___  ___ 
;   / __|_   _/ _ \| _ \
;   \__ \ | || (_) |  _/
;   |___/ |_| \___/|_|  
;                       
; generate Stop condition (rising edge on SDA while SCL=HIGH)
; Inputs:  B = reg 15 state  PSG reg 15 selected
; Outputs: B = reg 15 state   
; Modify: AF, B
J2CSTOP:
	LD	A,B
	BIT	6,A	; ABSEL ; Which port ?
	JR	NZ,BSTOP
;

; generate Stop condition on port A
ASTOP:
	RES	0,A	; ASDA ; SDA=0
	OUT	(PSGWR),A
	SET	1,A	; ASCL ; SCL=1
	OUT	(PSGWR),A
	SET	0,A	; ASDA ; SDA=1  
	OUT	(PSGWR),A
	LD	B,A	; save reg 15 state
	RET
;

; generate Stop condition on port B
BSTOP:
	RES	2,A	; BSDA ; SDA=0
	OUT	(PSGWR),A
	SET	3,A	; BSCL ; SCL=1
	OUT	(PSGWR),A
	SET	2,A	; BSDA ; SDA=1
	OUT	(PSGWR),A
	LD	B,A	; save reg 15 state
	RET
;




;    ___ _____ _   ___ _____  
;   / __|_   _/_\ | _ \_   _| 
;   \__ \ | |/ _ \|   / | |   
;   |___/ |_/_/ \_\_|_\ |_|   
;                             
; generate Start condition (falling edge on SDA while SCL=HIGH)
; Inputs:  B = reg 15 state  PSG reg 15 selected
; Outputs: B = reg 15 state   
; Modify: AF, B


; A = reg 15 state  PSG reg 15 selected
J2CSTART:
	LD	A,B
	BIT	6,A	; ABSEL
	JR	NZ,BSTART
	;

; generate Start condition on Port A
ASTART:
	SET	1,A	; ASCL ; SCL=1
	OUT	(PSGWR),A
	SET	0,A	; ASDA ; SDA=1
	OUT	(PSGWR),A
	RES	0,A	; ASDA ; SDA=0
	OUT	(PSGWR),A
	RES	1,A	; ASCL ; SCL=0
	OUT	(PSGWR),A
	SET	0,A	; ASDA ; SDA=1
	OUT	(PSGWR),A
	LD	B,A
	RET		; save reg 15 state 
;

; generate Start condition on Port B
BSTART:
	SET	3,A	; BSCL ; SCL=1
	OUT	(PSGWR),A
	SET	2,A	; BSDA ; SDA=1
	OUT	(PSGWR),A
	RES	2,A	; BSDA ; SDA=0
	OUT	(PSGWR),A
	RES	3,A	; BSCL ; SCL=0
	OUT	(PSGWR),A
	SET	2,A	; BSDA ; SDA=1
	OUT	(PSGWR),A
	LD	B,A	; save reg 15 state 
	RET
;



;    ___ _   _ _____   _____   _______ ___ 
;   | _ \ | | |_   _| | _ ) \ / /_   _| __|
;   |  _/ |_| | | |   | _ \\ V /  | | | _| 
;   |_|  \___/  |_|   |___/ |_|   |_| |___|
;                                          
; Put a byte on I2C bus
; Inputs:  B = reg 15 state  PSG reg 15 selected
;          C = byte to write 
; Outputs: B = reg 15 state
;          Cy=0 Acked, Cy=1 Timeout waiting for ack
; Modify: AF, BC

J2CPUTBYTE:
	LD	A,B	; restore A=PSG reg 15 state
	LD	B,8	; initialize counter (8 bits) 
	BIT	6,A	; ABSEL   ; test for A/B 
	JR	NZ,BPBYTE
	;

; Put a byte on I2C bus on port A
APBYTE:
	rlc	C
	RES	0,A	; ASDA
	JR	NC,APBY2	; SDA=CY
	SET	0,A	; ASDA
APBY2:
	OUT	(PSGWR),A
	SET	1,A	; ASCL ; SCL=1
	OUT	(PSGWR),A
	RES	1,A	; ASCL ; SCL=0
	OUT	(PSGWR),A
	DJNZ	APBYTE

	; Read ACK bit for port A
AGAK:
	SET	0,A	; ASDA ; SDA=1
	OUT	(PSGWR),A
	SET	1,A	; ASCL ; SCL=1
	OUT	(PSGWR),A
	PUSH	HL
	LD	HL,TIMEOUT
	LD	B,A	; save reg 15 state
	;
	LD	A,14
	OUT	(PSGAD),A	; Sel REG 14
AGAK1:
	IN	A,(PSGRD)
	AND	10h	; MSDA ; check bit and also clear CY
	JR	Z,AGAK2	; exit when acked (low data bit received)
	;
	DEC	HL
	LD	A,H
	OR	L
	JR	NZ,AGAK1
	;
	SCF		; Indicate TIMEOUT

AGAK2:
	LD	A,15
	OUT	(PSGAD),A	; Sel Reg 15
	LD	A,B
	RES	1,A	; ASCL
	OUT	(PSGWR),A
	LD	B,A	; save reg 15 state
	POP	HL
	RET
;

; Put a byte on I2C bus on port B
BPBYTE:
	rlc	C
	RES	2,A	; BSDA
	JR	NC,BPBY2	; SDA=CY
	SET	2,A	; BSDA
BPBY2:
	OUT	(PSGWR),A
	SET	3,A	; BSCL ; SCL=1
	OUT	(PSGWR),A
	RES	3,A	; BSCL ; SCL=0
	OUT	(PSGWR),A
	DJNZ	BPBYTE

	; Read ACK bit for port B
BGAK:
	SET	2,A	; BSDA ; SDA=1
	OUT	(PSGWR),A
	SET	3,A	; BSCL ; SCL=1
	OUT	(PSGWR),A
	PUSH	HL
	LD	HL,TIMEOUT
	LD	B,A	; save reg 15 state
	;
	LD	A,14
	OUT	(PSGAD),A	; Sel REG 14
BGAK1:
	IN	A,(PSGRD)
	AND	10h	; MSDA ; check bit and also clear CY
	JR	Z,BGAK2	; exit when acked (low data bit received)
	;
	DEC	HL
	LD	A,H
	OR	L
	JR	NZ,BGAK1
	;
	SCF		; Indicate TIMEOUT
;
BGAK2:
	LD	A,15
	OUT	(PSGAD),A	; Sel Reg 15
	LD	A,B
	RES	3,A	; BSCL
	OUT	(PSGWR),A
	LD	B,A	; save reg 15 state
	POP	HL
	RET
	;


;     ___ ___ _____   _____   _______ ___ 
;    / __| __|_   _| | _ ) \ / /_   _| __|
;   | (_ | _|  | |   | _ \\ V /  | | | _| 
;    \___|___| |_|   |___/ |_|   |_| |___|
;                                         
; Read a byte on I2C bus
; Inputs:  B = reg 15 state  PSG reg 15 selected
;          Cy = 0 to send ACK, 1 to send NAK
; outputs: C = byte read,
;          B = Reg15 state
; Modify: AF, BC, DE


J2CGETBYTE:
	push	af
	pop	de	;ACK to put in E

	LD	A,B
	BIT	6,A	; ABSEL
	JR	NZ,BGBYTE
	;

; Read a byte on I2C bus on port A
AGBYTE:
	SET	0,A	; ASDA ; SDA=1
	OUT	(PSGWR),A
	LD	BC,0800H	; B=8, C=0
	;
AGBY1:
	SET	1,A	; ASCL ; SCL=1
	OUT	(PSGWR),A
	LD	D,A	; Salva A
	LD	A,14
	OUT	(PSGAD),A	; Selec REG 14
	IN	A,(PSGRD)
	AND	10h	; MSDA   ; Mask for bit TRIGGER (SDA)
	NEG		; CY=(A==0)
	RL	C
	;
	LD	A,15
	OUT	(PSGAD),A
	LD	A,D	; Recupera est reg 15
	RES	1,A	; ASCL ; SCL=0
	OUT	(PSGWR),A
	DJNZ	AGBY1
	;
	LD	B,A	; save reg 15 state

; Put Ack bit on I2C bus Port A
APAK:
	push	de	;Get ACK from E
	pop	af
	ld	a,b

	RES	0,A	; ASDA
	OUT	(PSGWR),A
	JR	NC,APAK1	; SDA=CY
	SET	0,A	; ASDA
	;
APAK1:
	OUT	(PSGWR),A
	SET	1,A	; ASCL ; SCL=1
	OUT	(PSGWR),A
	RES	1,A	; ASCL ; SCL=0
	OUT	(PSGWR),A
	SET	0,A	; ASDA ; SDA=1
	OUT	(PSGWR),A
	LD	B,A	; save reg 15 state
	RET


; Read a byte on I2C bus on port B
BGBYTE:
	SET	2,A	; BSDA ; SDA=1
	OUT	(PSGWR),A
	LD	BC,0800H	; B=8, C=0
	;
BGBY1:
	SET	3,A	; BSCL ; SCL=1
	OUT	(PSGWR),A
	LD	D,A	; Save A (Reg 15 state)
	LD	A,14
	OUT	(PSGAD),A	; Selec REG 14
	IN	A,(PSGRD)
	AND	10h	; MSDA   ; Mask for bit TRIGGER (SDA)
	NEG		; CY=(A==0)  
	RL	C
	;
	LD	A,15
	OUT	(PSGAD),A
	LD	A,D	; Restore reg 15 state
	RES	3,A	; BSCL ; SCL=0
	OUT	(PSGWR),A
	DJNZ	BGBY1
	;
	LD	B,A	; save reg 15 state

BPAK:
	push	de	;Get ACK from E
	pop	af
	ld	a,b

	RES	2,A	; BSDA
	OUT	(PSGWR),A
	JR	NC,BPAK1	; SDA=CY
	SET	2,A	; BSDA
	;
BPAK1:
	OUT	(PSGWR),A
	SET	3,A	; BSCL ; SCL=1
	OUT	(PSGWR),A
	RES	3,A	; BSCL ; SCL=0
	OUT	(PSGWR),A
	SET	2,A	; BSDA ; SDA=1
	OUT	(PSGWR),A
	LD	B,A	; save reg 15 state
	RET


;--- Send a command to the ATECC608
;    Input:  A  = Chip address * 2
;            HL = Address of command (without address, count or checkum)
;            B  = Length of command (not including address, count or checkum; so minimum is 4)
;            DE = Address for output (length, result and CRC)
;    Output: A = 0: Ok
;                1: No response from chip
;                2: Chip NAKed command
;                3: Timeout waiting for response
;                4: CRC error on received data
;    Note that even if A=0 at the end, the chip may have returned an error code in the output.

ATECC_CMD:
	;--- Init on joystick port A, if that doesn't work, try on port B

	push de
	pop ix
	ld (ix),a	;Chip address

	ld c,a
	push hl
	push bc

	or a	
	call J2CINIT
	ld (ix+4),b ;Save PSG status
	call	J2CWAKE
	call	J2CSTART
	;jr nc,_ATECC_CMD_NEXT

	;scf
	;call J2CINIT
	;call	J2CWAKE
	;call	J2CSTART
	;jr nc,_ATECC_CMD_NEXT

	;pop bc
	;pop hl
	;ld a,1
	;ret

_ATECC_CMD_NEXT:
	
	;--- Calculate CRC
	
	pop bc
	ld a,b	;Command length
	add 3   ;Add length of length byte (1) and CRC (2)
	ld (ix+1),a
	push bc
	
	ld c,a
	call CRC_BYTE ;Now DE = CRC of length

	pop bc
	push bc
	call CRC_NEXT	;Now DE = CRC of length and command
	ld (ix+2),e
	ld (ix+3),d
	pop bc
	pop hl

	;--- Send command

	ld c,(ix)	;Chip address
	ld b,(ix+4)
	call J2CPUTBYTE
	jp c,_ATECC_CMD_ERR_2

	ld c,3	;"Command" address
	ld b,(ix+4)
	call J2CPUTBYTE
	jp c,_ATECC_CMD_ERR_2

	ld c,(ix+1)	;Length byte
	ld b,(ix+4)
	call J2CPUTBYTE
	jr c,_ATECC_CMD_ERR_2

	ld a,(ix+1)
	or a
	sbc 3	;Actual command length
	ld b,a

_ATECC_CMD_LOOP:
	push bc

	ld c,(hl)
	ld b,(ix+4)
	call J2CPUTBYTE
	pop bc
	jr c,_ATECC_CMD_ERR_2

	inc hl
	djnz _ATECC_CMD_LOOP

	ld c,(ix+2)	;Send CRC
	call J2CPUTBYTE
	jr c,_ATECC_CMD_ERR_2
	ld c,(ix+3)
	call J2CPUTBYTE
	jr c,_ATECC_CMD_ERR_2

	call J2CSTOP

	;--- Wait for the response

	call J2CSTART

	ld c,(ix)
	set 0,c ;"Read" bit
	ld b,(ix+4)
	call J2CPUTBYTE
	jr c,_ATECC_CMD_ERR_3

	ld b,(ix+4)
	or a
	call J2CGETBYTE

	;From this point we can't use the output buffer for temporary data anymore

	push ix	;Save start of output for calculating CRC later

	ld (ix),c	;Output length
	ld b,c
	dec b	;Remaining length minus one
	dec b
	ld c,(ix+4) ;PSG register value

	inc ix

_ATECC_CMD_LOOP2:
	push bc

	ld b,c
	or a
	call J2CGETBYTE
	ld (ix),c
	inc ix

	pop bc
	djnz _ATECC_CMD_LOOP2

	;Receive last byte NAKing it

	ld b,c
	scf
	call J2CGETBYTE
	ld (ix),c

	call J2CSTOP

	;--- Check CRC of response

	pop hl ;Start of output
	ld b,(hl) ;Byte count
	dec b
	dec b ;Exclude CRC field from count

	call CRC

	ld a,d
	cp (ix)
	ld a,4
	ret nz
	ld a,e
	cp (ix-1)
	ld a,4
	ret nz

	;--- CRC ok, we're all set!

	xor a
	ret

_ATECC_CMD_ERR_2:
	ld a,2
	ret

_ATECC_CMD_ERR_3:
	ld a,3
	ret


;--- Calculate CRC
;    In:  HL = Address, B = Length
;    Out: DE = CRC
CRC:
    ld de,0 ;Calculated CRC
CRC_NEXT:
loop_byte:
    push bc
    ld c,(hl)   ;Data byte

	call CRC_BYTE_NEXT

    inc hl
    pop bc
    djnz loop_byte
    ret


	;In:  C = Byte, DE=0
	;Out: DE = CRC
CRC_BYTE:
	ld de,0
CRC_BYTE_NEXT:
	ld b,8

loop_bit:
    xor a

    sla e
    rl d    ;CRC rotated left, old MSB to carry

    rla     ;A=1 or 0 depending on old MSB of CRC
    xor c
    and 1   ;A=1 if bit N of data = old MSB of CRC
    jr z,NOTXOR
    
    ld a,d
    xor #80
    ld d,a
    ld a,e
    xor #05
    ld e,a
NOTXOR:
    srl c   ;Rotate right data so bit 1 becomes LSB
    djnz loop_bit
	ret

