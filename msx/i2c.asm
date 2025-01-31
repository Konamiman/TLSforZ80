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
