	title	TLS for Z80 by Konamiman
	subttl	Key and shared secret generation using the P256 curve

.COMMENT \

This file is actually a "working stub". It always uses the number 1 as the private key,
this implies that the shared secret will be the first half of the peer's public key.
And indeed, that means that the connection will be effectively insecure.

If you want to use some external help to generate proper key pairs
(or if you somehow manage to implement the P256 curve in pure Z80 assembler!)
just adjust P256.GENERATE_KEY_PAIR and P256.GENERATE_SHARED_KEY while keeping
their input and output behaviors.

\
    
    public P256.GENERATE_KEY_PAIR
    public P256.GENERATE_SHARED_KEY

    module P256


;--- Generate a P256 key pair, store the private key internally,
;    and return the public key.
;
;    Input: HL = Destination address for the public key (64 bytes)

GENERATE_KEY_PAIR:
    ex de,hl
    ld hl,TRIVIAL_LOCAL_PUBLIC_KEY
    ld bc,64
    ldir
    ret

    ; Public key corresponding to a private key
    ; consisting of 63 zero bytes and then the byte 1.
TRIVIAL_LOCAL_PUBLIC_KEY:
    db 06Bh,017h,0D1h,0F2h,0E1h,02Ch,042h,047h
    db 0F8h,0BCh,0E6h,0E5h,063h,0A4h,040h,0F2h
    db 077h,003h,07Dh,081h,02Dh,0EBh,033h,0A0h
    db 0F4h,0A1h,039h,045h,0D8h,098h,0C2h,096h
    db 04Fh,0E3h,042h,0E2h,0FEh,01Ah,07Fh,09Bh
    db 08Eh,0E7h,0EBh,04Ah,07Ch,00Fh,09Eh,016h
    db 02Bh,0CEh,033h,057h,06Bh,031h,05Eh,0CEh
    db 0CBh,0B6h,040h,068h,037h,0BFh,051h,0F5h



;--- Generate a shared secret from the private key previously generated
;    with GENERATE_KEY_PAIR and the peer public key.
;
;    Input:  HL = Address of the remote public key
;            DE = Destination address for the generated shared secret (32 bytes)
;    Output: Cy = 0: Ok, 1: Error

GENERATE_SHARED_KEY:
    ; When the private key is 0,0,...,0,1
    ; the shared secret is the first half of the peer's public key.
    ld bc,32
    ldir
    or a
    ret

    endmod

    end
