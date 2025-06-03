	title	TLS for Z80 by Konamiman
	subttl	AES algorithm implementation

.COMMENT \

Implementation of the AES algorithm as specified in https://doi.org/10.6028/NIST.FIPS.197-upd1

Usage:
1. Call INIT passing the encryption key.
2. Call ENCRYPT and DECRYPT.

NOTE: The substitution tables must be located at a 256 byte boundary in memory.

\

    public AES.INIT
    public AES.ENCRYPT
    public AES.DECRYPT

    module AES


;   align 256


    ;--- Byte substitution tables
    ;    Adapted from https://github.com/mbowen13/AES/blob/master/src/AES.java

SUBS_TAB:
    db 63h, 7ch, 77h, 7bh, 0f2h, 6bh, 6fh, 0c5h, 30h, 01h, 67h, 2bh, 0feh, 0d7h, 0abh, 76h
    db 0cah, 82h, 0c9h, 7dh, 0fah, 59h, 47h, 0f0h, 0adh, 0d4h, 0a2h, 0afh, 9ch, 0a4h, 72h, 0c0h
    db 0b7h, 0fdh, 93h, 26h, 36h, 3fh, 0f7h, 0cch, 34h, 0a5h, 0e5h, 0f1h, 71h, 0d8h, 31h, 15h
    db 04h, 0c7h, 23h, 0c3h, 18h, 96h, 05h, 9ah, 07h, 12h, 80h, 0e2h, 0ebh, 27h, 0b2h, 75h
    db 09h, 83h, 2ch, 1ah, 1bh, 6eh, 5ah, 0a0h, 52h, 3bh, 0d6h, 0b3h, 29h, 0e3h, 2fh, 84h
    db 53h, 0d1h, 00h, 0edh, 20h, 0fch, 0b1h, 5bh, 6ah, 0cbh, 0beh, 39h, 4ah, 4ch, 58h, 0cfh
    db 0d0h, 0efh, 0aah, 0fbh, 43h, 4dh, 33h, 85h, 45h, 0f9h, 02h, 7fh, 50h, 3ch, 9fh, 0a8h
    db 51h, 0a3h, 40h, 8fh, 92h, 9dh, 38h, 0f5h, 0bch, 0b6h, 0dah, 21h, 10h, 0ffh, 0f3h, 0d2h
    db 0cdh, 0ch, 13h, 0ech, 5fh, 97h, 44h, 17h, 0c4h, 0a7h, 7eh, 3dh, 64h, 5dh, 19h, 73h
    db 60h, 81h, 4fh, 0dch, 22h, 2ah, 90h, 88h, 46h, 0eeh, 0b8h, 14h, 0deh, 5eh, 0bh, 0dbh
    db 0e0h, 32h, 3ah, 0ah, 49h, 06h, 24h, 5ch, 0c2h, 0d3h, 0ach, 62h, 91h, 95h, 0e4h, 79h
    db 0e7h, 0c8h, 37h, 6dh, 8dh, 0d5h, 4eh, 0a9h, 6ch, 56h, 0f4h, 0eah, 65h, 7ah, 0aeh, 08h
    db 0bah, 78h, 25h, 2eh, 1ch, 0a6h, 0b4h, 0c6h, 0e8h, 0ddh, 74h, 1fh, 4bh, 0bdh, 8bh, 8ah
    db 70h, 3eh, 0b5h, 66h, 48h, 03h, 0f6h, 0eh, 61h, 35h, 57h, 0b9h, 86h, 0c1h, 1dh, 9eh
    db 0e1h, 0f8h, 98h, 11h, 69h, 0d9h, 8eh, 94h, 9bh, 1eh, 87h, 0e9h, 0ceh, 55h, 28h, 0dfh
    db 8ch, 0a1h, 89h, 0dh, 0bfh, 0e6h, 42h, 68h, 41h, 99h, 2dh, 0fh, 0b0h, 54h, 0bbh, 16h

ISUB_TAB:
    db 52h, 09h, 6Ah, 0d5h, 30h, 36h, 0a5h, 38h, 0bFh, 40h, 0a3h, 9Eh, 81h, 0f3h, 0d7h, 0fBh
    db 7Ch, 0e3h, 39h, 82h, 9Bh, 2Fh, 0fFh, 87h, 34h, 8Eh, 43h, 44h, 0c4h, 0dEh, 0e9h, 0cBh
    db 54h, 7Bh, 94h, 32h, 0a6h, 0c2h, 23h, 3Dh, 0eEh, 4Ch, 95h, 0Bh, 42h, 0fAh, 0c3h, 4Eh
    db 08h, 2Eh, 0a1h, 66h, 28h, 0d9h, 24h, 0b2h, 76h, 5Bh, 0a2h, 49h, 6Dh, 8Bh, 0d1h, 25h
    db 72h, 0f8h, 0f6h, 64h, 86h, 68h, 98h, 16h, 0d4h, 0a4h, 5Ch, 0cCh, 5Dh, 65h, 0b6h, 92h
    db 6Ch, 70h, 48h, 50h, 0fDh, 0eDh, 0b9h, 0dAh, 5Eh, 15h, 46h, 57h, 0a7h, 8Dh, 9Dh, 84h
    db 90h, 0d8h, 0aBh, 00h, 8Ch, 0bCh, 0d3h, 0Ah, 0f7h, 0e4h, 58h, 05h, 0b8h, 0b3h, 45h, 06h
    db 0d0h, 2Ch, 1Eh, 8Fh, 0cAh, 3Fh, 0Fh, 02h, 0c1h, 0aFh, 0bDh, 03h, 01h, 13h, 8Ah, 6Bh
    db 3Ah, 91h, 11h, 41h, 4Fh, 67h, 0dCh, 0eAh, 97h, 0f2h, 0cFh, 0cEh, 0f0h, 0b4h, 0e6h, 73h
    db 96h, 0aCh, 74h, 22h, 0e7h, 0aDh, 35h, 85h, 0e2h, 0f9h, 37h, 0e8h, 1Ch, 75h, 0dFh, 6Eh
    db 47h, 0f1h, 1Ah, 71h, 1Dh, 29h, 0c5h, 89h, 6Fh, 0b7h, 62h, 0Eh, 0aAh, 18h, 0bEh, 1Bh
    db 0fCh, 56h, 3Eh, 4Bh, 0c6h, 0d2h, 79h, 20h, 9Ah, 0dBh, 0c0h, 0fEh, 78h, 0cDh, 5Ah, 0f4h
    db 1Fh, 0dDh, 0a8h, 33h, 88h, 07h, 0c7h, 31h, 0b1h, 12h, 10h, 59h, 27h, 80h, 0eCh, 5Fh
    db 60h, 51h, 7Fh, 0a9h, 19h, 0b5h, 4Ah, 0Dh, 2Dh, 0e5h, 7Ah, 9Fh, 93h, 0c9h, 9Ch, 0eFh
    db 0a0h, 0e0h, 3Bh, 4Dh, 0aEh, 2Ah, 0f5h, 0b0h, 0c8h, 0eBh, 0bBh, 3Ch, 83h, 53h, 99h, 61h
    db 17h, 2Bh, 04h, 7Eh, 0bAh, 77h, 0d6h, 26h, 0e1h, 69h, 14h, 63h, 55h, 21h, 0Ch, 7Dh


    ;--- Galois Multiplication lookup tables
    ;    Adapted from https://en.wikipedia.org/wiki/Rijndael_MixColumns#Galois_Multiplication_lookup_tables
    ;
    ;    DO NOT change the order of the 9-E tables in memory, as the code relies on it!

MULT_TAB_2:
    db 00h,02h,04h,06h,08h,0ah,0ch,0eh,10h,12h,14h,16h,18h,1ah,1ch,1eh
    db 20h,22h,24h,26h,28h,2ah,2ch,2eh,30h,32h,34h,36h,38h,3ah,3ch,3eh
    db 40h,42h,44h,46h,48h,4ah,4ch,4eh,50h,52h,54h,56h,58h,5ah,5ch,5eh
    db 60h,62h,64h,66h,68h,6ah,6ch,6eh,70h,72h,74h,76h,78h,7ah,7ch,7eh	
    db 80h,82h,84h,86h,88h,8ah,8ch,8eh,90h,92h,94h,96h,98h,9ah,9ch,9eh
    db 0a0h,0a2h,0a4h,0a6h,0a8h,0aah,0ach,0aeh,0b0h,0b2h,0b4h,0b6h,0b8h,0bah,0bch,0beh
    db 0c0h,0c2h,0c4h,0c6h,0c8h,0cah,0cch,0ceh,0d0h,0d2h,0d4h,0d6h,0d8h,0dah,0dch,0deh
    db 0e0h,0e2h,0e4h,0e6h,0e8h,0eah,0ech,0eeh,0f0h,0f2h,0f4h,0f6h,0f8h,0fah,0fch,0feh
    db 1bh,19h,1fh,1dh,13h,11h,17h,15h,0bh,09h,0fh,0dh,03h,01h,07h,05h
    db 3bh,39h,3fh,3dh,33h,31h,37h,35h,2bh,29h,2fh,2dh,23h,21h,27h,25h
    db 5bh,59h,5fh,5dh,53h,51h,57h,55h,4bh,49h,4fh,4dh,43h,41h,47h,45h
    db 7bh,79h,7fh,7dh,73h,71h,77h,75h,6bh,69h,6fh,6dh,63h,61h,67h,65h
    db 9bh,99h,9fh,9dh,93h,91h,97h,95h,8bh,89h,8fh,8dh,83h,81h,87h,85h
    db 0bbh,0b9h,0bfh,0bdh,0b3h,0b1h,0b7h,0b5h,0abh,0a9h,0afh,0adh,0a3h,0a1h,0a7h,0a5h
    db 0dbh,0d9h,0dfh,0ddh,0d3h,0d1h,0d7h,0d5h,0cbh,0c9h,0cfh,0cdh,0c3h,0c1h,0c7h,0c5h
    db 0fbh,0f9h,0ffh,0fdh,0f3h,0f1h,0f7h,0f5h,0ebh,0e9h,0efh,0edh,0e3h,0e1h,0e7h,0e5h

MULT_TAB_3:
    db 00h,03h,06h,05h,0ch,0fh,0ah,09h,18h,1bh,1eh,1dh,14h,17h,12h,11h
    db 30h,33h,36h,35h,3ch,3fh,3ah,39h,28h,2bh,2eh,2dh,24h,27h,22h,21h
    db 60h,63h,66h,65h,6ch,6fh,6ah,69h,78h,7bh,7eh,7dh,74h,77h,72h,71h
    db 50h,53h,56h,55h,5ch,5fh,5ah,59h,48h,4bh,4eh,4dh,44h,47h,42h,41h
    db 0c0h,0c3h,0c6h,0c5h,0cch,0cfh,0cah,0c9h,0d8h,0dbh,0deh,0ddh,0d4h,0d7h,0d2h,0d1h
    db 0f0h,0f3h,0f6h,0f5h,0fch,0ffh,0fah,0f9h,0e8h,0ebh,0eeh,0edh,0e4h,0e7h,0e2h,0e1h
    db 0a0h,0a3h,0a6h,0a5h,0ach,0afh,0aah,0a9h,0b8h,0bbh,0beh,0bdh,0b4h,0b7h,0b2h,0b1h
    db 90h,93h,96h,95h,9ch,9fh,9ah,99h,88h,8bh,8eh,8dh,84h,87h,82h,81h	
    db 9bh,98h,9dh,9eh,97h,94h,91h,92h,83h,80h,85h,86h,8fh,8ch,89h,8ah
    db 0abh,0a8h,0adh,0aeh,0a7h,0a4h,0a1h,0a2h,0b3h,0b0h,0b5h,0b6h,0bfh,0bch,0b9h,0bah
    db 0fbh,0f8h,0fdh,0feh,0f7h,0f4h,0f1h,0f2h,0e3h,0e0h,0e5h,0e6h,0efh,0ech,0e9h,0eah	
    db 0cbh,0c8h,0cdh,0ceh,0c7h,0c4h,0c1h,0c2h,0d3h,0d0h,0d5h,0d6h,0dfh,0dch,0d9h,0dah	
    db 5bh,58h,5dh,5eh,57h,54h,51h,52h,43h,40h,45h,46h,4fh,4ch,49h,4ah
    db 6bh,68h,6dh,6eh,67h,64h,61h,62h,73h,70h,75h,76h,7fh,7ch,79h,7ah	
    db 3bh,38h,3dh,3eh,37h,34h,31h,32h,23h,20h,25h,26h,2fh,2ch,29h,2ah
    db 0bh,08h,0dh,0eh,07h,04h,01h,02h,13h,10h,15h,16h,1fh,1ch,19h,1ah

MULT_TAB_9:
    db 00h,09h,12h,1bh,24h,2dh,36h,3fh,48h,41h,5ah,53h,6ch,65h,7eh,77h
    db 90h,99h,82h,8bh,0b4h,0bdh,0a6h,0afh,0d8h,0d1h,0cah,0c3h,0fch,0f5h,0eeh,0e7h
    db 3bh,32h,29h,20h,1fh,16h,0dh,04h,73h,7ah,61h,68h,57h,5eh,45h,4ch
    db 0abh,0a2h,0b9h,0b0h,8fh,86h,9dh,94h,0e3h,0eah,0f1h,0f8h,0c7h,0ceh,0d5h,0dch
    db 76h,7fh,64h,6dh,52h,5bh,40h,49h,3eh,37h,2ch,25h,1ah,13h,08h,01h
    db 0e6h,0efh,0f4h,0fdh,0c2h,0cbh,0d0h,0d9h,0aeh,0a7h,0bch,0b5h,8ah,83h,98h,91h
    db 4dh,44h,5fh,56h,69h,60h,7bh,72h,05h,0ch,17h,1eh,21h,28h,33h,3ah
    db 0ddh,0d4h,0cfh,0c6h,0f9h,0f0h,0ebh,0e2h,95h,9ch,87h,8eh,0b1h,0b8h,0a3h,0aah	
    db 0ech,0e5h,0feh,0f7h,0c8h,0c1h,0dah,0d3h,0a4h,0adh,0b6h,0bfh,80h,89h,92h,9bh	
    db 7ch,75h,6eh,67h,58h,51h,4ah,43h,34h,3dh,26h,2fh,10h,19h,02h,0bh
    db 0d7h,0deh,0c5h,0cch,0f3h,0fah,0e1h,0e8h,9fh,96h,8dh,84h,0bbh,0b2h,0a9h,0a0h
    db 47h,4eh,55h,5ch,63h,6ah,71h,78h,0fh,06h,1dh,14h,2bh,22h,39h,30h
    db 9ah,93h,88h,81h,0beh,0b7h,0ach,0a5h,0d2h,0dbh,0c0h,0c9h,0f6h,0ffh,0e4h,0edh
    db 0ah,03h,18h,11h,2eh,27h,3ch,35h,42h,4bh,50h,59h,66h,6fh,74h,7dh	
    db 0a1h,0a8h,0b3h,0bah,85h,8ch,97h,9eh,0e9h,0e0h,0fbh,0f2h,0cdh,0c4h,0dfh,0d6h
    db 31h,38h,23h,2ah,15h,1ch,07h,0eh,79h,70h,6bh,62h,5dh,54h,4fh,46h

MULT_TAB_B:
    db 00h,0bh,16h,1dh,2ch,27h,3ah,31h,58h,53h,4eh,45h,74h,7fh,62h,69h
    db 0b0h,0bbh,0a6h,0adh,9ch,97h,8ah,81h,0e8h,0e3h,0feh,0f5h,0c4h,0cfh,0d2h,0d9h
    db 7bh,70h,6dh,66h,57h,5ch,41h,4ah,23h,28h,35h,3eh,0fh,04h,19h,12h
    db 0cbh,0c0h,0ddh,0d6h,0e7h,0ech,0f1h,0fah,93h,98h,85h,8eh,0bfh,0b4h,0a9h,0a2h
    db 0f6h,0fdh,0e0h,0ebh,0dah,0d1h,0cch,0c7h,0aeh,0a5h,0b8h,0b3h,82h,89h,94h,9fh
    db 46h,4dh,50h,5bh,6ah,61h,7ch,77h,1eh,15h,08h,03h,32h,39h,24h,2fh
    db 8dh,86h,9bh,90h,0a1h,0aah,0b7h,0bch,0d5h,0deh,0c3h,0c8h,0f9h,0f2h,0efh,0e4h
    db 3dh,36h,2bh,20h,11h,1ah,07h,0ch,65h,6eh,73h,78h,49h,42h,5fh,54h
    db 0f7h,0fch,0e1h,0eah,0dbh,0d0h,0cdh,0c6h,0afh,0a4h,0b9h,0b2h,83h,88h,95h,9eh
    db 47h,4ch,51h,5ah,6bh,60h,7dh,76h,1fh,14h,09h,02h,33h,38h,25h,2eh
    db 8ch,87h,9ah,91h,0a0h,0abh,0b6h,0bdh,0d4h,0dfh,0c2h,0c9h,0f8h,0f3h,0eeh,0e5h
    db 3ch,37h,2ah,21h,10h,1bh,06h,0dh,64h,6fh,72h,79h,48h,43h,5eh,55h
    db 01h,0ah,17h,1ch,2dh,26h,3bh,30h,59h,52h,4fh,44h,75h,7eh,63h,68h
    db 0b1h,0bah,0a7h,0ach,9dh,96h,8bh,80h,0e9h,0e2h,0ffh,0f4h,0c5h,0ceh,0d3h,0d8h
    db 7ah,71h,6ch,67h,56h,5dh,40h,4bh,22h,29h,34h,3fh,0eh,05h,18h,13h
    db 0cah,0c1h,0dch,0d7h,0e6h,0edh,0f0h,0fbh,92h,99h,84h,8fh,0beh,0b5h,0a8h,0a3h

MULT_TAB_D:
    db 00h,0dh,1ah,17h,34h,39h,2eh,23h,68h,65h,72h,7fh,5ch,51h,46h,4bh
    db 0d0h,0ddh,0cah,0c7h,0e4h,0e9h,0feh,0f3h,0b8h,0b5h,0a2h,0afh,8ch,81h,96h,9bh
    db 0bbh,0b6h,0a1h,0ach,8fh,82h,95h,98h,0d3h,0deh,0c9h,0c4h,0e7h,0eah,0fdh,0f0h
    db 6bh,66h,71h,7ch,5fh,52h,45h,48h,03h,0eh,19h,14h,37h,3ah,2dh,20h
    db 6dh,60h,77h,7ah,59h,54h,43h,4eh,05h,08h,1fh,12h,31h,3ch,2bh,26h
    db 0bdh,0b0h,0a7h,0aah,89h,84h,93h,9eh,0d5h,0d8h,0cfh,0c2h,0e1h,0ech,0fbh,0f6h
    db 0d6h,0dbh,0cch,0c1h,0e2h,0efh,0f8h,0f5h,0beh,0b3h,0a4h,0a9h,8ah,87h,90h,9dh
    db 06h,0bh,1ch,11h,32h,3fh,28h,25h,6eh,63h,74h,79h,5ah,57h,40h,4dh
    db 0dah,0d7h,0c0h,0cdh,0eeh,0e3h,0f4h,0f9h,0b2h,0bfh,0a8h,0a5h,86h,8bh,9ch,91h
    db 0ah,07h,10h,1dh,3eh,33h,24h,29h,62h,6fh,78h,75h,56h,5bh,4ch,41h
    db 61h,6ch,7bh,76h,55h,58h,4fh,42h,09h,04h,13h,1eh,3dh,30h,27h,2ah
    db 0b1h,0bch,0abh,0a6h,85h,88h,9fh,92h,0d9h,0d4h,0c3h,0ceh,0edh,0e0h,0f7h,0fah
    db 0b7h,0bah,0adh,0a0h,83h,8eh,99h,94h,0dfh,0d2h,0c5h,0c8h,0ebh,0e6h,0f1h,0fch
    db 67h,6ah,7dh,70h,53h,5eh,49h,44h,0fh,02h,15h,18h,3bh,36h,21h,2ch
    db 0ch,01h,16h,1bh,38h,35h,22h,2fh,64h,69h,7eh,73h,50h,5dh,4ah,47h
    db 0dch,0d1h,0c6h,0cbh,0e8h,0e5h,0f2h,0ffh,0b4h,0b9h,0aeh,0a3h,80h,8dh,9ah,97h

MULT_TAB_E:
    db 00h,0eh,1ch,12h,38h,36h,24h,2ah,70h,7eh,6ch,62h,48h,46h,54h,5ah
    db 0e0h,0eeh,0fch,0f2h,0d8h,0d6h,0c4h,0cah,90h,9eh,8ch,82h,0a8h,0a6h,0b4h,0bah
    db 0dbh,0d5h,0c7h,0c9h,0e3h,0edh,0ffh,0f1h,0abh,0a5h,0b7h,0b9h,93h,9dh,8fh,81h
    db 3bh,35h,27h,29h,03h,0dh,1fh,11h,4bh,45h,57h,59h,73h,7dh,6fh,61h
    db 0adh,0a3h,0b1h,0bfh,95h,9bh,89h,87h,0ddh,0d3h,0c1h,0cfh,0e5h,0ebh,0f9h,0f7h
    db 4dh,43h,51h,5fh,75h,7bh,69h,67h,3dh,33h,21h,2fh,05h,0bh,19h,17h
    db 76h,78h,6ah,64h,4eh,40h,52h,5ch,06h,08h,1ah,14h,3eh,30h,22h,2ch
    db 96h,98h,8ah,84h,0aeh,0a0h,0b2h,0bch,0e6h,0e8h,0fah,0f4h,0deh,0d0h,0c2h,0cch
    db 41h,4fh,5dh,53h,79h,77h,65h,6bh,31h,3fh,2dh,23h,09h,07h,15h,1bh
    db 0a1h,0afh,0bdh,0b3h,99h,97h,85h,8bh,0d1h,0dfh,0cdh,0c3h,0e9h,0e7h,0f5h,0fbh
    db 9ah,94h,86h,88h,0a2h,0ach,0beh,0b0h,0eah,0e4h,0f6h,0f8h,0d2h,0dch,0ceh,0c0h
    db 7ah,74h,66h,68h,42h,4ch,5eh,50h,0ah,04h,16h,18h,32h,3ch,2eh,20h
    db 0ech,0e2h,0f0h,0feh,0d4h,0dah,0c8h,0c6h,9ch,92h,80h,8eh,0a4h,0aah,0b8h,0b6h
    db 0ch,02h,10h,1eh,34h,3ah,28h,26h,7ch,72h,60h,6eh,44h,4ah,58h,56h
    db 37h,39h,2bh,25h,0fh,01h,13h,1dh,47h,49h,5bh,55h,7fh,71h,63h,6dh
    db 0d7h,0d9h,0cbh,0c5h,0efh,0e1h,0f3h,0fdh,0a7h,0a9h,0bbh,0b5h,9fh,91h,83h,8dh

WORD_SIZE: equ 4
NUM_ROUNDS: equ 10


;--------------------------------------------------------------------
; Initialize the AES engine.
; This must be invoked whenever a new encryption key is to be used.
;
; Input:  HL = Pointer to the encryption key
;--------------------------------------------------------------------

INIT:
    push hl
    ld de,ENCRYPT_KEY
    ld bc,16
    ldir
    pop hl
    ld de,W ;w[0]-w[3] = encryption key
    ld bc,16
    ldir

    exx
    ld hl,RCON  ;HL = Pointer to next RCon
    ld a,(hl)
    inc hl
    exx

    ld ix,W+WORD_SIZE*4  ;IX = pointer to w[i], starting with i=4

    ;Key expansion loop:
    ; - Do temp = SubWord(RotWord(w[i-1])) xor current_Rcon
    ; - Then do w[i] = w[i-4] xor temp, i++
    ; - Then do w[i] = w[i-4] xor w[i-1], i++, 3 times
    ; - Repeat until current_Rcon is 0

INIT_LOOP1:
    push af ;save current_Rcon for later

    ; temp = RotWord(w[i-1])

    ld b,(ix-WORD_SIZE)
    ld l,(ix-WORD_SIZE+1)
    ld h,(ix-WORD_SIZE+2)
    ld c,(ix-WORD_SIZE+3)
    ld (TEMP),hl
    ld a,c
    ld (TEMP+2),a
    ld a,b
    ld (TEMP+3),a

    ; temp = SubWord(temp)

    ld hl,SUBS_TAB 
    ld a,(TEMP)
    ld l,a
    ld a,(hl)
    ld (TEMP),a
    ld a,(TEMP+1)
    ld l,a
    ld a,(hl)
    ld (TEMP+1),a
    ld a,(TEMP+2)
    ld l,a
    ld a,(hl)
    ld (TEMP+2),a
    ld a,(TEMP+3)
    ld l,a
    ld a,(hl)
    ld (TEMP+3),a

    ; temp = temp xor current_Rcon

    ld a,(TEMP)
    pop bc
    xor b
    ld (TEMP),a

    ; w[i] = w[i-4] xor temp

    ld l,(ix-WORD_SIZE*4)
    ld h,(ix-WORD_SIZE*4+1)
    ld de,(TEMP)
    ld a,h
    xor d
    ld h,a
    ld a,l
    xor e
    ld l,a
    ld (ix),l
    ld (ix+1),h
    ld l,(ix-WORD_SIZE*4+2)
    ld h,(ix-WORD_SIZE*4+3)
    ld de,(TEMP+2)
    ld a,h
    xor d
    ld h,a
    ld a,l
    xor e
    ld l,a
    ld (ix+2),l
    ld (ix+3),h
    
    ; i = i+1

    inc ix
    inc ix
    inc ix
    inc ix

    ; w[i] = w[i-4] xor w[i-1] for i=1 to 3

    ld hl,W+4
    ld de,W
    ld b,WORD_SIZE*3
INIT_LOOP2:
    ld c,(ix-WORD_SIZE*4)
    ld a,(ix-WORD_SIZE)
    xor c
    ld (ix),a
    inc ix  ;i = i+3 (after the loop ends)
    djnz INIT_LOOP2

    ; Grab next RCon, if 0 we're done

    exx
    ld a,(hl)   ;Next RCon
    inc hl
    exx
    or a
    ret z

    jp INIT_LOOP1


    ;Values of RCon to be used for key expansion,
    ;with a 0 at the end to detect the end of the processs.

RCON: db 1h, 2h, 4h, 8h, 10h, 20h, 40h, 80h, 1bh, 36h, 0


;--------------------------------------------------------------------
; Encrypt a 16 byte block of plaintext.
;
; Input: HL = Source address of the 16 byte plaintext
;        DE = Destination address for the 16 byte encrypted block
;--------------------------------------------------------------------

ENCRYPT:
    push de

    ; state = in

    ld ix,STATE
    ld b,4

ENCRYPT_LOOP0:
    ld a,(hl)
    ld (ix),a
    inc hl
    ld a,(hl)
    ld (ix+WORD_SIZE),a
    inc hl
    ld a,(hl)
    ld (ix+WORD_SIZE*2),a
    inc hl
    ld a,(hl)
    ld (ix+WORD_SIZE*3),a
    inc hl
    inc ix
    djnz ENCRYPT_LOOP0

_ENCRYPT_AFTER_INPUT:

    ; AddRoundKey(state, w[0, Nb-1])

    exx
    ld hl,W
    call ADD_ROUND_KEY

    ; for round = 1 step 1 to Nr
    ; (it's to Nr-1 in the spec, but we include the last round in the loop
    ;  and detect it in order to skip InvMixColumns)

    ld d,NUM_ROUNDS

ENCRYPT_LOOP1:
    exx

    ; SubBytes(state)

    ld b,16
    ld hl,SUBS_TAB
    ld de,STATE

ENCRYPT_LOOP2:
    ld a,(de)
    ld l,a
    ld a,(hl)
    ld (de),a
    inc de
    djnz ENCRYPT_LOOP2

_ENCRYPT_AFTER_SUB:

    ; ShiftRows(state)

    ld ix,STATE

    ld a,(ix+WORD_SIZE)
    ld l,(ix+WORD_SIZE+1)
    ld h,(ix+WORD_SIZE+2)
    ld c,(ix+WORD_SIZE+3)
    ld (STATE+WORD_SIZE),hl
    ld (ix+WORD_SIZE+2),c
    ld (ix+WORD_SIZE+3),a

    ld hl,(STATE+WORD_SIZE*2)
    ld de,(STATE+WORD_SIZE*2+2)
    ld (STATE+WORD_SIZE*2),de
    ld (STATE+WORD_SIZE*2+2),hl

    ld l,(ix+WORD_SIZE*3)
    ld h,(ix+WORD_SIZE*3+1)
    ld a,(ix+WORD_SIZE*3+2)
    ld c,(ix+WORD_SIZE*3+3)
    ld (STATE+WORD_SIZE*3+1),hl
    ld (ix+WORD_SIZE*3),c
    ld (ix+WORD_SIZE*3+3),a

_ENCRYPT_AFTER_SHIFT:

    ; MixColumns(state), unless it's the last iteration
    ; We rely on the fact that all the MULT_TABx tables are aligned 
    ; to a 256 byte boundary (their starting addresses are xx00h)

    exx
    ld a,d
    exx
    dec a
    jr z,ENCRYPT_MIXEND

    ld h,MULT_TAB_2/256
    ld d,MULT_TAB_3/256
    ld ix,STATE
    ld b,4  ;For all state columns

ENCRYPT_LOOP3:
    ;S'0c

    ld l,(ix)
    ld c,(hl)   ;{02} . S0c

    ld e,(ix+WORD_SIZE)
    ld a,(de)   ;{03} . S1c

    xor c

    ld c,(ix+WORD_SIZE*2)   ;S2c
    xor c
    ld c,(ix+WORD_SIZE*3)   ;S3c
    xor c

    ld (TEMP),a   ;S'0c

    ;'S'1c

    ld l,(ix+WORD_SIZE)
    ld c,(hl)   ;{02} . S1c

    ld e,(ix+WORD_SIZE*2)
    ld a,(de)   ;{03} . S2c

    xor c

    ld c,(ix)   ;S0c
    xor c
    ld c,(ix+WORD_SIZE*3)   ;S3c
    xor c

    ld (TEMP+1),a   ;S'1c

    ;'S'2c

    ld l,(ix+WORD_SIZE*2)
    ld c,(hl)   ;{02} . S2c

    ld e,(ix+WORD_SIZE*3)
    ld a,(de)   ;{03} . S3c

    xor c

    ld c,(ix)   ;S0c
    xor c
    ld c,(ix+WORD_SIZE)   ;S1c
    xor c

    ld (TEMP+2),a   ;S'2c

    ;'S'3c

    ld l,(ix+WORD_SIZE*3)
    ld c,(hl)   ;{02} . S3c

    ld e,(ix)
    ld a,(de)   ;{03} . S0c

    xor c

    ld c,(ix+WORD_SIZE)   ;S1c
    xor c
    ld c,(ix+WORD_SIZE*2)   ;S2c
    xor c

    ld (ix+WORD_SIZE*3),a   ;S'3c

    ;Set the column from the temp values

    ld a,(TEMP)
    ld (ix),a
    ld a,(TEMP+1)
    ld (ix+WORD_SIZE),a
    ld a,(TEMP+2)
    ld (ix+WORD_SIZE*2),a

    inc ix  ;Next column
    djnz ENCRYPT_LOOP3

_ENCRYPT_AFTER_MIX:

ENCRYPT_MIXEND:

    ; AddRoundKey(state, w[round*Nb, (round+1)*Nb-1])

    exx
    call ADD_ROUND_KEY

_ENCRYPT_AFTER_ADDKEY:

    ; end for (round = 1 step 1 to Nr)

    dec d
    jp nz,ENCRYPT_LOOP1
    exx

    ; out = state

ENCRYPT_OUT:
    pop de
    ld ix,STATE
    ld b,4
ENCRYPT_LOOP4:
    ld a,(ix)
    ld (de),a
    inc de
    ld a,(ix+WORD_SIZE)
    ld (de),a
    inc de
    ld a,(ix+WORD_SIZE*2)
    ld (de),a
    inc de
    ld a,(ix+WORD_SIZE*3)
    ld (de),a
    inc de
    inc ix
    djnz ENCRYPT_LOOP4

    ret


    ;--- Add current round key to state for encryption
    ;    Input:  HL = Point to current round key
    ;    Output: HL increased by 16 (pointing to next round key)
    ;    Modifies: AF, BC, IY

ADD_ROUND_KEY:
    ld iy,STATE

    ld b,4 ;Each loop step processes one column

ADD_ROUND_KEY_LOOP:
    ld c,(hl)
    ld a,(iy)
    xor c
    ld (iy),a
    inc hl

    ld c,(hl)
    ld a,(iy+4)
    xor c
    ld (iy+4),a
    inc hl

    ld c,(hl)
    ld a,(iy+8)
    xor c
    ld (iy+8),a
    inc hl

    ld c,(hl)
    ld a,(iy+12)
    xor c
    ld (iy+12),a
    inc hl

    ;At this point HL has been increased by one word

    inc iy  ;Increase column number

    djnz ADD_ROUND_KEY_LOOP
    ret


;--------------------------------------------------------------------
; Decrypt a 16 byte block of encrypted bytes.
;
; Input: HL = Source address of the 16 byte encrypted block
;        DE = Destination address for the 16 byte decrypted plaintext
;--------------------------------------------------------------------

DECRYPT:
    push de

    ; state = in

    ld ix,STATE
    ld b,4

DECRYPT_LOOP0:
    ld a,(hl)
    ld (ix),a
    inc hl
    ld a,(hl)
    ld (ix+WORD_SIZE),a
    inc hl
    ld a,(hl)
    ld (ix+WORD_SIZE*2),a
    inc hl
    ld a,(hl)
    ld (ix+WORD_SIZE*3),a
    inc hl
    inc ix
    djnz DECRYPT_LOOP0

_DECRYPT_AFTER_INPUT:

    ; AddRoundKey(state, w[Nr*Nb, (Nr+1)*Nb-1])

    exx
    ld hl,W+44*WORD_SIZE-1  ;Point to last bytee of last word
    call INVADD_ROUND_KEY

_DECRYPT_AFTER_ADDKEY0:

    ; for round = Nr step -1 downto 1
    ; (it's to Nr-1 in the spec, but we include the last round in the loop
    ;  and detect it in order to skip InvMixColumns)

    ld d,NUM_ROUNDS

DECRYPT_LOOP1:
    exx

    ; InvShiftRows(state)

    ld ix,STATE

    ld a,(ix+WORD_SIZE)
    ld l,(ix+WORD_SIZE+1)
    ld h,(ix+WORD_SIZE+2)
    ld c,(ix+WORD_SIZE+3)
    ld (STATE+WORD_SIZE+2),hl
    ld (ix+WORD_SIZE),c
    ld (ix+WORD_SIZE+1),a

    ld hl,(STATE+WORD_SIZE*2)
    ld de,(STATE+WORD_SIZE*2+2)
    ld (STATE+WORD_SIZE*2),de
    ld (STATE+WORD_SIZE*2+2),hl

    ld a,(ix+WORD_SIZE*3)
    ld l,(ix+WORD_SIZE*3+1)
    ld h,(ix+WORD_SIZE*3+2)
    ld c,(ix+WORD_SIZE*3+3)
    ld (STATE+WORD_SIZE*3),hl
    ld (ix+WORD_SIZE*3+2),c
    ld (ix+WORD_SIZE*3+3),a

_DECRYPT_AFTER_SHIFT:

    ; InvSubBytes(state)

    ld b,16
    ld hl,ISUB_TAB
    ld de,STATE

DECRYPT_LOOP2:
    ld a,(de)
    ld l,a
    ld a,(hl)
    ld (de),a
    inc de
    djnz DECRYPT_LOOP2

_DECRYPT_AFTER_SUB:

    ; AddRoundKey(state, w[round*Nb, (round+1)*Nb-1])

    exx
    call INVADD_ROUND_KEY

_DECRYPT_AFTER_ADDKEY:

    ; InvMixColumns(state), unless it's the last iteration
    ; We rely on the fact that all the MULT_TABx tables are aligned 
    ; to a 256 byte boundary (their starting addresses are xx00h)

    ld a,d
    exx
    dec a
    jp z,ENCRYPT_OUT ;If it's the last iteration there's nothing else to do

    ld h,MULT_TAB_9/256
    ld d,h
    ld ix,STATE
    ld b,4  ;For all state columns

DECRYPT_LOOP3:
    ;S'0c

    ld l,(ix+WORD_SIZE*3)
    ld a,(hl)   ;{09} . S3c
    inc h   ;point to table for b

    ld l,(ix+WORD_SIZE)
    ld c,(hl)   ;{0b} . S1c
    inc h   ;point to table for d
    xor c

    ld l,(ix+WORD_SIZE*2)
    ld c,(hl)   ;{0d} . S2c
    inc h   ;point to table for d
    xor c

    ld l,(ix)
    ld c,(hl)   ;{0e} . S0c
    xor c

    ld (TEMP),a   ;S'0c
    ld h,d  ;point to table for 9 again

    ;'S'1c

    ld l,(ix)
    ld a,(hl)   ;{09} . S0c
    inc h   ;point to table for b

    ld l,(ix+WORD_SIZE*2)
    ld c,(hl)   ;{0b} . S2c
    inc h   ;point to table for d
    xor c

    ld l,(ix+WORD_SIZE*3)
    ld c,(hl)   ;{0d} . S3c
    inc h   ;point to table for d
    xor c

    ld l,(ix+WORD_SIZE)
    ld c,(hl)   ;{0e} . S1c
    xor c

    ld (TEMP+1),a   ;S'1c
    ld h,d  ;point to table for 9 again

    ;'S'2c

    ld l,(ix+WORD_SIZE)
    ld a,(hl)   ;{09} . S1c
    inc h   ;point to table for b

    ld l,(ix+WORD_SIZE*3)
    ld c,(hl)   ;{0b} . S3c
    inc h   ;point to table for d
    xor c

    ld l,(ix)
    ld c,(hl)   ;{0d} . S0c
    inc h   ;point to table for d
    xor c

    ld l,(ix+WORD_SIZE*2)
    ld c,(hl)   ;{0e} . S2c
    xor c

    ld (TEMP+2),a   ;S'2c
    ld h,d  ;point to table for 9 again

    ;'S'3c

    ld l,(ix+WORD_SIZE*2)
    ld a,(hl)   ;{09} . S2c
    inc h   ;point to table for b

    ld l,(ix)
    ld c,(hl)   ;{0b} . S0c
    inc h   ;point to table for d
    xor c

    ld l,(ix+WORD_SIZE)
    ld c,(hl)   ;{0d} . S1c
    inc h   ;point to table for d
    xor c

    ld l,(ix+WORD_SIZE*3)
    ld c,(hl)   ;{0e} . S3c
    xor c

    ld (ix+WORD_SIZE*3),a   ;S'3c
    ld h,d  ;point to table for 9 again

    ;Set the column from the temp values

    ld a,(TEMP)
    ld (ix),a
    ld a,(TEMP+1)
    ld (ix+WORD_SIZE),a
    ld a,(TEMP+2)
    ld (ix+WORD_SIZE*2),a

    inc ix  ;Next column
    djnz DECRYPT_LOOP3

_DECRYPT_AFTER_MIX:

DECRYPT_MIXEND:

    ; end for (round = 1 step 1 to Nr)
    ; We can do an unconditional jump here because if D'=1
    ; a jump to ENCRYPT_OUT will have been executed already
    ; (right before InvMixColumns)

    exx
    dec d
    jp DECRYPT_LOOP1
    exx

    ; out = state

    jp ENCRYPT_OUT


    ;--- Add current round key to state for decryption
    ;    Input:  HL = Point to the last byte of current round key
    ;    Output: HL decreased by 16 (pointing to previous round key)
    ;    Modifies: AF, BC, IY

INVADD_ROUND_KEY:
    ld iy,STATE+3

    ld b,4 ;Each loop step processes one column

INVADD_ROUND_KEY_LOOP:
    ld c,(hl)
    ld a,(iy+12)
    xor c
    ld (iy+12),a
    dec hl

    ld c,(hl)
    ld a,(iy+8)
    xor c
    ld (iy+8),a
    dec hl

    ld c,(hl)
    ld a,(iy+4)
    xor c
    ld (iy+4),a
    dec hl

    ld c,(hl)
    ld a,(iy)
    xor c
    ld (iy),a
    dec hl

    ;At this point HL has been decreased by one word

    dec iy  ;Increase column number

    djnz INVADD_ROUND_KEY_LOOP
    ret


;--------------------------------------------------------------------
; Data area
;--------------------------------------------------------------------


ENCRYPT_KEY: ds 16
W: ds 44*WORD_SIZE    ; Key schedule, 44 words.
TEMP: ds 4
STATE: ds 16

    endmod

    end
