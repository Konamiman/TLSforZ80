    ;Note: this file is scaffolding intended to run in an emulator.
    

    public P256.GENERATE_KEY_PAIR
    public P256.GENERATE_SHARED_KEY

    module P256


;--- Generate P256 key pair, store the private key internally,
;    and return the public key.
;
;    Input: HL = Destination address for the public key (64 bytes)

GENERATE_KEY_PAIR:
    xor a
    jp 0006h


;--- Generate a shared secret from the private key generated
;    with GENERATE_KEY_PAIR and the peer public key:
;
;    Input:  HL = Address of the remote public key
;            DE = Destination address for the generated shared secret (32 bytes)
;    Output: Cy = 0: Ok, 1: Error

GENERATE_SHARED_KEY:
    ld a,1
    call 0006h
    or a
    ret

    endmod

    end
