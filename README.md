# TLS for Z80

This is an incomplete but functional implementation of a [TLS 1.3](https://en.wikipedia.org/wiki/Transport_Layer_Security) client for Z80 processors. It's a 100% software implementation, not making use of any external cryptographic hardware.


## What's implemented

* The client side of a TLS 1.3 connection, as specified by [RFC8446](https://datatracker.ietf.org/doc/html/rfc8446).
* A nasty trick for the shared secret generation using secp256r1 but not actually using it (details below).
* AES_128_GCM_SHA256 cipher suite.
* [Server Name Indication](https://datatracker.ietf.org/doc/html/rfc6066#section-3) (with user provided value) and [Maximum Fragment Length](https://datatracker.ietf.org/doc/html/rfc6066#section-4) (fixed to a value of 512 bytes) extensions in the `ClientHello` message sent.
* Verification of the server's `Finished` message.
* Key updates when the server requests it.
* Handshake records containing multiple handshake messages.


## What's NOT implemented

* The `HelloRetryRequest` message (if one is received the connection is aborted).
* Validation of server certificates. Except for updating the transcript hash for the validation of the server's `Finished` message, the received `Certificate` and `CertificateVerify` messages are ignored.
* Client certificates.
* Pre-shared keys.
* Session resumption (`NewSessionTicket` messages are ignored).
* Server extensions (received `EnceyptedExtensions` messages are ignored, again except for updating the transcript hash).
* Server handshake messages split in multiple records are allowed only for `Certificate` messages.
* Support for server handshake messages larger than 64 KBytes.


## WARNING: Insecure by default!

This TLS engine uses secp256r1 to generate the shared secret but doesn't actually implement the secp256r1 curve. Instead, it always uses the number 1 as the private key (more precisely, 511 zero bits followed by one 1 bit) and this makes the shared secret to simply be equal to the first half of the server's public key.

Of course, this means that this engine is as secure as not using TLS at all. So don't use it to transmit any data that you wouldn't transmit unencrypted.

If you want to use any external help for the secp256r1 curve (like cryptographic hardware or a dedicated server) in order to generate a proper pair of private and public keys (and thus a proper and truly secure shared secret), you need to reimplement the code in [the `p256.asm` file](z80/p256.asm), see the comments in the file itself for instructions.


## The data transport layer

The TLS protocol works on top of a byte-oriented data transport layer (typically a TCP connection), so one needs to be provided for this engine to work. This is done by implementing the stubbed routines in [`data_transport.asm`](z80/data_transport.asm), just follow the instructions in the file itself.

If you are developing an application for MSX computers you can use the [`msx/unapi.asm`](z80/msx/unapi.asm) file, an implementation of the data transport stub that is a thin layer on top of [a TCP/IP UNAPI implementation](https://github.com/Konamiman/MSX-UNAPI-specification/blob/master/docs/TCP-IP%20UNAPI%20specification.md).


## Building a TLS capable application

Once you have implemented a data transport layer suitable for the target system you need to develop your TLS-capable application. This implies interacting with the public methods in [the `tls_connection.asm` module](z80/tls_connection.asm). See the comments in the file itself for details, you can also take a look at the applications in [the `msx` folder](z80/msx).

For the assembly and linking process you need [Nestor80](https://github.com/Konamiman/Nestor80), more precisely the assembler (`N80`) and the linker (`LK80`). See [the makefile in the `msx` folder](z80/msx/Makefile) for a working example.

Note that [the `aes.asm` module](z80/aes.asm) needs to be linked at a 256 byte boundary in memory. Otherwise there are no restrictions on where the code is located or in which order it's linked.


## The dotNet folder

[The dotNet folder](dotNet/) contains a Visual Studio solution with a few C# projects that have been used as helper tools for the development of this project:

* `Tests` contains unit tests for the Z80 code. It uses [the Z80.NET](https://github.com/Konamiman/Z80dotNet/) and [the ZWatcher](https://github.com/Konamiman/ZWatcher/) projects.
* `TlsClient` is a reimplementation of [the TlsClient project](https://github.com/Konamiman/TlsClient/) where all the original C# code has been replaced with the equivalent Z80 code. This replacement was done gradually, as the Z80 code was being developed.
* `TlsConsole` also comes from the TlsClient project and is a simple Telnet-like command line application: it connects to the specified server using a TLS connection and then echoes any received data and sends any data coming from the keyboard.
* `PocketZ80` is a simplified and more performant version of Z80.NET used by TlsClient to run the Z80 code.
