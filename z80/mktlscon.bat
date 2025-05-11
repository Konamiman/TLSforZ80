@echo off
N80 tlscon.asm
if errorlevel 1 goto :end
LK80 -vb 3 --output-file TLSCON.COM --code 0100h tlscon.REL --code 1800h aes.REL aes-gcm.REL client_hello.REL hkdf.REL hmac.REL record_encryption.REL record_receiver.REL sha256.REL tls_connection.REL unapi.REL p256.REL server_hello.REL
if errorlevel 1 goto :end
wsl sudo mount -o loop,uid=konamiman,gid=konamiman /mnt/d/Dropbox/Dropbox/MSX/msxdos/discosa.dsk ~/floppy
copy TLSCON.COM \\wsl.localhost\Ubuntu\home\konamiman\floppy
wsl sudo umount ~/floppy
:end
