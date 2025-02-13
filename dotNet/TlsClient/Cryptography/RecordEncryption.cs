using Konamiman.TlsForZ80.TlsClient.Enums;
using Konamiman.TLSforZ80.TlsClient;

namespace Konamiman.TlsForZ80.TlsClient.Cryptography;

/// <summary>
/// This class handles AES encryption and decryption of application data,
/// handling the required sequence number/nonce increases.
/// </summary>
internal class RecordEncryption
{
    byte[] serverSequenceNumber;
    byte[] clientSequenceNumber;
    byte[] clientNonce;
    byte[] serverNonce;
    byte[] clientKey;
    byte[] serverKey;
    byte[] clientIv;
    byte[] serverIv;
    const int ivSize = 12;
    const int tagSize = 16;

    public RecordEncryption(TrafficKeys keys)
    {
        keys.KeysGenerated += OnKeysGenerated;
        OnKeysGenerated(keys, true);
        OnKeysGenerated(keys, false);
    }

    public byte[] Encrypt(RecordContentType contentType, byte[] content, int index = 0, int size = -1, int paddingLength = 0)
    {
        return Z80Runner.Encrypt((byte)contentType, content.Skip(index).Take(size == -1 ? content.Length : size).ToArray());
    }

    public (RecordContentType, int) Decrypt(byte[] encryptedContent, byte[] destination, int? encryptedLength = null)
    {
        encryptedLength ??= encryptedContent.Length;

        /*
         additional_data = TLSCiphertext.opaque_type ||
           TLSCiphertext.legacy_record_version ||
           TLSCiphertext.length
         */

        byte[] additionalData = [
            (byte)RecordContentType.ApplicationData,
            3,3,
            ..encryptedLength.Value.ToBigEndianUint16Bytes()
        ];

        var innerDataLength = encryptedLength.Value - tagSize;
        var tag = encryptedContent.Skip(innerDataLength).Take(tagSize).ToArray();
        var cipherText = encryptedContent.Take(innerDataLength).ToArray();

        var result = Z80Runner.AesGcmDecrypt(serverKey, serverNonce, cipherText, additionalData);
        var decryptedContent = result[0];
        var calculatedTag = result[1];

        var (z80Error, z80Decrypted, z80ContentType, z80AuthTag) = Z80Runner.Decrypt(encryptedContent.Take(encryptedLength.Value).ToArray());

        if(!calculatedTag.SequenceEqual(tag)) {
            throw new ProtocolError(AlertCode.badRecordMac, $"Error when decrypting data: mismatching tag");
        }

        /*
         struct {
           opaque content[TLSPlaintext.length];
           ContentType type;
           uint8 zeros[length_of_padding];
         } TLSInnerPlaintext;
         */

        decryptedContent = decryptedContent.Reverse().SkipWhile(c => c == 0).Reverse().ToArray();
        if(decryptedContent.Length == 0) {
            throw new ProtocolError(AlertCode.decodeError, "Received an encrypted message whose plaintext payload was all zeros");
        }

        var contentType = decryptedContent[^1];
        decryptedContent = decryptedContent.Take(decryptedContent.Length - 1).ToArray();
        Array.Copy(decryptedContent, destination, decryptedContent.Length);

        IncreaseSequenceNumber(serverSequenceNumber, serverNonce, serverIv);
        return ((RecordContentType)contentType, decryptedContent.Length);
    }

    private void IncreaseSequenceNumber(byte[] sequenceNumber, byte[] nonce, byte[] iv, int index = 0)
    {
        var sequenceIndex = ivSize - 1 - index;
        sequenceNumber[sequenceIndex]++;
        if(sequenceNumber[sequenceIndex] == 0) {
            IncreaseSequenceNumber(sequenceNumber, nonce, iv, index + 1);
        }

        nonce[sequenceIndex] = (byte)(sequenceNumber[sequenceIndex] ^ iv[sequenceIndex]);

        var x = Z80Runner.IncreaseSequenceNumber(sequenceNumber == serverSequenceNumber);
        var z80Nonce = x[0];
        var z80Seq = x[1];
    }

    private void OnKeysGenerated(object? sender, bool forServer)
    {
        var keys = sender as TrafficKeys;
        if(forServer) {
            serverKey = keys.ServerKey;
            serverIv = keys.ServerIv;
            serverSequenceNumber = Enumerable.Repeat<byte>(0, ivSize).ToArray();
            serverNonce = keys.ServerIv.ToArray();
        }
        else {
            clientKey = keys.ClientKey;
            clientIv = keys.ClientIv;
            clientSequenceNumber = Enumerable.Repeat<byte>(0, ivSize).ToArray();
            clientNonce = keys.ClientIv.ToArray();
        }

        Z80Runner.InitRecordEncryption(clientKey, clientIv, serverKey, serverIv );
    }
}

