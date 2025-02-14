using Konamiman.TlsForZ80.TlsClient.Enums;
using Konamiman.TLSforZ80.TlsClient;

namespace Konamiman.TlsForZ80.TlsClient.Cryptography;

/// <summary>
/// This class handles AES encryption and decryption of application data,
/// handling the required sequence number/nonce increases.
/// </summary>
internal class RecordEncryption
{
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
        
        var (z80Error, z80Decrypted, z80ContentType) = Z80Runner.Decrypt(encryptedContent.Take(encryptedLength.Value).ToArray());
        if(z80Error == 1) {
            throw new ProtocolError(AlertCode.badRecordMac, $"Error when decrypting data: mismatching tag");
        }
        if(z80Error == 2) {
            throw new ProtocolError(AlertCode.decodeError, "Received an encrypted message whose plaintext payload was all zeros");
        }

        Array.Copy(z80Decrypted, 0, destination, 0, z80Decrypted.Length);
        return ((RecordContentType)z80ContentType, z80Decrypted.Length);
    }

    private void OnKeysGenerated(object sender, bool forServer)
    {
        var keys = sender as TrafficKeys;
        Z80Runner.InitRecordEncryption(forServer ? keys.ServerKey : keys.ClientKey, forServer ? keys.ServerIv : keys.ClientIv, forServer);
    }
}

