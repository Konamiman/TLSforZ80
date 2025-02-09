using Konamiman.TLSforZ80.TlsClient;
using System;
using System.Collections.Generic;
using System.Linq;
using System.Security.Cryptography;
using System.Text;

namespace Konamiman.TlsForZ80.TlsClient.Cryptography;

/// <summary>
/// This class holds the keys and IVs for a TLS 1.3 connection,
/// and provides methods to (re)calculate them.
/// </summary>
internal class TrafficKeys
{
    readonly HMAC hmac;
    readonly HashAlgorithm hash;
    readonly int hashSize;
    const int keyLength = 16;
    const int ivLength = 12;
    static readonly byte[] empty = [];
    byte[] handshakeSecret = null;
    readonly byte[] emptyHash;
    byte[] clientSecret;
    byte[] serverSecret;

    public byte[] ClientKey { get; private set; }
    public byte[] ServerKey { get; private set; }
    public byte[] ClientIv { get; private set; }
    public byte[] ServerIv { get; private set; }

    public event EventHandler<bool> KeysGenerated; //true=for server, false=for client

    public TrafficKeys(HMAC hmacAlgorithm, HashAlgorithm hashAlgorithgm)
    {
        this.hmac = hmacAlgorithm;
        this.hash = hashAlgorithgm;
        hashSize = hmacAlgorithm.HashSize / 8; //We get bits, but we need bytes
        emptyHash = Z80Runner.CalculateSHA256(empty);
    }

    /// <summary>
    /// Compute the handshake traffic secrets according to RFC8446, section 7.1
    /// (https://datatracker.ietf.org/doc/html/rfc8446#section-7.1)
    /// </summary>
    /// <param name="sharedSecret"></param>
    /// <param name="handshakeHash"></param>
    public void ComputeHandshakeKeys(byte[] sharedSecret, byte[] handshakeHash)
    {
        var keys = Z80Runner.ComputeHandshakeKeys(sharedSecret, handshakeHash);
        clientSecret = keys[0];
        serverSecret = keys[1];
        ClientKey = keys[2];
        ServerKey = keys[3];
        ClientIv = keys[4];
        ServerIv = keys[5];

        if(KeysGenerated is not null) {
            KeysGenerated(this, true);
            KeysGenerated(this, false);
        }
    }

    /// <summary>
    /// Compute the application traffic secrets according to RFC8446, section 7.1
    /// (https://datatracker.ietf.org/doc/html/rfc8446#section-7.1)
    /// </summary>
    /// <param name="handshakeHash"></param>
    public void ComputeApplicationKeys(byte[] handshakeHash)
    {
        var keys = Z80Runner.ComputeApplicationKeys(handshakeHash);
        clientSecret = keys[0];
        serverSecret = keys[1];
        ClientKey = keys[2];
        ServerKey = keys[3];
        ClientIv = keys[4];
        ServerIv = keys[5];

        if(KeysGenerated is not null) {
            KeysGenerated(this, true);
            KeysGenerated(this, false);
        }
    }

    /// <summary>
    /// Update the client application traffic keys according to RFC8446, section 7.2
    /// (https://datatracker.ietf.org/doc/html/rfc8446#section-7.2)
    /// </summary>
    public void UpdateClientKeys()
    {
        clientSecret = ExpandLabel(clientSecret, "traffic upd", empty, hashSize);
        ComputeKeysFromSecrets(forServer: false);
    }

    /// <summary>
    /// Update the server application traffic keys according to RFC8446, section 7.2
    /// (https://datatracker.ietf.org/doc/html/rfc8446#section-7.2)
    /// </summary>
    public void UpdateServerKeys()
    {
        serverSecret = ExpandLabel(serverSecret, "traffic upd", empty, hashSize);
        ComputeKeysFromSecrets(forClient: false);
    }

    /// <summary>
    /// Get the key for calulating the data for "Finished" messages.
    /// </summary>
    /// <param name="ofServer">True to compute the server key, false to compute the client key.</param>
    /// <returns>The computed key.</returns>
    public byte[] ComputeFinishedKey(bool ofServer)
    {
        return Z80Runner.ComputeFinishedKey(ofServer);
    }

    /// <summary>
    /// Derive the handshake or application traffic keys according to RFC8446, section 7.3
    /// (https://datatracker.ietf.org/doc/html/rfc8446#section-7.3)
    /// </summary>
    /// <param name="forClient">True to derive the client keys.</param>
    /// <param name="forServer">True to derive the server keys.</param>
    private void ComputeKeysFromSecrets(bool forClient = true, bool forServer = true)
    {
        if(forClient) {
            ClientKey = ExpandLabel(clientSecret, "key", empty, keyLength);
            ClientIv = ExpandLabel(clientSecret, "iv", empty, ivLength);
            if(KeysGenerated is not null) {
                KeysGenerated(this, false);
            }
        }

        if(forServer) {
            ServerKey = ExpandLabel(serverSecret, "key", empty, keyLength);
            ServerIv = ExpandLabel(serverSecret, "iv", empty, ivLength);
            if(KeysGenerated is not null) {
                KeysGenerated(this, true);
            }
        }
    }

    /// <summary>
    /// "Extract" function as per RFC5869, section 2.2
    /// (https://datatracker.ietf.org/doc/html/rfc5869#section-2.2)
    /// </summary>
    /// <param name="salt"></param>
    /// <param name="ikm"></param>
    /// <returns></returns>
    private byte[] Extract(byte[] salt, byte[] ikm)
    {
        hmac.Key = salt;
        return Z80Runner.CalculateHMAC(salt, ikm);
    }

    /// <summary>
    /// "Expand" function as per RFC5869, section 2.3
    /// (https://datatracker.ietf.org/doc/html/rfc5869#section-2.3)
    /// </summary>
    /// <param name="prk"></param>
    /// <param name="info"></param>
    /// <param name="length"></param>
    /// <returns></returns>
    private byte[] Expand(byte[] prk, byte[] info, int length)
    {
        hmac.Key = prk;
        var steps = (int)Math.Ceiling((decimal)length / hashSize);
        var result = new List<byte>();
        var singleByte = new byte[] { 1 };
        var previous = empty;

        for(var i = 0; i < steps; i++) {
            previous = Z80Runner.CalculateHMAC(prk, [.. previous, .. info, .. singleByte]);
            result.AddRange(previous);
            singleByte[0]++;
        }

        return result.Take(length).ToArray();
    }

    /// <summary>
    /// "Expand label" function as per RFC8446, section 7.1
    /// (https://datatracker.ietf.org/doc/html/rfc8446#section-7.1)
    /// </summary>
    /// <param name="secret"></param>
    /// <param name="label"></param>
    /// <param name="context"></param>
    /// <param name="length"></param>
    /// <returns></returns>
    byte[] ExpandLabel(byte[] secret, string label, byte[] context, int length)
    {
        /*
        struct {
           uint16 length = Length;
           opaque label<7..255> = "tls13 " + Label;
           opaque context<0..255> = Context;
        } HkdfLabel;
        */

        var labelBytes = Encoding.ASCII.GetBytes("tls13 " + label);

        byte[] hkdfLabel = [
            .. length.ToBigEndianUint16Bytes(),
            (byte)labelBytes.Length, //size indicator for "label<7..255>"
            .. labelBytes,
            (byte)context.Length,    //size indicator for "context<0..255>"
            .. context
        ];

        return Expand(secret, hkdfLabel, length).Take(length).ToArray();
    }
}
