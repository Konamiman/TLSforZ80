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
    public byte[] ClientKey { get; private set; }
    public byte[] ServerKey { get; private set; }
    public byte[] ClientIv { get; private set; }
    public byte[] ServerIv { get; private set; }

    public event EventHandler<bool> KeysGenerated; //true=for server, false=for client

    public TrafficKeys()
    {
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
        ClientKey = keys[0];
        ServerKey = keys[1];
        ClientIv = keys[2];
        ServerIv = keys[3];

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
        ClientKey = keys[0];
        ServerKey = keys[1];
        ClientIv = keys[2];
        ServerIv = keys[3];

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
        var keys = Z80Runner.UpdateTrafficKey(false);
        ClientKey = keys[0];
        ClientIv = keys[1];

        if(KeysGenerated is not null) {
            KeysGenerated(this, false);
        }
    }

    /// <summary>
    /// Update the server application traffic keys according to RFC8446, section 7.2
    /// (https://datatracker.ietf.org/doc/html/rfc8446#section-7.2)
    /// </summary>
    public void UpdateServerKeys()
    {
        var keys = Z80Runner.UpdateTrafficKey(true);
        ServerKey = keys[0];
        ServerIv = keys[1];

        if(KeysGenerated is not null) {
            KeysGenerated(this, true);
        }
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
}
