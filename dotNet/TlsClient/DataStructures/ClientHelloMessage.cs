using Konamiman.TlsForZ80.TlsClient.Enums;
using Konamiman.TLSforZ80.TlsClient;
using System;
using System.Linq;
using System.Security.Cryptography;
using System.Text;

namespace Konamiman.TlsForZ80.TlsClient.DataStructures
{
    /// <summary>
    /// Represents a ClientHello message.
    /// After creating an instance, set its public properties as appropriate
    /// and then invoke "ToByteArray".
    /// </summary>
    internal class ClientHelloMessage
    {
        public CipherSuite[] CipherSuites { get; set; } = null;

        public byte[] P256PublicKey { get; set; } = null;

        public string ServerName { get; set; } = null;

        /// <summary>
        /// Serializes the message as a TLS record, not including
        /// the 5 byte record header nor the 4 byte handshake header.
        /// </summary>
        /// <returns></returns>
        public byte[] ToByteArray()
        {
             return Z80Runner.GetClientHello(ServerName, P256PublicKey);
        }
    }
}
