using Konamiman.TlsForZ80.TlsClient.Enums;
using Konamiman.TLSforZ80.TlsClient;

namespace Konamiman.TlsForZ80.TlsClient.DataStructures
{
    /// <summary>
    /// Represents a received ServerHello message.
    /// Create an instance from the received record data with "Parse",
    /// then read its public properties.
    /// </summary>
    internal class ServerHelloMessage
    {
        public CipherSuite CipherSuite { get; private set; }

        public bool IsTls13 { get; private set; }

        public bool IsHelloRetryRequest { get; private set; }

        public byte[] PublicKey { get; private set; } = null;

        /// <summary>
        /// Create a new instance of the class from the record data.
        /// </summary>
        /// <param name="data">Record data, not including the 5 byte record header nor the 4 byte handshake header.</param>
        /// <param name="index"></param>
        /// <param name="dataLength"></param>
        /// <returns></returns>
        public static ServerHelloMessage Parse(byte[] data)
        {
            return new ServerHelloMessage(data);
        }

        private ServerHelloMessage(byte[] data)
        {
            var z80Result = Z80Runner.ParseServerHello(data);
            switch(z80Result.Item1) {
                case 0:
                    IsTls13 = true;
                    CipherSuite = CipherSuite.TLS_AES_128_GCM_SHA256;
                    IsHelloRetryRequest = false;
                    PublicKey = [4, .. z80Result.Item2];
                    break;
                case 1:
                    throw new ProtocolError(AlertCode.decodeError, "The server didn't provide a properly formatted ServerHello message");
                case 2:
                    IsTls13 = true;
                    IsHelloRetryRequest = true;
                    break;
                case 3:
                    IsTls13 = false;
                    break;
                case 4:
                    CipherSuite = 0;
                    break;
                case 5:
                    throw new ProtocolError(AlertCode.handshakeFailure, "The server didn't provide a public key in the ServerHello message");
                case 6:
                    throw new ProtocolError(AlertCode.handshakeFailure, "The server didn't provide a matching session id in the ServerHello message");
                case 7:
                    throw new ProtocolError(AlertCode.handshakeFailure, "The server didn't provide a zero compression method in the ServerHello message");
                default:
                    throw new ProtocolError(AlertCode.internalError, $"Unexpected error code {z80Result.Item1} when parsing the ServerHello message");
            }

        }
    }
}
