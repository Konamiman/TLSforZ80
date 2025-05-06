using Konamiman.TlsForZ80.TlsClient.DataTransport;
using Konamiman.TlsForZ80.TlsClient.Enums;
using Konamiman.TLSforZ80.TlsClient;

namespace Konamiman.TlsForZ80.TlsClient;

/// <summary>
/// Implements a TLS 1.3 client connection on top of a data transport layer
/// (typically a TCP connection).
/// </summary>
public class TlsClientConnection
{
    /// <summary>
    /// Create a new instance of the class.
    /// </summary>
    /// <param name="dataTransport">The underlying data transport to use, it must be already properly initialized and functional.</param>
    /// <param name="privateKey">The X25519 private key to use, if null a random key will be generated.</param>
    /// <param name="hostName">The host name to send in a server_name extension in the ClientHello message, if null no server_name extension will be sent.</param>
    public TlsClientConnection(IDataTransport dataTransport, byte[] privateKey, string hostName)
    {
        Z80Runner.Init();
        Z80Runner.RecordReceiverInit(0xC000, 0x3000);
        Z80Runner.TlsConnectionInit(hostName);
    }

    public (byte, byte) GetErrorCode() => Z80Runner.TlsConnectionGetErrorCode();

    /// <summary>
    /// After an alert record is sent this property indicates the corresponsing alert code.
    /// </summary>
    public AlertCode? AlertSent
    {
        get
        {
            var alertSent = Z80Runner.TlsConnectionAlertSent();
            return alertSent == 0 ? null : (AlertCode)alertSent;
        }
    }

    /// <summary>
    /// After an alert record is received this property indicates the corresponsing alert code.
    /// </summary>
    public AlertCode? AlertReceived
    {
        get
        {
            var alertReceived = Z80Runner.TlsConnectionAlertReceived();
            return alertReceived == 0 ? null : (AlertCode)alertReceived;
        }
    }

    /// <summary>
    /// Current state of the TLS connection. Application data can be sent in the
    /// "Established" and "RemotelyClosed" states; application data can be received
    /// in the "Established" and "LocallyClosed" states.
    /// </summary>
    public ConnectionState State
    {
        get
        {
            RunStateMachine();
            var state = Z80Runner.TlsConnectionGetState();
            return state switch {
                0 => ConnectionState.Initial,
                1 => ConnectionState.Handshake,
                2 => ConnectionState.Established,
                3 => ConnectionState.LocallyClosed,
                4 => ConnectionState.RemotelyClosed,
                5 => ConnectionState.FullClosed,
                _ => throw new InvalidOperationException($"Invalid connection state {state}"),
            };
        }
    }

    /// <summary>
    /// Indicates if application data can be sent.
    /// </summary>
    public bool CanSend
    {
        get
        {
            RunStateMachine();
            return Z80Runner.TlsConnectionCanSend();
        }
    }

    /// <summary>
    /// Indicates if application data can be received.
    /// </summary>
    public bool CanReceive
    {
        get
        {
            RunStateMachine();
            return Z80Runner.TlsConnectionCanReceive();
        }
    }

    /// <summary>
    /// Get a given amount of application data from the connection.
    /// </summary>
    /// <param name="destination">Destination array for the data.</param>
    /// <param name="index">Destination index in the destination array for the data.</param>
    /// <param name="size">Number of data bytes to get.</param>
    /// <returns>Actual number of data bytes to get.</returns>
    public int GetApplicationData(byte[] destination, int index, int size)
    {
        RunStateMachine();
        var data = Z80Runner.TlsConnectionReceive(size);
        if(data.Length > 0) {
            Array.Copy(data, 0, destination, index, data.Length);
            return data.Length;
        }
        return data.Length;
    }

    /// <summary>
    /// Get a given amount of application data from the connection.
    /// </summary>
    /// <param name="size">Number of data bytes to get.</param>
    /// <returns>Application data, will be of the requested size or less.</returns>
    public byte[] GetApplicationData(int size)
    {
        RunStateMachine();
        return Z80Runner.TlsConnectionReceive(size);
    }

    /// <summary>
    /// Send application data to the connection.
    /// </summary>
    /// <param name="source">Source array of the data to sent.</param>
    /// <param name="index">Starting index in the source array of the data to sent, defaults to 0.</param>
    /// <param name="size">How many bytes to send, defaults to (size of source - index).</param>
    /// <returns></returns>
    public bool SendApplicationData(byte[] source, int index = 0, int size = -1)
    {
        RunStateMachine();
        source = source.Skip(index).ToArray();
        if(size != -1) {
            source = source.Take(size).ToArray();
        }
        return Z80Runner.TlsConnectionSend(source);
    }

    /// <summary>
    /// Locally close the connection, meaning that we don't intend to send any more data.
    /// Until the server closes the connection on its side it's still possible
    /// to receive data.
    /// </summary>
    public void Close()
    {
        RunStateMachine();
        Z80Runner.TlsConnectionClose();
    }

    //--- End of the public interface of the class ---

    private void RunStateMachine()
    {
        Z80Runner.TlsConnectionUpdate();
    }
}

