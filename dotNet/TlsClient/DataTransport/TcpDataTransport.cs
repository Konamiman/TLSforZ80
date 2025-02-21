using Konamiman.TLSforZ80.PocketZ80;
using System.Net.NetworkInformation;

namespace Konamiman.TlsForZ80.TlsClient.DataTransport;

/// <summary>
/// IDataTransport wrapper around a TCP connection.
/// </summary>
public class TcpDataTransport : IDataTransport
{
    readonly TcpConnection client;
    readonly string host;
    readonly int port;
    bool locallyClosed = false;

    public TcpDataTransport(string host, int port)
    {
        client = new TcpConnection(host, port);
        this.host = host;
        this.port = port;
    }

    public void Connect()
    {
        client.Connect();
    }

    public void Close()
    {
        client.Close();
        locallyClosed = true;
    }

    public bool HasDataToReceive()
    {
        return client.CanReceive() && client.AvailableCount > 0;
    }

    public bool IsLocallyClosed()
    {
        return locallyClosed;
    }

    public bool IsRemotelyClosed()
    {
        var state = client.GetState();
        return state is TcpState.Closed or TcpState.CloseWait;
    }

    public int Receive(byte[] destination, int index, int length)
    {
        if(!HasDataToReceive()) {
            return 0;
        }

        var data = client.Receive(length);
        Array.Copy(data, 0, destination, index, data.Length);
        return data.Length;
    }

    public bool Send(byte[] data, int index = 0, int? length = null)
    {
        length ??= data.Length - index;

        if (IsRemotelyClosed())
        {
            return false;
        }

        try
        {
            client.Send(data.Skip(index).Take(length.Value).ToArray(), true);
            return true;
        }
        catch
        {
            return false;
        }
    }

    public TcpState? GetConnectionState()
    {
        return client.GetState();
    }
}
