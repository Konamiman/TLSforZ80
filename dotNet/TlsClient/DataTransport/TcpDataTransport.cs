using Konamiman.TLSforZ80.PocketZ80;
using Konamiman.TLSforZ80.TlsClient;
using System.Net.NetworkInformation;

namespace Konamiman.TlsForZ80.TlsClient.DataTransport;

/// <summary>
/// IDataTransport wrapper around a TCP connection.
/// </summary>
public class TcpDataTransport : IDataTransport
{
    readonly TcpConnection client;

    public TcpDataTransport(string host, int port)
    {
        client = new TcpConnection(host, port);
    }

    public void Connect()
    {
        client.Connect();
    }

    public void BindConnectionToZ80()
    {
        Z80Runner.TcpConnection = client;
        Z80Runner.InitTcp();
    }

    public void Close()
    {
        Z80Runner.TcpClose();
    }

    public bool HasDataToReceive()
    {
        return Z80Runner.HasTcpData();
    }

    public bool IsRemotelyClosed()
    {
        return Z80Runner.TcpIsClosed();
    }

    public int Receive(byte[] destination, int index, int length)
    {
        if(!HasDataToReceive()) {
            return 0;
        }

        var data = Z80Runner.TcReceive(length);
        if(data.Length > 0) {
            Array.Copy(data, 0, destination, index, data.Length);
        }
        return data.Length;
    }

    public bool Send(byte[] data, int index = 0, int? length = null)
    {
        length ??= data.Length - index;

        if (IsRemotelyClosed())
        {
            return false;
        }

        return Z80Runner.TcpSend(data.Skip(index).Take(length.Value).ToArray());
    }

    public TcpState? GetConnectionState()
    {
        return client.GetState();
    }
}
