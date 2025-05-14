using System.Net.NetworkInformation;
using System.Net.Sockets;
using System.Net;

namespace Konamiman.TLSforZ80.PocketZ80;

/// <summary>
/// Encapsulates .NET TCP connections behind a simplified interface.
/// This class doesn't know anything about UNAPI (except for the IsTransient property, 
/// which the class itself doesn't use).
/// </summary>
public class TcpConnection
{
    private TcpClient tcpClient;
    private string host;
    private int port;
    private TcpListener listener;

    public TcpConnection(string host, int port)
    {
        tcpClient = new TcpClient(AddressFamily.InterNetwork);
        this.host = host;
        this.port = port;
    }

    public void Connect()
    {
        tcpClient.Connect(host, port);
        RemoteEndpoint = (IPEndPoint)tcpClient.Client.RemoteEndPoint;
    }

    public void Close()
    {
        try {
            listener?.Stop();
            tcpClient?.Client?.Shutdown(SocketShutdown.Send);
            isListening = false;
        }
        catch {
            Abort();
        }
    }

    public void Abort()
    {
        isListening = false;
        try {
            listener?.Stop();
            tcpClient?.Client?.Dispose();
        }
        catch { }

        IsClosed = true;
    }

    public TcpState GetState()
    {
        if(isListening)
            return TcpState.Listen;

        if(IsClosed)
            return TcpState.Closed;

        var info = IPGlobalProperties.GetIPGlobalProperties()
          .GetActiveTcpConnections()
          .SingleOrDefault(x => x.LocalEndPoint.Equals(tcpClient.Client?.LocalEndPoint)
                             && x.RemoteEndPoint.Equals(tcpClient.Client?.RemoteEndPoint)
          );

        return info?.State ?? TcpState.Closed;
    }

    public bool CanSend()
    {
        var state = GetState();
        return state == TcpState.Established || state == TcpState.CloseWait;
    }

    public void Send(byte[] data, bool push)
    {
        /*if(!CanSend())
            throw new InvalidOperationException("Can't send data in the current connection state");*/

        try {
            var stream = tcpClient.GetStream();
            stream.Write(data, 0, data.Length);
            if(push)
                stream.Flush();
        }
        catch {
            Abort();
        }
    }

    public void Flush()
    {
        try {
            var stream = tcpClient.GetStream();
            stream.Flush();
        }
        catch {
            Abort();
        }
    }

    public int AvailableCount
    {
        get
        {
            if(IsClosed || isListening)
                return 0;

            try {
                return tcpClient.Available;
            }
            catch {
                Abort();
                return 0;
            }
        }
    }

    public bool CanReceive()
    {
        var state = GetState();
        return state >= TcpState.Established;
    }

    public byte[] Receive(int count)
    {
        /*if(!CanReceive())
            throw new InvalidOperationException("Can't receive data in the current connection state");*/

        var available = AvailableCount;
        if(available == 0)
            return new byte[0];

        try {
            var stream = tcpClient.GetStream();
            var data = new byte[count];
            stream.Read(data, 0, count);
            return data;
        }
        catch {
            Abort();
            return new byte[0];
        }
    }

    public bool IsClosed { get; private set; }

    private bool isListening;

    public int LocalPort { get; set; }

    public IPEndPoint RemoteEndpoint { get; private set; }

    public bool IsTransient { get; set; }

    public static bool LocalPortIsInUse(int port)
    {
        var ipProperties = IPGlobalProperties.GetIPGlobalProperties();
        var activeConnections = ipProperties.GetActiveTcpConnections();
        var activeListeners = ipProperties.GetActiveTcpListeners();

        return
            activeConnections.Any(c => c.LocalEndPoint.Port == port) ||
            activeListeners.Any(l => l.Port == port);
    }
}
