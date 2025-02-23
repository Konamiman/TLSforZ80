using Konamiman.PocketZ80;
using System.Net;
using System.Net.NetworkInformation;
using System.Net.Sockets;

namespace Konamiman.TLSforZ80.PocketZ80;

internal partial class TcpIpUnapi
{
    private readonly NetworkInterface networkInterface;
    private readonly Z80Processor cpu;


    public TcpIpUnapi(Z80Processor cpu, TcpConnection connection)
    {
        this.cpu = cpu;
        this.tcpConnection = connection;

        bool hasIpv4Address(NetworkInterface iface)
        {
            return iface.GetIPProperties().UnicastAddresses.Any(a => IsIPv4(a.Address));
        }

        string ipAddress = "";
        var networkInterfaces = NetworkInterface.GetAllNetworkInterfaces()
            .Where(i => i.Supports(NetworkInterfaceComponent.IPv4));
        networkInterface =
            networkInterfaces.FirstOrDefault(i => hasIpv4Address(i) && i.NetworkInterfaceType != NetworkInterfaceType.Loopback)
            ?? networkInterfaces.FirstOrDefault(i => hasIpv4Address(i));

        if(networkInterface == null) {
            throw new Exception(ipAddress == "" ?
                "No IPv4 network interfaces available" :
                $"There is no network interface with the IP address {ipAddress}");
        }

        InitRoutinesArray();
        this.cpu = cpu;
    }

    private byte[] GetMemoryContents(int address, int length)
    {
        var contents = new byte[length];
        for(var i = 0; i < length; i++)
            contents[i] = cpu.Memory[address + i];
        return contents;
    }

    public void HandleEntryPointCall()
    {
        var functionNumber = cpu.A;

        if(functionNumber < Routines.Length && Routines[functionNumber] != null)
            cpu.A = Routines[functionNumber]();
        else
            cpu.A = ERR_NOT_IMP;

        cpu.ExecuteRet();
    }

    private Func<byte>[] Routines;
    private void InitRoutinesArray()
    {
        Routines =
        [
            null, //UNAPI_GET_INFO,
            null, //TCPIP_GET_CAPAB,
            null, //TCPIP_GET_IPINFO,
            null, //TCPIP_NET_STATE,
            null, //TCPIP_SEND_ECHO
            null, //TCPIP_RCV_ECHO
            null, //TCPIP_DNS_Q,
            null, //TCPIP_DNS_S,
            null, //TCPIP_UDP_OPEN,
            null, //TCPIP_UDP_CLOSE,
            null, //TCPIP_UDP_STATE,
            null, //TCPIP_UDP_SEND,
            null, //TCPIP_UDP_RCV,
            null, //TCPIP_TCP_OPEN,
            TCPIP_TCP_CLOSE,
            TCPIP_TCP_ABORT,
            TCPIP_TCP_STATE,
            TCPIP_TCP_SEND,
            TCPIP_TCP_RCV,
            TCPIP_TCP_FLUSH,
            null, //TCPIP_RAW_OPEN
            null, //TCPIP_RAW_CLOSE
            null, //TCPIP_RAW_STATE
            null, //TCPIP_RAW_SEND
            null, //TCPIP_RAW_RCV
            null, //TCPIP_CONFIG_AUTOIP,
            null, //TCPIP_CONFIG_IP,
            null, //TCPIP_CONFIG_TTL,
            null, //TCPIP_CONFIG_PING,
            null, //TCPIP_WAIT
        ];
    }

    private const int ERR_OK = 0;
    private const int ERR_NOT_IMP = 1;
    private const int ERR_NO_NETWORK = 2;
    private const int ERR_NO_DATA = 3;
    private const int ERR_INV_PAR = 4;
    private const int ERR_QUERY_EXISTS = 5;
    private const int ERR_INV_IP = 6;
    private const int ERR_NO_DNS = 7;
    private const int ERR_DNS = 8;
    private const int ERR_NO_FREE_CONN = 9;
    private const int ERR_CONN_EXISTS = 10;
    private const int ERR_NO_CONN = 11;
    private const int ERR_CONN_STATE = 12;
    private const int ERR_LARGE_DGRAM = 14;

    private bool IsIPv4(IPAddress ipAddress) =>
        ipAddress.AddressFamily == AddressFamily.InterNetwork;

    private bool NoNetworkAvailable()
    {
        return !(networkInterface.OperationalStatus == OperationalStatus.Up || networkInterface.OperationalStatus == OperationalStatus.Unknown);
    }
}
