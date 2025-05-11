using Konamiman.PocketZ80;
using System.Net.NetworkInformation;

namespace Konamiman.TLSforZ80.PocketZ80;

internal partial class TcpIpUnapi
{
    private TcpConnection tcpConnection { get; set; }

    private TcpConnection GetTcpConnection(byte connectionNumber)
    {
        return (connectionNumber == 1 && (tcpConnection?.IsClosed == false)) ? tcpConnection : null;
    }

    private byte TCPIP_TCP_CLOSE()
    {
        void action() =>
            tcpConnection?.Close();

        return TcpAbortOrClose(action);
    }

    private byte TCPIP_TCP_ABORT()
    {
        void action()
        {
            tcpConnection?.Abort();
            tcpConnection = null;
        }

        return TcpAbortOrClose(action);
    }

    private byte TcpAbortOrClose(Action action)
    {
        var connectionIndex = cpu.B - 1;
        if(connectionIndex is 0 or -1) {
            action();
            return ERR_OK;
        }
        else {
            return ERR_NO_CONN;
        }
    }

    private byte TCPIP_TCP_STATE()
    {
        cpu.C = 0;

        var connection = GetTcpConnection(cpu.B);
        if(connection == null)
            return ERR_NO_CONN;

        var connectionState = connection.GetState();
        if(connectionState == TcpState.Unknown)
            cpu.B = 0;
        else
            cpu.B = (byte)(((int)connectionState) - 1);

        var infoBlockPointer = cpu.HL;
        if(infoBlockPointer != 0) {
            void PutUshortInMem(int value, int address)
            {
                var bytes = BitConverter.GetBytes(value.ToUShort());
                cpu.Memory[address] = bytes[BitConverter.IsLittleEndian ? 0 : 1];
                cpu.Memory[address + 1] = bytes[BitConverter.IsLittleEndian ? 1 : 0];
            }

            var remoteAddressBytes = connection.RemoteEndpoint.Address.GetAddressBytes();
            for(var i = 0; i < 4; i++)
                cpu.Memory[infoBlockPointer + i] = remoteAddressBytes[i];
            PutUshortInMem(connection.RemoteEndpoint.Port, infoBlockPointer + 4);
            PutUshortInMem(connection.LocalPort, infoBlockPointer + 6);
        }

        cpu.HL = Math.Min(connection.AvailableCount, ushort.MaxValue).ToShort();
        cpu.DE = 0;
        cpu.IX = -1;
        cpu.A = 0;

        return ERR_OK;
    }

    private byte TCPIP_TCP_SEND()
    {
        var connection = GetTcpConnection(cpu.B);
        if(connection == null)
            return ERR_NO_CONN;

        /*if(!connection.CanSend())
            return ERR_CONN_STATE;*/

        if((cpu.C & 0b11111100) != 0)
            return ERR_INV_PAR;

        var dataAddress = cpu.DE.ToUShort();
        var dataLength = cpu.HL.ToUShort();
        if(dataLength == 0)
            return ERR_OK;

        var mustPush = (cpu.C & 1) == 1;

        var data = new byte[dataLength];
        for(var i = 0; i < dataLength; i++)
            data[i] = cpu.Memory[dataAddress + i];

        connection.Send(data, mustPush);

        return ERR_OK;
    }

    private byte TCPIP_TCP_RCV()
    {
        var connection = GetTcpConnection(cpu.B);
        if(connection == null)
            return ERR_NO_CONN;

        if(!connection.CanReceive())
            return ERR_CONN_STATE;

        var dataAddress = cpu.DE.ToUShort();
        var dataLength = cpu.HL.ToUShort();

        cpu.BC = 0;
        cpu.HL = 0;

        dataLength = Math.Min(connection.AvailableCount, dataLength).ToUShort();
        if(dataLength == 0)
            return ERR_OK;

        var data = connection.Receive(dataLength);

        for(var i = 0; i < dataLength; i++)
            cpu.Memory[dataAddress + i] = data[i];

        cpu.BC = dataLength.ToShort();

        return ERR_OK;
    }

    private byte TCPIP_TCP_FLUSH()
    {
        var connection = GetTcpConnection(cpu.B);
        if(connection == null)
            return ERR_NO_CONN;

        if(!connection.CanSend())
            return ERR_CONN_STATE;

        connection.Flush();

        return ERR_OK;
    }
}