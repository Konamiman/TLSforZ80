using Konamiman.PocketZ80;
using Konamiman.TLSforZ80.Tests;
using NUnit.Framework;

namespace Konamiman.TLSforZ80.TlsConsole;

public class TlsConnectionTests : TestBase
{
    [Test]
    public void TestSendPlainRecord()
    {
        byte[] data = [1, 2, 3, 4, 5];
        WriteToMemory(0xF000, data);

        Z80.A = 34;
        Z80.HL = 0xF000.ToShort();
        Z80.BC = data.Length.ToShort();

        Run("TLS_CONNECTION.SEND_RECORD");

        Assert.That(tcpDataSent, Is.EqualTo([34, 3, 3, 0, (byte)data.Length, ..data ]));
    }

    [Test]
    public void TestSendPlainAlertRecord()
    {
        Z80.A = 34;

        Run("TLS_CONNECTION.SEND_ALERT_RECORD");

        Assert.That(tcpDataSent, Is.EqualTo([TLS_RECORD_TYPE_ALERT, 3, 3, 0, 2, 2, 34]));
    }

    [Test]
    public void TestSendPlainHandshakeRecord()
    {
        byte[] data = [1, 2, 3, 4, 5];
        byte[] dataWithHeader = [34, 0, 0, (byte)data.Length, ..data];
        WriteToMemory(0xF000, dataWithHeader);

        Z80.HL = 0xF000.ToShort();

        Run("TLS_CONNECTION.SEND_HANDSHAKE_RECORD");

        Assert.That(tcpDataSent, Is.EqualTo([TLS_RECORD_TYPE_HANDSHAKE, 3, 3, 0, (byte)dataWithHeader.Length, .. dataWithHeader]));
    }
}
