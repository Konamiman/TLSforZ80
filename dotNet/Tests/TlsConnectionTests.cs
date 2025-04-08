using Konamiman.PocketZ80;
using Konamiman.TLSforZ80.Tests;
using NUnit.Framework;
using System.Text;

namespace Konamiman.TLSforZ80.TlsConsole;

public class TlsConnectionTests : TestBase
{
    const byte STATE_INITIAL = 0;
    const byte STATE_HANDSHAKE = 1;
    const byte STATE_ESTABLISHED = 2;
    const byte STATE_LOCALLY_CLOSED = 3;
    const byte STATE_REMOTELY_CLOSED = 4;
    const byte STATE_FULLY_CLOSED = 5;

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

    [Test]
    public void InitInitializesEverything()
    {
        Run("TLS_CONNECTION.INIT");

        AssertByteInMemory("TLS_CONNECTION.STATE", STATE_INITIAL);
        AssertByteInMemory("TLS_CONNECTION.ERROR_CODE", 0);
        AssertByteInMemory("TLS_CONNECTION.ALERT_SENT", 0);
        AssertByteInMemory("TLS_CONNECTION.ALERT_RECEIVED", 0);
    }

    [Test]
    public void RemoteCloseAfterInitClosesWithoutSendingAlert()
    {
        Run("TLS_CONNECTION.INIT");

        tcpConnectionIsRemotelyClosed = true;

        Run("TLS_CONNECTION.UPDATE");
        Assert.That(tcpDataSent, Is.Empty);
        AssertByteInMemory("TLS_CONNECTION.STATE", STATE_FULLY_CLOSED);
        AssertA(STATE_FULLY_CLOSED);
        Assert.That(tcpConnectionIsLocallyClosed, Is.True);
    }

    [Test]
    public void LocalCloseAfterInitClosesWithoutSendingAlert()
    {
        Run("TLS_CONNECTION.INIT");

        Run("TLS_CONNECTION.CLOSE");
        Assert.That(tcpDataSent, Is.Empty);
        AssertByteInMemory("TLS_CONNECTION.STATE", STATE_LOCALLY_CLOSED);
        AssertA(STATE_LOCALLY_CLOSED);
        Assert.That(tcpConnectionIsLocallyClosed, Is.True);

        // Now simulate another update after peer has closed too

        tcpConnectionIsRemotelyClosed = true;
        Run("TLS_CONNECTION.UPDATE");
        Assert.That(tcpDataSent, Is.Empty);
        AssertByteInMemory("TLS_CONNECTION.STATE", STATE_FULLY_CLOSED);
        AssertA(STATE_FULLY_CLOSED);
    }

    [Test]
    public void UpdateAfterInitSendsClientHello()
    {
        var serverName = "server.com";
        RunInit(serverName);
        Run("TLS_CONNECTION.UPDATE");
        AssertByteInMemory("TLS_CONNECTION.STATE", STATE_HANDSHAKE);
        AssertA(STATE_HANDSHAKE);

        var clientHelloSize = GetWordFromMemory("CLIENT_HELLO.SIZE") + 4;
        var clientHelloBytes = ReadFromMemory(symbols["CLIENT_HELLO.MESSAGE_HEADER"], clientHelloSize);

        Assert.That(
            tcpDataSent.ToArray(), 
            Is.EqualTo((byte[])
                [ TLS_RECORD_TYPE_HANDSHAKE, 3, 1, (byte)((clientHelloSize & 0xFF00)>>8), (byte)(clientHelloSize & 0xFF), .. clientHelloBytes]
            ));

        var serverNameBytes = Encoding.ASCII.GetBytes(serverName);
        Assert.That(ReadFromMemory(symbols["CLIENT_HELLO.SERVER_NAME"], serverNameBytes.Length), Is.EqualTo(serverNameBytes));
    }

    [Test]
    public void InitSendsPublicKeyToClientHello()
    {
        short publicKeyAddressReceivedByClientHelloInit = 0;
        Z80.ExecutionHooks[symbols["CLIENT_HELLO.INIT"]] = () => {
            publicKeyAddressReceivedByClientHelloInit = Z80.DE;
            Z80.ExecuteRet();
        };
        Z80.ExecutionHooks[symbols["P256.GENERATE_KEY_PAIR"]] = () => {
            Z80.HL = 0x1234;
            Z80.ExecuteRet();
        };

        RunInit();
        Assert.That(publicKeyAddressReceivedByClientHelloInit, Is.EqualTo(0x1234));
    }

    [Test]
    public void ChangeCipherSpecIsIgnoredDuringHandshake()
    {
        RunInit();
        Run("TLS_CONNECTION.UPDATE");

        ReceivedTcpData = [
            [
               TLS_RECORD_TYPE_CHANGE_CIHPER_SPEC,
               3, 3,
               0, 1, //Length
               34
            ]
        ];

        Run("TLS_CONNECTION.UPDATE");
        AssertA(STATE_HANDSHAKE);
    }

    [Test]
    public void UnexpectedRecordCausesErrorDuringHandshake()
    {
        RunInit();
        Run("TLS_CONNECTION.UPDATE");

        ReceivedTcpData = [
            [
               34,
               3, 3,
               0, 1, //Length
               89
            ]
        ];

        Run("TLS_CONNECTION.UPDATE");
        AssertA(STATE_LOCALLY_CLOSED);
        AssertByteInMemory("TLS_CONNECTION.ERROR_CODE", symbols["TLS_CONNECTION.ERROR_CODE.UNEXPECTED_RECORD_TYPE_IN_HANDSHAKE"]);
        AssertByteInMemory("TLS_CONNECTION.SUB_ERROR_CODE", 34);
    }

    [Test]
    public void AlertRecordCausesConnectionCloseDuringHandshake()
    {
        RunInit();
        Run("TLS_CONNECTION.UPDATE");

        ReceivedTcpData = [
            [
               TLS_RECORD_TYPE_ALERT,
               3, 3,
               0, 2, // Length
               1, 34
            ]
        ];

        Run("TLS_CONNECTION.UPDATE");
        AssertA(STATE_LOCALLY_CLOSED);
        AssertByteInMemory("TLS_CONNECTION.ERROR_CODE", symbols["TLS_CONNECTION.ERROR_CODE.ALERT_RECEIVED"]);
        AssertByteInMemory("TLS_CONNECTION.ALERT_RECEIVED", 34);
    }

    [Test]
    public void AlertRecordOfTypeCloseNotifyCausesFullCloseDuringHandshake()
    {
        RunInit();
        Run("TLS_CONNECTION.UPDATE");

        ReceivedTcpData = [
            [
               TLS_RECORD_TYPE_ALERT,
               3, 3,
               0, 2, // Length
               1, 0  // 0 = Close notify
            ]
        ];

        Run("TLS_CONNECTION.UPDATE");
        AssertA(STATE_FULLY_CLOSED);
        AssertByteInMemory("TLS_CONNECTION.ERROR_CODE", symbols["TLS_CONNECTION.ERROR_CODE.ALERT_RECEIVED"]);
        AssertByteInMemory("TLS_CONNECTION.ALERT_RECEIVED", 0);
    }

    private void RunInit(string serverName = null)
    {
        if(serverName == null) {
            Z80.B = 0;
        }
        else { 
            var serverNameBytes = Encoding.ASCII.GetBytes(serverName);
            WriteToMemory(0xF000, serverNameBytes);
            Z80.HL = 0xF000.ToShort();
            Z80.B = (byte)serverNameBytes.Length;
        }
        Run("TLS_CONNECTION.INIT");
    }
}
