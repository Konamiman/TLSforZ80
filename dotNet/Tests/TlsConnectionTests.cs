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
        RunInit();
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
        RunInit();
        Z80.A = 34;

        Run("TLS_CONNECTION.SEND_ALERT_RECORD");

        Assert.That(tcpDataSent, Is.EqualTo([TLS_RECORD_TYPE_ALERT, 3, 3, 0, 2, 2, 34]));
    }

    [Test]
    public void TestSendPlainHandshakeRecord()
    {
        RunInit();
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
    public void RecordReceiverErrorCausesErrorDuringHandshake()
    {
        Z80.ExecutionHooks[symbols["RECORD_RECEIVER.UPDATE"]] = () => {
            Z80.A = 3; //Bad record MAC
            Z80.ExecuteRet();
        };

        RunInit();
        Run("TLS_CONNECTION.UPDATE");
        Run("TLS_CONNECTION.UPDATE");

        AssertA(STATE_LOCALLY_CLOSED);
        AssertByteInMemory("TLS_CONNECTION.ERROR_CODE", symbols["TLS_CONNECTION.ERROR_CODE.RECEIVED_RECORD_DECODE_ERROR"]);
        AssertByteInMemory("TLS_CONNECTION.SUB_ERROR_CODE", 3);
        AssertByteInMemory("TLS_CONNECTION.ALERT_SENT", 20); //BAD_RECORD_MAC
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

    [Test]
    public void TestHelloExchange()
    {
        // This test uses data dumps from a real connection

        var clientHelloBytes = new byte[] {
             0x03,0x03,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,
             0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,
             0x00,0x00,0x20,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,
             0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,
             0x00,0x00,0x00,0x00,0x02,0x13,0x01,0x01,0x00,0x00,0x85,0x00,0x2B,0x00,0x03,0x02,
             0x03,0x04,0x00,0x01,0x00,0x01,0x01,0x00,0x0A,0x00,0x04,0x00,0x02,0x00,0x17,0x00,
             0x33,0x00,0x47,0x00,0x45,0x00,0x17,0x00,0x41,0x04,0x6B,0x17,0xD1,0xF2,0xE1,0x2C,
             0x42,0x47,0xF8,0xBC,0xE6,0xE5,0x63,0xA4,0x40,0xF2,0x77,0x03,0x7D,0x81,0x2D,0xEB,
             0x33,0xA0,0xF4,0xA1,0x39,0x45,0xD8,0x98,0xC2,0x96,0x4F,0xE3,0x42,0xE2,0xFE,0x1A,
             0x7F,0x9B,0x8E,0xE7,0xEB,0x4A,0x7C,0x0F,0x9E,0x16,0x2B,0xCE,0x33,0x57,0x6B,0x31,
             0x5E,0xCE,0xCB,0xB6,0x40,0x68,0x37,0xBF,0x51,0xF5,0x00,0x0D,0x00,0x0E,0x00,0x0C,
             0x04,0x01,0x05,0x01,0x08,0x04,0x08,0x05,0x04,0x03,0x05,0x03,0x00,0x00,0x00,0x10,
             0x00,0x0E,0x00,0x00,0x0B,0x74,0x6C,0x73,0x31,0x33,0x2E,0x31,0x64,0x2E,0x70,0x77
        };

        var serverHelloBytes = new byte[] {
             0x03,0x03,0xDE,0xAD,0xDE,0xAD,0xDE,0xAD,0xC0,0xDE,0x00,0x00,0x00,0x00,0x00,0x00,
             0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,
             0x00,0x00,0x20,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,
             0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,
             0x00,0x00,0x00,0x13,0x01,0x00,0x00,0x4F,0x00,0x33,0x00,0x45,0x00,0x17,0x00,0x41,
             0x04,0x1F,0xAD,0xAC,0x79,0x15,0x6E,0x08,0xC8,0x53,0x2C,0xE8,0x8D,0xF8,0x87,0x27,
             0x31,0x41,0xAC,0xE1,0x6E,0x44,0xE9,0xC2,0x68,0xCE,0x49,0x65,0x96,0xF4,0x1B,0x65,
             0xFA,0xF8,0x23,0x94,0x63,0x7B,0x6A,0xCF,0x00,0x4A,0xB2,0x53,0xF9,0x56,0xBD,0x2C,
             0xD6,0xCA,0x6C,0x9A,0xD8,0x45,0x4B,0xF1,0xFB,0xF2,0x81,0xA6,0xC5,0x4A,0x93,0xD9,
             0x9C,0x00,0x2B,0x00,0x02,0x03,0x04
        };

        Z80.ExecutionHooks[symbols["CLIENT_HELLO.INIT"]] = () => {
            WriteToMemory(symbols["CLIENT_HELLO.MESSAGE"], clientHelloBytes);
            WriteWordToMemory(symbols["CLIENT_HELLO.MESSAGE_HEADER"] + 2, (ushort)clientHelloBytes.Length, highEndian: true);
            WriteWordToMemory(symbols["CLIENT_HELLO.SIZE"], (ushort)clientHelloBytes.Length);
            Z80.HL = symbols["CLIENT_HELLO.MESSAGE"].ToShort();
            Z80.BC = clientHelloBytes.Length.ToShort();
            Z80.ExecuteRet();
        };

        /*var transmittedHandshakeBytes = new List<byte>();
        Z80.ExecutionHooks[symbols["SHA256.RUN"]] = () => {
            if(Z80.A != 1) return;
            transmittedHandshakeBytes.AddRange(ReadFromMemory(Z80.HL, Z80.BC));
        };*/

        /*Z80.ExecutionHooks[symbols["TLS_CONNECTION.SEND_HANDSHAKE_RECORD"]] = () => {
            var hr = ReadFromMemory(Z80.HL, Z80.BC);
            var s = ReadFromMemory(symbols["CLIENT_HELLO.SIZE"], 2);
        };*/

        /*Z80.ExecutionHooks[symbols["SERVER_HELLO.PARSE"]] = () => {
            var sh = ReadFromMemory(Z80.HL.ToUShort(), Z80.BC.ToUShort());
        };*/

        ReceivedTcpData = [
            [
                TLS_RECORD_TYPE_HANDSHAKE,
                3, 1,
                (byte)((serverHelloBytes.Length+4) >> 8),
                (byte)((serverHelloBytes.Length+4) & 0xFF),
                2, //server hello
                0,
                (byte)(serverHelloBytes.Length >> 8),
                (byte)(serverHelloBytes.Length & 0xFF),
                ..serverHelloBytes
            ]
        ];

        RunInit();
        Run("TLS_CONNECTION.UPDATE");
        Run("TLS_CONNECTION.UPDATE");

        /*
        var ec = Z80.Memory[symbols["TLS_CONNECTION.ERROR_CODE"]];
        var sec = Z80.Memory[symbols["TLS_CONNECTION.SUB_ERROR_CODE"]];
        var als = Z80.Memory[symbols["TLS_CONNECTION.ALERT_SENT"]];
        var hh = ReadFromMemory(symbols["RECORD_RECEIVER.HANDSHAKE_HEADER"], 4);
        */

        AssertByteInMemory("TLS_CONNECTION.STATE", STATE_HANDSHAKE);
        AssertA(STATE_HANDSHAKE);
        AssertByteInMemory("TLS_CONNECTION.FLAGS", 1); // HAS_KEYS

        var handshakeHash = new byte[] {
            0x6A,0x78,0x6B,0x30,0x28,0x59,0xF3,0x3E,0x21,0x90,0x25,0x7C,0x8E,0xD1,0x9F,0x2F,
            0xEA,0x56,0xDC,0x82,0xB7,0xFF,0x06,0xBE,0x63,0x71,0xB6,0x4C,0x68,0x93,0x86,0xD2
        };

        AssertMemoryContents("TLS_CONNECTION.HANDSHAKE_HASH", handshakeHash);

        var sharedSecred = new byte[] {
             0x1F,0xAD,0xAC,0x79,0x15,0x6E,0x08,0xC8,0x53,0x2C,0xE8,0x8D,0xF8,0x87,0x27,0x31,
             0x41,0xAC,0xE1,0x6E,0x44,0xE9,0xC2,0x68,0xCE,0x49,0x65,0x96,0xF4,0x1B,0x65,0xFA
        };

        AssertMemoryContents("TLS_CONNECTION.SHARED_SECRET", sharedSecred);

        var clientKey = new byte[] {
            0x5A,0xBA,0x9C,0x64,0x33,0xC8,0x68,0xEC,0xD6,0x44,0xFB,0x52,0x3F,0x5A,0x33,0x2E
        };

        AssertMemoryContents("HKDF.CLIENT_KEY", clientKey);

        var serverKey = new byte[] {
            0x53,0xC7,0x08,0xE4,0x32,0x3B,0x0D,0x99,0xA3,0xE6,0x34,0x39,0x8E,0x07,0x25,0xC2
        };

        AssertMemoryContents("HKDF.SERVER_KEY", serverKey);
    }

    [Test]
    public void TestUnexpectedMessageDuringHandshake()
    {
        RunInit();
        Run("TLS_CONNECTION.UPDATE");

        ReceivedTcpData = [
            [
               TLS_RECORD_TYPE_HANDSHAKE,
               3, 3,
               0, 7, // Length
               34,
               0, 0, 3,
               1, 2, 3
            ]
        ];

        Run("TLS_CONNECTION.UPDATE");
        AssertA(STATE_LOCALLY_CLOSED);
        AssertByteInMemory("TLS_CONNECTION.ERROR_CODE", symbols["TLS_CONNECTION.ERROR_CODE.UNEXPECTED_HANDSHAKE_TYPE_IN_HANDSHAKE"]);
        AssertByteInMemory("TLS_CONNECTION.SUB_ERROR_CODE", 34);
    }

    [Test]
    public void TestSecondServerHelloReceivedDuringHandshake()
    {
        RunInit();
        Run("TLS_CONNECTION.UPDATE");

        var serverHelloBytes = new byte[] {
             0x03,0x03,0xDE,0xAD,0xDE,0xAD,0xDE,0xAD,0xC0,0xDE,0x00,0x00,0x00,0x00,0x00,0x00,
             0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,
             0x00,0x00,0x20,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,
             0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,
             0x00,0x00,0x00,0x13,0x01,0x00,0x00,0x4F,0x00,0x33,0x00,0x45,0x00,0x17,0x00,0x41,
             0x04,0x1F,0xAD,0xAC,0x79,0x15,0x6E,0x08,0xC8,0x53,0x2C,0xE8,0x8D,0xF8,0x87,0x27,
             0x31,0x41,0xAC,0xE1,0x6E,0x44,0xE9,0xC2,0x68,0xCE,0x49,0x65,0x96,0xF4,0x1B,0x65,
             0xFA,0xF8,0x23,0x94,0x63,0x7B,0x6A,0xCF,0x00,0x4A,0xB2,0x53,0xF9,0x56,0xBD,0x2C,
             0xD6,0xCA,0x6C,0x9A,0xD8,0x45,0x4B,0xF1,0xFB,0xF2,0x81,0xA6,0xC5,0x4A,0x93,0xD9,
             0x9C,0x00,0x2B,0x00,0x02,0x03,0x04
        };

        ReceivedTcpData = [
            [
                TLS_RECORD_TYPE_HANDSHAKE,
                3, 1,
                (byte)((serverHelloBytes.Length+4) >> 8),
                (byte)((serverHelloBytes.Length+4) & 0xFF),
                2, //server hello
                0,
                (byte)(serverHelloBytes.Length >> 8),
                (byte)(serverHelloBytes.Length & 0xFF),
                ..serverHelloBytes
            ],
            [
                TLS_RECORD_TYPE_HANDSHAKE,
                3, 1,
                (byte)((serverHelloBytes.Length+4) >> 8),
                (byte)((serverHelloBytes.Length+4) & 0xFF),
                2, //server hello
                0,
                (byte)(serverHelloBytes.Length >> 8),
                (byte)(serverHelloBytes.Length & 0xFF),
                ..serverHelloBytes
            ]
        ];

        Run("TLS_CONNECTION.UPDATE");   // First ServerHello received
        Run("TLS_CONNECTION.UPDATE");   // Second ServerHello received
        AssertA(STATE_LOCALLY_CLOSED);
        AssertByteInMemory("TLS_CONNECTION.ERROR_CODE", symbols["TLS_CONNECTION.ERROR_CODE.SECOND_SERVER_HELLO_RECEIVED"]);
        AssertByteInMemory("TLS_CONNECTION.ALERT_SENT", symbols["TLS_CONNECTION.ALERT_CODE.UNEXPECTED_MESSAGE"]);
    }

    [Test]
    public void ServerHelloParseErrorCausesErrorDuringHandshake()
    {
        RunInit();

        var serverHelloBytes = new byte[] {
             0x03,0x03,0xDE,0xAD,0xDE,0xAD,0xDE,0xAD,0xC0,0xDE,0x00,0x00,0x00,0x00,0x00,0x00,
             0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,
             0x00,0x00,0x20,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,
             0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,
             0x00,0x00,0x00,0x13,0x01,0x00,0x00,0x4F,0x00,0x33,0x00,0x45,0x00,0x17,0x00,0x41,
             0x04,0x1F,0xAD,0xAC,0x79,0x15,0x6E,0x08,0xC8,0x53,0x2C,0xE8,0x8D,0xF8,0x87,0x27,
             0x31,0x41,0xAC,0xE1,0x6E,0x44,0xE9,0xC2,0x68,0xCE,0x49,0x65,0x96,0xF4,0x1B,0x65,
             0xFA,0xF8,0x23,0x94,0x63,0x7B,0x6A,0xCF,0x00,0x4A,0xB2,0x53,0xF9,0x56,0xBD,0x2C,
             0xD6,0xCA,0x6C,0x9A,0xD8,0x45,0x4B,0xF1,0xFB,0xF2,0x81,0xA6,0xC5,0x4A,0x93,0xD9,
             0x9C,0x00,0x2B,0x00,0x02,0x03,0x04
        };

        ReceivedTcpData = [
            [
                TLS_RECORD_TYPE_HANDSHAKE,
                3, 1,
                (byte)((serverHelloBytes.Length+4) >> 8),
                (byte)((serverHelloBytes.Length+4) & 0xFF),
                2, //server hello
                0,
                (byte)(serverHelloBytes.Length >> 8),
                (byte)(serverHelloBytes.Length & 0xFF),
                ..serverHelloBytes
            ]
        ];

        Z80.ExecutionHooks[symbols["SERVER_HELLO.PARSE"]] = () => {
            Z80.A = 4; //Illegal parameter
            Z80.ExecuteRet();
        };

        Run("TLS_CONNECTION.UPDATE");
        Run("TLS_CONNECTION.UPDATE");

        AssertA(STATE_LOCALLY_CLOSED);
        AssertByteInMemory("TLS_CONNECTION.ERROR_CODE", symbols["TLS_CONNECTION.ERROR_CODE.INVALID_SERVER_HELLO"]);
        AssertByteInMemory("TLS_CONNECTION.SUB_ERROR_CODE", 4);
        AssertByteInMemory("TLS_CONNECTION.ALERT_SENT", 47); //ILLEGAL_PARAMETER
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
