using Konamiman.PocketZ80;
using NUnit.Framework;

namespace Konamiman.TLSforZ80.Tests;

public class DataReceiverTests : TestBase
{
    [Test]
    public void TestTcpDataReception()
    {
        // Simple scenario: receive all the data

        ReceivedTcpData = [
            [1,2,3,4,5],
            [6,7,8,9,10]
        ];

        RunAsCall("DATA_TRANSPORT.HAS_IN_DATA");
        AssertCarrySet();

        Z80.Registers.HL = 0x8000.ToShort();
        Z80.Registers.BC = 5;
        RunAsCall("DATA_TRANSPORT.RECEIVE");
        AssertBC(5);
        AssertMemoryContents(0x8000, [1, 2, 3, 4, 5]);

        RunAsCall("DATA_TRANSPORT.HAS_IN_DATA");
        AssertCarrySet();

        Z80.Registers.HL = 0x8000.ToShort();
        Z80.Registers.BC = 5;
        RunAsCall("DATA_TRANSPORT.RECEIVE");
        AssertBC(5);
        AssertMemoryContents(0x8000, [6, 7, 8, 9, 10]);

        RunAsCall("DATA_TRANSPORT.HAS_IN_DATA");
        AssertCarryReset();

        Z80.Registers.HL = 0x8000.ToShort();
        Z80.Registers.BC = 5;
        RunAsCall("DATA_TRANSPORT.RECEIVE");
        AssertBC(0);

        // Receive data in chunks

        ReceivedTcpData = [
            [1,2,3,4,5],
            [6,7,8,9,10]
        ];

        RunAsCall("DATA_TRANSPORT.HAS_IN_DATA");
        AssertCarrySet();

        Z80.Registers.HL = 0x8000.ToShort();
        Z80.Registers.BC = 3;
        RunAsCall("DATA_TRANSPORT.RECEIVE");
        AssertBC(3);
        AssertMemoryContents(0x8000, [1, 2, 3]);

        RunAsCall("DATA_TRANSPORT.HAS_IN_DATA");
        AssertCarrySet();

        Z80.Registers.HL = 0x8000.ToShort();
        Z80.Registers.BC = 5;
        RunAsCall("DATA_TRANSPORT.RECEIVE");
        AssertBC(2);
        AssertMemoryContents(0x8000, [4, 5]);

        RunAsCall("DATA_TRANSPORT.HAS_IN_DATA");
        AssertCarrySet();

        Z80.Registers.HL = 0x8000.ToShort();
        Z80.Registers.BC = 2;
        RunAsCall("DATA_TRANSPORT.RECEIVE");
        AssertBC(2);
        AssertMemoryContents(0x8000, [6, 7]);

        RunAsCall("DATA_TRANSPORT.HAS_IN_DATA");
        AssertCarrySet();

        Z80.Registers.HL = 0x8000.ToShort();
        Z80.Registers.BC = 2;
        RunAsCall("DATA_TRANSPORT.RECEIVE");
        AssertBC(2);
        AssertMemoryContents(0x8000, [8, 9]);

        RunAsCall("DATA_TRANSPORT.HAS_IN_DATA");
        AssertCarrySet();

        Z80.Registers.HL = 0x8000.ToShort();
        Z80.Registers.BC = 2;
        RunAsCall("DATA_TRANSPORT.RECEIVE");
        AssertBC(1);
        AssertMemoryContents(0x8000, [10]);

        RunAsCall("DATA_TRANSPORT.HAS_IN_DATA");
        AssertCarryReset();

        Z80.Registers.HL = 0x8000.ToShort();
        Z80.Registers.BC = 5;
        RunAsCall("DATA_TRANSPORT.RECEIVE");
        AssertBC(0);
    }

    [Test]
    public void AssertNoChangeIfNoData()
    {
        ReceivedTcpData = [];
        RunAsCall("RECORD_RECEIVER.UPDATE");
        AssertA("RECORD_RECEIVER.ERROR_NO_CHANGE");
        RunAsCall("RECORD_RECEIVER.UPDATE");
        AssertA("RECORD_RECEIVER.ERROR_NO_CHANGE");
    }

    [Test]
    public void AssertReceiveAlertRecordInOneGo()
    {
        ReceivedTcpData = [
            [
                TLS_RECORD_TYPE_ALERT,
                3, 3,
                0, 4,   //Length
                1, 2, 3, 4
            ]
        ];

        RunAsCall("RECORD_RECEIVER.UPDATE");
        AssertA("RECORD_RECEIVER.ERROR_FULL_RECORD_AVAILABLE");
        AssertBC(4);
        AssertMemoryContents(Z80.Registers.HL.ToUShort(), [1, 2, 3, 4]);
        Assert.That(Z80.Registers.D, Is.EqualTo(TLS_RECORD_TYPE_ALERT));
    }

    [Test]
    public void AssertReceiveAlertRecordInMultipleTcpDatagrams()
    {
        ReceivedTcpData = [
            [
                TLS_RECORD_TYPE_ALERT,
                3, 3,
                0, 4   //Length
            ],
            [],
            [1,2],
            [3],
            [4]
        ];

        RunAsCall("RECORD_RECEIVER.UPDATE");
        AssertA("RECORD_RECEIVER.ERROR_NO_CHANGE");
        RunAsCall("RECORD_RECEIVER.UPDATE");
        AssertA("RECORD_RECEIVER.ERROR_NO_CHANGE");
        RunAsCall("RECORD_RECEIVER.UPDATE");
        AssertA("RECORD_RECEIVER.ERROR_NO_CHANGE");

        RunAsCall("RECORD_RECEIVER.UPDATE");
        AssertA("RECORD_RECEIVER.ERROR_FULL_RECORD_AVAILABLE");
        AssertBC(4);
        AssertMemoryContents(Z80.Registers.HL.ToUShort(), [1, 2, 3, 4]);
        Assert.That(Z80.Registers.D, Is.EqualTo(TLS_RECORD_TYPE_ALERT));
    }

    [Test]
    public void AssertErrorReceivedIfConnectionIsClosed()
    {
        tcpConnectionIsRemotelyClosed = true;
        ReceivedTcpData = [];

        RunAsCall("RECORD_RECEIVER.UPDATE");
        AssertA("RECORD_RECEIVER.ERROR_CONNECTION_CLOSED");
        RunAsCall("RECORD_RECEIVER.UPDATE");
        AssertA("RECORD_RECEIVER.ERROR_CONNECTION_CLOSED");
    }

    [Test]
    public void AssertErrorReceivedIfRecordIstooBig()
    {
        // First receive a record of exactly the buffer size

        Z80.Registers.HL = 0x8000.ToShort();
        Z80.Registers.BC = 10;
        Run("RECORD_RECEIVER.INIT");

        ReceivedTcpData = [
            [
                TLS_RECORD_TYPE_ALERT,
                3, 3,
                0, 5,   //Length
                1, 2, 3, 4, 5
            ]
        ];

        RunAsCall("RECORD_RECEIVER.UPDATE");
        AssertA("RECORD_RECEIVER.ERROR_FULL_RECORD_AVAILABLE");
        AssertBC(5);
        AssertMemoryContents(Z80.Registers.HL.ToUShort(), [1, 2, 3, 4, 5]);
        Assert.That(Z80.Registers.D, Is.EqualTo(TLS_RECORD_TYPE_ALERT));

        // Now receive a record one byte too big

        Z80.Registers.HL = 0x8000.ToShort();
        Z80.Registers.BC = 9;
        Run("RECORD_RECEIVER.INIT");

        ReceivedTcpData = [
            [
                TLS_RECORD_TYPE_ALERT,
                3, 3,
                0, 5,   //Length
                1, 2, 3, 4, 5
            ]
        ];

        RunAsCall("RECORD_RECEIVER.UPDATE");
        AssertA("RECORD_RECEIVER.ERROR_RECORD_TOO_LONG");
    }

    [Test]
    public void AssertErrorReceivedIfRecordIsOver16K()
    {
        Z80.Registers.HL = 0x8000.ToShort();
        Z80.Registers.BC = 20000;
        Run("RECORD_RECEIVER.INIT");

        var recordContent = Enumerable.Repeat<byte>(34, 0x4100).ToArray();

        ReceivedTcpData = [
            [
                TLS_RECORD_TYPE_ALERT,
                3, 3,
                0x41, 0,   //Length: 16384+256
                ..recordContent
            ]
        ];

        Run("RECORD_RECEIVER.UPDATE");
        AssertA("RECORD_RECEIVER.ERROR_FULL_RECORD_AVAILABLE");
        AssertBC(0x4100);
        AssertMemoryContents(Z80.Registers.HL.ToUShort(), recordContent);
        Assert.That(Z80.Registers.D, Is.EqualTo(TLS_RECORD_TYPE_ALERT));

        ReceivedTcpData = [
            [
                TLS_RECORD_TYPE_ALERT,
                3, 3,
                0x41, 1,   //Length: 16384+256+1
                ..recordContent,
                34
            ]
        ];

        Run("RECORD_RECEIVER.UPDATE");
        AssertA("RECORD_RECEIVER.ERROR_RECORD_OVER_16K");
    }

    [Test]
    public void TestBadAuthTagInEncryptedRecord()
    {
        ReceivedTcpData = [
           [
                TLS_RECORD_TYPE_APP_DATA,
                3, 3,
                0, 5,   //Length
                1, 2, 3, 4, 5
            ]
       ];

        badAuthTag = true;

        Run("RECORD_RECEIVER.UPDATE");
        AssertA("RECORD_RECEIVER.ERROR_BAD_AUTH_TAG");
    }

    [Test]
    public void TestRecordAllZerosInEncryptedRecord()
    {
        ReceivedTcpData = [
           [
                TLS_RECORD_TYPE_APP_DATA,
                3, 3,
                0, 5,   //Length
                1, 2, 3, 4, 5
            ]
       ];

        recordAllZeros = true;

        Run("RECORD_RECEIVER.UPDATE");
        AssertA("RECORD_RECEIVER.ERROR_MSG_ALL_ZEROS");
    }

    [Test]
    public void TestRceiveEncryptedRecord()
    {
        ReceivedTcpData = [
           [
                TLS_RECORD_TYPE_APP_DATA,
                3, 3,
                0, 8,   //Length
                1, 2, 3, 4, 5, 6, 7, 8
            ]
        ];

        encryptedRecordType = TLS_RECORD_TYPE_DUMMY;

        Run("RECORD_RECEIVER.UPDATE");
        AssertA("RECORD_RECEIVER.ERROR_FULL_RECORD_AVAILABLE");
        Assert.That(Z80.Registers.D, Is.EqualTo(TLS_RECORD_TYPE_DUMMY));
        AssertBC(7);
        AssertMemoryContents(Z80.Registers.HL.ToUShort(), [0x81, 0x82, 0x83, 0x84, 0x85, 0x86, 0x87]);
    }

    [Test]
    public void TlsReceiveTooLongHandshakeMessage()
    {
        ReceivedTcpData = [
            [
                TLS_RECORD_TYPE_HANDSHAKE,
                3, 3,
                0, 9,    //Record length
                TLS_HANDSHAKE_TYPE_DUMMY,
                1, 0, 0, //Handshake length
                1, 2, 3, 4, 5
            ]
        ];

        Run("RECORD_RECEIVER.UPDATE");
        AssertA("RECORD_RECEIVER.ERROR_HANDSHAKE_MSG_TOO_LONG");
    }

    [Test]
    public void TlsReceiveSingleHandshakeMessage()
    {
        ReceivedTcpData = [
            [
                TLS_RECORD_TYPE_HANDSHAKE,
                3, 3,
                0, 9,    //Record length
                TLS_HANDSHAKE_TYPE_DUMMY,
                0, 0, 5, //Handshake length
                1, 2, 3, 4, 5
            ]
        ];

        Run("RECORD_RECEIVER.UPDATE");
        AssertA("RECORD_RECEIVER.ERROR_FULL_HANDSHAKE_MESSAGE");
        AssertBC(5);
        Assert.That(Z80.Registers.E, Is.EqualTo(TLS_HANDSHAKE_TYPE_DUMMY));
        AssertMemoryContents(Z80.Registers.HL.ToUShort(), [1, 2, 3, 4, 5]);
        AssertMemoryContents(symbols["RECORD_RECEIVER.HANDSHAKE_HEADER"], [TLS_HANDSHAKE_TYPE_DUMMY, 0, 0, 5]);

        Run("RECORD_RECEIVER.UPDATE");
        AssertA("RECORD_RECEIVER.ERROR_NO_CHANGE");
    }

    [Test]
    public void TlsReceiveMultipleHandshakeMessagesInOneRecord()
    {
        ReceivedTcpData = [
            [
                TLS_RECORD_TYPE_HANDSHAKE,
                3, 3,
                0, 16,    //Record length
                TLS_HANDSHAKE_TYPE_DUMMY,
                0, 0, 5, //Handshake length
                1, 2, 3, 4, 5,
                TLS_HANDSHAKE_TYPE_DUMMY_2,
                0, 0, 3, //Handshake length
                6, 7, 8
            ]
        ];

        Run("RECORD_RECEIVER.UPDATE");
        AssertA("RECORD_RECEIVER.ERROR_FULL_HANDSHAKE_MESSAGE");
        AssertBC(5);
        Assert.That(Z80.Registers.E, Is.EqualTo(TLS_HANDSHAKE_TYPE_DUMMY));
        AssertMemoryContents(symbols["RECORD_RECEIVER.HANDSHAKE_HEADER"], [TLS_HANDSHAKE_TYPE_DUMMY, 0, 0, 5]);
        AssertMemoryContents(Z80.Registers.HL.ToUShort(), [1, 2, 3, 4, 5]);

        Run("RECORD_RECEIVER.UPDATE");
        AssertA("RECORD_RECEIVER.ERROR_FULL_HANDSHAKE_MESSAGE");
        AssertBC(3);
        Assert.That(Z80.Registers.E, Is.EqualTo(TLS_HANDSHAKE_TYPE_DUMMY_2));
        AssertMemoryContents(symbols["RECORD_RECEIVER.HANDSHAKE_HEADER"], [TLS_HANDSHAKE_TYPE_DUMMY_2, 0, 0, 3]);
        AssertMemoryContents(Z80.Registers.HL.ToUShort(), [6, 7, 8]);

        Run("RECORD_RECEIVER.UPDATE");
        AssertA("RECORD_RECEIVER.ERROR_NO_CHANGE");
    }

    [Test]
    public void TlsReceiveHandshakeMessageSplitInMultipleRecords()
    {
        ReceivedTcpData = [
            [
                TLS_RECORD_TYPE_HANDSHAKE,
                3, 3,
                0, 9,    //Record length
                TLS_HANDSHAKE_TYPE_DUMMY,
                0, 0, 20, //Handshake length
                1, 2, 3, 4, 5
            ],
            [
                TLS_RECORD_TYPE_HANDSHAKE,
                3, 3,
                0, 7,    //Record length
                6, 7, 8, 9, 10, 11, 12
            ],
            [
                TLS_RECORD_TYPE_HANDSHAKE,
                3, 3,
                0, 8,    //Record length
                13, 14, 15, 16, 17, 18, 19, 20
            ]
        ];

        Run("RECORD_RECEIVER.UPDATE");
        AssertA("RECORD_RECEIVER.ERROR_SPLIT_HANDSHAKE_FIRST");
        AssertBC(5);
        Assert.That(Z80.Registers.E, Is.EqualTo(TLS_HANDSHAKE_TYPE_DUMMY));
        AssertMemoryContents(symbols["RECORD_RECEIVER.HANDSHAKE_HEADER"], [TLS_HANDSHAKE_TYPE_DUMMY, 0, 0, 20]);
        AssertMemoryContents(Z80.Registers.HL.ToUShort(), [1, 2, 3, 4, 5]);
        AssertWordInMemory("RECORD_RECEIVER.HANDSHAKE_MSG_SIZE", 20);

        Run("RECORD_RECEIVER.UPDATE");
        AssertA("RECORD_RECEIVER.ERROR_SPLIT_HANDSHAKE_NEXT");
        AssertBC(7);
        Assert.That(Z80.Registers.E, Is.EqualTo(TLS_HANDSHAKE_TYPE_DUMMY));
        AssertMemoryContents(symbols["RECORD_RECEIVER.HANDSHAKE_HEADER"], [TLS_HANDSHAKE_TYPE_DUMMY, 0, 0, 20]);
        AssertMemoryContents(Z80.Registers.HL.ToUShort(), [6, 7, 8, 9, 10, 11, 12]);
        AssertWordInMemory("RECORD_RECEIVER.HANDSHAKE_MSG_SIZE", 20);

        Run("RECORD_RECEIVER.UPDATE");
        AssertA("RECORD_RECEIVER.ERROR_SPLIT_HANDSHAKE_LAST");
        AssertBC(8);
        Assert.That(Z80.Registers.E, Is.EqualTo(TLS_HANDSHAKE_TYPE_DUMMY));
        AssertMemoryContents(symbols["RECORD_RECEIVER.HANDSHAKE_HEADER"], [TLS_HANDSHAKE_TYPE_DUMMY, 0, 0, 20]);
        AssertMemoryContents(Z80.Registers.HL.ToUShort(), [13, 14, 15, 16, 17, 18, 19, 20]);
        AssertWordInMemory("RECORD_RECEIVER.HANDSHAKE_MSG_SIZE", 20);

        Run("RECORD_RECEIVER.UPDATE");
        AssertA("RECORD_RECEIVER.ERROR_NO_CHANGE");
    }

    [Test]
    public void TlsReceiveHandshakeMessageSplitInMultipleRecordsAndNonHandshakeInBetween()
    {
        ReceivedTcpData = [
            [
                TLS_RECORD_TYPE_HANDSHAKE,
                3, 3,
                0, 9,    //Record length
                TLS_HANDSHAKE_TYPE_DUMMY,
                0, 0, 20, //Handshake length
                1, 2, 3, 4, 5
            ],
            [
                TLS_RECORD_TYPE_DUMMY,
                3, 3,
                0, 3,    //Record length
                1, 2, 3
            ]
        ];

        Run("RECORD_RECEIVER.UPDATE");
        AssertA("RECORD_RECEIVER.ERROR_SPLIT_HANDSHAKE_FIRST");

        Run("RECORD_RECEIVER.UPDATE");
        AssertA("RECORD_RECEIVER.ERROR_NON_HANDSHAKE_RECEIVED");

        Run("RECORD_RECEIVER.UPDATE");
        AssertA("RECORD_RECEIVER.ERROR_NO_CHANGE");
    }

    [Test]
    public void TlsReceiveMultipleHandshakeMessagesInOneRecordAndThenAFragment()
    {
        ReceivedTcpData = [
            [
                TLS_RECORD_TYPE_HANDSHAKE,
                3, 3,
                0, 25,    //Record length
                TLS_HANDSHAKE_TYPE_DUMMY,
                0, 0, 5, //Handshake length
                1, 2, 3, 4, 5,
                TLS_HANDSHAKE_TYPE_DUMMY_2,
                0, 0, 3, //Handshake length
                6, 7, 8,
                TLS_HANDSHAKE_TYPE_DUMMY,
                0, 0, 25, //Handshake length
                1, 2, 3, 4, 5
            ]
        ];

        Run("RECORD_RECEIVER.UPDATE");
        AssertA("RECORD_RECEIVER.ERROR_FULL_HANDSHAKE_MESSAGE");

        Run("RECORD_RECEIVER.UPDATE");
        AssertA("RECORD_RECEIVER.ERROR_FULL_HANDSHAKE_MESSAGE");

        Run("RECORD_RECEIVER.UPDATE");
        AssertA("RECORD_RECEIVER.ERROR_SPLIT_HANDSHAKE_FIRST");
        AssertBC(5);
        Assert.That(Z80.Registers.E, Is.EqualTo(TLS_HANDSHAKE_TYPE_DUMMY));
        AssertMemoryContents(symbols["RECORD_RECEIVER.HANDSHAKE_HEADER"], [TLS_HANDSHAKE_TYPE_DUMMY, 0, 0, 25]);
        AssertMemoryContents(Z80.Registers.HL.ToUShort(), [1, 2, 3, 4, 5]);
        AssertWordInMemory("RECORD_RECEIVER.HANDSHAKE_MSG_SIZE", 25);

        Run("RECORD_RECEIVER.UPDATE");
        AssertA("RECORD_RECEIVER.ERROR_NO_CHANGE");
    }

    [Test]
    public void TlsReceiveHandshakeMessageSplitInMultipleRecordsAndThenEntireMessages()
    {
        ReceivedTcpData = [
            [
                TLS_RECORD_TYPE_HANDSHAKE,
                3, 3,
                0, 9,    //Record length
                TLS_HANDSHAKE_TYPE_DUMMY,
                0, 0, 8, //Handshake length
                1, 2, 3, 4, 5
            ],
            [
                TLS_RECORD_TYPE_HANDSHAKE,
                3, 3,
                0, 22,    //Record length
                6, 7, 8,
                TLS_HANDSHAKE_TYPE_DUMMY_2,
                0, 0, 4, //Handshake length
                1, 2, 3, 4,
                TLS_HANDSHAKE_TYPE_DUMMY,
                0, 0, 7, //Handshake length
                1, 2, 3, 4, 5, 6, 7
            ]
        ];

        Run("RECORD_RECEIVER.UPDATE");
        AssertA("RECORD_RECEIVER.ERROR_SPLIT_HANDSHAKE_FIRST");
        AssertBC(5);
        Assert.That(Z80.Registers.E, Is.EqualTo(TLS_HANDSHAKE_TYPE_DUMMY));
        AssertMemoryContents(symbols["RECORD_RECEIVER.HANDSHAKE_HEADER"], [TLS_HANDSHAKE_TYPE_DUMMY, 0, 0, 8]);
        AssertMemoryContents(Z80.Registers.HL.ToUShort(), [1, 2, 3, 4, 5]);
        AssertWordInMemory("RECORD_RECEIVER.HANDSHAKE_MSG_SIZE", 8);

        Run("RECORD_RECEIVER.UPDATE");
        AssertA("RECORD_RECEIVER.ERROR_SPLIT_HANDSHAKE_LAST");
        AssertBC(3);
        Assert.That(Z80.Registers.E, Is.EqualTo(TLS_HANDSHAKE_TYPE_DUMMY));
        AssertMemoryContents(symbols["RECORD_RECEIVER.HANDSHAKE_HEADER"], [TLS_HANDSHAKE_TYPE_DUMMY, 0, 0, 8]);
        AssertMemoryContents(Z80.Registers.HL.ToUShort(), [6, 7, 8]);
        AssertWordInMemory("RECORD_RECEIVER.HANDSHAKE_MSG_SIZE", 8);

        Run("RECORD_RECEIVER.UPDATE");
        AssertA("RECORD_RECEIVER.ERROR_FULL_HANDSHAKE_MESSAGE");
        AssertBC(4);
        Assert.That(Z80.Registers.E, Is.EqualTo(TLS_HANDSHAKE_TYPE_DUMMY_2));
        AssertMemoryContents(symbols["RECORD_RECEIVER.HANDSHAKE_HEADER"], [TLS_HANDSHAKE_TYPE_DUMMY_2, 0, 0, 4]);
        AssertMemoryContents(Z80.Registers.HL.ToUShort(), [1, 2, 3, 4]);
        AssertWordInMemory("RECORD_RECEIVER.HANDSHAKE_MSG_SIZE", 4);

        Run("RECORD_RECEIVER.UPDATE");
        AssertA("RECORD_RECEIVER.ERROR_FULL_HANDSHAKE_MESSAGE");
        AssertBC(7);
        Assert.That(Z80.Registers.E, Is.EqualTo(TLS_HANDSHAKE_TYPE_DUMMY));
        AssertMemoryContents(symbols["RECORD_RECEIVER.HANDSHAKE_HEADER"], [TLS_HANDSHAKE_TYPE_DUMMY, 0, 0, 7]);
        AssertMemoryContents(Z80.Registers.HL.ToUShort(), [1, 2, 3, 4, 5, 6, 7]);
        AssertWordInMemory("RECORD_RECEIVER.HANDSHAKE_MSG_SIZE", 7);

        Run("RECORD_RECEIVER.UPDATE");
        AssertA("RECORD_RECEIVER.ERROR_NO_CHANGE");
    }

    [Test]
    public void TlsReceiveHandshakeMessageSplitInMultipleRecordsAndThenEntireMessagesAndThenSplitAgain()
    {
        ReceivedTcpData = [
            [
                TLS_RECORD_TYPE_HANDSHAKE,
                3, 3,
                0, 9,    //Record length
                TLS_HANDSHAKE_TYPE_DUMMY,
                0, 0, 8, //Handshake length
                1, 2, 3, 4, 5
            ],
            [
                TLS_RECORD_TYPE_HANDSHAKE,
                3, 3,
                0, 31,    //Record length
                6, 7, 8,
                TLS_HANDSHAKE_TYPE_DUMMY_2,
                0, 0, 4, //Handshake length
                1, 2, 3, 4,
                TLS_HANDSHAKE_TYPE_DUMMY,
                0, 0, 7, //Handshake length
                1, 2, 3, 4, 5, 6, 7,
                // Another split message begins!
                TLS_HANDSHAKE_TYPE_DUMMY_2,
                0, 0, 8, //Handshake length
                1, 2, 3, 4, 5
            ],
            [
                TLS_RECORD_TYPE_HANDSHAKE,
                3, 3,
                0, 3,    //Record length
                6, 7, 8
            ]
        ];

        Run("RECORD_RECEIVER.UPDATE");
        AssertA("RECORD_RECEIVER.ERROR_SPLIT_HANDSHAKE_FIRST");
        AssertBC(5);
        Assert.That(Z80.Registers.E, Is.EqualTo(TLS_HANDSHAKE_TYPE_DUMMY));
        AssertMemoryContents(symbols["RECORD_RECEIVER.HANDSHAKE_HEADER"], [TLS_HANDSHAKE_TYPE_DUMMY, 0, 0, 8]);
        AssertMemoryContents(Z80.Registers.HL.ToUShort(), [1, 2, 3, 4, 5]);
        AssertWordInMemory("RECORD_RECEIVER.HANDSHAKE_MSG_SIZE", 8);

        Run("RECORD_RECEIVER.UPDATE");
        AssertA("RECORD_RECEIVER.ERROR_SPLIT_HANDSHAKE_LAST");
        AssertBC(3);
        Assert.That(Z80.Registers.E, Is.EqualTo(TLS_HANDSHAKE_TYPE_DUMMY));
        AssertMemoryContents(symbols["RECORD_RECEIVER.HANDSHAKE_HEADER"], [TLS_HANDSHAKE_TYPE_DUMMY, 0, 0, 8]);
        AssertMemoryContents(Z80.Registers.HL.ToUShort(), [6, 7, 8]);
        AssertWordInMemory("RECORD_RECEIVER.HANDSHAKE_MSG_SIZE", 8);

        Run("RECORD_RECEIVER.UPDATE");
        AssertA("RECORD_RECEIVER.ERROR_FULL_HANDSHAKE_MESSAGE");
        AssertBC(4);
        Assert.That(Z80.Registers.E, Is.EqualTo(TLS_HANDSHAKE_TYPE_DUMMY_2));
        AssertMemoryContents(symbols["RECORD_RECEIVER.HANDSHAKE_HEADER"], [TLS_HANDSHAKE_TYPE_DUMMY_2, 0, 0, 4]);
        AssertMemoryContents(Z80.Registers.HL.ToUShort(), [1, 2, 3, 4]);
        AssertWordInMemory("RECORD_RECEIVER.HANDSHAKE_MSG_SIZE", 4);

        Run("RECORD_RECEIVER.UPDATE");
        AssertA("RECORD_RECEIVER.ERROR_FULL_HANDSHAKE_MESSAGE");
        AssertBC(7);
        Assert.That(Z80.Registers.E, Is.EqualTo(TLS_HANDSHAKE_TYPE_DUMMY));
        AssertMemoryContents(symbols["RECORD_RECEIVER.HANDSHAKE_HEADER"], [TLS_HANDSHAKE_TYPE_DUMMY, 0, 0, 7]);
        AssertMemoryContents(Z80.Registers.HL.ToUShort(), [1, 2, 3, 4, 5, 6, 7]);
        AssertWordInMemory("RECORD_RECEIVER.HANDSHAKE_MSG_SIZE", 7);

        Run("RECORD_RECEIVER.UPDATE");
        AssertA("RECORD_RECEIVER.ERROR_SPLIT_HANDSHAKE_FIRST");
        AssertBC(5);
        Assert.That(Z80.Registers.E, Is.EqualTo(TLS_HANDSHAKE_TYPE_DUMMY_2));
        AssertMemoryContents(symbols["RECORD_RECEIVER.HANDSHAKE_HEADER"], [TLS_HANDSHAKE_TYPE_DUMMY_2, 0, 0, 8]);
        AssertMemoryContents(Z80.Registers.HL.ToUShort(), [1, 2, 3, 4, 5]);
        AssertWordInMemory("RECORD_RECEIVER.HANDSHAKE_MSG_SIZE", 8);

        Run("RECORD_RECEIVER.UPDATE");
        AssertA("RECORD_RECEIVER.ERROR_SPLIT_HANDSHAKE_LAST");
        AssertBC(3);
        Assert.That(Z80.Registers.E, Is.EqualTo(TLS_HANDSHAKE_TYPE_DUMMY_2));
        AssertMemoryContents(symbols["RECORD_RECEIVER.HANDSHAKE_HEADER"], [TLS_HANDSHAKE_TYPE_DUMMY_2, 0, 0, 8]);
        AssertMemoryContents(Z80.Registers.HL.ToUShort(), [6, 7, 8]);
        AssertWordInMemory("RECORD_RECEIVER.HANDSHAKE_MSG_SIZE", 8);

        Run("RECORD_RECEIVER.UPDATE");
        AssertA("RECORD_RECEIVER.ERROR_NO_CHANGE");
    }
}
