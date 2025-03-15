using Konamiman.Nestor80.Assembler;
using Konamiman.Nestor80.Linker;
using Konamiman.PocketZ80;
using NUnit.Framework;
using System.Collections;
using System.Reflection;

namespace Konamiman.TLSforZ80.Tests;

public class DataReceiverTests
{
    const byte TLS_RECORD_TYPE_ALERT = 21;
    const byte TLS_RECORD_TYPE_HANDSHAKE = 22;
    const byte TLS_RECORD_TYPE_APP_DATA = 23;
    const byte TLS_RECORD_TYPE_DUMMY = 99;
    const byte TLS_HANDSHAKE_TYPE_DUMMY = 199;
    const byte TLS_HANDSHAKE_TYPE_DUMMY_2 = 200;


    private static Z80Processor Z80;

    private static Dictionary<string, ushort> symbols = [];
    private byte encryptedRecordType;
    private bool badAuthTag;
    private bool recordAllZeros;

    [OneTimeSetUp]
    public void OneTimeSetUp()
    {
        Z80 = new Z80Processor();

        var z80Codedir = Path.GetFullPath(" ../../../../../../../z80", Path.GetDirectoryName(Assembly.GetExecutingAssembly().Location));
        var files = Directory.GetFiles(z80Codedir, "*.asm");
        var linkingSequence = new List<ILinkingSequenceItem>() {
            new SetCodeBeforeDataMode(),
            new SetCodeSegmentAddress() { Address = 0x100 }
        };
        var tempFiles = new List<(string, FileStream)>();

        //We need aes.asm to be assembled first
        files = files.OrderBy(x => Path.GetFileNameWithoutExtension(x) == "aes" ? "a" : Path.GetFileNameWithoutExtension(x)).ToArray();

        foreach(var file in files) {
            var assemblyResult = AssemblySourceProcessor.Assemble(File.ReadAllText(file), new AssemblyConfiguration() {
                BuildType = BuildType.Relocatable,
                GetStreamForInclude = fileName => File.OpenRead(Path.Combine(Path.GetDirectoryName(file), fileName))
            });

            if(assemblyResult.HasErrors) {
                var errorString = string.Join("\r\n", assemblyResult.Errors.Select(e => $"{e.LineNumber}: {e.Message}").ToArray());
                throw new Exception($"Error assembling file {Path.GetFileName(file)}:\r\n\r\n" + errorString);
            }

            assemblyResult.ProgramName = Path.GetFileNameWithoutExtension(file);
            var tempFile = Path.GetTempFileName();
            var tempFileStream = File.OpenWrite(tempFile);

            var size = OutputGenerator.GenerateRelocatable(assemblyResult, tempFileStream, true, true);
            tempFileStream.Close();
            linkingSequence.Add(new RelocatableFileReference() {
                FullName = tempFile,
                DisplayName = Path.GetFileName(file),
            });

            /*
            var x = new MemoryStream();
            var sw = new StreamWriter(x);
            ListingFileGenerator.GenerateListingFile(assemblyResult, sw, new ListingFileConfiguration() {
                MaxSymbolLength = 100
            });
            sw.Close();
            var l = Encoding.UTF8.GetString(x.ToArray());
            */
        }

        var config = new LinkingConfiguration() {
            LinkingSequenceItems = linkingSequence.ToArray(),
            OpenFile = file => { var stream = File.OpenRead(file); tempFiles.Add((file, stream)); return stream; }
        };

        var outputFile = Path.GetTempFileName();
        var outputStream = File.OpenWrite(outputFile);
        var linkingResult = RelocatableFilesProcessor.Link(config, outputStream);
        outputStream.Close();
        var outputBytes = File.ReadAllBytes(outputFile);
        Array.Copy(outputBytes, 0, Z80.Memory, 0x100, outputBytes.Length);

        var totalSize = linkingResult.ProgramsData.Sum(d => d.CodeSegmentSize);

        foreach(var programInfo in linkingResult.ProgramsData) {
            foreach(var symbol in programInfo.PublicSymbols) {
                symbols.Add(symbol.Key, symbol.Value);
            }
        }

        foreach(var file in tempFiles) {
            file.Item2.Close();
            File.Delete(file.Item1);
        }
    }

    private byte[][] _receivedTcpData;
    private byte[][] ReceivedTcpData
    {
        get
        {
            return _receivedTcpData;
        }
        set
        {
            _receivedTcpData = value;
            receivedTcpDataEnumerator = _receivedTcpData.GetEnumerator();
            receivedTcpDataEnumerator.Reset();
            hasMoreReceivedTcpData = receivedTcpDataEnumerator.MoveNext();
        }
    }

    private IEnumerator receivedTcpDataEnumerator;
    private bool hasMoreReceivedTcpData;
    private byte[] tcpDataRemainingFromPreviousReceive = null;
    private bool tcpConnectionIsRemotelyClosed;

    [SetUp]
    public void SetUp()
    {
        tcpConnectionIsRemotelyClosed = false;
        ReceivedTcpData = [];
        hasMoreReceivedTcpData = false;
        tcpDataRemainingFromPreviousReceive = null;
        badAuthTag = false;
        recordAllZeros = false;

        Z80.ExecutionHooks.Clear();
        Z80.ExecutionHooks[symbols["DATA_TRANSPORT.HAS_IN_DATA"]] = () => {
            Z80.CF = hasMoreReceivedTcpData || tcpDataRemainingFromPreviousReceive != null ? 1 : 0;
            Z80.ExecuteRet();
        };
        Z80.ExecutionHooks[symbols["DATA_TRANSPORT.IS_REMOTELY_CLOSED"]] = () => {
            Z80.CF = tcpConnectionIsRemotelyClosed ? 1 : 0;
            Z80.ExecuteRet();
        };
        Z80.ExecutionHooks[symbols["DATA_TRANSPORT.RECEIVE"]] = () => {
            var requestedLength = Z80.BC.ToUShort();
            if(tcpDataRemainingFromPreviousReceive != null) {
                if(requestedLength >= tcpDataRemainingFromPreviousReceive.Length) {
                    Array.Copy(tcpDataRemainingFromPreviousReceive, 0, Z80.Memory, Z80.HL.ToUShort(), tcpDataRemainingFromPreviousReceive.Length);
                    Z80.BC = tcpDataRemainingFromPreviousReceive.Length.ToShort();
                    tcpDataRemainingFromPreviousReceive = null;
                }
                else {
                    Array.Copy(tcpDataRemainingFromPreviousReceive, 0, Z80.Memory, Z80.HL.ToUShort(), requestedLength);
                    Z80.BC = requestedLength.ToShort();
                    tcpDataRemainingFromPreviousReceive = tcpDataRemainingFromPreviousReceive.Skip(requestedLength).ToArray();
                }
            }
            else if(hasMoreReceivedTcpData) {
                var data = (byte[])receivedTcpDataEnumerator.Current;
                if(requestedLength >= data.Length) {
                    Array.Copy(data, 0, Z80.Memory, Z80.HL.ToUShort(), data.Length);
                    Z80.BC = data.Length.ToShort();
                }
                else {
                    Array.Copy(data, 0, Z80.Memory, Z80.HL.ToUShort(), requestedLength);
                    Z80.BC = requestedLength.ToShort();
                    tcpDataRemainingFromPreviousReceive = data.Skip(requestedLength).ToArray();
                }
                hasMoreReceivedTcpData = receivedTcpDataEnumerator.MoveNext();
            } else {
                Z80.BC = 0;
            }
            Z80.ExecuteRet();
        };
        Z80.ExecutionHooks[symbols["RECORD_ENCRYPTION.DECRYPT"]] = () => {
            if(badAuthTag) {
                Z80.A = 1; //"Bad auth tag" error
            }
            else if(recordAllZeros) {
                Z80.A = 2; //"Record is all zeros" error
            }
            else {
                // Simulate "decryption" by simply removing last data byte and setting the high byte of all the content
                var data = Z80.Memory.Skip(Z80.HL.ToUShort()).Take(Z80.BC.ToUShort()).ToArray();
                data = data.Select(x => (byte)(x | 0x80)).ToArray();
                Array.Copy(data, 0, Z80.Memory, Z80.DE.ToUShort(), data.Length - 1);

                Z80.A = 0;
                Z80.BC = (short)(data.Length - 1);
                Z80.D = encryptedRecordType;
            }
            Z80.ExecuteRet();
        };

            Z80.HL = 0x8000.ToShort();
        Z80.BC = 1024;
        Run("DATA_RECEIVER.INIT");
    }

    [Test]
    public void TestTcpDataReception()
    {
        // Simple scenario: receive all the data

        ReceivedTcpData = [
            [1,2,3,4,5],
            [6,7,8,9,10]
        ];

        Run("DATA_TRANSPORT.HAS_IN_DATA");
        AssertCarrySet();

        Z80.HL = 0x8000.ToShort();
        Z80.BC = 5;
        Run("DATA_TRANSPORT.RECEIVE");
        AssertBC(5);
        AssertMemoryContents(0x8000, [1, 2, 3, 4, 5]);

        Run("DATA_TRANSPORT.HAS_IN_DATA");
        AssertCarrySet();

        Z80.HL = 0x8000.ToShort();
        Z80.BC = 5;
        Run("DATA_TRANSPORT.RECEIVE");
        AssertBC(5);
        AssertMemoryContents(0x8000, [6, 7, 8, 9, 10]);

        Run("DATA_TRANSPORT.HAS_IN_DATA");
        AssertCarryReset();

        Z80.HL = 0x8000.ToShort();
        Z80.BC = 5;
        Run("DATA_TRANSPORT.RECEIVE");
        AssertBC(0);

        // Receive data in chunks

        ReceivedTcpData = [
            [1,2,3,4,5],
            [6,7,8,9,10]
        ];

        Run("DATA_TRANSPORT.HAS_IN_DATA");
        AssertCarrySet();

        Z80.HL = 0x8000.ToShort();
        Z80.BC = 3;
        Run("DATA_TRANSPORT.RECEIVE");
        AssertBC(3);
        AssertMemoryContents(0x8000, [1, 2, 3]);

        Run("DATA_TRANSPORT.HAS_IN_DATA");
        AssertCarrySet();

        Z80.HL = 0x8000.ToShort();
        Z80.BC = 5;
        Run("DATA_TRANSPORT.RECEIVE");
        AssertBC(2);
        AssertMemoryContents(0x8000, [4, 5]);

        Run("DATA_TRANSPORT.HAS_IN_DATA");
        AssertCarrySet();

        Z80.HL = 0x8000.ToShort();
        Z80.BC = 2;
        Run("DATA_TRANSPORT.RECEIVE");
        AssertBC(2);
        AssertMemoryContents(0x8000, [6, 7]);

        Run("DATA_TRANSPORT.HAS_IN_DATA");
        AssertCarrySet();

        Z80.HL = 0x8000.ToShort();
        Z80.BC = 2;
        Run("DATA_TRANSPORT.RECEIVE");
        AssertBC(2);
        AssertMemoryContents(0x8000, [8, 9]);

        Run("DATA_TRANSPORT.HAS_IN_DATA");
        AssertCarrySet();

        Z80.HL = 0x8000.ToShort();
        Z80.BC = 2;
        Run("DATA_TRANSPORT.RECEIVE");
        AssertBC(1);
        AssertMemoryContents(0x8000, [10]);

        Run("DATA_TRANSPORT.HAS_IN_DATA");
        AssertCarryReset();

        Z80.HL = 0x8000.ToShort();
        Z80.BC = 5;
        Run("DATA_TRANSPORT.RECEIVE");
        AssertBC(0);
    }

    [Test]
    public void AssertNoChangeIfNoData()
    {
        ReceivedTcpData = [];
        Run("DATA_RECEIVER.UPDATE");
        AssertA("DATA_RECEIVER.ERROR_NO_CHANGE");
        Run("DATA_RECEIVER.UPDATE");
        AssertA("DATA_RECEIVER.ERROR_NO_CHANGE");
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

        Run("DATA_RECEIVER.UPDATE");
        AssertA("DATA_RECEIVER.ERROR_FULL_RECORD_AVAILABLE");
        AssertBC(4);
        AssertMemoryContents(Z80.HL.ToUShort(), [1, 2, 3, 4]);
        Assert.That(Z80.D, Is.EqualTo(TLS_RECORD_TYPE_ALERT));
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

        Run("DATA_RECEIVER.UPDATE");
        AssertA("DATA_RECEIVER.ERROR_NO_CHANGE");
        Run("DATA_RECEIVER.UPDATE");
        AssertA("DATA_RECEIVER.ERROR_NO_CHANGE");
        Run("DATA_RECEIVER.UPDATE");
        AssertA("DATA_RECEIVER.ERROR_NO_CHANGE");

        Run("DATA_RECEIVER.UPDATE");
        AssertA("DATA_RECEIVER.ERROR_FULL_RECORD_AVAILABLE");
        AssertBC(4);
        AssertMemoryContents(Z80.HL.ToUShort(), [1, 2, 3, 4]);
        Assert.That(Z80.D, Is.EqualTo(TLS_RECORD_TYPE_ALERT));
    }

    [Test]
    public void AssertErrorReceivedIfConnectionIsClosed()
    {
        tcpConnectionIsRemotelyClosed = true;
        ReceivedTcpData = [];

        Run("DATA_RECEIVER.UPDATE");
        AssertA("DATA_RECEIVER.ERROR_CONNECTION_CLOSED");
        Run("DATA_RECEIVER.UPDATE");
        AssertA("DATA_RECEIVER.ERROR_CONNECTION_CLOSED");
    }

    [Test]
    public void AssertErrorReceivedIfRecordIstooBig()
    {
        // First receive a record of exactly the buffer size

        Z80.HL = 0x8000.ToShort();
        Z80.BC = 10;
        Run("DATA_RECEIVER.INIT");

        ReceivedTcpData = [
            [
                TLS_RECORD_TYPE_ALERT,
                3, 3,
                0, 5,   //Length
                1, 2, 3, 4, 5
            ]
        ];

        Run("DATA_RECEIVER.UPDATE");
        AssertA("DATA_RECEIVER.ERROR_FULL_RECORD_AVAILABLE");
        AssertBC(5);
        AssertMemoryContents(Z80.HL.ToUShort(), [1, 2, 3, 4, 5]);
        Assert.That(Z80.D, Is.EqualTo(TLS_RECORD_TYPE_ALERT));

        // Now receive a record one byte too big

        Z80.HL = 0x8000.ToShort();
        Z80.BC = 9;
        Run("DATA_RECEIVER.INIT");

        ReceivedTcpData = [
            [
                TLS_RECORD_TYPE_ALERT,
                3, 3,
                0, 5,   //Length
                1, 2, 3, 4, 5
            ]
        ];

        Run("DATA_RECEIVER.UPDATE");
        AssertA("DATA_RECEIVER.ERROR_RECORD_TOO_LONG");
    }

    [Test]
    public void AssertErrorReceivedIfRecordIsOver16K()
    {
        Z80.HL = 0x8000.ToShort();
        Z80.BC = 20000;
        Run("DATA_RECEIVER.INIT");

        var recordContent = Enumerable.Repeat<byte>(34, 0x4100).ToArray();

        ReceivedTcpData = [
            [
                TLS_RECORD_TYPE_ALERT,
                3, 3,
                0x41, 0,   //Length: 16384+256
                ..recordContent
            ]
        ];

        Run("DATA_RECEIVER.UPDATE");
        AssertA("DATA_RECEIVER.ERROR_FULL_RECORD_AVAILABLE");
        AssertBC(0x4100);
        AssertMemoryContents(Z80.HL.ToUShort(), recordContent);
        Assert.That(Z80.D, Is.EqualTo(TLS_RECORD_TYPE_ALERT));

        ReceivedTcpData = [
            [
                TLS_RECORD_TYPE_ALERT,
                3, 3,
                0x41, 1,   //Length: 16384+256+1
                ..recordContent,
                34
            ]
        ];

        Run("DATA_RECEIVER.UPDATE");
        AssertA("DATA_RECEIVER.ERROR_RECORD_OVER_16K");
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

        Run("DATA_RECEIVER.UPDATE");
        AssertA("DATA_RECEIVER.ERROR_BAD_AUTH_TAG");
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

        Run("DATA_RECEIVER.UPDATE");
        AssertA("DATA_RECEIVER.ERROR_MSG_ALL_ZEROS");
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

        Run("DATA_RECEIVER.UPDATE");
        AssertA("DATA_RECEIVER.ERROR_FULL_RECORD_AVAILABLE");
        Assert.That(Z80.D, Is.EqualTo(TLS_RECORD_TYPE_DUMMY));
        AssertBC(7);
        AssertMemoryContents(Z80.HL.ToUShort(), [0x81, 0x82, 0x83, 0x84, 0x85, 0x86, 0x87]);
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

        Run("DATA_RECEIVER.UPDATE");
        AssertA("DATA_RECEIVER.ERROR_HANDSHAKE_MSG_TOO_LONG");
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

        Run("DATA_RECEIVER.UPDATE");
        AssertA("DATA_RECEIVER.ERROR_FULL_HANDSHAKE_MESSAGE");
        AssertBC(5);
        Assert.That(Z80.E, Is.EqualTo(TLS_HANDSHAKE_TYPE_DUMMY));
        AssertMemoryContents(Z80.HL.ToUShort(), [1, 2, 3, 4, 5]);
        AssertMemoryContents(symbols["DATA_RECEIVER.HANDSHAKE_HEADER"], [TLS_HANDSHAKE_TYPE_DUMMY, 0, 0, 5]);

        Run("DATA_RECEIVER.UPDATE");
        AssertA("DATA_RECEIVER.ERROR_NO_CHANGE");
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

        Run("DATA_RECEIVER.UPDATE");
        AssertA("DATA_RECEIVER.ERROR_FULL_HANDSHAKE_MESSAGE");
        AssertBC(5);
        Assert.That(Z80.E, Is.EqualTo(TLS_HANDSHAKE_TYPE_DUMMY));
        AssertMemoryContents(symbols["DATA_RECEIVER.HANDSHAKE_HEADER"], [TLS_HANDSHAKE_TYPE_DUMMY, 0, 0, 5]);
        AssertMemoryContents(Z80.HL.ToUShort(), [1, 2, 3, 4, 5]);

        Run("DATA_RECEIVER.UPDATE");
        AssertA("DATA_RECEIVER.ERROR_FULL_HANDSHAKE_MESSAGE");
        AssertBC(3);
        Assert.That(Z80.E, Is.EqualTo(TLS_HANDSHAKE_TYPE_DUMMY_2));
        AssertMemoryContents(symbols["DATA_RECEIVER.HANDSHAKE_HEADER"], [TLS_HANDSHAKE_TYPE_DUMMY_2, 0, 0, 3]);
        AssertMemoryContents(Z80.HL.ToUShort(), [6, 7, 8]);

        Run("DATA_RECEIVER.UPDATE");
        AssertA("DATA_RECEIVER.ERROR_NO_CHANGE");
    }

    private void AssertMemoryContents(int address, byte[] expectedContents)
    {
        var actualContents = Z80.Memory.Skip(address).Take(expectedContents.Length).ToArray();
        Assert.That(actualContents, Is.EqualTo(expectedContents));
    }

    private void AssertCarrySet()
    {
        Assert.That(Z80.CF, Is.EqualTo(1));
    }

    private void AssertCarryReset()
    {
        Assert.That(Z80.CF, Is.EqualTo(0));
    }

    private void AssertBC(int value)
    {
        Assert.That(Z80.BC.ToUShort(), Is.EqualTo(value));
    }

    private void AssertA(string errorCodeName)
    {
        Assert.That(Z80.A, Is.EqualTo(symbols[errorCodeName]));
    }

    private static void Run(string symbol)
    {
        Z80.Start(symbols[symbol]);
    }
}
