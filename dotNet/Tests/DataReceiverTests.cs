using Konamiman.Nestor80.Assembler;
using Konamiman.Nestor80.Linker;
using Konamiman.PocketZ80;
using NUnit.Framework;
using System.Collections;
using System.Reflection;

namespace Konamiman.TLSforZ80.Tests;

public class DataReceiverTests
{
    const int BUFFER_IN = 0x8000;
    const int BUFFER_OUT = 0xC000;
    const byte TLS_RECORD_TYPE_ALERT = 21;

    private static Z80Processor Z80;

    private static Dictionary<string, ushort> symbols = [];

    [SetUp]
    public void SetUp()
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

        SetupMocks();
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

    private void SetupMocks()
    {
        tcpConnectionIsRemotelyClosed = false;

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
    public void AssertReceiveAlertRecord()
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
