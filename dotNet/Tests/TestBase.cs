using Konamiman.Nestor80.Assembler;
using Konamiman.Nestor80.Linker;
using Konamiman.Z80dotNet;
using Konamiman.ZWatcher;
using NUnit.Framework;
using System.Collections;
using System.Reflection;

namespace Konamiman.TLSforZ80.Tests;

public abstract class TestBase
{
    protected const byte TLS_RECORD_TYPE_CHANGE_CIHPER_SPEC = 20;
    protected const byte TLS_RECORD_TYPE_ALERT = 21;
    protected const byte TLS_RECORD_TYPE_HANDSHAKE = 22;
    protected const byte TLS_RECORD_TYPE_APP_DATA = 23;
    protected const byte TLS_RECORD_TYPE_DUMMY = 99;
    protected const byte TLS_HANDSHAKE_TYPE_DUMMY = 199;
    protected const byte TLS_HANDSHAKE_TYPE_DUMMY_2 = 200;

    protected static Z80Processor Z80;
    protected static Z80Watcher watcher = null;

    protected Dictionary<string, ushort> symbols = [];
    protected byte encryptedRecordType;
    protected bool badAuthTag;
    protected bool recordAllZeros;
    protected byte[] z80ProgramBytes;
    protected int? outputBufferSize = null;

    [OneTimeSetUp]
    protected void OneTimeSetUp()
    {
        Z80 = new Z80Processor();
        Z80.AutoStopOnRetWithStackEmpty = true;
        symbols.Clear();

        var z80Codedir = Path.GetFullPath(" ../../../../../../../z80", Path.GetDirectoryName(Assembly.GetExecutingAssembly().Location));
        var files = Directory.GetFiles(z80Codedir, "*.asm");
        var linkingSequence = new List<ILinkingSequenceItem>() {
            new SetCodeBeforeDataMode(),
            new SetCodeSegmentAddress() { Address = 0x100 }
        };
        var tempFiles = new List<(string, FileStream)>();

        //We need aes.asm to be assembled first
        files = files.OrderBy(x => Path.GetFileNameWithoutExtension(x) == "aes" ? "a" : Path.GetFileNameWithoutExtension(x)).ToArray();

        List<(string, ushort)> predefinedSymbols = [("DEBUGGING", 0xFFFF)];
        if(outputBufferSize.HasValue) {
            predefinedSymbols.Add(("TLS_CONNECTION.OUTPUT_DATA_BUFFER_LENGTH", outputBufferSize.Value.ToUShort()));
        }
        foreach(var file in files) {
            var assemblyResult = AssemblySourceProcessor.Assemble(File.ReadAllText(file), new AssemblyConfiguration() {
                BuildType = BuildType.Relocatable,
                GetStreamForInclude = fileName => File.OpenRead(Path.Combine(Path.GetDirectoryName(file), fileName)),
                PredefinedSymbols = predefinedSymbols.ToArray()
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
        z80ProgramBytes = File.ReadAllBytes(outputFile);
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

        if(watcher is not null) {
            watcher.Dispose();
        }
        watcher = new Z80Watcher(Z80);
        foreach(var symbol in symbols) {
            watcher.Symbols.Add(symbol.Key, symbol.Value);
        }
    }

    private byte[][] _receivedTcpData;
    protected byte[][] ReceivedTcpData
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

    protected IEnumerator receivedTcpDataEnumerator;
    protected bool hasMoreReceivedTcpData;
    protected byte[] tcpDataRemainingFromPreviousReceive = null;
    protected bool tcpConnectionIsRemotelyClosed;
    protected bool tcpConnectionIsLocallyClosed;

    protected List<byte> tcpDataSent = [];

    [SetUp]
    public virtual void SetUp()
    {
        tcpConnectionIsRemotelyClosed = false;
        tcpConnectionIsLocallyClosed = false;
        ReceivedTcpData = [];
        tcpDataSent.Clear();
        hasMoreReceivedTcpData = false;
        tcpDataRemainingFromPreviousReceive = null;
        badAuthTag = false;
        recordAllZeros = false;

        Z80.Memory.SetContents(0x100, z80ProgramBytes);
        watcher.RemoveAllWatches();

        watcher
            .BeforeFetchingInstructionAt("DATA_TRANSPORT.HAS_IN_DATA")
            .Do(context => {
                context.Z80.Registers.CF = hasMoreReceivedTcpData || tcpDataRemainingFromPreviousReceive != null ? 1 : 0;
            })
            .ExecuteRet();

        watcher
            .BeforeFetchingInstructionAt("DATA_TRANSPORT.IS_REMOTELY_CLOSED")
            .Do(context => {
                context.Z80.Registers.CF = tcpConnectionIsRemotelyClosed ? 1 : 0;
            })
            .ExecuteRet();

        watcher
            .BeforeFetchingInstructionAt("DATA_TRANSPORT.RECEIVE")
            .Do (context => {
                var requestedLength = context.Z80.Registers.BC.ToUShort();
                if(tcpDataRemainingFromPreviousReceive != null) {
                    if(requestedLength >= tcpDataRemainingFromPreviousReceive.Length) {
                        context.Z80.Memory.SetContents(context.Z80.Registers.HL.ToUShort(), tcpDataRemainingFromPreviousReceive);
                        context.Z80.Registers.BC = tcpDataRemainingFromPreviousReceive.Length.ToShort();
                        tcpDataRemainingFromPreviousReceive = null;
                    }
                    else {
                        context.Z80.Memory.SetContents(context.Z80.Registers.HL.ToUShort(), tcpDataRemainingFromPreviousReceive, 0, requestedLength);
                        context.Z80.Registers.BC = requestedLength.ToShort();
                        tcpDataRemainingFromPreviousReceive = tcpDataRemainingFromPreviousReceive.Skip(requestedLength).ToArray();
                    }
                }
                else if(hasMoreReceivedTcpData) {
                    var data = (byte[])receivedTcpDataEnumerator.Current;
                    if(requestedLength >= data.Length) {
                        context.Z80.Memory.SetContents(context.Z80.Registers.HL.ToUShort(), data);
                        context.Z80.Registers.BC = data.Length.ToShort();
                    }
                    else {
                        context.Z80.Memory.SetContents(context.Z80.Registers.HL.ToUShort(), data, 0, requestedLength);
                        context.Z80.Registers.BC = requestedLength.ToShort();
                        tcpDataRemainingFromPreviousReceive = data.Skip(requestedLength).ToArray();
                    }
                    hasMoreReceivedTcpData = receivedTcpDataEnumerator.MoveNext();
                }
                else {
                    context.Z80.Registers.BC = 0;
                }
            })
            .ExecuteRet();

        watcher
            .BeforeFetchingInstructionAt("RECORD_ENCRYPTION.DECRYPT")
            .Do(context => {
                if(badAuthTag) {
                    context.Z80.Registers.A = 1; //"Bad auth tag" error
                }
                else if(recordAllZeros) {
                    context.Z80.Registers.A = 2; //"Record is all zeros" error
                }
                else {
                    // Simulate "decryption" by simply removing last data byte and setting the high byte of all the content
                    var data = context.Z80.Memory.GetContents(context.Z80.Registers.HL.ToUShort(), context.Z80.Registers.BC.ToUShort());
                    data = data.Select(x => (byte)(x | 0x80)).ToArray();
                    context.Z80.Memory.SetContents(context.Z80.Registers.DE.ToUShort(), data, 0, data.Length - 1);

                    context.Z80.Registers.A = 0;
                    context.Z80.Registers.BC = (short)(data.Length - 1);
                    context.Z80.Registers.D = encryptedRecordType;
                }
            })
            .ExecuteRet();

        watcher
            .BeforeFetchingInstructionAt("DATA_TRANSPORT.SEND")
            .Do(context => {
                    tcpDataSent.AddRange(context.Z80.Memory.GetContents(context.Z80.Registers.HL.ToUShort(), context.Z80.Registers.BC.ToUShort()));
                    context.Z80.Registers.CF = 0; // Alway asssume success
                })
            .ExecuteRet();

        watcher
            .BeforeFetchingInstructionAt("DATA_TRANSPORT.CLOSE")
            .Do(context => {
                tcpConnectionIsLocallyClosed = true;
            })
            .ExecuteRet();

        Z80.Reset();
        Z80.Registers.HL = 0x8000.ToShort();
        Z80.Registers.BC = 1024;
        Run("RECORD_RECEIVER.INIT");
    }

    [TearDown]
    public virtual void TearDown()
    {
        watcher.RemoveAllWatches();
        outputBufferSize = null;
    }

    protected void AssertMemoryContents(int address, byte[] expectedContents)
    {
        Assert.That(Z80.Memory.GetContents(address, expectedContents.Length), Is.EqualTo(expectedContents));
    }

    protected void AssertMemoryContents(string symbol, byte[] expectedContents)
    {
        Assert.That(Z80.Memory.GetContents(symbols[symbol], expectedContents.Length), Is.EqualTo(expectedContents));
    }

    protected byte[] ReadFromMemory(int address, int length)
    {
        return Z80.Memory.GetContents(address, length);
    }

    protected void WriteToMemory(int address, byte[] contents)
    {
        Z80.Memory.SetContents(address, contents);
    }

    protected void WriteWordToMemory(string symbol, ushort value, bool highEndian = false)
    {
        WriteWordToMemory(symbols[symbol], value, highEndian);
    }

    protected void WriteWordToMemory(int address, ushort value, bool highEndian = false)
    {
        if(highEndian) {
            Z80.Memory[address] = (byte)(value >> 8);
            Z80.Memory[address + 1] = (byte)(value & 0xFF);
        }
        else {
            Z80.Memory[address] = (byte)(value & 0xFF);
            Z80.Memory[address + 1] = (byte)(value >> 8);
        }
    }

    protected void AssertCarrySet()
    {
        Assert.That(Z80.Registers.CF.Value, Is.EqualTo(1));
    }

    protected void AssertCarryReset()
    {
        Assert.That(Z80.Registers.CF.Value, Is.EqualTo(0));
    }

    protected void AssertBC(int value)
    {
        Assert.That(Z80.Registers.BC.ToUShort(), Is.EqualTo(value));
    }

    protected void AssertA(string errorCodeName)
    {
        Assert.That(Z80.Registers.A, Is.EqualTo(symbols[errorCodeName]));
    }

    protected void AssertA(int value)
    {
        Assert.That(Z80.Registers.A, Is.EqualTo(value));
    }

    protected void AssertWordInMemory(string addressName, int expected)
    {
        Assert.That(GetWordFromMemory(addressName), Is.EqualTo(expected));
    }

    protected int GetWordFromMemory(string addressName)
    {
        var address = symbols[addressName];
        return Z80.Memory[address] + (Z80.Memory[address + 1] << 8);
    }

    protected void AssertByteInMemory(string addressName, int expected)
    {
        Assert.That(Z80.Memory[symbols[addressName]], Is.EqualTo(expected));
    }

    protected void Run(string symbol)
    {
        Run(symbols[symbol]);
    }

    protected void Run(ushort address)
    {
        Z80.Registers.SP = 0xFFFF.ToShort();
        Z80.Registers.PC = address;
        Z80.Continue();
    }

    // Z80.NET does not honor the AutoStopOnRetWithStackEmpty property when ExecuteRet is invoked,
    // only when an actual RET instruction is executed. Thus when we are directly executing a routine
    // that gets completely mocked (so no actual RET instruction is executed), we need to execute it
    // indirectly, via CALL + RET. Our code starts at 100h so we just put the CALL instruction at address 0.
    protected void RunAsCall(string symbol)
    {
        Z80.Memory[0] = 0xCD; // CALL
        WriteWordToMemory(1, symbols[symbol]);
        Z80.Memory[3] = 0xC9; // RET

        Run(0);
    }

    protected void ReassembleWithDifferentOutputBufferSize(int size)
    {
        outputBufferSize = size;
        OneTimeSetUp();
        SetUp();
    }
}
