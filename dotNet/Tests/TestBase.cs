using Konamiman.Nestor80.Assembler;
using Konamiman.Nestor80.Linker;
using Konamiman.PocketZ80;
using NUnit.Framework;
using System.Collections;
using System.Reflection;

namespace Konamiman.TLSforZ80.Tests;

public abstract class TestBase
{
    protected const byte TLS_RECORD_TYPE_ALERT = 21;
    protected const byte TLS_RECORD_TYPE_HANDSHAKE = 22;
    protected const byte TLS_RECORD_TYPE_APP_DATA = 23;
    protected const byte TLS_RECORD_TYPE_DUMMY = 99;
    protected const byte TLS_HANDSHAKE_TYPE_DUMMY = 199;
    protected const byte TLS_HANDSHAKE_TYPE_DUMMY_2 = 200;

    protected static Z80Processor Z80;

    protected static Dictionary<string, ushort> symbols = [];
    protected byte encryptedRecordType;
    protected bool badAuthTag;
    protected bool recordAllZeros;

    [OneTimeSetUp]
    protected void OneTimeSetUp()
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
                GetStreamForInclude = fileName => File.OpenRead(Path.Combine(Path.GetDirectoryName(file), fileName)),
                PredefinedSymbols = [("DEBUGGING", 0xFFFF)]
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

    protected List<byte> tcpDataSent = [];

    [SetUp]
    public virtual void SetUp()
    {
        tcpConnectionIsRemotelyClosed = false;
        ReceivedTcpData = [];
        tcpDataSent.Clear();
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
            }
            else {
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
        Z80.ExecutionHooks[symbols["DATA_TRANSPORT.SEND"]] = () => {
            tcpDataSent.AddRange(ReadFromMemory(Z80.HL.ToUShort(), Z80.BC.ToUShort()));
            Z80.CF = 0; // Alway asssume success
            Z80.ExecuteRet();
        };

        Z80.HL = 0x8000.ToShort();
        Z80.BC = 1024;
        Run("RECORD_RECEIVER.INIT");
    }

    protected void AssertMemoryContents(int address, byte[] expectedContents)
    {
        Assert.That(ReadFromMemory(address, expectedContents.Length), Is.EqualTo(expectedContents));
    }

    protected byte[] ReadFromMemory(int address, int length)
    {
        return Z80.Memory.Skip(address).Take(length).ToArray();
    }

    protected void WriteToMemory(int address, byte[] contents)
    {
        Array.Copy(contents, 0, Z80.Memory, address, contents.Length);
    }

    protected void AssertCarrySet()
    {
        Assert.That(Z80.CF, Is.EqualTo(1));
    }

    protected void AssertCarryReset()
    {
        Assert.That(Z80.CF, Is.EqualTo(0));
    }

    protected void AssertBC(int value)
    {
        Assert.That(Z80.BC.ToUShort(), Is.EqualTo(value));
    }

    protected void AssertA(string errorCodeName)
    {
        Assert.That(Z80.A, Is.EqualTo(symbols[errorCodeName]));
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

    protected static void Run(string symbol)
    {
        Z80.Start(symbols[symbol]);
    }
}
