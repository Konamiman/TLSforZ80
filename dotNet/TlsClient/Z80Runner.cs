using Konamiman.Nestor80.Assembler;
using Konamiman.Nestor80.Linker;
using Konamiman.PocketZ80;
using System.Reflection;

namespace Konamiman.TLSforZ80.TlsClient;

internal class Z80Runner
{
    const int BUFFER_IN = 0x8000;
    const int BUFFER_OUT = 0xC000;

    private static Z80Processor Z80;

    private static Dictionary<string, ushort> symbols = [];

    public static void Init()
    {
        Z80 = new Z80Processor();

        var z80Codedir = Path.GetFullPath(" ../../../../../../../z80", Path.GetDirectoryName(Assembly.GetExecutingAssembly().Location));
        var files = Directory.GetFiles(z80Codedir, "*.asm");
        var linkingSequence = new List<ILinkingSequenceItem>() {
            new SetCodeBeforeDataMode(),
            new SetCodeSegmentAddress() { Address = 0x100 }
        };
        var tempFiles = new List<(string, FileStream)>();

        foreach(var file in files) {
            var assemblyResult = AssemblySourceProcessor.Assemble(File.ReadAllText(file), new AssemblyConfiguration() {
                BuildType = BuildType.Relocatable,
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

    public static byte GetFoobar()
    {
        Z80.Reset();
        Z80.Start(symbols["FOOBAR.DO"]);
        Z80.Start(symbols["FIZZBUZZ.DO"]);
        return (byte)(Z80.A + Z80.B);
    }

    public static byte[] CalculateSHA256(byte[] data)
    {
        Z80.A = 3;
        Z80.HL = unchecked((short)BUFFER_IN);
        Z80.BC = (short)data.Length;
        Z80.DE = unchecked((short)BUFFER_OUT);

        SetInputBuffer(data);
        Run("SHA256.RUN");
        return GetOutputBuffer(32);
    }

    public static byte[] CalculateHMAC(byte[] key, byte[] data)
    {
        Z80.A = 3;
        Z80.IX = unchecked((short)BUFFER_IN);
        Z80.BC = (short)data.Length;
        Z80.IY = unchecked((short)(BUFFER_IN+data.Length));
        Z80.HL = (short)key.Length;
        Z80.DE = unchecked((short)BUFFER_OUT);

        SetInputBuffer(data);
        SetInputBuffer(key, BUFFER_IN+data.Length);
        Run("HMAC.RUN");
        return GetOutputBuffer(32);
    }

    public static byte[][] ComputeHandshakeKeys(byte[] sharedSecret, byte[] handshakeHash)
    {
        return ComputeKeys(sharedSecret, handshakeHash);
    }

    public static byte[][] ComputeApplicationKeys(byte[] handshakeHash)
    {
        return ComputeKeys(null, handshakeHash);
    }

    private static byte[][] ComputeKeys(byte[] sharedSecret, byte[] handshakeHash)
    {
        Z80.HL = unchecked((short)BUFFER_IN);
        SetInputBuffer(handshakeHash);
        Z80.IY = unchecked((short)BUFFER_OUT);
        if(sharedSecret != null) {
            Z80.IX = unchecked((short)(BUFFER_IN + handshakeHash.Length));
            SetInputBuffer(sharedSecret, BUFFER_IN + handshakeHash.Length);
            Z80.Start(symbols["HKDF.DERIVE_HS_KEYS"]);
        }
        else {
            Z80.Start(symbols["HKDF.DERIVE_AP_KEYS"]);
        }

        return [
            GetOutputBuffer(32, symbols["HKDF.CLIENT_SECRET"]),
            GetOutputBuffer(32, symbols["HKDF.SERVER_SECRET"]),
            GetOutputBuffer(16, symbols["HKDF.CLIENT_KEY"]),
            GetOutputBuffer(16, symbols["HKDF.SERVER_KEY"]),
            GetOutputBuffer(12, symbols["HKDF.CLIENT_IV"]),
            GetOutputBuffer(12, symbols["HKDF.SERVER_IV"])
        ];
    }

    private static void SetInputBuffer(byte[] data, int address = BUFFER_IN)
    {
        if(data.Length > 0) {
            Array.Copy(data, 0, Z80.Memory, address, data.Length);
        }
    }

    private static byte[] GetOutputBuffer(int length, int address = BUFFER_OUT)
    {
        return Z80.Memory.Skip(address).Take(length).ToArray();
    }

    private static void Run(string symbol)
    {
        Z80.Start(symbols[symbol]);
    }
}