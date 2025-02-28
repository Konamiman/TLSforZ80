using Konamiman.Nestor80.Assembler;
using Konamiman.Nestor80.Linker;
using Konamiman.PocketZ80;
using NUnit.Framework;
using System.Reflection;

namespace Konamiman.TLSforZ80.Tests;

public class DataReceiverTests
{
    const int BUFFER_IN = 0x8000;
    const int BUFFER_OUT = 0xC000;

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
    }

    [Test]
    public void TestFoo()
    {
        Run("DATA_RECEIVER.UPDATE");
        Assert.That(Z80.B, Is.EqualTo(23));
    }

    private static void Run(string symbol)
    {
        Z80.Start(symbols[symbol]);
    }
}
