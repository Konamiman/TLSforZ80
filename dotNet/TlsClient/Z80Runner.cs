using Konamiman.Nestor80.Assembler;
using Konamiman.PocketZ80;
using System.Reflection;

namespace Konamiman.TLSforZ80.TlsClient;

internal class Z80Runner
{
    private static Z80Processor Z80;

    private static Dictionary<string, ushort> symbols = [];

    public static void Init()
    {
        Z80 = new Z80Processor();

        var assemblyAddress = 0x100;
        var z80Codedir = Path.GetFullPath(" ../../../../../../../z80", Path.GetDirectoryName(Assembly.GetExecutingAssembly().Location));
        var files = Directory.GetFiles(z80Codedir, "*.asm");

        foreach(var file in files) {
            var z80SourceCode = $"  org {assemblyAddress:X}h\r\n" + File.ReadAllText(file);

            var assemblyResult = AssemblySourceProcessor.Assemble(z80SourceCode, new AssemblyConfiguration() {
                BuildType = BuildType.Absolute
            });

            if(assemblyResult.HasErrors) {
                var errorString = string.Join("\r\n", assemblyResult.Errors.Select(e => $"{e.LineNumber}: {e.Message}").ToArray());
                throw new Exception($"Error assembling file {Path.GetFileName(file)}:\r\n\r\n" + errorString);
            }

            var ms = new MemoryStream();
            var size = OutputGenerator.GenerateAbsolute(assemblyResult, ms);

            Array.Copy(ms.ToArray(), 0, Z80.Memory, assemblyAddress, size);
            assemblyAddress += size;

            symbols = new[] { symbols, assemblyResult.Symbols.ToDictionary(s => s.Name, s => s.Value) }.SelectMany(x => x).ToDictionary();
        }
    }

    public static byte GetFoobar()
    {
        Z80.Reset();
        Z80.Start(symbols["FOOBAR.DO"]);
        Z80.Start(symbols["FIZZBUZZ.DO"]);
        return (byte)(Z80.A + Z80.B);
    }
}