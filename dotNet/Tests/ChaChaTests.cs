using Konamiman.PocketZ80;
using NUnit.Framework;

namespace Konamiman.TLSforZ80.Tests;

internal class ChaChaTests : TestBase
{
    [Test]
    public void Poly1305_WithTestVector_ProducesCorrectTag()
    {
        // Test data from RFC 8439
        byte[] key = [
            0x85, 0xd6, 0xbe, 0x78, 0x57, 0x55, 0x6d, 0x33,
            0x7f, 0x44, 0x52, 0xfe, 0x42, 0xd5, 0x06, 0xa8,
            0x01, 0x03, 0x80, 0x8a, 0xfb, 0x0d, 0xb2, 0xfd,
            0x4a, 0xbf, 0xf6, 0xaf, 0x41, 0x49, 0xf5, 0x1b
        ];

        byte[] message = System.Text.Encoding.ASCII.GetBytes(
            "Cryptographic Forum Research Group");

        // Expected tag from RFC 8439
        byte[] expectedTag = [
            0xa8, 0x06, 0x1d, 0xc1, 0x30, 0x51, 0x36, 0xc6,
            0xc2, 0x2b, 0x8b, 0xaf, 0x0c, 0x01, 0x27, 0xa9
        ];

        // Write test data to memory
        WriteToMemory(0x8000, key);        // Key at 8000h
        WriteToMemory(0x8020, message);    // Message at 8020h
        WriteToMemory(0x8040, new byte[16]); // Tag buffer at 8040h

        // Initialize Poly1305 with the key
        Z80.Registers.HL = 0x8000.ToShort();
        Run("POLY1305.INIT");

        // Process the message
        Z80.Registers.IX = 0x8020.ToShort(); // Message pointer
        Z80.Registers.BC = message.Length.ToShort(); // Message length
        Run("POLY1305.AUTHTAG");

        // Get the final tag
        Z80.Registers.HL = 0x8040.ToShort(); // Tag buffer
        Run("POLY1305.FINISH");

        // Verify the tag
        AssertMemoryContents(0x8040, expectedTag);
    }

    [Test]
    public void TestModulo130Minus5()
    {
        var num = ParseHexString("21dcc992d0c659ba4036f65bb7f88562ae59b32c2b3b8f7efc8b00f78e548a26");
        var expectedResult = ParseHexString("2d8adaf23b0337fa7cccfb4ea344b30de");

        WriteToMemory(0x8000, num);
        Z80.Registers.HL = 0x8000.ToShort();
        Z80.Registers.DE = 0x9000.ToShort();
        Z80.Registers.BC = num.Length.ToShort();

        Run("POLY1305.Modulo2_130_5");

        var x = ReadFromMemory(0x9000, 17);
        AssertMemoryContents(0x9000, expectedResult);
    }

    static byte[] ParseHexString(string hex)
    {
        if(hex.Length % 2 != 0)
            hex = "0" + hex;

        byte[] result = new byte[hex.Length / 2];

        for(int i = 0; i < result.Length; i++) {
            string byteString = hex.Substring(i * 2, 2);
            result[i] = Convert.ToByte(byteString, 16);
        }

        return result;
    }

    static string ToHexString(byte[] bytes)
    {
        return BitConverter.ToString(bytes).Replace("-", "");
    }
}
