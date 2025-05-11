using Konamiman.Nestor80.Assembler;
using Konamiman.Nestor80.Linker;
using Konamiman.PocketZ80;
using Konamiman.TLSforZ80.PocketZ80;
using System.Reflection;
using System.Text;

namespace Konamiman.TLSforZ80.TlsClient;

internal class Z80Runner
{
    const int BUFFER_IN = 0x8000;
    const int BUFFER_OUT = 0xA000;

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

        //We need aes.asm to be assembled first
        files = files.OrderBy(x => Path.GetFileNameWithoutExtension(x) == "aes" ? "a" : Path.GetFileNameWithoutExtension(x)).ToArray();

        foreach(var file in files) {
            var assemblyResult = AssemblySourceProcessor.Assemble(File.ReadAllText(file), new AssemblyConfiguration() {
                BuildType = BuildType.Relocatable,
                GetStreamForInclude = fileName => File.OpenRead(Path.Combine(Path.GetDirectoryName(file), fileName)),
                //PredefinedSymbols = [("DEBUGGING", 0xFFFF)]
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
            Run("HKDF.DERIVE_HS_KEYS");
        }
        else {
            Run("HKDF.DERIVE_AP_KEYS");
        }

        return [
            GetOutputBuffer(16, symbols["HKDF.CLIENT_KEY"]),
            GetOutputBuffer(16, symbols["HKDF.SERVER_KEY"]),
            GetOutputBuffer(12, symbols["HKDF.CLIENT_IV"]),
            GetOutputBuffer(12, symbols["HKDF.SERVER_IV"])
        ];
    }

    public static byte[] ComputeFinishedKey(bool ofServer)
    {
        Z80.CF = ofServer ? 1 : 0;
        Z80.DE = unchecked((short)BUFFER_OUT);
        Run("HKDF.COMPUTE_FINISHED_KEY");
        return GetOutputBuffer(32);
    }

    public static byte[][] UpdateTrafficKey(bool ofServer)
    {
        Z80.CF = ofServer ? 1 : 0;
        Run("HKDF.UPDATE_TRAFFIC_KEY");
        return ofServer ? [
            GetOutputBuffer(16, symbols["HKDF.SERVER_KEY"]),
            GetOutputBuffer(12, symbols["HKDF.SERVER_IV"])
        ] : [
            GetOutputBuffer(16, symbols["HKDF.CLIENT_KEY"]),
            GetOutputBuffer(12, symbols["HKDF.CLIENT_IV"])
        ];
    }

    public static byte[][] AesGcmEncrypt(byte[] clientKey, byte[] clientNonce, byte[] contentToEncrypt, byte[] additionalData)
    {
        Z80.HL = unchecked((short)BUFFER_IN);
        Z80.DE = unchecked((short)(BUFFER_IN+16));
        Z80.BC = unchecked((short)(BUFFER_IN+16+12));
        SetInputBuffer(clientKey);
        SetInputBuffer(clientNonce, BUFFER_IN+16);
        SetInputBuffer(additionalData, BUFFER_IN + 16+12);
        Run("AES_GCM.INIT");

        Z80.HL = unchecked((short)BUFFER_IN);
        Z80.DE = unchecked((short)BUFFER_IN); //Encrypt in-place
        Z80.BC = (short)contentToEncrypt.Length;
        SetInputBuffer(contentToEncrypt);
        Run("AES_GCM.ENCRYPT");

        Z80.HL = unchecked((short)(BUFFER_OUT-16));
        Run("AES_GCM.FINISH");

        return [
            GetOutputBuffer(contentToEncrypt.Length, BUFFER_IN),
            GetOutputBuffer(16, BUFFER_OUT-16)
        ];
    }

    public static byte[][] AesGcmDecrypt(byte[] serverKey, byte[] serverNonce, byte[] cipherText, byte[] additionalData)
    {
        // Decrypt

        Z80.HL = unchecked((short)BUFFER_IN);
        Z80.DE = unchecked((short)(BUFFER_IN + 16));
        Z80.BC = unchecked((short)(BUFFER_IN + 16 + 12));
        SetInputBuffer(serverKey);
        SetInputBuffer(serverNonce, BUFFER_IN + 16);
        SetInputBuffer(additionalData, BUFFER_IN + 16 + 12);
        Run("AES_GCM.INIT");

        Z80.HL = unchecked((short)(BUFFER_IN + 16 + 12 + 5));
        Z80.DE = unchecked((short)BUFFER_OUT);
        Z80.BC = (short)cipherText.Length;
        SetInputBuffer(cipherText, BUFFER_IN + 16 + 12 + 5);
        Run("AES_GCM.DECRYPT");

        // Calculate auth tag

        Z80.HL = unchecked((short)BUFFER_IN);
        Z80.DE = unchecked((short)(BUFFER_IN + 16));
        Z80.BC = unchecked((short)(BUFFER_IN + 16 + 12));
        Run("AES_GCM.INIT");

        Z80.IX = unchecked((short)(BUFFER_IN + 16 + 12 + 5));
        Z80.BC = (short)cipherText.Length;
        Run("AES_GCM.AUTHTAG");

        Z80.HL = unchecked((short)(BUFFER_IN - 16));
        Run("AES_GCM.FINISH");

        // Return data

        return [
            GetOutputBuffer(cipherText.Length, BUFFER_OUT),
            GetOutputBuffer(16, BUFFER_IN-16)
        ];
    }

    public static void InitRecordEncryption(byte[] key, byte[] iv, bool forServer)
    {
        Z80.HL = unchecked((short)BUFFER_IN);
        Z80.DE = unchecked((short)(BUFFER_IN+16));
        Z80.CF = forServer ? 1 : 0;
        SetInputBuffer(key, BUFFER_IN);
        SetInputBuffer(iv, BUFFER_IN+16);

        Run("RECORD_ENCRYPTION.INIT");
    }

    public static byte[][] IncreaseSequenceNumber(bool forServer)
    {
        Z80.IX = unchecked((short)(symbols[forServer ? "RECORD_ENCRYPTION.SERVER_NONCE" : "RECORD_ENCRYPTION.CLIENT_NONCE"]+11));
        Run("RECORD_ENCRYPTION.INC_SEQ");

        return [
            GetOutputBuffer(12, symbols[forServer ? "RECORD_ENCRYPTION.SERVER_NONCE" : "RECORD_ENCRYPTION.CLIENT_NONCE"]),
            GetOutputBuffer(12, symbols[forServer ? "RECORD_ENCRYPTION.SERVER_SEQUENCE" : "RECORD_ENCRYPTION.CLIENT_SEQUENCE"]),
        ];
    }

    public static byte[] Encrypt(byte contentType, byte[] content)
    {
        Z80.A = contentType;
        Z80.HL = unchecked((short)BUFFER_IN);
        Z80.BC = (short)content.Length;
        Z80.DE = unchecked((short)BUFFER_IN);
        SetInputBuffer(content, BUFFER_IN);

        Run("RECORD_ENCRYPTION.ENCRYPT");

        return GetOutputBuffer(Z80.BC, BUFFER_IN);
    }

    public static (byte errorCode, byte[] decrypted, byte contentType) Decrypt(byte[] encryptedData)
    {
        Z80.HL = unchecked((short)BUFFER_IN);
        Z80.BC = (short)encryptedData.Length;
        Z80.DE = unchecked((short)BUFFER_IN);
        SetInputBuffer(encryptedData, BUFFER_IN);

        Run("RECORD_ENCRYPTION.DECRYPT");

        return (Z80.A, GetOutputBuffer(Z80.BC, BUFFER_IN), Z80.D);
    }

    public static byte[] GetClientHello(string serverName, byte[] publicKey)
    {
        var serverNameBytes = Encoding.ASCII.GetBytes(serverName);
        Z80.HL = unchecked((short)BUFFER_IN);
        Z80.B = (byte)serverNameBytes.Length;
        Z80.DE = unchecked((short)(BUFFER_IN+128));
        SetInputBuffer(serverNameBytes, BUFFER_IN);
        SetInputBuffer(publicKey, BUFFER_IN+128);
        Run("CLIENT_HELLO.INIT");
        return GetOutputBuffer(Z80.BC, Z80.HL);
    }

    public static (byte, byte[]) ParseServerHello(byte[] message)
    {
        Z80.HL = unchecked((short)BUFFER_IN);
        Z80.BC = (short)message.Length;
        SetInputBuffer(message, BUFFER_IN);
        Run("SERVER_HELLO.PARSE");
        return (Z80.A, Z80.A == 0 ? GetOutputBuffer(64, Z80.HL) : null);
    }

    public static TcpConnection TcpConnection
    {
        set
        {
            Z80.TcpConnection = value;
        }
    }

    public static void InitTcp()
    {
        SetInputBuffer([0xC3, 3, 0]);
        Z80.A = 1;
        Z80.HL = unchecked((short)BUFFER_IN);
        Run("DATA_TRANSPORT.INIT");
    }

    public static bool HasTcpData()
    {
        Run("DATA_TRANSPORT.HAS_IN_DATA");
        return Z80.CF == 1;
    }

    public static bool TcpIsClosed()
    {
        Run("DATA_TRANSPORT.IS_REMOTELY_CLOSED");
        return Z80.CF == 1;
    }

    public static void TcpClose()
    {
        Run("DATA_TRANSPORT.CLOSE");
    }

    public static bool TcpSend(byte[] data)
    {
        Z80.HL = unchecked((short)BUFFER_IN);
        Z80.BC = (short)data.Length;
        SetInputBuffer(data, BUFFER_IN);
        Run("DATA_TRANSPORT.SEND");
        return Z80.CF == 0;
    }

    public static byte[] TcReceive(int length)
    {
        Z80.HL = unchecked((short)BUFFER_OUT);
        Z80.BC = (short)length;
        Run("DATA_TRANSPORT.RECEIVE");
        return GetOutputBuffer(Z80.BC);
    }

    public static byte[] P256GenerateKeyPair()
    {
        Z80.HL = unchecked((short)BUFFER_OUT);
        Run("P256.GENERATE_KEY_PAIR");
        return GetOutputBuffer(64);
    }

    public static byte[] P256GenerateSharedSecret(byte[] remotePublicKey)
    {
        Z80.HL = unchecked((short)BUFFER_IN);
        Z80.DE = unchecked((short)BUFFER_OUT);
        SetInputBuffer(remotePublicKey);
        Run("P256.GENERATE_SHARED_KEY");
        return Z80.CF == 0 ? GetOutputBuffer(32) : null;
    }

    public static void RecordReceiverInit(ushort bufferAddress, ushort bufferLength)
    {
        Z80.HL = bufferAddress.ToShort();
        Z80.BC = bufferLength.ToShort();
        Run("RECORD_RECEIVER.INIT");
    }

    public static (byte status, byte[] data, byte recordType, byte handhskaType) RecordReceiverUpdate()
    {
        Run("RECORD_RECEIVER.UPDATE");
        var status = Z80.A;
        if(status < 128) {
            return (status, null, 0, 0);
        }

        var data = GetOutputBuffer(Z80.BC, Z80.HL.ToUShort()).ToArray();
        return (status, data, Z80.D, Z80.E);
    }

    public static (byte[] handshakeHeader, int handshakeSize) RecordReceiverGetHandhsakeData()
    {
        var handshakeHeader = GetOutputBuffer(4, symbols["RECORD_RECEIVER.HANDSHAKE_HEADER"]);
        var handshakeSize = GetWordFromMemory("RECORD_RECEIVER.HANDSHAKE_MSG_SIZE");
        return (handshakeHeader, handshakeSize);
    }

    public static void TlsConnectionInit(string serverName = null)
    {
        if(serverName is null) {
            Z80.B = 0;
        }
        else {
            var serverNameBytes = Encoding.ASCII.GetBytes(serverName);
            Z80.HL = BUFFER_IN.ToShort();
            Z80.B = (byte)serverNameBytes.Length;
            SetInputBuffer(serverNameBytes, BUFFER_IN);
        }
        Run("TLS_CONNECTION.INIT");
    }

    public static byte TlsConnectionUpdate()
    {
        Run("TLS_CONNECTION.UPDATE");
        /*
        var x = Z80.Memory[symbols["TLS_CONNECTION.INCOMING_DATA_LENGTH"]] + (Z80.Memory[symbols["TLS_CONNECTION.INCOMING_DATA_LENGTH"] + 1] << 8);
        if(x > 0) {
            var address = Z80.Memory[symbols["TLS_CONNECTION.INCOMING_DATA_POINTER"]] + (Z80.Memory[symbols["TLS_CONNECTION.INCOMING_DATA_POINTER"] + 1] << 8);
            var contents = GetOutputBuffer(x, address);
            var wow = Encoding.ASCII.GetString(contents);
        }
        */
        
        return Z80.A;
    }

    public static bool TlsConnectionSend(byte[] data)
    {
        Z80.HL = BUFFER_IN.ToShort();
        Z80.BC = (short)data.Length;
        SetInputBuffer(data, BUFFER_IN);
        Run("TLS_CONNECTION.SEND");
        var x = Z80.Memory[0xF100] + (Z80.Memory[0xF101] << 8);
        return Z80.CF == 0;
    }

    public static byte[] TlsConnectionReceive(int length)
    {
        Z80.DE = BUFFER_OUT.ToShort();
        Z80.BC = (short)length;
        Run("TLS_CONNECTION.RECEIVE");
        return Z80.BC == 0 ? [] : GetOutputBuffer(Z80.BC, BUFFER_OUT);
    }

    public static void TlsConnectionClose()
    {
        Run("TLS_CONNECTION.CLOSE");
    }

    public static byte TlsConnectionGetState()
    {
        return Z80.Memory[symbols["TLS_CONNECTION.STATE"]];
    }

    public static (byte, byte) TlsConnectionGetErrorCode()
    { 
        return (Z80.Memory[symbols["TLS_CONNECTION.ERROR_CODE"]], Z80.Memory[symbols["TLS_CONNECTION.SUB_ERROR_CODE"]]);
    }

    public static byte TlsConnectionAlertSent()
    {
        return Z80.Memory[symbols["TLS_CONNECTION.ALERT_SENT"]];
    }

    public static byte TlsConnectionAlertReceived()
    {
        return Z80.Memory[symbols["TLS_CONNECTION.ALERT_RECEIVED"]];
    }

    public static bool TlsConnectionCanSend()
    {
       Run("TLS_CONNECTION.CAN_SEND");
       return Z80.CF == 1;
    }

    public static bool TlsConnectionCanReceive()
    {
        Run("TLS_CONNECTION.CAN_RECEIVE");
        return Z80.CF == 1;
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

    private static int GetWordFromMemory(string addressName)
    {
        var address = symbols[addressName];
        return Z80.Memory[address] + (Z80.Memory[address + 1] << 8);
    }

    private static void Run(string symbol)
    {
        Z80.Start(symbols[symbol]);
    }
}