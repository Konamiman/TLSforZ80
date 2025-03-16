using Konamiman.TLSforZ80.PocketZ80;
using System.Diagnostics;
using System.Security.Cryptography;
using System.Security.Cryptography.X509Certificates;

namespace Konamiman.PocketZ80
{
    /// <summary>
    /// Z80 processor simulator with partial CP/M function call support.
    /// This is a simplified version of the processor class implemented as part of
    /// the Z80.NET project (https://github.com/Konamiman/Z80dotNet):
    /// - Port access is not supported
    /// - Interrupts are not supported
    /// - An undefined Z80 instruction will crash the application
    /// - HALT will crash the application
    /// - Registers and intruction executors are embedded instead of being separate classes
    /// - No events are triggered
    /// - The only supported execution stop condition is RET with the original stack pointer
    /// </summary>
    public partial class Z80Processor
    {
        public byte[] Memory { get; private set; } = new byte[65536];

        private TcpIpUnapi tcpIpUnapi;

        public Dictionary<ushort, Action> ExecutionHooks { get; private set; } = [];

        public TcpConnection TcpConnection 
        { 
            set
            {
                tcpIpUnapi = new TcpIpUnapi(this, value);
            }
        }

        public Z80Processor()
        {
            InitializeInstructionTables();
        }

        public void Start(ushort address)
        {
            PC = address;
            unchecked { SP = (short)0xFFFF; }

            InstructionExecutionLoop();
        }

        private void InstructionExecutionLoop()
        {
            var watcher = new Stopwatch();
            watcher.Start();
            while (SP < 0)
            {
                if(ExecutionHooks.ContainsKey(PC)) {
                    ExecutionHooks[PC]();
                }
                else {
                    switch(PC) {
                        case 0x0000:
                            return;
                        case 0x0003:
                            tcpIpUnapi.HandleEntryPointCall();
                            break;
                        //case 0x0006:
                        //    HandleP256Call();
                        //    break;
                        default:
                            Execute(Memory[PC++]);
                            break;
                    }
                }

                if(watcher.ElapsedMilliseconds > 3000) {
                    watcher.Stop();
                    throw new Exception("Z80 code took too long to execute");
                }
            }
        }

        ECDiffieHellman localP256Key;

        private void HandleP256Call()
        {
            if(A == 0) {
                // Create new key, store private key internally, return public key

                var localPrivateKeyBytes = new byte[32];
                RandomNumberGenerator.Create().GetBytes(localPrivateKeyBytes);

                localP256Key = ECDiffieHellman.Create(new ECParameters {
                    Curve = ECCurve.NamedCurves.nistP256,
                    D = localPrivateKeyBytes
                });


                var publicKey = localP256Key.ExportSubjectPublicKeyInfo().Skip(27).ToArray();
                Array.Copy(publicKey, 0, Memory, HL.ToUShort(), publicKey.Length);
            }
            else {
                // Create shared secret from the previously stored private key and the remote public key

                var remotePublicKey = Memory.Skip(HL.ToUShort()).Take(64).ToArray();
                var remoteEcdhKey = ECDiffieHellman.Create(new ECParameters {
                    Curve = ECCurve.NamedCurves.nistP256,
                    Q = new ECPoint {
                        X = remotePublicKey.Take(32).ToArray(),
                        Y = remotePublicKey.Skip(32).ToArray(),
                    }
                });
                var sharedSecret = localP256Key.DeriveRawSecretAgreement(remoteEcdhKey.PublicKey);
                Array.Copy(sharedSecret, 0, Memory, DE.ToUShort(), sharedSecret.Length);
            }

            ExecuteRet();
        }

        public void Reset()
        {
            IFF1 = 0;
            IFF2 = 0;
            PC = 0;
            unchecked { AF = (short)0xFFFF; }
            unchecked { SP = (short)0xFFFF; }
        }

        public void ExecuteRet()
        {
            var sp = (ushort)SP;
            var newPC = NumberUtils.CreateShort(Memory[sp], Memory[(ushort)(sp + 1)]);

            PC = (ushort)newPC;
            SP += 2;
        }
    }
}
