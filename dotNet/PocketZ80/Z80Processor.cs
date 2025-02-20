using System;
using System.Diagnostics;
using System.IO;
using System.Linq;

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
                switch(PC) {
                    case 0x0000:
                        return;
                }

                Execute(Memory[PC++]);

                if(watcher.ElapsedMilliseconds > 3000) {
                    watcher.Stop();
                    throw new Exception("Z80 code took too long to execute");
                }
            }
        }

        public void Reset()
        {
            IFF1 = 0;
            IFF2 = 0;
            PC = 0;
            unchecked { AF = (short)0xFFFF; }
            unchecked { SP = (short)0xFFFF; }
        }

        private void ExecuteRet()
        {
            var sp = (ushort)SP;
            var newPC = NumberUtils.CreateShort(Memory[sp], Memory[(ushort)(sp + 1)]);

            PC = (ushort)newPC;
            SP += 2;
        }
    }
}
