using System;

namespace Konamiman.PocketZ80
{
    public partial class Z80Processor
    {
        /// <summary>
        /// The DJNZ d instruction.
        /// </summary>
        void DJNZ_d()
        {
            var offset = Memory[PC++];
            var oldValue = B;
            B = (byte)(oldValue - 1);

            if (oldValue == 1)
                return;

            PC = (ushort)(PC + (SByte)offset);
        }
    }
}
