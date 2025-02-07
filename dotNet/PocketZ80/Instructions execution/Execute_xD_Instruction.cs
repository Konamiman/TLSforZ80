namespace Konamiman.PocketZ80
{
    public partial class Z80Processor
    {
        private void Execute_DD_Instruction()
        {
            var secondOpcodeByte = Memory[PC++];

            if (secondOpcodeByte == 0xCB)
            {
                var offset = Memory[PC++];
                DDCB_InstructionExecutors[Memory[PC++]](offset);
            }
            else
            {
                DD_InstructionExecutors[secondOpcodeByte]();
            }
        }

        private void Execute_FD_Instruction()
        {
            var secondOpcodeByte = Memory[PC++];

            if (secondOpcodeByte == 0xCB)
            {
                var offset = Memory[PC++];
                FDCB_InstructionExecutors[Memory[PC++]](offset);
            }
            else
            {
                FD_InstructionExecutors[secondOpcodeByte]();
            }
        }
    }
}
