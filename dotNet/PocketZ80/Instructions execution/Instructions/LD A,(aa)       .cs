namespace Konamiman.PocketZ80
{
    public partial class Z80Processor
    {
        /// <summary>
        /// The LD A,(nn) instruction.
        /// </summary>
        private void LD_A_aa()
        {
            var address = (ushort)FetchWord();
            A = Memory[address];
        }
    }
}
