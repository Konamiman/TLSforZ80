namespace Konamiman.PocketZ80
{
    public partial class Z80Processor
    {
        /// <summary>
        /// The EX DE,HL instruction
        /// </summary>
        void EX_DE_HL()
        {
            var temp = DE;
            DE = HL;
            HL = temp;
        }
    }
}
