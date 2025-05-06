namespace Konamiman.TlsForZ80.TlsClient.Enums
{
    public enum RecordContentType : byte
    {
        None = 0,
        ChangeCipherSpec = 20,
        Alert = 21,
        Handshake = 22,
        ApplicationData = 23
    }
}
