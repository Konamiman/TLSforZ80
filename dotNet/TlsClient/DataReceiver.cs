using Konamiman.TlsForZ80.TlsClient.Cryptography;
using Konamiman.TlsForZ80.TlsClient.Enums;
using Konamiman.TLSforZ80.TlsClient;
using System;
using System.Linq;
using System.Runtime.CompilerServices;

[assembly: InternalsVisibleTo("NestorTLSTester")]

namespace Konamiman.TlsForZ80.TlsClient;

/// <summary>
/// This class handles the reception of TLS records, taking care of all the low-level nuances:
/// 
/// - All the possible fragmentations:
///   - TLS records fragmented in several frames/packets at the data transport level.
///   - Handshake messages fragmented in several TLS records.
///   - Several handshake messages coalesced in one single TLS record.
///   - Any combination of the above (e.g. a record containing "two and half" handshake messages).
/// - Decryption of "application data" records.
/// 
/// How to use:
/// 
/// 1. Invoke the "Run" method.
/// 2. Look at the "IsComplete" property. If it's false, goto 1.
/// 3. Look at the "RecordType", "HandshakeType" and "Data" properties (also "HandshakeHeader" if needed).
/// 4. To start over (and receive the next record), just goto 1.
/// 
/// For handshake messages "Data" will always contain one single full message, regardless of
/// message fragmentation or coalescing.
/// </summary>
internal class DataReceiver
{
    /// <summary>
    /// The data decryptor to use. Needs to be set as soon as the keys are negotiated.
    /// </summary>
    public RecordEncryption Encryption { get; set; } = null;

    /// <summary>
    /// Indicates that a full record has been received and thus the values of
    /// "RecordType", "HandshakeType", "Data" and "HandshakeHeader" are good.
    /// </summary>
    public bool IsComplete { get; private set; } = false;

    /// <summary>
    /// The received record data, already decrypted (if it had been received encrypted),
    /// and not including the 5 byte record header nor (if it's a handshake message)
    /// the 4 byte handshake header.
    /// </summary>
    public byte[] Data { get; private set; } = null;

    /// <summary>
    /// The received 4 byte handshake header (if a handshake message has been received).
    /// </summary>
    public byte[] HandshakeHeader { get; private set; } = null;

    /// <summary>
    /// The received record type.
    /// </summary>
    public RecordContentType RecordType { get; private set; } = RecordContentType.None;

    /// <summary>
    /// The received handshake message type (if a handshake message has been received).
    /// </summary>
    public HandshakeType HandshakeType { get; private set; } = HandshakeType.None;

    public DataReceiver()
    {
        Z80Runner.RecordReceiverInit(0xC000, 0x3000);
    }

    public void Run()
    {
        if(IsComplete) {
            IsComplete = false;
        }

        var (receiverStatus, receivedData, receivedRecordType, receivedHandshakeType) = Z80Runner.RecordReceiverUpdate();
        if(receiverStatus == 0) {
            return;
        }
        if(receiverStatus < 128) {
            throw new ProtocolError(AlertCode.decodeError, $"Record receiver error: {receiverStatus}");
        }

        if(receiverStatus == 128) { //Non-handshake record
            IsComplete = true;
            Data = receivedData;
            RecordType = (RecordContentType)receivedRecordType;
        }
        else if(receiverStatus == 129) { //Full handshake message
            IsComplete = true;
            Data = receivedData;
            RecordType = RecordContentType.Handshake;
            HandshakeType = (HandshakeType)receivedHandshakeType;
            (HandshakeHeader, _) = Z80Runner.RecordReceiverGetHandhsakeData();
        }
        else if(receiverStatus == 130) { //First part of split handshake message
            Data = receivedData;
            RecordType = RecordContentType.Handshake;
            HandshakeType = (HandshakeType)receivedHandshakeType;
            (HandshakeHeader, _) = Z80Runner.RecordReceiverGetHandhsakeData();
        }
        else if(receiverStatus == 131) { //Next part of split handshake message
            Data = [..Data, ..receivedData];
        }
        else if(receiverStatus == 132) { //Last part of split handshake message
            IsComplete = true;
            Data = [..Data, ..receivedData];
        }
        else {
            throw new Exception($"Unexpected status code from record receiver: {receiverStatus}");
        }
    }
}
