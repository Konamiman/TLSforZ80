using Konamiman.PocketZ80;
using Konamiman.TlsForZ80.TlsClient.Cryptography;
using Konamiman.TlsForZ80.TlsClient.DataStructures;
using Konamiman.TlsForZ80.TlsClient.DataTransport;
using Konamiman.TlsForZ80.TlsClient.Enums;
using Konamiman.TLSforZ80.TlsClient;
using System.Diagnostics;
using System.Security.Cryptography;
using System.Security.Cryptography.X509Certificates;

namespace Konamiman.TlsForZ80.TlsClient;

/// <summary>
/// Implements a TLS 1.3 client connection on top of a data transport layer
/// (typically a TCP connection).
/// </summary>
public class TlsClientConnection
{
    /// <summary>
    /// Create a new instance of the class.
    /// </summary>
    /// <param name="dataTransport">The underlying data transport to use, it must be already properly initialized and functional.</param>
    /// <param name="privateKey">The X25519 private key to use, if null a random key will be generated.</param>
    /// <param name="hostName">The host name to send in a server_name extension in the ClientHello message, if null no server_name extension will be sent.</param>
    public TlsClientConnection(IDataTransport dataTransport, byte[] privateKey, string hostName)
    {
        Z80Runner.Init();

        this.dataTransport = dataTransport;
        this.dataReceiver = new DataReceiver();
        state = ConnectionState.Initial;
        this.hostName = hostName;
        this.encryption = null;
    }

    /// <summary>
    /// Indicates if the handshake must be aborted and the connection closed if the server certificate verification fails.
    /// </summary>
    public bool AbortIfInvalidCertificate { get; set; } = true;

    /// <summary>
    /// The certificates sent by the server, null if the server hasn't sent certificates (yet).
    /// </summary>
    public X509Certificate2[] ServerCertificates { get; private set; } = null;

    /// <summary>
    /// Indicates if the server certificate verification succeeded.
    /// </summary>
    public bool CertificateIsValid { get; private set; } = false;

    /// <summary>
    /// If the connection was locally closed due to a TLS fatal error (and thus an alert was sent) this contains more details about what went wrong.
    /// </summary>
    public string ErrorMessage { get; private set; } = null;

    /// <summary>
    /// If an unexpected exception was thrown at some point, this contains a copy of the exception.
    /// </summary>
    public Exception InternalError { get; private set; } = null;

    /// <summary>
    /// This event is fired when a record is received (if a handshake message is split
    /// across several records, the event will be fired once the full message is assembled,
    /// and the payload supplied will be the entire message). The event arguments are:
    /// record type, handshake message type (when record type is "Handshake") and
    /// record payload, not including the 5 byte record header nor 
    /// (when it's a handshake record) the 4 byte handshake header.
    /// </summary>
    public event EventHandler<(RecordContentType, HandshakeType, byte[])> RecordReceived;

    /// <summary>
    /// This event is fired when a record is sent (note that handshake messages sent
    /// are never split in multiple records). The event arguments are:
    /// record type, handshake message type (when record type is "Handshake"),
    /// record payload not including the 5 byte record header nor 
    /// (when it's a handshake record) the 4 byte handshake header, and a boolean
    /// indicating if the record was sent encrypted (in this case, the payload array
    /// contains the plain data before the encryption, and an EncryptedRecordSent
    /// event will follow).
    /// </summary>
    public event EventHandler<(RecordContentType, HandshakeType, byte[], bool)> RecordSent;

    /// <summary>
    /// This event is fired when an encrypted record is sent. The payload is the encrypted
    /// record sent, not including the 5 byte record header. Immediately before this event,
    /// RecordSent is fired for the unencrypted content.
    /// </summary>
    public event EventHandler<byte[]> EncryptedRecordSent;

    /// <summary>
    /// This event is fired when the value of the State property changes.
    /// The payload is the new value of the property.
    /// </summary>
    public event EventHandler<ConnectionState> StateChanged;

    /// <summary>
    /// After an alert record is sent this property indicates the corresponsing alert code.
    /// </summary>
    public AlertCode? AlertSent { get; private set; } = null;

    /// <summary>
    /// After an alert record is received this property indicates the corresponsing alert code.
    /// </summary>
    public AlertCode? AlertReceived { get; private set; } = null;

    /// <summary>
    /// Current state of the TLS connection. Application data can be sent in the
    /// "Established" and "RemotelyClosed" states; application data can be received
    /// in the "Established" and "LocallyClosed" states.
    /// </summary>
    public ConnectionState State
    {
        get
        {
            RunStateMachine();
            return state;
        }
        set
        {
            if(state == value) {
                return;
            }
            state = value;
            if(StateChanged is not null) { 
                StateChanged(this, state);
            }
        }
    }

    /// <summary>
    /// Indicates if application data can be sent.
    /// </summary>
    public bool CanSend
    {
        get
        {
            RunStateMachine();
            return state is ConnectionState.Established or ConnectionState.RemotelyClosed;
        }
    }

    /// <summary>
    /// Indicates if application data can be received.
    /// </summary>
    public bool CanReceive
    {
        get
        {
            RunStateMachine();
            return state is ConnectionState.Established or ConnectionState.LocallyClosed;
        }
    }

    /// <summary>
    /// Indicates if the server requested us to send a certificate
    /// (but we didn't: support for client certificates isn't implemented).
    /// </summary>
    public bool ServerRequestedCertificate { get; private set; } = false;

    /// <summary>
    /// Get a given amount of application data from the connection.
    /// </summary>
    /// <param name="destination">Destination array for the data.</param>
    /// <param name="index">Destination index in the destination array for the data.</param>
    /// <param name="size">Number of data bytes to get.</param>
    /// <returns>Actual number of data bytes to get.</returns>
    public int GetApplicationData(byte[] destination, int index, int size)
    {
        try {
            return GetApplicationDataCore(destination, index, size);
        }
        catch(Exception ex) {
            HandleException(ex);
            return 0;
        }
    }

    /// <summary>
    /// Get a given amount of application data from the connection.
    /// </summary>
    /// <param name="size">Number of data bytes to get.</param>
    /// <returns>Application data, will be of the requested size or less.</returns>
    public byte[] GetApplicationData(int size)
    {
        var destination = new byte[size];
        var actualSize = GetApplicationData(destination, 0, size);
        return destination.Take(actualSize).ToArray();
    }

    /// <summary>
    /// Send application data to the connection.
    /// </summary>
    /// <param name="source">Source array of the data to sent.</param>
    /// <param name="index">Starting index in the source array of the data to sent, defaults to 0.</param>
    /// <param name="size">How many bytes to send, defaults to (size of source - index).</param>
    /// <returns></returns>
    public bool SendApplicationData(byte[] source, int index = 0, int size = -1)
    {
        try {
            return SendApplicationDataCore(source, index, size);
        }
        catch(Exception ex) {
            HandleException(ex);
            return false;
        }
    }

    /// <summary>
    /// Locally close the connection, meaning that we don't intend to send any more data.
    /// Until the server closes the connection on its side it's still possible
    /// to receive data.
    /// </summary>
    public void Close()
    {
        RunStateMachine();
        CloseCore();
    }

    //--- End of the public interface of the class ---

    //RFC8446 says that encryption keys are good for about 24M records
    //(https://datatracker.ietf.org/doc/html/rfc8446#section-5.5)
    const int MAX_RECORDS_PER_KEY = 20_000_000;

    private readonly IDataTransport dataTransport;
    TrafficKeys keys = null;
    RecordEncryption encryption;
    ConnectionState state;
    int receivedRecordLength = 0;
    string hostName;
    HashAlgorithm hashAlgorithm;
    HMAC hmacAlgorithm;
    List<byte> transmittedHandshakeBytes;
    int maxFragmentLength = 16384;
    int recordsSent = 0;
    byte[] receivedRecord;
    HandshakeType? receivedHandshakeType;
    DataReceiver dataReceiver;
    OutputBuffer applicationDataBuffer = new();
    bool runningStateMachine = false;

    private int GetApplicationDataCore(byte[] destination, int index, int size)
    {
        RunStateMachine();

        if(state < ConnectionState.Established) {
            return 0;
        }

        // If there's remaining data from a previous record we need to return that
        // before trying to retrieve more data from the connection.
        if(!applicationDataBuffer.IsEmpty) {
            return applicationDataBuffer.Extract(destination, index, size);
        }

        if(state is not ConnectionState.Established or ConnectionState.LocallyClosed) {
            return 0; 
        }

        ReceiveRecord();
        if(!dataReceiver.IsComplete) {
            return 0;
        }

        var receivedRecordType = dataReceiver.RecordType;
        if(receivedRecordType is RecordContentType.None or RecordContentType.ChangeCipherCpec) {
            return 0;
        }
        else if(receivedRecordType is RecordContentType.Alert) {
            HandleAlertReceived();
            return 0;
        }
        else if(receivedRecordType is RecordContentType.Handshake) {
            HandleEstablishedHandshakeReceived();
            return 0;
        }
        else if(receivedRecordType is not RecordContentType.ApplicationData) {
            throw new ProtocolError(AlertCode.unexpectedMessage, $"Unexpected record of type {receivedRecordType} received while retrieving application data");
        }

        // The received record might contain more data than what's requested in this call.
        // We then put this remainder data in applicationDataBuffer for later retrieval.
        if(size >= dataReceiver.Data.Length) {
            Array.Copy(dataReceiver.Data, 0, destination, index, dataReceiver.Data.Length);
            return dataReceiver.Data.Length;
        }
        else {
            applicationDataBuffer.Initialize(dataReceiver.Data);
            Array.Copy(dataReceiver.Data, 0, destination, index, size);
            return size;
        }
    }

    private bool SendApplicationDataCore(byte[] source, int index, int size) 
    {
        RunStateMachine();

        if(!CanSend) {
            return false;
        }

        if(size == -1) {
            size = source.Length;
        }

        //We apply fragmentation here, instead of at SendRecord,
        //because any other messages sent by us (handshake, alert)
        //will never be >512 bytes. This would change if support
        //for client certificates is implemented.
        for(int i=0; i<size; i+=maxFragmentLength) {
            var ok = SendRecord(RecordContentType.ApplicationData, source.Skip(index+i).Take(maxFragmentLength).ToArray());
            if(!ok) {
                return false;
            }
        }

        return true;
    }

    /// <summary>
    /// Send a handshake message to the server.
    /// </summary>
    /// <param name="type">Handshake message type.</param>
    /// <param name="data">Handshake message payload, not including the 5 byte record header nor the 4 byte handshake header.</param>
    /// <returns>True on success, false on failure.</returns>
    private bool SendHandshakeMessage(HandshakeType type, byte[] data)
    {
        if(RecordSent is not null) {
            RecordSent(this, (RecordContentType.Handshake, type, data, encryption is not null));
        }

        data = [
            (byte)type,
            ..data.Length.ToBigEndianUint24Bytes(),
            ..data
        ];

        return SendRecord(RecordContentType.Handshake, data, type is HandshakeType.ClientHello ? 0x0301 : 0x0303);
    }

    /// <summary>
    /// Send a record to the server.
    /// </summary>
    /// <param name="type">Record type code.</param>
    /// <param name="recordData">Record payload, not including the 5 byte record header.</param>
    /// <param name="legacyRecordVersion">Value for the legacy_record_version field, should be 0x0301 for ClientHello and 0x0303 for anything else.</param>
    /// <returns>True on success, false on failure.</returns>
    private bool SendRecord(RecordContentType type, byte[] recordData, int legacyRecordVersion = 0x0303)
    {
        if(state is ConnectionState.FullClosed) { 
            return false;
        }

        if(type is RecordContentType.Handshake && state is ConnectionState.Handshake) {
            transmittedHandshakeBytes.AddRange(recordData);
        }

        var mustEncrypt = encryption is not null && (type is RecordContentType.ApplicationData or RecordContentType.Handshake);
        if(type is RecordContentType.ApplicationData && !mustEncrypt) {
            throw new InvalidOperationException("Can't send application data, no encryption keys available!");
        }

        if(RecordSent is not null && type is not RecordContentType.Handshake) {
            RecordSent(this, (type, HandshakeType.None, recordData, mustEncrypt));
        }

        if(mustEncrypt) {
            //TODO: Maybe add some padding, based on some policy.
            recordData = encryption.Encrypt(type, recordData);
            type = RecordContentType.ApplicationData;
            if(EncryptedRecordSent is not null) {
                EncryptedRecordSent(this, recordData);
            }
        }

        byte[] fullRecord = [
            (byte)type,
            ..legacyRecordVersion.ToBigEndianUint16Bytes(),
            ..recordData.Length.ToBigEndianUint16Bytes(),
            ..recordData
        ];

        var sendOk = dataTransport.Send(fullRecord);

        if(state >= ConnectionState.Established) {
            recordsSent++;
            if(recordsSent == MAX_RECORDS_PER_KEY - 1) {
                SendHandshakeMessage(HandshakeType.KeyUpdate, [0]);
                keys.UpdateClientKeys();
                recordsSent = 0;
            }
        }

        return sendOk;
    }

    /// <summary>
    /// Receive the next record from the server. Handshake message fragmentation/coalescing
    /// is handled transparently and complete messages are always returned, see the DataReceiver class.
    /// 
    /// Sets receivedRecord, receivedRecordLength and receivedHandshakeType if it returns
    /// a value that is not RecordContentType.None. Note that receivedRecord
    /// will not include the 5 byte record header nor (when receiving a handshake message)
    /// the 4 byte handshake header.
    /// </summary>
    /// <returns>Received ecord type, or RecordContentType.None if a full record is not available yet.</returns>
    private RecordContentType ReceiveRecord()
    {
        dataReceiver.Run();
        if(dataReceiver.IsComplete) {
            if(RecordReceived is not null) {
                RecordReceived(this, (dataReceiver.RecordType, dataReceiver.HandshakeType, dataReceiver.Data));
            }

            receivedRecord = dataReceiver.Data.ToArray();
            receivedRecordLength = receivedRecord.Length;
            receivedHandshakeType = dataReceiver.HandshakeType;
            if(dataReceiver.RecordType is RecordContentType.Handshake && state is ConnectionState.Handshake) {
                transmittedHandshakeBytes.AddRange([.. dataReceiver.HandshakeHeader, .. dataReceiver.Data]);
            }

            return dataReceiver.RecordType;
        }
        else {
            return RecordContentType.None;
        }
    }

    /// <summary>
    /// Send an alert record if one hasn't been sent yet.
    /// </summary>
    /// <param name="code">Alert code to send.</param>
    /// <returns>True on success, false on failure.</returns>
    private bool SendAlert(AlertCode code)
    {
        if(AlertSent is not null) {
            return false;
        }

        if(state is ConnectionState.Initial or ConnectionState.LocallyClosed or ConnectionState.FullClosed) {
            return false;
        }

        AlertSent = code;
        var sendOk = SendRecord(
            RecordContentType.Alert,
            [ (byte)(code is AlertCode.userCanceled or AlertCode.closeNotify ? 1 : 2), (byte)code ]
        );

        return sendOk;
    }

    private void CloseCore()
    {
        if(state is not ConnectionState.Initial && AlertSent is null) {
            SendAlert(
                state is ConnectionState.Handshake ? 
                AlertCode.userCanceled : AlertCode.closeNotify
            );
        }

        State = state is ConnectionState.Established ? ConnectionState.LocallyClosed : ConnectionState.FullClosed;
        dataTransport.Close();
    }

    private void HandleAlertReceived()
    {
        AlertReceived = (AlertCode)dataReceiver.Data[1];

        if(AlertReceived is AlertCode.closeNotify) {
            switch(state) {
                case ConnectionState.Established:
                    State = ConnectionState.RemotelyClosed;
                    break;
                case ConnectionState.Initial:
                case ConnectionState.Handshake:
                case ConnectionState.LocallyClosed:
                    State = ConnectionState.FullClosed;
                    break;
            }
        } else { 
            CloseCore();
        }
    }

    private void HandleException(Exception ex)
    {
        if(ex is ProtocolError perr) {
            SendAlert(perr.AlertCode);
            ErrorMessage = perr.Message;
        }
        else {
            SendAlert(AlertCode.internalError);
            ErrorMessage = $"Unexpected exception, see {nameof(InternalError)}";
            InternalError = ex;
        }
        CloseCore();
    }

    /// <summary>
    /// Run the main state machine of the connection, this happens
    /// whenever any public property or method of the class is invoked.
    /// </summary>
    private void RunStateMachine()
    {
        if(runningStateMachine) {
            return;
        }

        runningStateMachine = true;
        try {
            RunStateMachineCore();
        }
        catch(Exception ex) {
            HandleException(ex);
        }
        finally {
            runningStateMachine = false;
        }
    }

    private void RunStateMachineCore()
    {
        if(state < ConnectionState.Established) {
            RunHandshakeStateMachine();
        }

        if(dataTransport.IsRemotelyClosed() &&
            !dataTransport.HasDataToReceive() &&
            state is not ConnectionState.RemotelyClosed and not ConnectionState.FullClosed) {

            //Data transport was remotely closed but no alert was received
            CloseCore();
        }
    }

    /// <summary>
    /// Perform the next step in the handshake procedure,
    /// which basically means retrieving the next handshake message from the server,
    /// processing it, and sending another handshake message in response if needed.
    /// </summary>
    private void RunHandshakeStateMachine()
    {
        if(state is ConnectionState.Initial) {
            State = ConnectionState.Handshake;

            var clientHello = new ClientHelloMessage() {
                P256PublicKey = Z80Runner.P256GenerateKeyPair(),
                ServerName = hostName
            };
            var clientHelloBytes = clientHello.ToByteArray();
            Debug.WriteLine("*** ClientHello:");
            Debug.WriteLine(NumberUtils.BytesToHexDump(clientHelloBytes));
            transmittedHandshakeBytes = [];
            SendHandshakeMessage(HandshakeType.ClientHello, clientHelloBytes);

            return;
        }

        var receivedType = ReceiveRecord();
        if(receivedType is RecordContentType.None or RecordContentType.ChangeCipherCpec) {
            return;
        }

        else if(receivedType is RecordContentType.Alert) {
            HandleAlertReceived();
            return;
        }

        else if(receivedType is not RecordContentType.Handshake) {
            throw new ProtocolError(AlertCode.unexpectedMessage, $"Unexpected record of type {receivedType} received during handshake");
        }

        if(receivedHandshakeType is HandshakeType.ServerHello) {
            if(keys is not null) {
                throw new ProtocolError(AlertCode.unexpectedMessage, $"A second ServerHello message has been received");
            }

            ServerHelloMessage serverHello;
            try {
                Debug.WriteLine("*** ServerHello:");
                Debug.WriteLine(NumberUtils.BytesToHexDump(receivedRecord));
                serverHello = ServerHelloMessage.Parse(receivedRecord);
            }
            catch {
                throw new ProtocolError(AlertCode.decodeError, "Couldn't decode the received ServerHello message");
            }

            if(serverHello.IsHelloRetryRequest) {
                throw new ProtocolError(AlertCode.handshakeFailure, $"HelloRetryRequest message received");
            }
            if(!serverHello.IsTls13) {
                throw new ProtocolError(AlertCode.protocolVersion, $"The server doesn't support TLS 1.3");
            }

            if(serverHello.CipherSuite is not CipherSuite.TLS_AES_128_GCM_SHA256) {
                throw new ProtocolError(AlertCode.illegalParameter, $"The server returned {serverHello.CipherSuite} as the cipher suite in ServerHello");
            }

            hashAlgorithm = SHA256.Create();
            hmacAlgorithm = new HMACSHA256();
            keys = new TrafficKeys();

            var sharedSecret = Z80Runner.P256GenerateSharedSecret(serverHello.PublicKey.Skip(1).ToArray());
            Debug.WriteLine("*** Shared secret:");
            Debug.WriteLine(NumberUtils.BytesToHexDump(sharedSecret));


            Debug.WriteLine("*** Transmitted handshake bytes hash:");
            Debug.WriteLine(NumberUtils.BytesToHexDump(Z80Runner.CalculateSHA256(transmittedHandshakeBytes.ToArray())));

            keys.ComputeHandshakeKeys(sharedSecret, Z80Runner.CalculateSHA256(transmittedHandshakeBytes.ToArray()));
            encryption = new RecordEncryption(keys);
            dataReceiver.Encryption = encryption;

            Debug.WriteLine("*** Client key:");
            Debug.WriteLine(NumberUtils.BytesToHexDump(keys.ClientKey));
            Debug.WriteLine("*** Server key:");
            Debug.WriteLine(NumberUtils.BytesToHexDump(keys.ServerKey));
        }

        else if(receivedHandshakeType is HandshakeType.Finished) {
            if(keys is null) {
                throw new ProtocolError(AlertCode.unexpectedMessage, $"Finished message received before ServerHello");
            }

            if(ServerCertificates is null) {
                throw new ProtocolError(AlertCode.certificateRequired, $"Finished message received before Certificate");
            }

            var serverTransmittedBytes = transmittedHandshakeBytes.Take(transmittedHandshakeBytes.Count - dataReceiver.HandshakeHeader.Length - receivedRecordLength);
            var serverHandshakeHash = hashAlgorithm.ComputeHash(serverTransmittedBytes.ToArray());
            hmacAlgorithm.Key = keys.ComputeFinishedKey(ofServer: true);
            var serverVerifyData = hmacAlgorithm.ComputeHash(serverHandshakeHash);
            var serverFinishedOk = serverVerifyData.SequenceEqual(receivedRecord);

            if(!serverFinishedOk) {
                throw new ProtocolError(AlertCode.decryptError, "Verification of server Finished message failed");
            }

            var handshakeHash = hashAlgorithm.ComputeHash(transmittedHandshakeBytes.ToArray());
            hmacAlgorithm.Key = keys.ComputeFinishedKey(ofServer: false);
            var verifyData = hmacAlgorithm.ComputeHash(handshakeHash);

            if(ServerRequestedCertificate) {
                SendHandshakeMessage(HandshakeType.Certificate, [0, 0, 0, 0]);
            }

            SendRecord(RecordContentType.ChangeCipherCpec, [1]);

            SendHandshakeMessage(HandshakeType.Finished, verifyData);

            keys.ComputeApplicationKeys(handshakeHash);

            State = ConnectionState.Established;
        }

        else if(receivedHandshakeType is HandshakeType.Certificate) {
            if(keys is null) {
                throw new ProtocolError(AlertCode.unexpectedMessage, $"Certificate message received before ServerHello");
            }

            var contextLength = receivedRecord[0]; //Should be 0
            var index = 1 + contextLength;
            var totalSize = receivedRecord.ExtractBigEndianUint24(index);
            index += 3;
            var certificates = new List<X509Certificate2>();
            while(totalSize > 0) {
                var certificateSize = receivedRecord.ExtractBigEndianUint24(index);
                var certificateData = receivedRecord.Skip(index + 3).Take(certificateSize).ToArray();
                index += 3 + certificateSize;
                totalSize -= (3 + certificateSize);

                try {
                    certificates.Add(new X509Certificate2(certificateData));
                }
                catch(CryptographicException ex) {
                    throw new ProtocolError(AlertCode.badCertificate, $"Error when instantiating one of the server certificates: {ex.Message}");
                }

                var extensionsSize = receivedRecord.ExtractBigEndianUint16(index);
                index += 2 + extensionsSize;
                totalSize -= (2 + extensionsSize);
            }
            ServerCertificates = certificates.ToArray();
        }

        else if(receivedHandshakeType is HandshakeType.CertificateVerify) {
            // :shrug:
        }
        else if(receivedHandshakeType is HandshakeType.EncryptedExtensions) {
            if(keys is null) {
                throw new ProtocolError(AlertCode.unexpectedMessage, $"EncryptedExtensions message received before ServerHello");
            }

            var extensionsLength = receivedRecord.ExtractBigEndianUint16(0);
            var index = 2;
            while(index < extensionsLength + 2) {
                var extensionType = (HandshakeExtensionType)receivedRecord.ExtractBigEndianUint16(index);
                var extensionDataLength = receivedRecord.ExtractBigEndianUint16(index + 2);
                index += 4;

                if(extensionType is HandshakeExtensionType.MaxFragmentLength) {
                    var fragmentLength = receivedRecord[index];
                    if(fragmentLength != 1) {
                        throw new ProtocolError(AlertCode.illegalParameter, $"Received the max_fragment_length extension with value {fragmentLength}");
                    }
                    maxFragmentLength = 512;
                }

                //TODO: The other extensions should be checked, and if any is not allowed in this message, an alert should be sent

                index += extensionDataLength;
            }
        }
        else if(receivedHandshakeType is HandshakeType.CertificateRequest) {
            if(keys is null) {
                throw new ProtocolError(AlertCode.unexpectedMessage, $"CertificateRequest message received before ServerHello");
            }

            ServerRequestedCertificate = true;
        }
        else {
            throw new ProtocolError(AlertCode.unexpectedMessage, $"Unexpected handshake message of type {receivedHandshakeType} received during handshake");
        }
    }

    /// <summary>
    /// Handle a handshake message received during the "Established" (or "LocallyClosed") state.
    /// </summary>
    private void HandleEstablishedHandshakeReceived()
    {
        if(receivedHandshakeType is HandshakeType.KeyUpdate) {
            if(receivedRecord.Length is not 1 || receivedRecord[0] is not 0 and not 1) {
                throw new ProtocolError(AlertCode.decodeError, "Ivalid KeyUpdate message received");
            }

            keys.UpdateServerKeys();
            var clientUpdateRequested = receivedRecord[0] != 0;
            if(clientUpdateRequested) {
                SendHandshakeMessage(HandshakeType.KeyUpdate, [0]);
                keys.UpdateClientKeys();
                recordsSent = 0;
            }
        }

        else if(receivedHandshakeType is not HandshakeType.NewSessionTicket) {
            throw new ProtocolError(AlertCode.unexpectedMessage, $"Unexpected handshake message of type {receivedHandshakeType} received after the handshake");
        }
    }
}

