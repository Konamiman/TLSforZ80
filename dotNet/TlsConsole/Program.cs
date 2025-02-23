using Konamiman.TlsForZ80.TlsClient;
using Konamiman.TlsForZ80.TlsClient.DataTransport;
using System.Text;
using static System.Console;
using ConnectionState = Konamiman.TlsForZ80.TlsClient.Enums.ConnectionState;

namespace Konamiman.TlsForZ80.TlsConsole;

class Program
{
    static bool keepRunning = true;

    public static void Main(string[] args)
    {
        bool httpGet = false;

        if(args.Length == 0) {
            WriteLine("TCP based TLS 1.3 console");
            WriteLine("Usage: TLSCON <host>[:<port>] [-hg|--http-get");
            return;
        }

        var hostParts = args[0].Split(':');
        var host = hostParts[0];
        int port = hostParts.Length > 1 ? int.Parse(hostParts[1]) : 443;

        if(args.Length > 1) {
            var arg1 = args[1].ToLower();
            if(arg1 is "-hg" or "--http-get") {
                httpGet = true;
            }
            else {
                WriteLine("*** Invalid arguments");
                return;
            }
        }

        keepRunning = true;
        Console.CancelKeyPress += Console_CancelKeyPress;
        WriteLine("--- Opening connection...");

        var tcpTransport = new TcpDataTransport(host, port);
        try {
            tcpTransport.Connect();
        }
        catch(Exception ex) {
            WriteLine($"*** Connection failed: {ex.Message}");
            return;
        }

        var connection = new TlsClientConnection(tcpTransport, null, host);
        tcpTransport.BindConnectionToZ80();

        while(connection.State < ConnectionState.Established) ;

        if(httpGet) {
            connection.SendApplicationData(Encoding.ASCII.GetBytes($"GET / HTTP/1.1\r\nHost: {host}\r\n"));
        }
        WriteLine("--- Connected! Typed lines will be sent when pressing ENTER");

        while(keepRunning) {
            if(KeyAvailable) {
                var line = ReadLine();
                connection.SendApplicationData(Encoding.ASCII.GetBytes(line + "\r\n"));
            }

            var incomingData = connection.GetApplicationData(1024);
            if(incomingData.Length != 0) {
                WriteLine(Encoding.ASCII.GetString(incomingData));
            }

            keepRunning &= connection.State == ConnectionState.Established;
        }

        if(connection.ErrorMessage is not null) {
            WriteLine($"--- Something went wrong: {connection.ErrorMessage}");
            if(connection.AlertSent is not null) {
                WriteLine($"---Alert sent: {connection.AlertSent}");
            }
        }
        else if(connection.State != ConnectionState.Established) {
            WriteLine("--- Connection closed by peer");
            if(connection.AlertReceived is not null) {
                WriteLine($"--- TLS alert received: {connection.AlertReceived}");
            }
        }

        connection.Close();
    }

    static void Console_CancelKeyPress(object sender, ConsoleCancelEventArgs e)
    {
        Console.WriteLine("--- Connection closed locally");
        keepRunning = false;
        e.Cancel = true;
    }
}