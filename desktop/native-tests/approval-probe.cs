using System;
using System.Net;
using System.Net.Sockets;
using System.Diagnostics;
using System.Web.Script.Serialization;

class LimenApprovalProbe {
    static int Main(string[] args) {
        var elapsed = Stopwatch.StartNew();
        try {
            if (args.Length != 3 || (args[0] != "TCP" && args[0] != "UDP")) throw new Exception("Invalid probe parameters");
            IPAddress address = IPAddress.Parse(args[1]); int port = int.Parse(args[2]);
            if (port < 1 || port > 65535) throw new Exception("Invalid probe port");
            if (args[0] == "TCP") {
                using (var socket = new Socket(address.AddressFamily, SocketType.Stream, ProtocolType.Tcp)) {
                    IAsyncResult connection = socket.BeginConnect(address, port, null, null);
                    using (connection.AsyncWaitHandle) {
                        if (!connection.AsyncWaitHandle.WaitOne(3000)) throw new TimeoutException("TCP connection timed out");
                        socket.EndConnect(connection);
                    }
                }
            } else {
                using (var socket = new Socket(address.AddressFamily, SocketType.Dgram, ProtocolType.Udp)) {
                    socket.ReceiveTimeout = 2500; socket.SendTimeout = 2500;
                    byte[] query = new byte[] { 0x32,0x51,1,0,0,1,0,0,0,0,0,0,7,101,120,97,109,112,108,101,3,99,111,109,0,0,1,0,1 };
                    byte[] transaction = new byte[2]; new System.Security.Cryptography.RNGCryptoServiceProvider().GetBytes(transaction);
                    query[0] = transaction[0]; query[1] = transaction[1];
                    socket.SendTo(query, new IPEndPoint(address, port));
                    byte[] response = new byte[4096]; EndPoint peer = new IPEndPoint(address.AddressFamily == AddressFamily.InterNetwork ? IPAddress.Any : IPAddress.IPv6Any, 0);
                    int count = socket.ReceiveFrom(response, ref peer);
                    var endpoint = (IPEndPoint)peer;
                    if (!endpoint.Address.Equals(address) || endpoint.Port != port || count < 12 || response[0] != query[0]
                        || response[1] != query[1] || (response[2] & 128) == 0 || (response[3] & 15) != 0)
                        throw new Exception("DNS response identity or status mismatch");
                }
            }
            Console.WriteLine(new JavaScriptSerializer().Serialize(new { success=true, protocol=args[0], address=args[1], port=port, elapsedMs=elapsed.ElapsedMilliseconds }));
            return 0;
        } catch (Exception error) {
            Console.WriteLine(new JavaScriptSerializer().Serialize(new { success=false, error=error.Message, socketError=error is SocketException ? ((SocketException)error).SocketErrorCode.ToString() : null, elapsedMs=elapsed.ElapsedMilliseconds }));
            return 0;
        }
    }
}
