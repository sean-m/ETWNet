using Microsoft.Diagnostics.Tracing;
using Microsoft.Diagnostics.Tracing.Parsers;
using Microsoft.Diagnostics.Tracing.Session;
using System.Diagnostics;

namespace McETWNet {
    class pinfo {
        public int Id { get; set; }
        public string Name { get; set; }
    }

    class Program {
        static void Main(string[] args)
        {
            // Local process cache to speed lookup later
            var processes = Process.GetProcesses().Select(p => new pinfo
            {
                Name = p.ProcessName,
                Id = p.Id
            }).ToDictionary(p => p.Id);

            string TryGetProcessName(TraceEvent evt)
            {
                if (!string.IsNullOrEmpty(evt.ProcessName))
                    return evt.ProcessName;
                return processes.TryGetValue(evt.ProcessID, out var info) ? info.Name : string.Empty;
            }


            using (var session = new TraceEventSession(Environment.OSVersion.Version.Build >= 9200 ? "McETWNetSession" : KernelTraceEventParser.KernelSessionName))
            {
                session.EnableKernelProvider(KernelTraceEventParser.Keywords.NetworkTCPIP);
                var parser = session.Source.Kernel;

                Console.WriteLine($"DateTime: Protocol\tEvent\tConnectionID\tLocal > Remote\tPID\tProcessName\tFailureCode\tFailureMsg");

                parser.TcpIpConnect += e =>
                {
                    Console.ForegroundColor = ConsoleColor.Green;
                    var name = TryGetProcessName(e);
                    Console.WriteLine($"{e.TimeStamp}.{e.TimeStamp.Millisecond:D3}: TCP\tConnect\t{e.connid}\t{e.saddr}:{e.sport} -> {e.daddr}:{e.dport}\t{e.ProcessID}\t{name}");
                };

                parser.TcpIpConnectIPV6 += e =>
                {
                    Console.ForegroundColor = ConsoleColor.Green;
                    var name = TryGetProcessName(e);
                    Console.WriteLine($"{e.TimeStamp}.{e.TimeStamp.Millisecond:D3}: TCPv6\tConnect\t{e.connid}\t{e.saddr}:{e.sport} -> {e.daddr}:{e.dport}\t{e.ProcessID}\t{name}");
                };

                parser.TcpIpDisconnect += e =>
                {
                    Console.ForegroundColor = ConsoleColor.DarkYellow;
                    var name = TryGetProcessName(e);
                    Console.WriteLine($"{e.TimeStamp}.{e.TimeStamp.Millisecond:D3}: TCP\tDisconnect\t{e.connid}\t{e.saddr}:{e.sport} -> {e.daddr}:{e.dport}\t{e.ProcessID}\t{name}");
                };

                parser.TcpIpDisconnectIPV6 += e =>
                {
                    Console.ForegroundColor = ConsoleColor.DarkYellow;
                    var name = TryGetProcessName(e);
                    Console.WriteLine($"{e.TimeStamp}.{e.TimeStamp.Millisecond:D3}: TCPv6\tDisconnect\t{e.connid}\t{e.saddr}:{e.sport} -> {e.daddr}:{e.dport}\t{e.ProcessID}\t{name}");
                };

                parser.TcpIpFail += e =>
                {
                    Console.ForegroundColor = ConsoleColor.Red;
                    var name = TryGetProcessName(e);
                    Console.WriteLine($"{e.TimeStamp}.{e.TimeStamp.Millisecond:D3}: TCP\tFail\t\txxxx:xx - xxxx:xx\t{e.ProcessID}\t{name}\t{e.FailureCode}\t{e.FormattedMessage}");
                };

                parser.TcpIpRetransmit += e =>
                {
                    Console.ForegroundColor = ConsoleColor.Magenta;
                    var name = TryGetProcessName(e);
                    Console.WriteLine($"{e.TimeStamp}.{e.TimeStamp.Millisecond:D3}: TCP\tRetransmit\t{e.connid}\t{e.saddr}:{e.sport} -> {e.daddr}:{e.dport}\t{e.ProcessID}\t{name}");
                };

                parser.TcpIpRetransmitIPV6 += e =>
                {
                    Console.ForegroundColor = ConsoleColor.Magenta;
                    var name = TryGetProcessName(e);
                    Console.WriteLine($"{e.TimeStamp}.{e.TimeStamp.Millisecond:D3}: TCPv6\tRetransmit\t{e.connid}\t{e.saddr}:{e.sport} -> {e.daddr}:{e.dport}\t{e.ProcessID}\t{name}");
                };

                parser.UdpIpSend += e =>
                {
                    Console.ForegroundColor = ConsoleColor.Yellow;
                    var name = TryGetProcessName(e);
                    Console.WriteLine($"{e.TimeStamp}.{e.TimeStamp.Millisecond:D3}: UDP\tSend\t\t{e.saddr}:{e.sport} -> {e.daddr}:{e.dport}\t{e.ProcessID}\t{name}");
                };

                parser.UdpIpRecv += e =>
                {
                    Console.ForegroundColor = ConsoleColor.Yellow;
                    var name = TryGetProcessName(e);
                    Console.WriteLine($"{e.TimeStamp}.{e.TimeStamp.Millisecond:D3}: UDP\tRecv\t\t{e.daddr}:{e.dport} <- {e.saddr}:{e.sport}\t{e.ProcessID}\t{name}");
                };

                parser.UdpIpSendIPV6 += e =>
                {
                    Console.ForegroundColor = ConsoleColor.Yellow;
                    var name = TryGetProcessName(e);
                    Console.WriteLine($"{e.TimeStamp}.{e.TimeStamp.Millisecond:D3}: UDPv6\tSend\t{e.connid}\t{e.saddr}:{e.sport} -> {e.daddr}:{e.dport}\t{e.ProcessID}\t{name}");
                };

                parser.UdpIpRecvIPV6 += e =>
                {
                    Console.ForegroundColor = ConsoleColor.Yellow;
                    var name = TryGetProcessName(e);
                    Console.WriteLine($"{e.TimeStamp}.{e.TimeStamp.Millisecond:D3}: UDPv6\tRecv\t\t{e.daddr}:{e.dport} <- {e.saddr}:{e.sport}\t{e.ProcessID}\t{name}");
                };

                Task.Run(() => session.Source.Process());
                while (true) { Thread.Sleep(10); }
            }
        }
    }
}