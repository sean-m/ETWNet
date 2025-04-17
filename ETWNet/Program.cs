using Microsoft.Diagnostics.Tracing;
using Microsoft.Diagnostics.Tracing.Parsers;
using Microsoft.Diagnostics.Tracing.Session;
using System.Diagnostics;

namespace McETWNet {

    class Program {
        static void Main(string[] args)
        {
            // Local process cache to speed lookup later
            var processes = Process.GetProcesses()
                .ToDictionary(p => p.Id, p => p.ProcessName);

            string TryGetProcessName(TraceEvent evt)
            {
                if (!string.IsNullOrEmpty(evt.ProcessName))
                    return evt.ProcessName;
                return processes.TryGetValue(evt.ProcessID, out var name) ? name : string.Empty;
            }


            using (var session = new TraceEventSession(Environment.OSVersion.Version.Build >= 9200 ? "MyKernelSession" : KernelTraceEventParser.KernelSessionName))
            {
                session.EnableKernelProvider(KernelTraceEventParser.Keywords.NetworkTCPIP);

                // Microsoft-Windows-DNS-Client
                var dnsGuid = Guid.Parse("1C95126E-7EEA-49A9-A3FE-A378B03DDB4D");
                session.EnableProvider(dnsGuid, TraceEventLevel.Always);

                var dnsParser = session.Source.Dynamic;
                dnsParser.All += e =>
                {
                    // Query
                    switch (e.EventName) {
                        case "EventID(3006)":
                        case "EventID(3009)":
                            Console.ForegroundColor = ConsoleColor.Green;
                            Console.Write($"{e.TimeStamp.ToString("O")}: DNS ");
                            Console.WriteLine($"{e.EventName} {e.FormattedMessage}");
                            break;
                        case "EventID(3008)":
                        case "EventID(3020)":
                            Console.ForegroundColor = ConsoleColor.Blue;
                            Console.Write($"{e.TimeStamp.ToString("O")}: DNS ");
                            Console.WriteLine($"{e.EventName} {e.FormattedMessage}");
                            break;
                        case "EventID(3018)":
                            Console.ForegroundColor = ConsoleColor.Magenta;
                            Console.Write($"{e.TimeStamp.ToString("O")}: DNS ");
                            Console.WriteLine($"{e.EventName} {e.FormattedMessage} {e.ProcessName}");
                            break;
                    }
                    Console.ResetColor();
                };

                var parser = session.Source.Kernel;

                Console.WriteLine($"DateTime: Protocol\tEvent\tConnectionID\tLocal > Remote\tPID\tProcessName\tFailureCode\tFailureMsg");

                parser.TcpIpConnect += e =>
                {
                    Console.ForegroundColor = ConsoleColor.Green;
                    var name = TryGetProcessName(e);
                    Console.WriteLine($"{e.TimeStamp.ToString("O")}: TCP\tConnect\t{e.connid}\t{e.saddr}:{e.sport} -> {e.daddr}:{e.dport}\t{e.ProcessID}\t{name}");
                };

                parser.TcpIpConnectIPV6 += e =>
                {
                    Console.ForegroundColor = ConsoleColor.Green;
                    var name = TryGetProcessName(e);
                    Console.WriteLine($"{e.TimeStamp.ToString("O")}: TCPv6\tConnect\t{e.connid}\t{e.saddr}:{e.sport} -> {e.daddr}:{e.dport}\t{e.ProcessID}\t{name}");
                };

                parser.TcpIpDisconnect += e =>
                {
                    Console.ForegroundColor = ConsoleColor.DarkYellow;
                    var name = TryGetProcessName(e);
                    Console.WriteLine($"{e.TimeStamp.ToString("O")}: TCP\tDisconn\t{e.connid}\t{e.saddr}:{e.sport} -> {e.daddr}:{e.dport}\t{e.ProcessID}\t{name}");
                };

                parser.TcpIpDisconnectIPV6 += e =>
                {
                    Console.ForegroundColor = ConsoleColor.DarkYellow;
                    var name = TryGetProcessName(e);
                    Console.WriteLine($"{e.TimeStamp.ToString("O")}: TCPv6\tDisconn\t{e.connid}\t{e.saddr}:{e.sport} -> {e.daddr}:{e.dport}\t{e.ProcessID}\t{name}");
                };

                parser.TcpIpFail += e =>
                {
                    Console.ForegroundColor = ConsoleColor.Red;
                    var name = TryGetProcessName(e);
                    Console.WriteLine($"{e.TimeStamp.ToString("O")}: TCP\tFail\t\txxxx:xx - xxxx:xx\t{e.ProcessID}\t{name}\t{e.FailureCode}\t{e.FormattedMessage}");
                };

                parser.TcpIpRetransmit += e =>
                {
                    Console.ForegroundColor = ConsoleColor.Magenta;
                    var name = TryGetProcessName(e);
                    Console.WriteLine($"{e.TimeStamp.ToString("O")}: TCP\tRetr\t{e.connid}\t{e.saddr}:{e.sport} -> {e.daddr}:{e.dport}\t{e.ProcessID}\t{name}");
                };

                parser.TcpIpRetransmitIPV6 += e =>
                {
                    Console.ForegroundColor = ConsoleColor.Magenta;
                    var name = TryGetProcessName(e);
                    Console.WriteLine($"{e.TimeStamp.ToString("O")}: TCPv6\tRetr\t{e.connid}\t{e.saddr}:{e.sport} -> {e.daddr}:{e.dport}\t{e.ProcessID}\t{name}");
                };

                parser.UdpIpSend += e =>
                {
                    Console.ForegroundColor = ConsoleColor.Yellow;
                    var name = TryGetProcessName(e);
                    if (e.dport == 53)
                    {
                        //dns
                        var s = e;
                    }
                    Console.WriteLine($"{e.TimeStamp.ToString("O")}: UDP\tSend\t\t{e.saddr}:{e.sport} -> {e.daddr}:{e.dport}\t{e.ProcessID}\t{name}");
                };

                parser.UdpIpRecv += e =>
                {
                    Console.ForegroundColor = ConsoleColor.Yellow;
                    var name = TryGetProcessName(e);
                    Console.WriteLine($"{e.TimeStamp.ToString("O")}: UDP\tRecv\t\t{e.daddr}:{e.dport} <- {e.saddr}:{e.sport}\t{e.ProcessID}\t{name}");
                };

                parser.UdpIpSendIPV6 += e =>
                {
                    Console.ForegroundColor = ConsoleColor.Yellow;
                    var name = TryGetProcessName(e);
                    Console.WriteLine($"{e.TimeStamp.ToString("O")}: UDPv6\tSend\t{e.connid}\t{e.saddr}:{e.sport} -> {e.daddr}:{e.dport}\t{e.ProcessID}\t{name}");
                };

                parser.UdpIpRecvIPV6 += e =>
                {
                    Console.ForegroundColor = ConsoleColor.Yellow;
                    var name = TryGetProcessName(e);
                    Console.WriteLine($"{e.TimeStamp.ToString("O")}: UDPv6\tRecv\t\t{e.daddr}:{e.dport} <- {e.saddr}:{e.sport}\t{e.ProcessID}\t{name}");
                };


                Task.Run(() => session.Source.Process());
                while (true) { Thread.Sleep(100); }
            }
        }
    }
}