// See https://aka.ms/new-console-template for more information

using System.Net;
using System.Net.Sockets;
using System.Text;
using System.Text.Json;
using System.Text.Json.Serialization;

namespace KCP_CS;
public class Program
{
    public static UdpClient sock;
    public static Kcp kcp;
    public static void Main(string[] args)
    {

        var ipep = new IPEndPoint(IPAddress.Loopback, 22103);
        sock = new UdpClient(ipep);
        
        kcp = new Kcp(0, 0, (byte[] bytes) =>
        {
            Console.WriteLine("Sending {f} bytes", bytes.Length);
            sock.Send(bytes, bytes.Length, ipep);
        });
        while (true)
        {
            Task.Run(BackgroundUpdate).Wait();
        }
        
    }

    private static async Task BackgroundUpdate()
    {
        var data = await sock.ReceiveAsync();
        try
        {
            kcp.Input(data.Buffer);
            while (true)
            {
                try
                {
                    kcp.Update((uint)DateTime.Now.Millisecond);
                    var len = kcp.PeekSize();
                    var buf = new byte[len];
                    
                    Console.WriteLine(len);
                    kcp.Recv(buf);
                    Console.WriteLine($"Recieved {buf.Length} bytes");
                    Console.WriteLine(Encoding.Default.GetString(buf));
                }
                catch (Exception e)
                {
                    Console.WriteLine(e.Message);
                    break;
                }
            }

        }
        catch(Exception e)
        {
            //Console.WriteLine(e);
        }

        await Task.Yield();
        // Task.Run(BackgroundUpdate);
    }

}