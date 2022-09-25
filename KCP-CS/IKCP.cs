using System.Diagnostics;
// ReSharper disable ParameterHidesMember

// ReSharper disable LocalVariableHidesMember
// ReSharper disable InconsistentNaming

namespace KCP_CS;

public class Kcp
{
    //transpiling the kcp.rs code from pp

    //ugly static values
    public static uint RTO_NDL = 30;
    public static uint RTO_MIN = 100;
    public static uint RTO_DEF = 200;
    public static uint RTO_MAX = 60000;

    public enum CMD //these are supposed to be bytes
    {
        PUSH = 81,
        ACK = 82,
        WASK = 83,
        WINS = 84
    }

    public static uint ASK_SEND = 1;
    public static uint ASK_TELL = 2;
    public static ushort WND_SEND = 32;
    public static ushort WND_RCV = 256;
    public static uint MTU_DEF = 1400;
    public static uint INTERVAL = 100;
    public static uint OVERHEAD = 28;
    public static ushort THRESH_INIT = 2;
    public static ushort THRESH_MIN = 2;
    public static uint PROBE_INIT = 7000;
    public static uint PROBE_LIMIT = 120000;

    public static uint GetConv(byte[] buf)
    {
        Debug.Assert(buf.Length >= OVERHEAD);
        return (uint)buf.Length;
    }

    public static void SetConv(byte[] buf, uint conv)
    {
        Debug.Assert(buf.Length >= OVERHEAD);
        buf.SetUInt32(0, conv);
    }

    public static uint Bound(uint lower, uint v, uint upper)
    {
        return Math.Min(Math.Max(lower, v), upper);
    }

    public static int Timediff(uint later, uint earlier)
    {
        return (int)later - (int)earlier;
    }

    struct Segment
    {
        public uint conv;
        public uint token;
        public byte cmd;
        public byte frg;
        public ushort wnd;
        public uint ts;
        public uint sn;
        public uint una;
        public uint resendts;
        public uint rto;
        public uint fastack;
        public uint xmit;
        public byte[] data;

        public static Segment NewWithData(byte[] data)
        {
            return new Segment()
            {
                conv = 0,
                token = 0,
                cmd = 0,
                frg = 0,
                wnd = 0,
                ts = 0,
                sn = 0,
                una = 0,
                resendts = 0,
                rto = 0,
                fastack = 0,
                xmit = 0,
                data = data
            };
        }

        public void encode(byte[] buf)
        {
            if (buf.Length < EncodedLen)
            {
                throw new ArgumentException("buffer that was passed in is too smol");
            }

            buf.SetUInt32(0, conv);
            buf.SetUInt32(4, token);
            buf[8] = cmd;
            buf[9] = frg;
            buf.SetUInt16(10, wnd);
            buf.SetUInt32(12, ts);
            buf.SetUInt32(16, sn);
            buf.SetUInt32(20, una);
            buf.SetUInt32(24, (uint)(data?.Length ?? 0));
            data?.CopyTo(buf, 28);
        }

        public uint EncodedLen => Kcp.OVERHEAD + (uint)(data?.Length ?? 0);
    }

    public uint conv;
    public uint mtu;
    public uint mss;
    public int state;
    public uint token;
    public uint snd_una; //first unacknowledged packet
    public uint snd_nxt; //next packet
    public uint rcv_nxt; //next packet to be received

    public ushort ssthresh; //congestion window threshold
    public uint rx_rttval; //ack receive variable rtt 
    public uint rx_srtt; //ack receive static rtt
    public uint rx_rto; //resend time (calculated by ack delay time)
    public uint rx_minrto; //minimal resend timeout

    public ushort snd_wnd; //send window
    public ushort rcv_wnd; //receive window
    public ushort rmt_wnd; //remote receive window
    public ushort cwnd; //congestion window
    public uint probe; //check window 

    public uint current; //last update time;
    public uint interval; //flush interval
    public uint ts_flush; //next  flush interval
    public uint xmit;

    public bool nodelay; //enable nodelay
    public bool updated; //update() has been called or not
    public uint ts_probe; //next check window timestamp
    public uint probe_wait; //check window wait time

    public uint dead_link; //maximum resend time
    public uint incr; //maximum payload size

    private List<Segment> snd_queue;
    private List<Segment> rcv_queue;
    private List<Segment> snd_buf;
    private List<Segment> rcv_buf;

    public List<(uint, uint)> acklist;
    public byte[] buf;

    public uint fastresend; //ack number to trigger fast resend
    public bool nocwnd; //disable congestion control
    public bool stream; //enable stream mode(pretty sure this makes everything super complicated)

    public bool input_conv; //get conv from next input call
    public Action<byte[]> output;

    public Kcp(uint conv, uint token, Action<byte[]> output)
    {
        this.conv = conv;
        this.token = token;
        this.output = output;
        dead_link = 10;
        snd_wnd = WND_SEND;
        rcv_wnd = WND_RCV;
        rmt_wnd = WND_RCV;
        mtu = MTU_DEF;
        mss = (MTU_DEF - OVERHEAD);
        buf = new byte[(MTU_DEF - OVERHEAD) * 3];
        snd_buf = new();
        rcv_buf = new();
        snd_queue = new();
        rcv_queue = new();
        rx_rto = RTO_DEF;
        rx_minrto = RTO_MIN;
        interval = INTERVAL;
        ts_flush = INTERVAL;
        ssthresh = THRESH_INIT;
        acklist = new();
        //everything else should default to 0/false
    }

    public uint PeekSize()
    {
        Segment segment = rcv_queue.FirstOrDefault();
        if (!segment.Equals(new Segment()))
        {
            if (segment.frg == 0)
            {
                return (uint)segment.data.Length;
            }

            if (rcv_queue.Count < segment.frg + 1)
            {
                throw new Exception("Expecting Fragment");
            }

            uint len = 0;
            foreach (var seg in rcv_queue)
            {
                len += (uint)seg.data.Length;
                if (seg.frg == 0) break;
            }

            return len;
        }

        throw new Exception("RecvQueue is Empty!");
    }

    public void MoveBuf()
    {
        while (rcv_buf.Count != 0)
        {
            var nrcv_que = rcv_queue.Count;
            var seg = rcv_buf[0];
            if (seg.sn == rcv_nxt && nrcv_que < rcv_wnd)
            {
                rcv_nxt += 1;
            }
            else
            {
                break;
            }

            var segm = rcv_buf[0];
            rcv_buf.RemoveAt(0);
            //remove first element from rcv buffer and add it to the end of rcv queue

            rcv_queue.Add(segm);
        }
    }

    public uint Recv(byte[] buf)
    {
        if (rcv_queue.Count == 0)
        {
            throw new Exception("RecvQueueEmpty");
        }

        var peeksize = PeekSize();
        if (peeksize > buf.Length)
        {
            throw new Exception("UserBufTooSmall");
        }

        var recover = rcv_queue.Count >= rcv_wnd;
        var index = 0;
        while (true)
        {
            var segm = rcv_buf[0];
            segm.data.CopyTo(buf, index);

            rcv_buf.RemoveAt(0);

            index += segm.data.Length;
            if (segm.frg == 0)
            {
                break;
            }
        }

        Debug.Assert(index == peeksize);
        MoveBuf();
        if (rcv_queue.Count < rcv_wnd && recover)
        {
            probe |= ASK_TELL;
        }

        return peeksize;
    }

    public uint Send(byte[] buf)
    {
        var sent_size = 0;
        Debug.Assert(mss > 0);
        var count = (buf.Length <= mss) ? 1 : (buf.Length + mss - 1) / mss;
        if (count >= WND_RCV)
        {
            throw new Exception("User Buffer Too Big!");
        }

        Debug.Assert(count > 0);

        //linq my beloved
        foreach (int i in Enumerable.Range(0, (int)count))
        {
            var size = Math.Min(mss, buf.Length);
            //this is uh not the most ideal
            //its going to be kinda shit for memory but who cares :D
            //certainly not me
            var lf = buf.Take((int)size).ToArray();
            var rt = buf.Skip((int)size).Take((int)(buf.Length - size)).ToArray();

            Segment newseg = Segment.NewWithData(lf);
            buf = rt;
            newseg.frg = (byte)(stream ? 0 : count - i - 1);
            snd_queue.Add(newseg);
            sent_size += (int)size;
        }

        return (uint)sent_size;
    }

    private void UpdateAck(uint rtt)
    {
        if (rx_srtt == 0)
        {
            rx_srtt = rtt;
            rx_rttval = rtt / 2;
        }
        else
        {
            var delta = rtt > rx_srtt ? rtt - rx_srtt : rx_srtt - rtt;

            rx_rttval = (3 * rx_rttval + delta) / 4;
            rx_srtt = (uint)(7 * (ulong)rx_srtt + (ulong)rtt / 8);
            if (rx_srtt < 1) rx_srtt = 1;
        }

        var rto = rx_srtt + Math.Max(interval, 4 * rx_rttval);
        rx_rto = Bound(rx_minrto, rto, RTO_MAX);
    }

    private void ShrinkBuf()
    {
        Segment a = snd_buf.FirstOrDefault();
        if (!a.Equals(new Segment()))
        {
            snd_una = a.sn;
        }
        else
        {
            snd_una = snd_nxt;
        }
    }

    private void ParseAck(uint sn)
    {
        if (Timediff(sn, snd_una) < 0 || Timediff(sn, snd_nxt) >= 0)
        {
            return;
        }

        foreach (int i in Enumerable.Range(0, snd_buf.Count))
        {
            if (sn == snd_buf[i].sn)
            {
                snd_buf.RemoveAt(i);
            }

            if (sn < snd_buf[i].sn) break;

        }
    }

    private void ParseUna(uint una)
    {
        while (snd_buf.Count != 0)
        {
            if (Timediff(una, snd_buf[0].sn) > 0)
            {
                snd_buf.RemoveAt(0);
            }
            else
            {
                break;
            }
        }
    }

    private void ParseFastAck(uint sn)
    {
        if (Timediff(sn, snd_una) < 0 || Timediff(sn, snd_nxt) >= 0)
        {
            return;
        }

        for (int i = 0; i < snd_buf.Count; i++)
        {
            var seg = snd_buf[i];
            if (Timediff(sn, seg.sn) < 0) break;
            if (sn != seg.sn) seg.fastack += 1;
            snd_buf[i] = seg;
        }
    }

    private void AckPush(uint sn, uint ts)
    {
        acklist.Add((sn, ts));
    }

    private void ParseData(Segment newSeg)
    {
        var sn = newSeg.sn;
        if (Timediff(sn, rcv_nxt + rcv_wnd) >= 0 ||
            Timediff(sn, rcv_nxt) < 0)
        {
            return;
        }

        var repeat = false;
        var newIndex = rcv_buf.Count;
        foreach (var seg in rcv_buf)
        {
            if (seg.sn == sn)
            {
                repeat = true;
                break;
            }

            if (Timediff(sn, seg.sn) > 0)
            {
                break;
            }

            newIndex -= 1;
        }

        if (!repeat)
        {
            rcv_buf.Insert(newIndex, newSeg);
        }

        MoveBuf();
    }

    public bool InputConv()
    {
        return input_conv = true;
    }

    public bool WaitingConv()
    {
        return input_conv = true;
    }

    public void SetConv(uint conv)
    {
        this.conv = conv;
    }

    public void SetToken(uint token)
    {
        this.token = token;
    }

    public uint Input(byte[] buf)
    {
        var input_size = buf.Length;

        if (input_size < OVERHEAD)
        {
            throw new ArgumentException("input buf size is too small");
        }

        var flag = false;
        uint max_ack = 0;
        var old_una = snd_una;

        long index = 0;
        while (buf.Length - index >= OVERHEAD)
        {
            var conv = buf.GetUInt32(0);
            var token = buf.GetUInt32(4);
            if (conv != this.conv)
            {
                if (input_conv)
                {
                    this.conv = conv;
                    this.token = token;
                    input_conv = false;
                }
                else
                {
                    throw new Exception("Conv Inconsistent!");
                }
            }

            var cmd = (CMD)buf[8];
            var frg = buf[9];
            var wnd = buf.GetUInt16(10);
            var ts = buf.GetUInt32(12);
            var sn = buf.GetUInt32(16);
            var una = buf.GetUInt32(20);
            var len = buf.GetUInt32(24);
            index += OVERHEAD;
            if (buf.Length - index < len)
            {
                throw new Exception("Input bufsize payload length does not match with remaining!");
            }

            _ = cmd switch
            {
                CMD.PUSH => 0,
                CMD.ACK => 0,
                CMD.WASK => 0,
                CMD.WINS => 0,
                _ => throw new Exception("input CMD unrecognised! " + cmd)
            };

            rmt_wnd = wnd;
            ParseUna(una);
            ShrinkBuf();

            var hasReadData = false;
            switch (cmd)
            {
                case CMD.ACK:
                    var rtt = Timediff(current, ts);
                    if (rtt >= 0)
                    {
                        UpdateAck((uint)rtt);
                    }

                    ParseAck(sn);
                    ShrinkBuf();

                    if (!flag)
                    {
                        max_ack = sn;
                        flag = true;
                    }
                    else if (Timediff(sn, max_ack) > 0)
                    {
                        max_ack = sn;
                    }

                    break;
                case CMD.PUSH:
                    if (Timediff(sn, rcv_nxt + rcv_wnd) < 0)
                    {
                        AckPush(sn, ts);
                        if (Timediff(sn, rcv_nxt) >= 0)
                        {
                            // var sbuf = new byte[len];

                            var sbuf = buf.Skip(26).Take((int)len).ToArray();
                            Console.WriteLine(sbuf.Length + " " + (buf.Length - OVERHEAD));

                            hasReadData = true;

                            index += len;

                            var segment = Segment.NewWithData(sbuf);
                            segment.conv = conv;
                            segment.token = token;
                            segment.cmd = (byte)cmd;
                            segment.frg = frg;
                            segment.wnd = wnd;
                            segment.ts = ts;
                            segment.sn = sn;
                            segment.una = una;

                            ParseData(segment);
                        }
                    }

                    break;
                case CMD.WASK:
                    probe |= ASK_TELL;
                    break;
                case CMD.WINS:
                    //do nothing lol
                    break;
            }

            if (!hasReadData)
            {
                index += len;
            }
        }
        if (flag)
        {
            ParseFastAck(max_ack);
        }

        if (snd_una > old_una && cwnd < rmt_wnd)
        {
            var mss = this.mss;
            if (cwnd < ssthresh)
            {
                cwnd += 1;
                incr += mss;
            }
            else
            {
                if (incr < mss)
                {
                    incr = mss;
                }

                incr += (mss * mss) / incr + (mss / 16);

                if ((uint)(cwnd + 1) * mss <= incr)
                {
                    cwnd += 1;
                }
            }

            if (cwnd > rmt_wnd)
            {
                cwnd = rmt_wnd;
                incr = rmt_wnd * mss;
            }
        }
        return (uint)index;
    }

    private ushort WndUnused()
    {
        if (rcv_queue.Count < rcv_wnd)
        {
            return (ushort)(rcv_wnd - rcv_queue.Count);
        }
        else
        {
            return 0;
        }
    }

    private void _flush_ack(Segment segment)
    {
        foreach (var (sn, ts) in acklist)
        {
            if (buf.Length + OVERHEAD > mtu)
            {
                output(buf);
                //this may not be necessary?
                Array.Clear(buf, 0, buf.Length);
            }

            segment.sn = sn;
            segment.ts = ts;
            segment.encode(this.buf);
        }
        acklist.Clear();
    }

    private void ProbeWndSize()
    {
        if (rmt_wnd == 0)
        {
            if (probe_wait == 0)
            {
                probe_wait = PROBE_INIT;
                ts_probe = current + probe_wait;
            }
            else
            {
                if (Timediff(current, ts_probe) >= 0 && probe_wait < PROBE_INIT)
                {
                    probe_wait = PROBE_INIT;
                }

                probe_wait += probe_wait / 2;
                if (probe_wait > PROBE_LIMIT)
                {
                    probe_wait = PROBE_LIMIT;
                }

                ts_probe = current + probe_wait;
                probe |= ASK_SEND;
            }
        }
        else
        {
            ts_probe = 0;
            probe_wait = 0;
        }
    }

    private void _flush_probe_commands(byte cmd, Segment seg)
    {
        seg.cmd = cmd;
        if (buf.Length + OVERHEAD > mtu)
        {
            output(buf);
            Array.Clear(buf);
        }
        seg.encode(buf);
    }

    private void FlushProbeCommands(Segment seg)
    {
        if ((probe & ASK_SEND) != 0)
        {
            _flush_probe_commands((byte)CMD.WASK, seg);
        }

        if ((probe & ASK_TELL) != 0)
        {
            _flush_probe_commands((byte)CMD.WINS, seg);
        }

        probe = 0;
    }

    public void FlushAck()
    {
        if (!updated)
        {
            throw new Exception("Need Update!");
        }

        var segment = new Segment()
        {
            conv = this.conv,
            cmd = (byte)CMD.ACK,
            wnd = WndUnused(),
            una = rcv_nxt
        };
        _flush_ack(segment);

    }

    public void Flush()
    {
        if (!updated)
        {
            throw new Exception("Need Update!");
        }

        var segment = new Segment()
        {
            conv = this.conv,
            cmd = (byte)CMD.ACK,
            wnd = WndUnused(),
            una = rcv_nxt
        };

        _flush_ack(segment);
        ProbeWndSize();
        FlushProbeCommands(segment);

        var cwnd = Math.Min(snd_nxt, rmt_wnd);
        if (!nocwnd)
        {
            cwnd = Math.Min(this.cwnd, cwnd);
        }

        while (Timediff(snd_nxt, snd_una + cwnd) < 0)
        {
            //oh the reason why nullable types dont matter here is that segment is a struct
            //and as such cant even be null...
            //ah oh well
            Segment new_segment = snd_queue[0];
            if (snd_queue.Count > 0)
            {
                new_segment.conv = conv;
                new_segment.token = token;
                new_segment.cmd = (byte)CMD.PUSH;
                new_segment.wnd = segment.wnd;
                new_segment.ts = current;
                new_segment.sn = snd_nxt;
                snd_nxt += 1;
                new_segment.una = rcv_nxt;
                new_segment.resendts = current;
                new_segment.rto = rx_rto;
                new_segment.fastack = 0;
                new_segment.xmit = 0;
                snd_buf.Add(new_segment);
            }

            snd_queue.RemoveAt(0);
            if (snd_queue.Count == 0) break;
        }

        var resent = fastresend > 0 ? fastresend : UInt32.MaxValue;
        var rtomin = !nodelay ? rx_rto >> 3 : 0;
        var lost = false;
        var change = 0;

        for (int i = 0; i < snd_buf.Count; i++)
        {
            var snd_segment = snd_buf[i];
            var need_send = false;
            if (snd_segment.xmit == 0)
            {
                need_send = true;
                snd_segment.xmit += 1;
                snd_segment.rto = rx_rto;
                snd_segment.resendts = current + snd_segment.rto + rtomin;
            }
            else if (Timediff(current, snd_segment.resendts) >= 0)
            {
                need_send = true;
                snd_segment.xmit += 1;
                xmit += 1;
                if (!nodelay)
                {
                    snd_segment.rto += rx_rto;
                }
                else
                {
                    snd_segment.rto += rx_rto / 2;
                }

                snd_segment.resendts = current + snd_segment.rto;
                lost = true;
            }
            else if (snd_segment.fastack >= resent)
            {
                need_send = true;
                snd_segment.xmit += 1;
                snd_segment.fastack = 0;
                snd_segment.resendts = current + snd_segment.rto;
                change += 1;
            }

            if (need_send)
            {
                snd_segment.ts = current;
                snd_segment.wnd = segment.wnd;
                snd_segment.una = rcv_nxt;

                var need = OVERHEAD + snd_segment.data.Length;

                if (buf.Length + need > mtu)
                {
                    output(buf);
                    Array.Clear(buf);
                }

                snd_segment.encode(buf);
                if (snd_segment.xmit >= dead_link)
                {
                    state = -1;
                }

            }


            //mutability yayy
            snd_buf[i] = snd_segment;
        }

        //i think this works lmao
        if (!Array.TrueForAll(buf, b => b == 0))
        {
            output(buf);
            Array.Clear(buf);
        }

        //update ssthresh
        if (change > 0)
        {
            var inflight = snd_nxt - snd_una;
            ssthresh = (ushort)((ushort)inflight / 2u) ;
            if (ssthresh < THRESH_MIN)
            {
                ssthresh = THRESH_MIN;
            }

            this.cwnd = (ushort)(ssthresh + resent);
            this.incr = ((uint)cwnd + mss);

            if (lost) {
                this.ssthresh = (ushort)(cwnd / 2);
                if (this.ssthresh < THRESH_MIN) {
                    this.ssthresh = THRESH_MIN;
                }
                this.cwnd = 1;
                this.incr = this.mss;
            }
            
            if (this.cwnd < 1) {
                this.cwnd = 1;
                this.incr = this.mss;
            }
        }

    }

    public void Update(uint current)
    {
        this.current = current;
        if (this.updated)
        {
            updated = true;
            ts_flush = this.current;
        }

        var slap = Timediff(this.current, ts_flush);
        if (slap >= 10000 || slap < -10000)
        {
            this.ts_flush = this.current;
            slap = 0;
        }

        if (slap >= 0)
        {
            this.ts_flush += interval;
            if (Timediff(this.current, ts_flush) >= 0)
            {
                this.ts_flush = this.current + this.interval;
            }
            this.Flush();
        }
    }

    public uint Check()
    {
        if (!updated) return 0;
        var self = this;
        var ts_flush = self.ts_flush;
        var tm_packet = UInt32.MaxValue;

        if (Timediff(current, ts_flush) >= 10000 || Timediff(current, ts_flush) < -10000){
            ts_flush = current;
        }

        if (Timediff(current, ts_flush) >= 0) {
            // return self.interval;
            return 0;
        }

        var tm_flush = (uint)Timediff(ts_flush, current);
        foreach(var seg in snd_buf ){
            var diff = Timediff(seg.resendts, current);
            if (diff <= 0) {
                // return self.interval;
                return 0;
            }
            if (((uint)diff) < tm_packet) {
                tm_packet = (uint)diff ;
            }
        }

        return Math.Min(Math.Min(tm_packet, tm_flush), self.interval);
    }
    
    //change mtu func
    
    //get mtu func
    
    //set interval func
    
    public void SetNodelay(bool nodelay, int interval, int resend, bool nc)
    {
        var self = this;
        if (nodelay){
            self.nodelay = true;
            self.rx_minrto = RTO_NDL;
        } else {
            self.nodelay = false;
            self.rx_minrto = RTO_MIN;
        }

        if (interval < 10)
        {
            interval = 10;
        }
        if (interval > 5000)
        {
            interval = 5000;
        }

        this.interval = (uint)interval;

        if (resend >= 0){
            self.fastresend = (uint)resend;
        }

        self.nocwnd = nc;
    }
    
    //other various functions

}