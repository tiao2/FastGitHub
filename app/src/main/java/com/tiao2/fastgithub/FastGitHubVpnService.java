package com.tiao2.fastgithub;
import android.app.*;
import android.content.*;
import android.net.VpnService;
import android.os.*;
import android.util.Log;
import java.io.*;
import java.net.*;
import java.util.*;
import java.util.concurrent.*;
public class FastGitHubVpnService extends VpnService {
    private static final String TAG="FastGitHubVPN";
    private static final String VPN_ADDR="10.0.0.1";
    private static final int PREFIX=32, DNS_PORT=53, BUFSZ=4096;
    private static final long UPDATE_INTERVAL=1;
    private ParcelFileDescriptor tun;
    private ScheduledExecutorService scheduler;
    private volatile Map<String,String> hostMap;
    private volatile boolean running=false;
    @Override public void onCreate() {
        super.onCreate();
        hostMap=HostsLoader.loadFromAssets(this);
        Log.i(TAG, "初始 hosts 加载完成，条目数: "+hostMap.size());
        scheduler=Executors.newSingleThreadScheduledExecutor();
        scheduler.scheduleAtFixedRate(this::updateHosts, 0, UPDATE_INTERVAL, TimeUnit.HOURS);
    }
    @Override public int onStartCommand(Intent intent, int flags, int startId) {
        startForegroundService();
        startVpn();
        return START_STICKY;
    }
    private void startForegroundService() {
        String ch="fastgithub_vpn_channel";
        if (Build.VERSION.SDK_INT >= Build.VERSION_CODES.O) {
            NotificationChannel nc = new NotificationChannel(ch, "Fast GitHub VPN", NotificationManager.IMPORTANCE_LOW);
            NotificationManager nm = getSystemService(NotificationManager.class);
            if (nm != null) nm.createNotificationChannel(nc);
        }
        Intent i = new Intent(this, MainActivity.class);
        PendingIntent pi = PendingIntent.getActivity(this, 0, i, PendingIntent.FLAG_IMMUTABLE);
        Notification n = new Notification.Builder(this, ch)
                .setContentTitle("Fast GitHub 运行中")
                .setContentText("DNS劫持+路由优化")
                .setSmallIcon(android.R.drawable.ic_menu_share)
                .setContentIntent(pi)
                .build();
        startForeground(1, n);
    }
    private synchronized void startVpn() {
        try {
            Builder b = new Builder();
            b.addAddress(VPN_ADDR, PREFIX);
            b.addDnsServer(VPN_ADDR);
            Map<String,String> cur=hostMap;
            if (cur != null) {
                int count=0;
                for (String ip : cur.values()) {
                    if (ip != null && !ip.isEmpty()) {
                        try {
                            String[] parts = ip.split("\\.");
                            if (parts.length == 4) { b.addRoute(ip, 32); count++; }
                        } catch (Exception e) {}
                    }
                }
                Log.i(TAG, "添加 "+count+" 条 /32 路由");
            }
            b.setMtu(1500);
            b.setSession("Fast GitHub VPN");
            tun = b.establish();
            running = true;
            new Thread(this::handleDns).start();
            Log.i(TAG, "VPN 启动成功");
        } catch (Exception e) { Log.e(TAG, "VPN 启动失败", e); stopSelf(); }
    }
    private void handleDns() {
        try {
            FileInputStream in = new FileInputStream(tun.getFileDescriptor());
            FileOutputStream out = new FileOutputStream(tun.getFileDescriptor());
            byte[] buf = new byte[BUFSZ];
            while (running) {
                int len = in.read(buf);
                if (len < 28) continue;
                int ver = (buf[0] >> 4) & 0x0F;
                if (ver != 4) continue;
                int hlen = (buf[0] & 0x0F) * 4;
                if (len < hlen + 8) continue;
                if ((buf[9] & 0xFF) != 17) continue;
                int srcPort = ((buf[hlen] & 0xFF)<<8) | (buf[hlen+1] & 0xFF);
                int dstPort = ((buf[hlen+2] & 0xFF)<<8) | (buf[hlen+3] & 0xFF);
                if (dstPort != DNS_PORT) continue;
                int dnsOff = hlen + 8;
                int dnsLen = len - dnsOff;
                String domain = DnsPacketHandler.extractDomain(buf, dnsOff);
                String mapped = null;
                if (domain != null) {
                    String clean = domain.endsWith(".") ? domain.substring(0, domain.length()-1) : domain;
                    mapped = hostMap.get(clean);
                    Log.d(TAG, "DNS: "+clean+" -> "+(mapped!=null?mapped:"未命中"));
                }
                byte[] resp;
                if (mapped != null) {
                    DatagramPacket qp = new DatagramPacket(buf, dnsOff, dnsLen);
                    resp = DnsPacketHandler.buildAResponse(qp, dnsLen, mapped);
                } else {
                    DatagramPacket fwd = new DatagramPacket(buf, dnsOff, dnsLen, InetSocketAddress.createUnresolved("114.114.114.114", 53));
                    DatagramSocket sock = new DatagramSocket();
                    protect(sock);
                    sock.send(fwd);
                    byte[] rbuf = new byte[BUFSZ];
                    DatagramPacket recv = new DatagramPacket(rbuf, rbuf.length);
                    sock.receive(recv);
                    resp = new byte[recv.getLength()];
                    System.arraycopy(recv.getData(), 0, resp, 0, recv.getLength());
                    sock.close();
                }
                if (resp == null) continue;
                int total = hlen + 8 + resp.length;
                byte[] outPkt = new byte[total];
                System.arraycopy(buf, 0, outPkt, 0, hlen);
                for (int i=0;i<4;i++) { byte tmp=outPkt[12+i]; outPkt[12+i]=outPkt[16+i]; outPkt[16+i]=tmp; }
                outPkt[2] = (byte)((total>>8)&0xFF); outPkt[3] = (byte)(total&0xFF);
                outPkt[10]=0; outPkt[11]=0;
                int ipcs = ipChecksum(outPkt, hlen);
                outPkt[10] = (byte)((ipcs>>8)&0xFF); outPkt[11] = (byte)(ipcs&0xFF);
                int udpOff = hlen;
                outPkt[udpOff] = (byte)((dstPort>>8)&0xFF); outPkt[udpOff+1] = (byte)(dstPort&0xFF);
                outPkt[udpOff+2] = (byte)((srcPort>>8)&0xFF); outPkt[udpOff+3] = (byte)(srcPort&0xFF);
                int udpLen = 8 + resp.length;
                outPkt[udpOff+4] = (byte)((udpLen>>8)&0xFF); outPkt[udpOff+5] = (byte)(udpLen&0xFF);
                System.arraycopy(resp, 0, outPkt, udpOff+8, resp.length);
                int udpcs = udpChecksum(outPkt, hlen, udpOff, udpLen,
                        outPkt[12], outPkt[13], outPkt[14], outPkt[15],
                        outPkt[16], outPkt[17], outPkt[18], outPkt[19]);
                outPkt[udpOff+6] = (byte)((udpcs>>8)&0xFF); outPkt[udpOff+7] = (byte)(udpcs&0xFF);
                out.write(outPkt);
            }
        } catch (Exception e) { Log.e(TAG, "DNS异常", e); }
    }
    private int ipChecksum(byte[] pkt, int hlen) {
        int sum=0;
        for (int i=0;i<hlen;i+=2) sum += ((pkt[i]&0xFF)<<8) | (pkt[i+1]&0xFF);
        while ((sum>>16)!=0) sum = (sum&0xFFFF) + (sum>>16);
        return ~sum & 0xFFFF;
    }
    private int udpChecksum(byte[] pkt, int ipHlen, int udpOff, int udpLen,
                            byte s1,byte s2,byte s3,byte s4,
                            byte d1,byte d2,byte d3,byte d4) {
        int sum=0;
        sum += ((s1&0xFF)<<8)|(s2&0xFF); sum += ((s3&0xFF)<<8)|(s4&0xFF);
        sum += ((d1&0xFF)<<8)|(d2&0xFF); sum += ((d3&0xFF)<<8)|(d4&0xFF);
        sum += 17; sum += udpLen;
        int dlen=udpLen, off=udpOff;
        while (dlen>1) { sum += ((pkt[off]&0xFF)<<8)|(pkt[off+1]&0xFF); off+=2; dlen-=2; }
        if (dlen==1) sum += (pkt[off]&0xFF)<<8;
        while ((sum>>16)!=0) sum = (sum&0xFFFF) + (sum>>16);
        int res = ~sum & 0xFFFF;
        return res==0 ? 0xFFFF : res;
    }
    private void updateHosts() {
        Log.i(TAG, "开始更新 hosts...");
        Map<String,String> newMap = null;
        try {
            HttpURLConnection conn = (HttpURLConnection) new URL("https://raw.hellogithub.com/hosts").openConnection();
            conn.setConnectTimeout(8000); conn.setReadTimeout(8000);
            conn.connect();
            if (conn.getResponseCode() == HttpURLConnection.HTTP_OK) {
                String text = readAll(conn);
                newMap = parseHosts(text);
            }
            conn.disconnect();
        } catch (Exception e) { Log.w(TAG, "直连失败，尝试代理..."); }
        if (newMap == null || newMap.isEmpty()) newMap = ChallengeSolver.fetchViaProxy();
        if (newMap == null || newMap.isEmpty()) { Log.w(TAG, "所有更新失败"); return; }
        if (!newMap.equals(hostMap)) {
            hostMap = newMap;
            Log.i(TAG, "hosts 更新，条目: "+newMap.size());
            if (tun != null && running) restartVpn();
        } else Log.i(TAG, "无变化");
    }
    private synchronized void restartVpn() {
        Log.i(TAG, "重启 VPN 应用新路由...");
        running = false;
        if (tun != null) { try { tun.close(); } catch (Exception ignored) {} tun = null; }
        startVpn();
    }
    private String readAll(HttpURLConnection conn) {
        try (BufferedReader r = new BufferedReader(new InputStreamReader(conn.getInputStream()))) {
            StringBuilder sb = new StringBuilder(); String line;
            while ((line = r.readLine()) != null) sb.append(line).append("\n");
            return sb.toString();
        } catch (Exception e) { return ""; }
    }
    private Map<String,String> parseHosts(String text) {
        Map<String,String> map = new HashMap<>();
        for (String line : text.split("\n")) {
            line=line.trim();
            if (line.isEmpty() || line.startsWith("#")) continue;
            String[] p=line.split("\\s+");
            if (p.length>=2) {
                String ip=p[0];
                for (int i=1;i<p.length;i++) map.put(p[i], ip);
            }
        }
        return map;
    }
    @Override public void onRevoke() { stopVpn(); }
    private void stopVpn() {
        running = false;
        if (scheduler != null) scheduler.shutdownNow();
        if (tun != null) { try { tun.close(); } catch (Exception ignored) {} }
        stopForeground(true);
        stopSelf();
    }
    @Override public void onDestroy() { stopVpn(); super.onDestroy(); }
}
