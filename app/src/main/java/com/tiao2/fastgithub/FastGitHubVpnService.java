package com.tiao2.fastgithub;
import android.app.Notification;
import android.app.NotificationChannel;
import android.app.NotificationManager;
import android.app.PendingIntent;
import android.content.Intent;
import android.net.VpnService;
import android.os.Build;
import android.os.ParcelFileDescriptor;
import android.util.Log;
import java.io.FileInputStream;
import java.io.FileOutputStream;
import java.net.DatagramPacket;
import java.net.DatagramSocket;
import java.net.InetSocketAddress;
import java.util.Map;
import java.util.concurrent.ExecutorService;
import java.util.concurrent.Executors;
public class FastGitHubVpnService extends VpnService {
    private static final String TAG = "FastGitHubVPN";
    private static final String VPN_ADDRESS = "10.0.0.1";
    private static final int VPN_PREFIX = 32;
    private static final String DNS_SERVER = "114.114.114.114";
    private static final int DNS_PORT = 53;
    private static final int BUFFER_SIZE = 4096;
    private ParcelFileDescriptor vpnInterface;
    private ExecutorService executor;
    private Map<String, String> hostMap;
    private volatile boolean running = false;
    @Override
    public void onCreate() {
        super.onCreate();
        hostMap = HostsLoader.loadFromAssets(this);
    }
    @Override
    public int onStartCommand(Intent intent, int flags, int startId) {
        startForegroundService();
        startVpn();
        return START_STICKY;
    }
    private void startForegroundService() {
        String channelId = "fastgithub_vpn_channel";
        if (Build.VERSION.SDK_INT >= Build.VERSION_CODES.O) {
            NotificationChannel channel = new NotificationChannel(
                    channelId,
                    "Fast GitHub VPN",
                    NotificationManager.IMPORTANCE_LOW
            );
            NotificationManager manager = getSystemService(NotificationManager.class);
            if (manager != null) {
                manager.createNotificationChannel(channel);
            }
        }
        Intent intent = new Intent(this, MainActivity.class);
        PendingIntent pendingIntent = PendingIntent.getActivity(
                this, 0, intent, PendingIntent.FLAG_IMMUTABLE
        );
        Notification notification = new Notification.Builder(this, channelId)
                .setContentTitle("Fast GitHub 运行中")
                .setContentText("已劫持 GitHub 相关 DNS 解析")
                .setSmallIcon(android.R.drawable.ic_menu_share)
                .setContentIntent(pendingIntent)
                .build();
        startForeground(1, notification);
    }
    private void startVpn() {
        try {
            Builder builder = new Builder();
            builder.addAddress(VPN_ADDRESS, VPN_PREFIX);
            builder.addDnsServer(VPN_ADDRESS);
            builder.addRoute("0.0.0.0", 0);
            builder.setMtu(1500);
            builder.setSession("Fast GitHub VPN");
            vpnInterface = builder.establish();
            running = true;
            executor = Executors.newSingleThreadExecutor();
            executor.submit(this::handleTraffic);
            Log.i(TAG, "VPN 启动成功");
        } catch (Exception e) {
            Log.e(TAG, "VPN 启动失败", e);
            stopSelf();
        }
    }
    private void handleTraffic() {
        try {
            FileInputStream in = new FileInputStream(vpnInterface.getFileDescriptor());
            FileOutputStream out = new FileOutputStream(vpnInterface.getFileDescriptor());
            byte[] buffer = new byte[BUFFER_SIZE];
            DatagramSocket upstreamSocket = new DatagramSocket();
            protect(upstreamSocket);
            while (running) {
                int length = in.read(buffer);
                if (length <= 0) continue;
                if (length < 20) continue;
                int version = (buffer[0] >> 4) & 0x0F;
                if (version != 4) continue;
                int headerLen = (buffer[0] & 0x0F) * 4;
                if (length < headerLen + 8) continue;
                int protocol = buffer[9] & 0xFF;
                if (protocol != 17) continue;
                int srcPort = ((buffer[headerLen] & 0xFF) << 8) | (buffer[headerLen + 1] & 0xFF);
                int dstPort = ((buffer[headerLen + 2] & 0xFF) << 8) | (buffer[headerLen + 3] & 0xFF);
                if (dstPort != DNS_PORT) {
                    out.write(buffer, 0, length);
                    continue;
                }
                int dnsOffset = headerLen + 8;
                int dnsLen = length - dnsOffset;
                String domain = DnsPacketHandler.extractDomain(buffer, dnsOffset);
                String mappedIp = null;
                if (domain != null) {
                    String cleanDomain = domain.endsWith(".") ?
                            domain.substring(0, domain.length() - 1) : domain;
                    mappedIp = hostMap.get(cleanDomain);
                    Log.d(TAG, "DNS 查询: " + cleanDomain + " -> " + (mappedIp != null ? mappedIp : "转发上游"));
                }
                byte[] response;
                if (mappedIp != null) {
                    DatagramPacket queryPacket = new DatagramPacket(buffer, dnsOffset, dnsLen);
                    response = DnsPacketHandler.buildAResponse(queryPacket, dnsLen, mappedIp);
                } else {
                    DatagramPacket forwardPacket = new DatagramPacket(
                            buffer, dnsOffset, dnsLen,
                            InetSocketAddress.createUnresolved(DNS_SERVER, DNS_PORT)
                    );
                    upstreamSocket.send(forwardPacket);
                    byte[] respBuf = new byte[BUFFER_SIZE];
                    DatagramPacket recvPacket = new DatagramPacket(respBuf, respBuf.length);
                    upstreamSocket.receive(recvPacket);
                    response = new byte[recvPacket.getLength()];
                    System.arraycopy(recvPacket.getData(), 0, response, 0, recvPacket.getLength());
                }
                if (response != null) {
                    int totalLen = headerLen + 8 + response.length;
                    byte[] outPacket = new byte[totalLen];
                    System.arraycopy(buffer, 0, outPacket, 0, headerLen);
                    outPacket[2] = (byte) ((totalLen >> 8) & 0xFF);
                    outPacket[3] = (byte) (totalLen & 0xFF);
                    for (int i = 0; i < 4; i++) {
                        byte tmp = outPacket[12 + i];
                        outPacket[12 + i] = outPacket[16 + i];
                        outPacket[16 + i] = tmp;
                    }
                    outPacket[10] = 0;
                    outPacket[11] = 0;
                    int sum = 0;
                    for (int i = 0; i < headerLen; i += 2) {
                        sum += ((outPacket[i] & 0xFF) << 8) | (outPacket[i + 1] & 0xFF);
                    }
                    while ((sum >> 16) != 0) sum = (sum & 0xFFFF) + (sum >> 16);
                    outPacket[10] = (byte) (~sum >> 8);
                    outPacket[11] = (byte) (~sum & 0xFF);
                    int udpOffset = headerLen;
                    outPacket[udpOffset] = (byte) ((dstPort >> 8) & 0xFF);
                    outPacket[udpOffset + 1] = (byte) (dstPort & 0xFF);
                    outPacket[udpOffset + 2] = (byte) ((srcPort >> 8) & 0xFF);
                    outPacket[udpOffset + 3] = (byte) (srcPort & 0xFF);
                    int udpLen = 8 + response.length;
                    outPacket[udpOffset + 4] = (byte) ((udpLen >> 8) & 0xFF);
                    outPacket[udpOffset + 5] = (byte) (udpLen & 0xFF);
                    outPacket[udpOffset + 6] = 0;
                    outPacket[udpOffset + 7] = 0;
                    System.arraycopy(response, 0, outPacket, udpOffset + 8, response.length);
                    outPacket[udpOffset + 6] = 0;
                    outPacket[udpOffset + 7] = 0;
                    out.write(outPacket);
                }
            }
        } catch (Exception e) {
            Log.e(TAG, "流量处理异常", e);
        }
    }
    @Override
    public void onRevoke() {
        stopVpn();
    }
    private void stopVpn() {
        running = false;
        if (executor != null) {
            executor.shutdownNow();
        }
        if (vpnInterface != null) {
            try {
                vpnInterface.close();
            } catch (Exception ignored) {}
        }
        stopForeground(true);
        stopSelf();
    }
    @Override
    public void onDestroy() {
        stopVpn();
        super.onDestroy();
    }
}
