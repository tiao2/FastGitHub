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

import java.io.BufferedReader;
import java.io.FileInputStream;
import java.io.FileOutputStream;
import java.io.InputStreamReader;
import java.net.DatagramPacket;
import java.net.HttpURLConnection;
import java.net.InetSocketAddress;
import java.net.URL;
import java.util.HashMap;
import java.util.Map;
import java.util.concurrent.Executors;
import java.util.concurrent.ScheduledExecutorService;
import java.util.concurrent.TimeUnit;

public class FastGitHubVpnService extends VpnService {
    private static final String TAG = "FastGitHubVPN";
    private static final String VPN_ADDRESS = "10.0.0.1";
    private static final int VPN_PREFIX = 32;
    private static final int DNS_PORT = 53;
    private static final int BUFFER_SIZE = 4096;
    private static final long UPDATE_INTERVAL_HOURS = 1;

    private ParcelFileDescriptor vpnInterface;
    private ScheduledExecutorService scheduler;
    private volatile Map<String, String> hostMap;
    private volatile boolean running = false;

    @Override
    public void onCreate() {
        super.onCreate();
        hostMap = HostsLoader.loadFromAssets(this);
        Log.i(TAG, "初始 hosts 加载完成，条目数: " + hostMap.size());
        scheduler = Executors.newSingleThreadScheduledExecutor();
        scheduler.scheduleAtFixedRate(this::updateHostsFromNetwork, 0, UPDATE_INTERVAL_HOURS, TimeUnit.HOURS);
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
                .setContentText("DNS 劫持已启动")
                .setSmallIcon(android.R.drawable.ic_menu_share)
                .setContentIntent(pendingIntent)
                .build();
        startForeground(1, notification);
    }

    private synchronized void startVpn() {
        try {
            Builder builder = new Builder();
            builder.addAddress(VPN_ADDRESS, VPN_PREFIX);
            builder.addDnsServer(VPN_ADDRESS);   // 将 DNS 指向本地
            // 重要：不添加任何路由，只劫持 DNS 查询，TCP 流量走物理网络
            builder.setMtu(1500);
            builder.setSession("Fast GitHub DNS");
            vpnInterface = builder.establish();
            running = true;
            new Thread(this::handleDnsTraffic).start();
            Log.i(TAG, "VPN 启动成功（仅 DNS 模式）");
        } catch (Exception e) {
            Log.e(TAG, "VPN 启动失败", e);
            stopSelf();
        }
    }

    private void handleDnsTraffic() {
        try {
            FileInputStream in = new FileInputStream(vpnInterface.getFileDescriptor());
            FileOutputStream out = new FileOutputStream(vpnInterface.getFileDescriptor());
            byte[] buffer = new byte[BUFFER_SIZE];

            while (running) {
                int length = in.read(buffer);
                if (length <= 0) continue;
                if (length < 28) continue;

                int version = (buffer[0] >> 4) & 0x0F;
                if (version != 4) continue;

                int headerLen = (buffer[0] & 0x0F) * 4;
                if (length < headerLen + 8) continue;

                int protocol = buffer[9] & 0xFF;
                if (protocol != 17) continue;

                int srcPort = ((buffer[headerLen] & 0xFF) << 8) | (buffer[headerLen + 1] & 0xFF);
                int dstPort = ((buffer[headerLen + 2] & 0xFF) << 8) | (buffer[headerLen + 3] & 0xFF);
                if (dstPort != DNS_PORT) continue;

                int dnsOffset = headerLen + 8;
                int dnsLen = length - dnsOffset;

                String domain = DnsPacketHandler.extractDomain(buffer, dnsOffset);
                String mappedIp = null;
                if (domain != null) {
                    String cleanDomain = domain.endsWith(".") ?
                            domain.substring(0, domain.length() - 1) : domain;
                    Map<String, String> currentMap = hostMap;
                    mappedIp = currentMap.get(cleanDomain);
                    Log.d(TAG, "DNS 查询: " + cleanDomain + " -> " + (mappedIp != null ? mappedIp : "未命中"));
                }

                byte[] response;
                if (mappedIp != null) {
                    DatagramPacket queryPacket = new DatagramPacket(buffer, dnsOffset, dnsLen);
                    response = DnsPacketHandler.buildAResponse(queryPacket, dnsLen, mappedIp);
                } else {
                    // 转发给上游 DNS（114.114.114.114）
                    DatagramPacket forwardPacket = new DatagramPacket(
                            buffer, dnsOffset, dnsLen,
                            InetSocketAddress.createUnresolved("114.114.114.114", 53)
                    );
                    java.net.DatagramSocket upstream = new java.net.DatagramSocket();
                    protect(upstream);
                    upstream.send(forwardPacket);
                    byte[] respBuf = new byte[BUFFER_SIZE];
                    DatagramPacket recvPacket = new DatagramPacket(respBuf, respBuf.length);
                    upstream.receive(recvPacket);
                    response = new byte[recvPacket.getLength()];
                    System.arraycopy(recvPacket.getData(), 0, response, 0, recvPacket.getLength());
                    upstream.close();
                }

                if (response != null) {
                    // 构造 IP + UDP 响应包，写回 TUN
                    int totalLen = headerLen + 8 + response.length;
                    byte[] outPacket = new byte[totalLen];
                    System.arraycopy(buffer, 0, outPacket, 0, headerLen);

                    // 交换 IP 源和目标
                    for (int i = 0; i < 4; i++) {
                        byte tmp = outPacket[12 + i];
                        outPacket[12 + i] = outPacket[16 + i];
                        outPacket[16 + i] = tmp;
                    }

                    // IP 总长度
                    outPacket[2] = (byte) ((totalLen >> 8) & 0xFF);
                    outPacket[3] = (byte) (totalLen & 0xFF);

                    // IP 校验和
                    outPacket[10] = 0;
                    outPacket[11] = 0;
                    int ipChecksum = computeIpChecksum(outPacket, headerLen);
                    outPacket[10] = (byte) ((ipChecksum >> 8) & 0xFF);
                    outPacket[11] = (byte) (ipChecksum & 0xFF);

                    // UDP 头（交换端口）
                    int udpOffset = headerLen;
                    outPacket[udpOffset] = (byte) ((dstPort >> 8) & 0xFF);
                    outPacket[udpOffset + 1] = (byte) (dstPort & 0xFF);
                    outPacket[udpOffset + 2] = (byte) ((srcPort >> 8) & 0xFF);
                    outPacket[udpOffset + 3] = (byte) (srcPort & 0xFF);

                    int udpLen = 8 + response.length;
                    outPacket[udpOffset + 4] = (byte) ((udpLen >> 8) & 0xFF);
                    outPacket[udpOffset + 5] = (byte) (udpLen & 0xFF);

                    // DNS 数据
                    System.arraycopy(response, 0, outPacket, udpOffset + 8, response.length);

                    // UDP 校验和（含伪头部）
                    int udpChecksum = computeUdpChecksum(
                            outPacket, headerLen, udpOffset, udpLen,
                            outPacket[12], outPacket[13], outPacket[14], outPacket[15],
                            outPacket[16], outPacket[17], outPacket[18], outPacket[19]
                    );
                    outPacket[udpOffset + 6] = (byte) ((udpChecksum >> 8) & 0xFF);
                    outPacket[udpOffset + 7] = (byte) (udpChecksum & 0xFF);

                    out.write(outPacket);
                }
            }
        } catch (Exception e) {
            Log.e(TAG, "DNS 处理异常", e);
        }
    }

    private int computeIpChecksum(byte[] packet, int headerLen) {
        int sum = 0;
        for (int i = 0; i < headerLen; i += 2) {
            sum += ((packet[i] & 0xFF) << 8) | (packet[i + 1] & 0xFF);
        }
        while ((sum >> 16) != 0) {
            sum = (sum & 0xFFFF) + (sum >> 16);
        }
        return ~sum & 0xFFFF;
    }

    private int computeUdpChecksum(byte[] packet, int ipHeaderLen, int udpOffset, int udpLen,
                                   byte src1, byte src2, byte src3, byte src4,
                                   byte dst1, byte dst2, byte dst3, byte dst4) {
        int sum = 0;
        sum += ((src1 & 0xFF) << 8) | (src2 & 0xFF);
        sum += ((src3 & 0xFF) << 8) | (src4 & 0xFF);
        sum += ((dst1 & 0xFF) << 8) | (dst2 & 0xFF);
        sum += ((dst3 & 0xFF) << 8) | (dst4 & 0xFF);
        sum += 17; // UDP protocol
        sum += udpLen;

        int dataLen = udpLen;
        int offset = udpOffset;
        while (dataLen > 1) {
            sum += ((packet[offset] & 0xFF) << 8) | (packet[offset + 1] & 0xFF);
            offset += 2;
            dataLen -= 2;
        }
        if (dataLen == 1) {
            sum += (packet[offset] & 0xFF) << 8;
        }
        while ((sum >> 16) != 0) {
            sum = (sum & 0xFFFF) + (sum >> 16);
        }
        int result = ~sum & 0xFFFF;
        return result == 0 ? 0xFFFF : result;
    }

    private void updateHostsFromNetwork() {
        Log.i(TAG, "开始更新 hosts...");
        Map<String, String> newMap = null;

        try {
            URL url = new URL("https://raw.hellogithub.com/hosts");
            HttpURLConnection conn = (HttpURLConnection) url.openConnection();
            conn.setConnectTimeout(8000);
            conn.setReadTimeout(8000);
            conn.setRequestMethod("GET");
            conn.connect();
            if (conn.getResponseCode() == HttpURLConnection.HTTP_OK) {
                String text = readAll(conn);
                newMap = parseHostsFromText(text);
            }
            conn.disconnect();
        } catch (Exception e) {
            Log.w(TAG, "直连失败，无代理降级");
        }

        if (newMap == null || newMap.isEmpty()) {
            Log.w(TAG, "所有更新方式均失败，保持当前 hosts");
            return;
        }

        boolean changed = !newMap.equals(hostMap);
        if (changed) {
            hostMap = newMap;
            Log.i(TAG, "hosts 已更新，条目数: " + newMap.size());
            if (vpnInterface != null && running) {
                restartVpn();
            }
        } else {
            Log.i(TAG, "hosts 无变化，无需重启");
        }
    }

    private synchronized void restartVpn() {
        Log.i(TAG, "正在重启 VPN 以应用新路由...");
        running = false;
        if (vpnInterface != null) {
            try {
                vpnInterface.close();
            } catch (Exception e) {
                Log.e(TAG, "关闭旧 VPN 失败", e);
            }
            vpnInterface = null;
        }
        startVpn();
    }

    private String readAll(HttpURLConnection conn) {
        try (BufferedReader br = new BufferedReader(new InputStreamReader(conn.getInputStream()))) {
            StringBuilder sb = new StringBuilder();
            String line;
            while ((line = br.readLine()) != null) sb.append(line).append("\n");
            return sb.toString();
        } catch (Exception e) {
            return "";
        }
    }

    private Map<String, String> parseHostsFromText(String text) {
        Map<String, String> map = new HashMap<>();
        for (String line : text.split("\n")) {
            line = line.trim();
            if (line.isEmpty() || line.startsWith("#")) continue;
            String[] parts = line.split("\\s+");
            if (parts.length >= 2) {
                String ip = parts[0];
                for (int i = 1; i < parts.length; i++) {
                    map.put(parts[i], ip);
                }
            }
        }
        return map;
    }

    @Override
    public void onRevoke() {
        stopVpn();
    }

    private void stopVpn() {
        running = false;
        if (scheduler != null) {
            scheduler.shutdownNow();
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