package com.tiao2.fastgithub;
import java.io.*;
import java.net.*;
import java.util.*;
import java.util.regex.*;
import javax.crypto.*;
import javax.crypto.spec.*;
public class ChallengeSolver {
    private static final String PROXY_URL = "https://pl-service.page.gd/proxy.php?url=https://raw.hellogithub.com/hosts";
    private static final Pattern HEX32 = Pattern.compile("toNumbers\\(\"([a-f0-9]{32})\"\\)");
    private static final Pattern I_PARAM = Pattern.compile("[?&]i=(\\d+)");
    public static Map<String,String> fetchViaProxy() {
        try {
            HttpURLConnection conn = (HttpURLConnection) new URL(PROXY_URL).openConnection();
            conn.setConnectTimeout(15000); conn.setReadTimeout(15000);
            conn.setRequestMethod("GET");
            conn.setInstanceFollowRedirects(false);
            conn.connect();
            String loc = conn.getHeaderField("Location");
            String html = readAll(conn);
            conn.disconnect();
            if (html.trim().startsWith("#") || html.trim().startsWith("140.")) return parseHosts(html);
            String iParam = "1";
            if (loc != null) { Matcher m = I_PARAM.matcher(loc); if (m.find()) iParam = m.group(1); }
            if (iParam.equals("1")) { Matcher m = I_PARAM.matcher(html); if (m.find()) iParam = m.group(1); }
            Matcher m = HEX32.matcher(html);
            String[] hexes = new String[3];
            int idx=0;
            while (m.find() && idx<3) hexes[idx++] = m.group(1);
            if (idx<3) return null;
            byte[] key = hexToBytes(hexes[0]);
            byte[] iv = hexToBytes(hexes[1]);
            byte[] cip = hexToBytes(hexes[2]);
            Cipher cipher = Cipher.getInstance("AES/CBC/NoPadding");
            cipher.init(Cipher.DECRYPT_MODE, new SecretKeySpec(key, "AES"), new IvParameterSpec(iv));
            byte[] dec = cipher.doFinal(cip);
            int len = dec.length;
            while (len>0 && dec[len-1]==0) len--;
            byte[] trimmed = new byte[len];
            System.arraycopy(dec, 0, trimmed, 0, len);
            String cookie = bytesToHex(trimmed);
            String finalUrl = PROXY_URL + "&i=" + iParam;
            HttpURLConnection conn2 = (HttpURLConnection) new URL(finalUrl).openConnection();
            conn2.setRequestMethod("GET");
            conn2.setRequestProperty("Cookie", "__test=" + cookie);
            conn2.setRequestProperty("Accept", "application/json, text/plain, */*");
            conn2.setConnectTimeout(15000); conn2.setReadTimeout(15000);
            conn2.connect();
            String result = readAll(conn2);
            conn2.disconnect();
            return parseHosts(result);
        } catch (Exception e) { e.printStackTrace(); return null; }
    }
    private static String readAll(HttpURLConnection conn) {
        try (BufferedReader r = new BufferedReader(new InputStreamReader(conn.getInputStream()))) {
            StringBuilder sb = new StringBuilder(); String line;
            while ((line = r.readLine()) != null) sb.append(line).append("\n");
            return sb.toString();
        } catch (Exception e) { return ""; }
    }
    private static Map<String,String> parseHosts(String text) {
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
        return map.isEmpty() ? null : map;
    }
    private static byte[] hexToBytes(String s) {
        int len=s.length();
        byte[] data = new byte[len/2];
        for (int i=0;i<len;i+=2) data[i/2] = (byte)((Character.digit(s.charAt(i),16)<<4) + Character.digit(s.charAt(i+1),16));
        return data;
    }
    private static String bytesToHex(byte[] bytes) {
        StringBuilder sb = new StringBuilder();
        for (byte b : bytes) sb.append(String.format("%02x", b));
        return sb.toString();
    }
}
