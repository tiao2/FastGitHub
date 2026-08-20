package com.tiao2.fastgithub;
import android.content.Context;
import java.io.BufferedReader;
import java.io.InputStreamReader;
import java.util.HashMap;
import java.util.Map;
public class HostsLoader {
    public static Map<String, String> loadFromAssets(Context context) {
        Map<String, String> map = new HashMap<>();
        try (BufferedReader reader = new BufferedReader(
                new InputStreamReader(context.getAssets().open("github_hosts.txt")))) {
            String line;
            while ((line = reader.readLine()) != null) {
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
        } catch (Exception e) {
            e.printStackTrace();
            map.put("github.com", "20.205.243.166");
            map.put("api.github.com", "20.205.243.168");
        }
        return map;
    }
}
