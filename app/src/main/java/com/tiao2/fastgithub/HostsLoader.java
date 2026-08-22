package com.tiao2.fastgithub;
import android.content.Context;
import java.io.*;
import java.util.*;
public class HostsLoader {
    public static Map<String,String> loadFromAssets(Context ctx) {
        Map<String,String> map = new HashMap<>();
        try (BufferedReader r = new BufferedReader(new InputStreamReader(ctx.getAssets().open("github_hosts.txt")))) {
            String line;
            while ((line = r.readLine()) != null) {
                line=line.trim();
                if (line.isEmpty() || line.startsWith("#")) continue;
                String[] p=line.split("\\s+");
                if (p.length>=2) {
                    String ip=p[0];
                    for (int i=1;i<p.length;i++) map.put(p[i], ip);
                }
            }
        } catch (Exception e) {
            e.printStackTrace();
            map.put("github.com","20.205.243.166");
            map.put("api.github.com","20.205.243.168");
        }
        return map;
    }
}
