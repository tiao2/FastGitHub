package com.tiao2.fastgithub;
import android.app.Activity;
import android.content.Intent;
import android.net.VpnService;
import android.os.Bundle;
import android.view.View;
import android.widget.Button;
import android.widget.TextView;
import androidx.appcompat.app.AppCompatActivity;
public class MainActivity extends AppCompatActivity {
    private static final int REQ=1000;
    private Button btn;
    private TextView status;
    private boolean running=false;
    @Override protected void onCreate(Bundle savedInstanceState) {
        super.onCreate(savedInstanceState);
        setContentView(R.layout.activity_main);
        btn = findViewById(R.id.btnToggle);
        status = findViewById(R.id.txtStatus);
        btn.setOnClickListener(v -> {
            if (running) stopVpn();
            else { Intent i = VpnService.prepare(this); if (i != null) startActivityForResult(i, REQ); else startVpn(); }
        });
    }
    @Override protected void onActivityResult(int req, int res, Intent data) {
        super.onActivityResult(req, res, data);
        if (req == REQ && res == Activity.RESULT_OK) startVpn();
    }
    private void startVpn() {
        startService(new Intent(this, FastGitHubVpnService.class));
        running = true;
        btn.setText("关闭 VPN");
        status.setText("● 已开启");
        status.setTextColor(0xFF4CAF50);
    }
    private void stopVpn() {
        stopService(new Intent(this, FastGitHubVpnService.class));
        running = false;
        btn.setText("开启 VPN");
        status.setText("○ 未开启");
        status.setTextColor(0xFF999999);
    }
}
