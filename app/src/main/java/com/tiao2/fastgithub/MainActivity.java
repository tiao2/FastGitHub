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
    private static final int VPN_REQUEST_CODE = 1000;
    private Button btnToggle;
    private TextView txtStatus;
    private boolean isRunning = false;
    @Override
    protected void onCreate(Bundle savedInstanceState) {
        super.onCreate(savedInstanceState);
        setContentView(R.layout.activity_main);
        btnToggle = findViewById(R.id.btnToggle);
        txtStatus = findViewById(R.id.txtStatus);
        btnToggle.setOnClickListener(v -> {
            if (isRunning) {
                stopVpnService();
            } else {
                Intent intent = VpnService.prepare(this);
                if (intent != null) {
                    startActivityForResult(intent, VPN_REQUEST_CODE);
                } else {
                    startVpnService();
                }
            }
        });
    }
    @Override
    protected void onActivityResult(int requestCode, int resultCode, Intent data) {
        super.onActivityResult(requestCode, resultCode, data);
        if (requestCode == VPN_REQUEST_CODE && resultCode == Activity.RESULT_OK) {
            startVpnService();
        }
    }
    private void startVpnService() {
        Intent intent = new Intent(this, FastGitHubVpnService.class);
        startService(intent);
        isRunning = true;
        btnToggle.setText("关闭 VPN");
        txtStatus.setText("● 已开启");
        txtStatus.setTextColor(0xFF4CAF50);
    }
    private void stopVpnService() {
        Intent intent = new Intent(this, FastGitHubVpnService.class);
        stopService(intent);
        isRunning = false;
        btnToggle.setText("开启 VPN");
        txtStatus.setText("○ 未开启");
        txtStatus.setTextColor(0xFF999999);
    }
}
