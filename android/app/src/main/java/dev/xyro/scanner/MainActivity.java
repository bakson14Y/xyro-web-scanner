package dev.xyro.scanner;

import android.Manifest;
import android.app.Activity;
import android.content.Intent;
import android.content.pm.PackageManager;
import android.graphics.Color;
import android.net.Uri;
import android.os.Build;
import android.os.Bundle;
import android.webkit.JavascriptInterface;
import android.webkit.WebResourceRequest;
import android.webkit.WebSettings;
import android.webkit.WebView;
import android.webkit.WebViewClient;
import android.widget.TextView;
import android.widget.Toast;
import com.chaquo.python.Python;
import com.chaquo.python.android.AndroidPlatform;
import java.io.File;
import java.io.FileInputStream;
import java.io.OutputStream;

public class MainActivity extends Activity {
    private WebView web;
    private String pendingExport;
    private String localOrigin;
    @Override public void onCreate(Bundle state) {
        super.onCreate(state);
        TextView loading = new TextView(this);
        loading.setText("XYRO\n\nЗапуск локального ядра…");
        loading.setTextColor(Color.WHITE); loading.setTextSize(24); loading.setPadding(32,64,32,32);
        setContentView(loading);
        if (Build.VERSION.SDK_INT >= 33 && checkSelfPermission(Manifest.permission.POST_NOTIFICATIONS) != PackageManager.PERMISSION_GRANTED)
            requestPermissions(new String[]{Manifest.permission.POST_NOTIFICATIONS}, 5);
        new Thread(() -> {
            try {
                if (!Python.isStarted()) Python.start(new AndroidPlatform(getApplicationContext()));
                Python py = Python.getInstance();
                String nativeDir = getApplicationInfo().nativeLibraryDir;
                if (BuildConfig.DEBUG && getIntent().getBooleanExtra("smoke", false)) {
                    py.getModule("engine.android_api").callAttr("smoke", getFilesDir().getAbsolutePath(), nativeDir);
                }
                String url = py.getModule("engine.android_api").callAttr("start", getApplicationContext(), nativeDir).toString();
                runOnUiThread(() -> open(url));
            } catch (Exception error) {
                runOnUiThread(() -> loading.setText("Ошибка запуска:\n" + error));
            }
        }, "xyro-init").start();
    }
    private void open(String url) {
        if (isFinishing() || isDestroyed()) return;
        localOrigin = url.substring(0, url.indexOf('/', 8));
        web = new WebView(this);
        web.setBackgroundColor(Color.rgb(16,19,21));
        WebSettings s = web.getSettings();
        s.setJavaScriptEnabled(true); s.setDomStorageEnabled(true);
        s.setAllowFileAccess(false); s.setAllowContentAccess(false);
        s.setMixedContentMode(WebSettings.MIXED_CONTENT_NEVER_ALLOW);
        web.addJavascriptInterface(new ExportBridge(), "AndroidExport");
        web.setWebViewClient(new WebViewClient() {
            @Override public boolean shouldOverrideUrlLoading(WebView view, WebResourceRequest request) {
                Uri u = request.getUrl();
                return !(u.getScheme() + "://" + u.getAuthority()).equals(localOrigin);
            }
        });
        setContentView(web); web.loadUrl(url);
    }
    private class ExportBridge {
        @JavascriptInterface public void save(String job) {
            if (!job.matches("[0-9a-f]{24}")) return;
            new Thread(() -> {
                try {
                    pendingExport = Python.getInstance().getModule("engine.android_api").callAttr("export_job", job).toString();
                    Intent intent = new Intent(Intent.ACTION_CREATE_DOCUMENT);
                    intent.addCategory(Intent.CATEGORY_OPENABLE); intent.setType("application/zip");
                    intent.putExtra(Intent.EXTRA_TITLE, "XYRO-" + job + ".zip");
                    runOnUiThread(() -> startActivityForResult(intent, 10));
                } catch (Exception e) {
                    runOnUiThread(() -> Toast.makeText(MainActivity.this, e.toString(), Toast.LENGTH_LONG).show());
                }
            }).start();
        }
    }
    @Override protected void onActivityResult(int request, int result, Intent data) {
        super.onActivityResult(request, result, data);
        if (request != 10 || result != RESULT_OK || data == null || pendingExport == null) return;
        String source = pendingExport;
        Uri destination = data.getData();
        new Thread(() -> {
            try (FileInputStream in = new FileInputStream(new File(source)); OutputStream out = getContentResolver().openOutputStream(destination)) {
                if (out == null) throw new java.io.IOException("Не удалось открыть файл");
                byte[] buffer = new byte[65536]; int size;
                while ((size = in.read(buffer)) != -1) out.write(buffer, 0, size);
                runOnUiThread(() -> Toast.makeText(this, "Отчёт сохранён", Toast.LENGTH_SHORT).show());
            } catch (Exception e) { runOnUiThread(() -> Toast.makeText(this, e.toString(), Toast.LENGTH_LONG).show()); }
        }).start();
    }
    @Override protected void onDestroy() {
        if (web != null) { web.removeJavascriptInterface("AndroidExport"); web.destroy(); }
        super.onDestroy();
    }
}
