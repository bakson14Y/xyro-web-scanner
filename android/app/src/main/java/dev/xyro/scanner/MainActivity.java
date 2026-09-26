package dev.xyro.scanner;

import android.Manifest;
import android.app.Activity;
import android.content.Intent;
import android.content.pm.PackageManager;
import android.graphics.Color;
import android.net.Uri;
import android.os.Build;
import android.os.Bundle;
import android.provider.DocumentsContract;
import android.webkit.JavascriptInterface;
import android.webkit.WebResourceRequest;
import android.webkit.WebSettings;
import android.webkit.WebChromeClient;
import android.webkit.ValueCallback;
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
    private ValueCallback<Uri[]> filePicker;
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
                String url = py.getModule("engine.android_api").callAttr("start", getApplicationContext(), nativeDir).toString();
                if (BuildConfig.DEBUG && getIntent().getBooleanExtra("smoke", false)) {
                    py.getModule("engine.android_api").callAttr("smoke", getFilesDir().getAbsolutePath(), nativeDir);
                }
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
        web.setWebChromeClient(new WebChromeClient() {
            @Override public boolean onShowFileChooser(WebView view, ValueCallback<Uri[]> callback,
                                                       FileChooserParams parameters) {
                if (filePicker != null) filePicker.onReceiveValue(null);
                filePicker = callback;
                Intent intent = new Intent(Intent.ACTION_OPEN_DOCUMENT);
                intent.addCategory(Intent.CATEGORY_OPENABLE);
                // HAR files have inconsistent MIME types across Android providers.
                // The shared interface validates the selected JSON/HAR content.
                intent.setType("*/*");
                intent.putExtra(Intent.EXTRA_ALLOW_MULTIPLE, false);
                try { startActivityForResult(intent, 11); }
                catch (android.content.ActivityNotFoundException error) {
                    filePicker.onReceiveValue(null); filePicker = null;
                    Toast.makeText(MainActivity.this, "Не найден системный выбор файлов", Toast.LENGTH_LONG).show();
                }
                return true;
            }
        });
        web.setWebViewClient(new WebViewClient() {
            @Override public boolean shouldOverrideUrlLoading(WebView view, WebResourceRequest request) {
                Uri u = request.getUrl();
                if ((u.getScheme() + "://" + u.getAuthority()).equals(localOrigin)) return false;
                if (request.isForMainFrame() && request.hasGesture() && ("https".equals(u.getScheme()) || "http".equals(u.getScheme()))) {
                    try { startActivity(new Intent(Intent.ACTION_VIEW, u)); }
                    catch (android.content.ActivityNotFoundException ignored) { }
                }
                return true;
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
        if (request == 11) {
            if (filePicker != null) {
                Uri document = result == RESULT_OK && data != null ? data.getData() : null;
                if (document != null && (!"content".equals(document.getScheme()) ||
                        !DocumentsContract.isDocumentUri(this, document))) document = null;
                filePicker.onReceiveValue(document == null ? null : new Uri[]{document});
                filePicker = null;
            }
            return;
        }
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
        if (filePicker != null) { filePicker.onReceiveValue(null); filePicker = null; }
        if (web != null) { web.removeJavascriptInterface("AndroidExport"); web.destroy(); }
        super.onDestroy();
    }
}
