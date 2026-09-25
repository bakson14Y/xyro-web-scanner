package dev.xyro.scanner;

import android.app.Notification;
import android.app.NotificationChannel;
import android.app.NotificationManager;
import android.app.PendingIntent;
import android.app.Service;
import android.content.Intent;
import android.os.IBinder;
import android.os.PowerManager;
import com.chaquo.python.Python;
import com.chaquo.python.android.AndroidPlatform;
import java.io.File;

public class WorkerService extends Service {
    private volatile String folder;
    private PowerManager.WakeLock wake;
    private boolean running;
    @Override public IBinder onBind(Intent intent) { return null; }
    @Override public int onStartCommand(Intent intent, int flags, int id) {
        if (intent == null) { stopSelf(); return START_NOT_STICKY; }
        if ("cancel".equals(intent.getAction())) { cancel(); return START_NOT_STICKY; }
        if (running) return START_NOT_STICKY;
        running = true;
        folder = intent.getStringExtra("folder");
        String nativeDir = intent.getStringExtra("native");
        NotificationManager nm = getSystemService(NotificationManager.class);
        nm.createNotificationChannel(new NotificationChannel("scan", "Проверка сайта", NotificationManager.IMPORTANCE_LOW));
        PendingIntent open = PendingIntent.getActivity(this, 0, new Intent(this, MainActivity.class), PendingIntent.FLAG_IMMUTABLE | PendingIntent.FLAG_UPDATE_CURRENT);
        Intent cancel = new Intent(this, WorkerService.class).setAction("cancel");
        PendingIntent stop = PendingIntent.getService(this, 1, cancel, PendingIntent.FLAG_IMMUTABLE | PendingIntent.FLAG_UPDATE_CURRENT);
        Notification notification = new Notification.Builder(this, "scan").setContentTitle("XYRO · Проверка выполняется")
            .setContentText("Нажмите, чтобы открыть ход проверки").setSmallIcon(android.R.drawable.ic_menu_search)
            .setContentIntent(open).setOngoing(true).addAction(new Notification.Action.Builder(null, "Остановить", stop).build()).build();
        startForeground(1, notification);
        wake = getSystemService(PowerManager.class).newWakeLock(PowerManager.PARTIAL_WAKE_LOCK, "XYRO:scan");
        wake.acquire(10 * 60 * 60 * 1000L);
        new Thread(() -> {
            try {
                if (!Python.isStarted()) Python.start(new AndroidPlatform(getApplicationContext()));
                Python.getInstance().getModule("engine.worker").callAttr("run", folder, nativeDir);
            } finally {
                if (wake != null && wake.isHeld()) wake.release();
                stopForeground(STOP_FOREGROUND_REMOVE); stopSelf();
                // A fresh embedded interpreter for each scan prevents upstream global-state leakage.
                android.os.Process.killProcess(android.os.Process.myPid());
            }
        }, "xyro-worker").start();
        return START_NOT_STICKY;
    }
    private void cancel() { if (folder != null) try { new File(folder, "cancel").createNewFile(); } catch (Exception ignored) {} }
    @Override public void onDestroy() { cancel(); super.onDestroy(); }
}
