package io.github.jetvac.turnvk

import android.app.Notification
import android.app.NotificationChannel
import android.app.NotificationManager
import android.app.PendingIntent
import android.content.Context
import android.content.Intent
import android.content.pm.PackageManager
import android.content.pm.ServiceInfo
import android.net.ConnectivityManager
import android.net.Network
import android.net.VpnService
import android.os.Build
import android.provider.Settings
import java.util.concurrent.Executors

/**
 * The VPN service: runs the Go engine (mobile.Mobile) and gives it the TUN
 * interface, socket protection and a way to show captchas.
 */
class TunnelService : VpnService(), mobile.Platform {

    companion object {
        const val ACTION_CONNECT = "connect"
        const val ACTION_DISCONNECT = "disconnect"
        const val EXTRA_LINK = "link"
        const val EXTRA_SESSIONS = "sessions"
        const val EXTRA_OBFS = "obfs"

        private const val CHANNEL = "tunnel"
        private const val CHANNEL_CAPTCHA = "captcha"
        private const val NOTE_ID = 1
        private const val NOTE_CAPTCHA = 2

        /** Packages whose traffic never enters the tunnel. */
        private val BYPASS = listOf("com.vkontakte.android", "com.vk.calls")

        fun connect(ctx: Context, link: String, sessions: Int, obfs: String) {
            val i = Intent(ctx, TunnelService::class.java)
                .setAction(ACTION_CONNECT)
                .putExtra(EXTRA_LINK, link)
                .putExtra(EXTRA_SESSIONS, sessions)
                .putExtra(EXTRA_OBFS, obfs)
            if (Build.VERSION.SDK_INT >= 26) ctx.startForegroundService(i) else ctx.startService(i)
        }

        fun disconnect(ctx: Context) {
            ctx.startService(Intent(ctx, TunnelService::class.java).setAction(ACTION_DISCONNECT))
        }
    }

    private val worker = Executors.newSingleThreadExecutor()
    private var networkCallback: ConnectivityManager.NetworkCallback? = null

    override fun onStartCommand(intent: Intent?, flags: Int, startId: Int): Int {
        when (intent?.action) {
            ACTION_DISCONNECT -> {
                stopTunnel()
                return START_NOT_STICKY
            }
            ACTION_CONNECT -> {
                startForegroundCompat(note(getString(R.string.app_name), "Подключение…"))
                val link = intent.getStringExtra(EXTRA_LINK).orEmpty()
                val sessions = intent.getIntExtra(EXTRA_SESSIONS, 16)
                val obfs = intent.getStringExtra(EXTRA_OBFS) ?: "audio"
                worker.execute { run(link, sessions, obfs) }
            }
        }
        return START_NOT_STICKY
    }

    private fun run(link: String, sessions: Int, obfs: String) {
        if (mobile.Mobile.running()) return
        TunnelState.setError(null)
        TunnelState.setStatus(Status(state = "connecting", target = sessions))
        val deviceId = Settings.Secure.getString(contentResolver, Settings.Secure.ANDROID_ID) ?: "android"
        try {
            mobile.Mobile.start(link, deviceId, sessions.toLong(), obfs, this)
            watchNetwork()
        } catch (e: Exception) {
            val msg = e.message ?: e.toString()
            log("не удалось подключиться: $msg")
            TunnelState.setError(msg)
            TunnelState.setStatus(Status(state = "failed", lastError = msg))
            stopTunnel()
        }
    }

    private fun stopTunnel() {
        unwatchNetwork()
        worker.execute {
            mobile.Mobile.stop()
            TunnelState.setCaptcha(null)
            val s = TunnelState.status.value
            if (s.state != "failed") TunnelState.setStatus(Status(state = "stopped"))
            stopForeground(STOP_FOREGROUND_REMOVE)
            stopSelf()
        }
    }

    override fun onRevoke() {
        log("VPN отключён системой")
        stopTunnel()
    }

    override fun onDestroy() {
        unwatchNetwork()
        mobile.Mobile.stop()
        super.onDestroy()
    }

    // --- mobile.Platform ---

    override fun protect(fd: Long): Boolean = protect(fd.toInt())

    override fun openTun(address: String, prefixLen: Long, dns: String, mtu: Long): Long {
        val b = Builder()
            .setSession(getString(R.string.app_name))
            .setMtu(mtu.toInt())
            .addAddress(address, prefixLen.toInt())
            .addRoute("0.0.0.0", 0)
        // No IPv6 in the tunnel: route it in and drop it there, so that it
        // does not leak around the VPN.
        runCatching { b.addAddress("fd00:7475:726e::1", 128).addRoute("::", 0) }
        dns.split(",").map { it.trim() }.filter { it.isNotEmpty() }.forEach { runCatching { b.addDnsServer(it) } }
        // The app's own sockets (TURN, VK API) and VK apps go around the tunnel.
        runCatching { b.addDisallowedApplication(packageName) }
        BYPASS.forEach { p ->
            try { b.addDisallowedApplication(p) } catch (_: PackageManager.NameNotFoundException) {}
        }
        if (Build.VERSION.SDK_INT >= 29) b.setMetered(false)
        b.setConfigureIntent(
            PendingIntent.getActivity(this, 0, Intent(this, MainActivity::class.java), PendingIntent.FLAG_IMMUTABLE)
        )
        val pfd = b.establish() ?: return -1
        return pfd.detachFd().toLong()
    }

    override fun onStatus(status: String) {
        val s = Status.parse(status)
        val prev = TunnelState.status.value
        TunnelState.setStatus(s)
        if (s.state != prev.state || s.sessions != prev.sessions) {
            val text = when (s.state) {
                "connected" -> "Подключено · сессий ${s.sessions}/${s.target}"
                "captcha" -> "Нужно пройти проверку VK"
                "connecting" -> "Подключение…"
                "failed" -> "Ошибка: ${s.lastError}"
                else -> s.state
            }
            notify(NOTE_ID, note(getString(R.string.app_name), text))
        }
        if (s.state == "failed") {
            TunnelState.setError(s.lastError)
            stopTunnel()
        }
    }

    override fun onCaptcha(url: String) {
        log("VK просит пройти проверку")
        TunnelState.setCaptcha(url)
        val open = Intent(this, CaptchaActivity::class.java)
            .addFlags(Intent.FLAG_ACTIVITY_NEW_TASK)
            .putExtra(CaptchaActivity.EXTRA_URL, url)
        val pi = PendingIntent.getActivity(this, 1, open, PendingIntent.FLAG_IMMUTABLE or PendingIntent.FLAG_UPDATE_CURRENT)
        val n = noteBuilder(CHANNEL_CAPTCHA)
            .setSmallIcon(R.drawable.ic_stat_vpn)
            .setContentTitle("Проверка VK")
            .setContentText("Нажмите, чтобы подтвердить, что вы не робот")
            .setContentIntent(pi)
            .setAutoCancel(true)
            .build()
        notify(NOTE_CAPTCHA, n)
        // In the foreground the app opens the captcha itself (MainActivity
        // watches TunnelState.captcha).
    }

    override fun log(line: String) = TunnelState.log(line)

    // --- network changes ---

    private fun watchNetwork() {
        val cm = getSystemService(ConnectivityManager::class.java) ?: return
        var first = true
        var current: Network? = null
        val cb = object : ConnectivityManager.NetworkCallback() {
            override fun onAvailable(network: Network) {
                if (!first && network != current) mobile.Mobile.networkChanged()
                first = false
                current = network
            }
        }
        runCatching { cm.registerDefaultNetworkCallback(cb) }.onSuccess { networkCallback = cb }
    }

    private fun unwatchNetwork() {
        val cb = networkCallback ?: return
        networkCallback = null
        runCatching { getSystemService(ConnectivityManager::class.java)?.unregisterNetworkCallback(cb) }
    }

    // --- notifications ---

    private fun channels() {
        if (Build.VERSION.SDK_INT < 26) return
        val nm = getSystemService(NotificationManager::class.java)
        nm.createNotificationChannel(NotificationChannel(CHANNEL, "Подключение", NotificationManager.IMPORTANCE_LOW))
        nm.createNotificationChannel(NotificationChannel(CHANNEL_CAPTCHA, "Проверка VK", NotificationManager.IMPORTANCE_HIGH))
    }

    @Suppress("DEPRECATION")
    private fun noteBuilder(channel: String): Notification.Builder {
        channels()
        return if (Build.VERSION.SDK_INT >= 26) Notification.Builder(this, channel) else Notification.Builder(this)
    }

    private fun note(title: String, text: String): Notification {
        val pi = PendingIntent.getActivity(this, 0, Intent(this, MainActivity::class.java), PendingIntent.FLAG_IMMUTABLE)
        return noteBuilder(CHANNEL)
            .setSmallIcon(R.drawable.ic_stat_vpn)
            .setContentTitle(title)
            .setContentText(text)
            .setContentIntent(pi)
            .setOngoing(true)
            .build()
    }

    private fun notify(id: Int, n: Notification) {
        runCatching { getSystemService(NotificationManager::class.java).notify(id, n) }
    }

    private fun startForegroundCompat(n: Notification) {
        if (Build.VERSION.SDK_INT >= 34) {
            startForeground(NOTE_ID, n, ServiceInfo.FOREGROUND_SERVICE_TYPE_SPECIAL_USE)
        } else {
            startForeground(NOTE_ID, n)
        }
    }
}
