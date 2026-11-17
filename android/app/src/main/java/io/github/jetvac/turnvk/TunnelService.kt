package io.github.jetvac.turnvk

import android.app.Notification
import android.app.NotificationChannel
import android.app.NotificationManager
import android.app.PendingIntent
import android.content.ComponentName
import android.content.Context
import android.content.Intent
import android.content.pm.PackageManager
import android.content.pm.ServiceInfo
import android.graphics.drawable.Icon
import android.net.ConnectivityManager
import android.net.Network
import android.net.VpnService
import android.os.Build
import android.provider.Settings
import android.service.quicksettings.TileService
import java.util.concurrent.Executors

/**
 * The VPN service: runs the Go engine (mobile.Mobile) and gives it the TUN
 * interface, socket protection and a way to show captchas. It connects to
 * the selected profile with the saved settings, whoever starts it: the
 * app, the quick settings tile, the boot receiver or Android's always-on
 * VPN.
 */
class TunnelService : VpnService(), mobile.Platform {

    companion object {
        const val ACTION_CONNECT = "connect"
        const val ACTION_DISCONNECT = "disconnect"

        private const val CHANNEL = "tunnel"
        private const val CHANNEL_CAPTCHA = "captcha"
        private const val NOTE_ID = 1
        private const val NOTE_CAPTCHA = 2

        /** Packages whose traffic never enters the tunnel. */
        val BYPASS = listOf("com.vkontakte.android", "com.vk.calls")

        fun connect(ctx: Context) {
            val i = Intent(ctx, TunnelService::class.java).setAction(ACTION_CONNECT)
            if (Build.VERSION.SDK_INT >= 26) ctx.startForegroundService(i) else ctx.startService(i)
        }

        fun disconnect(ctx: Context) {
            ctx.startService(Intent(ctx, TunnelService::class.java).setAction(ACTION_DISCONNECT))
        }

        /** The captcha was answered or is no longer needed. */
        fun clearCaptcha(ctx: Context) {
            TunnelState.setCaptcha(null)
            runCatching { ctx.getSystemService(NotificationManager::class.java).cancel(NOTE_CAPTCHA) }
        }
    }

    private val worker = Executors.newSingleThreadExecutor()
    private var networkCallback: ConnectivityManager.NetworkCallback? = null
    private val store by lazy { Store(this) }

    override fun onStartCommand(intent: Intent?, flags: Int, startId: Int): Int {
        when (intent?.action) {
            ACTION_DISCONNECT -> {
                stopTunnel()
                return START_NOT_STICKY
            }
            // The app, the tile and the boot receiver send ACTION_CONNECT;
            // always-on VPN starts the service with SERVICE_INTERFACE.
            ACTION_CONNECT, SERVICE_INTERFACE, null -> {
                startForegroundCompat(note("Подключение…"))
                worker.execute { run() }
            }
        }
        return START_NOT_STICKY
    }

    private fun run() {
        if (mobile.Mobile.running()) return
        val profile = store.current
        if (profile == null) {
            fail("Добавьте сервер: ссылку wdtt://")
            return
        }
        val sessions = store.sessions
        TunnelState.setError(null)
        TunnelState.setStatus(Status(state = "connecting", target = sessions))
        log("подключение к «${profile.name}», сессий $sessions")
        val deviceId = Settings.Secure.getString(contentResolver, Settings.Secure.ANDROID_ID) ?: "android"
        try {
            mobile.Mobile.setCaptchaMode(if (store.captchaAuto) "auto" else "manual")
            // VK guest tokens are kept here between runs: fewer captchas.
            mobile.Mobile.setDataDir(filesDir.absolutePath)
            mobile.Mobile.setStats(store.serverStats, "TurnVK ${BuildConfig.VERSION_NAME} android")
            mobile.Mobile.start(profile.link, deviceId, sessions.toLong(), store.obfs, this)
            watchNetwork()
        } catch (e: Exception) {
            fail(e.message ?: e.toString())
        }
    }

    private fun fail(msg: String) {
        log("не удалось подключиться: $msg")
        TunnelState.setError(msg)
        TunnelState.setStatus(Status(state = "failed", lastError = msg))
        stopTunnel()
    }

    private fun stopTunnel() {
        unwatchNetwork()
        worker.execute {
            mobile.Mobile.stop()
            clearCaptcha(this)
            val s = TunnelState.status.value
            if (s.state != "failed") TunnelState.setStatus(Status(state = "stopped"))
            updateTile()
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
            .setSession(store.current?.name ?: getString(R.string.app_name))
            .setMtu(mtu.toInt())
            .addAddress(address, prefixLen.toInt())
            .addRoute("0.0.0.0", 0)
        // No IPv6 in the tunnel: route it in and drop it there, so that it
        // does not leak around the VPN.
        runCatching { b.addAddress("fd00:7475:726e::1", 128).addRoute("::", 0) }
        dns.split(",").map { it.trim() }.filter { it.isNotEmpty() }.forEach { runCatching { b.addDnsServer(it) } }
        // The app's own sockets (TURN, VK API), VK apps and the apps the
        // user excluded go around the tunnel.
        runCatching { b.addDisallowedApplication(packageName) }
        (BYPASS + store.excludedApps).toSet().forEach { p ->
            try {
                b.addDisallowedApplication(p)
            } catch (_: PackageManager.NameNotFoundException) {
            }
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
        if (s.state != prev.state || s.sessions != prev.sessions || s.captcha != prev.captcha) {
            val text = when (s.state) {
                "connected" -> if (s.captcha) {
                    "Подключено · нужна проверка VK"
                } else {
                    "Подключено · маршрутов ${s.sessions} из ${s.target}"
                }
                "captcha" -> "Нужно пройти проверку VK"
                "connecting" -> "Подключение…"
                "failed" -> "Ошибка: ${s.lastError}"
                else -> s.state
            }
            notify(NOTE_ID, note(text))
        }
        if (s.state != prev.state) updateTile()
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
        val working = TunnelState.status.value.state == "connected"
        val text = if (working) {
            "VPN работает. Пройдите проверку, чтобы он и дальше переподключался без перебоев."
        } else {
            "Подключение ждёт: подтвердите в VK, что вы не робот."
        }
        val b = noteBuilder(CHANNEL_CAPTCHA)
            .setSmallIcon(R.drawable.ic_stat_vpn)
            .setContentTitle("Нужна проверка VK")
            .setContentText(text)
            .setStyle(Notification.BigTextStyle().bigText(text))
            .setContentIntent(pi)
            .setCategory(Notification.CATEGORY_REMINDER)
            .setShowWhen(true)
            .setAutoCancel(true)
            .addAction(Notification.Action.Builder(null as Icon?, "Пройти проверку", pi).build())
        if (Build.VERSION.SDK_INT < 26) headsUp(b)
        val nm = getSystemService(NotificationManager::class.java)
        if (nm == null || !nm.areNotificationsEnabled()) {
            log("уведомления отключены: откройте приложение, чтобы пройти проверку")
        }
        notify(NOTE_CAPTCHA, b.build())
        // In the foreground the app opens the captcha itself (MainActivity
        // watches TunnelState.captcha).
    }

    override fun onCaptchaDone() = clearCaptcha(this)

    override fun log(line: String) = TunnelState.log(line)

    // --- quick settings tile ---

    private fun updateTile() {
        runCatching { TileService.requestListeningState(this, ComponentName(this, QuickTile::class.java)) }
    }

    // --- network changes ---

    private fun watchNetwork() {
        val cm = getSystemService(ConnectivityManager::class.java) ?: return
        var first = true
        var current: Network? = null
        val cb = object : ConnectivityManager.NetworkCallback() {
            override fun onAvailable(network: Network) {
                if (!first && network != current) {
                    log("сеть сменилась, переподключаем маршруты")
                    mobile.Mobile.networkChanged()
                }
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
        nm.createNotificationChannel(
            NotificationChannel(CHANNEL_CAPTCHA, "Проверка VK", NotificationManager.IMPORTANCE_HIGH).apply {
                description = "Когда VK просит подтвердить, что вы не робот"
                enableVibration(true)
            }
        )
    }

    /** Before Android 8 the alert level is set per notification. */
    @Suppress("DEPRECATION")
    private fun headsUp(b: Notification.Builder) {
        b.setPriority(Notification.PRIORITY_HIGH).setDefaults(Notification.DEFAULT_ALL)
    }

    @Suppress("DEPRECATION")
    private fun noteBuilder(channel: String): Notification.Builder {
        channels()
        return if (Build.VERSION.SDK_INT >= 26) Notification.Builder(this, channel) else Notification.Builder(this)
    }

    private fun note(text: String): Notification {
        val open = PendingIntent.getActivity(this, 0, Intent(this, MainActivity::class.java), PendingIntent.FLAG_IMMUTABLE)
        val stop = PendingIntent.getService(
            this, 2, Intent(this, TunnelService::class.java).setAction(ACTION_DISCONNECT), PendingIntent.FLAG_IMMUTABLE,
        )
        return noteBuilder(CHANNEL)
            .setSmallIcon(R.drawable.ic_stat_vpn)
            .setContentTitle(store.current?.name ?: getString(R.string.app_name))
            .setContentText(text)
            .setContentIntent(open)
            .setOngoing(true)
            .addAction(Notification.Action.Builder(null as Icon?, "Отключить", stop).build())
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
