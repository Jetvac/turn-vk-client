package io.github.jetvac.turnvk

import android.app.Notification
import android.app.NotificationChannel
import android.app.NotificationManager
import android.app.PendingIntent
import android.content.ComponentName
import android.content.Context
import android.content.Intent
import android.content.pm.ApplicationInfo
import android.content.pm.PackageManager
import android.content.pm.ServiceInfo
import android.graphics.drawable.Icon
import android.net.ConnectivityManager
import android.net.Network
import android.net.NetworkCapabilities
import android.net.VpnService
import android.net.wifi.WifiInfo
import android.net.wifi.WifiManager
import android.os.BatteryManager
import android.os.Build
import android.os.ParcelFileDescriptor
import android.os.PowerManager
import android.provider.Settings
import android.service.quicksettings.TileService
import android.telephony.CellSignalStrengthGsm
import android.telephony.CellSignalStrengthLte
import android.telephony.CellSignalStrengthNr
import android.telephony.CellSignalStrengthTdscdma
import android.telephony.CellSignalStrengthWcdma
import android.telephony.TelephonyManager
import org.json.JSONObject
import java.net.InetAddress
import java.net.InetSocketAddress
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
        const val ACTION_RESTART = "restart"
        const val ACTION_MARK = "mark"

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

        /** Reconnects, so that a new list of apps let into the VPN applies. */
        fun restart(ctx: Context) {
            val i = Intent(ctx, TunnelService::class.java).setAction(ACTION_RESTART)
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
    /** The physical network the routes open on (never the VPN itself). */
    @Volatile private var underlying: Network? = null
    private val store by lazy { Store(this) }
    private var wifiLocks: List<WifiManager.WifiLock> = emptyList()
    private var noteText = ""
    @Volatile private var power = Power.BALANCED
    // Set once the tunnel stops: a late status must not take the Wi-Fi lock.
    @Volatile private var stopped = false

    override fun onStartCommand(intent: Intent?, flags: Int, startId: Int): Int {
        when (intent?.action) {
            ACTION_DISCONNECT -> {
                stopTunnel()
                return START_NOT_STICKY
            }
            // "Something is wrong now" from the notification.
            ACTION_MARK -> {
                Marker.mark(this, "")
                return START_NOT_STICKY
            }
            // The app, the tile and the boot receiver send ACTION_CONNECT;
            // always-on VPN starts the service with SERVICE_INTERFACE.
            ACTION_RESTART -> {
                startForegroundCompat(note("Переподключение…"))
                worker.execute {
                    log("переподключение: изменились правила для приложений")
                    mobile.Mobile.stop()
                    TunnelState.setPlan(null)
                    run()
                }
            }
            ACTION_CONNECT, SERVICE_INTERFACE, null -> {
                startForegroundCompat(note("Подключение…"))
                worker.execute { run() }
            }
        }
        return START_NOT_STICKY
    }

    private fun run() {
        if (mobile.Mobile.running()) return
        stopped = false
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
            // The rules the user set (the service may start without the app).
            runCatching { mobile.Mobile.setSplit(store.split) }
            runCatching { mobile.Mobile.setListsWiFiOnly(store.listsWifiOnly) }
            // The network now: its mode (rules by network) applies from the start.
            runCatching { mobile.Mobile.setNetwork(networkKind(), "") }
            mobile.Mobile.loadLists()
            mobile.Mobile.setStats(store.serverStats, "TurnVK ${BuildConfig.VERSION_NAME} android")
            power = store.power
            mobile.Mobile.setPower(power)
            TunnelState.setPower(power)
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
        stopped = true
        unwatchNetwork()
        releaseWifi()
        worker.execute {
            mobile.Mobile.stop()
            TunnelState.setPlan(null)
            TunnelState.setPower(null)
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
        stopped = true
        unwatchNetwork()
        releaseWifi()
        mobile.Mobile.stop()
        super.onDestroy()
    }

    /**
     * Wi-Fi without power saving while the tunnel carries traffic: in power
     * saving the phone wakes for incoming packets only every 100-300 ms,
     * which games feel as ping spikes. The low-latency lock (Android 10+)
     * works while TurnVK is on screen; the high-performance one also in the
     * background up to Android 13 (from 14 it turns into the low-latency
     * lock). An idle tunnel (Status.quiet) lets go of them: Wi-Fi without
     * power saving drains the battery. The power mode decides in the end:
     * the saver never holds them, "always" holds them all the time.
     */
    @Suppress("DEPRECATION")
    @Synchronized
    private fun holdWifi() {
        if (stopped || wifiLocks.isNotEmpty()) return
        val wm = applicationContext.getSystemService(WifiManager::class.java) ?: return
        val modes = buildList {
            if (Build.VERSION.SDK_INT >= 29) add(WifiManager.WIFI_MODE_FULL_LOW_LATENCY)
            add(WifiManager.WIFI_MODE_FULL_HIGH_PERF)
        }
        wifiLocks = modes.mapNotNull { mode ->
            runCatching {
                wm.createWifiLock(mode, "TurnVK:$mode").apply {
                    setReferenceCounted(false)
                    acquire()
                }
            }.getOrNull()
        }
    }

    @Synchronized
    private fun releaseWifi() {
        wifiLocks.forEach { runCatching { it.release() } }
        wifiLocks = emptyList()
    }

    /** Installed apps the system files as games (their store category). */
    @Suppress("DEPRECATION")
    private fun gameApps(): List<String> = runCatching {
        packageManager.getInstalledApplications(0).filter { ai ->
            ai.packageName != packageName && (
                (Build.VERSION.SDK_INT >= 26 && ai.category == ApplicationInfo.CATEGORY_GAME) ||
                    (ai.flags and ApplicationInfo.FLAG_IS_GAME) != 0
                )
        }.map { it.packageName }
    }.getOrDefault(emptyList())

    // --- mobile.Platform ---

    override fun protect(fd: Long): Boolean {
        if (!protect(fd.toInt())) return false
        bindToNetwork(fd.toInt())
        return true
    }

    /**
     * Binds a route's socket to the network it opens on: after a switch
     * (weak Wi-Fi to mobile data) the old routes keep working over the old
     * network while new ones open, instead of dying at once (the engine's
     * SwitchNetwork). A failure leaves the socket on the default network,
     * as before.
     */
    private fun bindToNetwork(fd: Int) {
        val n = underlying ?: return
        runCatching { ParcelFileDescriptor.fromFd(fd).use { n.bindSocket(it.fileDescriptor) } }
    }

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
        // Which apps enter the tunnel (split tunneling, mobile.AppPlan).
        val planJson = runCatching { mobile.Mobile.appPlan() }.getOrDefault("")
        val plan = runCatching { JSONObject(planJson) }.getOrNull()
        val planApps = plan?.optJSONArray("apps")?.let { a -> (0 until a.length()).map { a.getString(it) } }.orEmpty()
        if (plan?.optString("mode") == "allow") {
            // Only the apps sent through the VPN. With none (or none
            // installed), the app itself, so that the list is not empty:
            // an empty list lets every app in.
            var added = 0
            planApps.filter { it != packageName && it !in BYPASS }.forEach { p ->
                try {
                    b.addAllowedApplication(p)
                    added++
                } catch (_: PackageManager.NameNotFoundException) {
                }
            }
            if (added == 0) b.addAllowedApplication(packageName)
        } else {
            // The app's own sockets (TURN, VK API, captcha), VK apps and the
            // apps sent direct that no rule can bring back go around the
            // tunnel.
            runCatching { b.addDisallowedApplication(packageName) }
            // "Games direct": the game apps too.
            val games = if (plan?.optBoolean("games") == true) gameApps() else emptyList()
            if (games.isNotEmpty()) log("игры напрямую: ${games.size}")
            (BYPASS + planApps + games).toSet().forEach { p ->
                try {
                    b.addDisallowedApplication(p)
                } catch (_: PackageManager.NameNotFoundException) {
                }
            }
        }
        TunnelState.setPlan(planJson)
        if (Build.VERSION.SDK_INT >= 29) b.setMetered(false)
        b.setConfigureIntent(
            PendingIntent.getActivity(this, 0, Intent(this, MainActivity::class.java), PendingIntent.FLAG_IMMUTABLE)
        )
        val pfd = b.establish() ?: return -1
        return pfd.detachFd().toLong()
    }

    // From any of the engine's goroutines.
    @Synchronized
    override fun onStatus(status: String) {
        val s = Status.parse(status)
        val prev = TunnelState.status.value
        TunnelState.setStatus(s)
        val wifi = s.state == "connected" && when (power) {
            Power.SAVER -> false
            Power.ALWAYS -> true
            else -> !s.quiet
        }
        if (wifi) holdWifi() else releaseWifi()
        val text = when (s.state) {
            "connected" -> when {
                s.captcha -> "Подключено · нужна проверка VK"
                s.quiet -> "Подключено · простой, экономия заряда"
                else -> "Подключено · маршрутов ${s.sessions} из ${s.target}"
            }
            "captcha" -> "Нужно пройти проверку VK"
            "connecting" -> "Подключение…"
            "failed" -> "Ошибка: ${s.lastError}"
            else -> s.state
        }
        // Only a new text is posted: each post wakes the system's UI.
        if (text != noteText) {
            noteText = text
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

    /** The app behind a connection in the tunnel (Android 10+; -1: unknown). */
    override fun ownerUID(proto: Long, srcIP: String, srcPort: Long, dstIP: String, dstPort: Long): Long {
        if (Build.VERSION.SDK_INT < 29) return -1
        val cm = getSystemService(ConnectivityManager::class.java) ?: return -1
        return runCatching {
            cm.getConnectionOwnerUid(
                proto.toInt(),
                InetSocketAddress(InetAddress.getByName(srcIP), srcPort.toInt()),
                InetSocketAddress(InetAddress.getByName(dstIP), dstPort.toInt()),
            ).toLong()
        }.getOrDefault(-1L)
    }

    override fun packagesForUID(uid: Long): String =
        runCatching { packageManager.getPackagesForUid(uid.toInt())?.joinToString(",") }.getOrNull().orEmpty()

    /**
     * Battery and power state for the statistics (engine.DeviceState): read
     * once a minute, no receivers kept. The charge counter (mAh) is finer
     * than the level; devices that lack it report 0 or Int.MIN_VALUE.
     */
    override fun device(): String = runCatching {
        val bm = getSystemService(BatteryManager::class.java)
        val pm = getSystemService(PowerManager::class.java)
        fun prop(id: Int): Int = bm?.getIntProperty(id)?.takeIf { it != Int.MIN_VALUE } ?: 0
        JSONObject()
            .put("batt", prop(BatteryManager.BATTERY_PROPERTY_CAPACITY))
            .put("chg", bm?.isCharging == true)
            .put("screen", pm?.isInteractive == true)
            .put("doze", pm?.isDeviceIdleMode == true)
            .put("saver", pm?.isPowerSaveMode == true)
            .put("mah", prop(BatteryManager.BATTERY_PROPERTY_CHARGE_COUNTER) / 1000)
            .put("ma", prop(BatteryManager.BATTERY_PROPERTY_CURRENT_NOW) / 1000)
            .toString()
    }.getOrDefault("")

    /**
     * The physical network for the statistics (engine.NetState): its kind,
     * signal and Wi-Fi link, never its name. No extra permissions: Wi-Fi
     * from the network's capabilities (link and band from Android 12), the
     * mobile signal from TelephonyManager (Android 10+).
     */
    override fun network(): String = runCatching {
        val cm = getSystemService(ConnectivityManager::class.java)
        val net = underlying ?: cm?.activeNetwork
        val caps = net?.let { cm?.getNetworkCapabilities(it) }
        val o = JSONObject()
        when {
            caps == null -> o.put("kind", "none")
            caps.hasTransport(NetworkCapabilities.TRANSPORT_WIFI) -> {
                o.put("kind", "wifi")
                if (Build.VERSION.SDK_INT >= 29) {
                    caps.signalStrength.takeIf { it in -127..-1 }?.let { o.put("rssi", it) }
                }
                if (Build.VERSION.SDK_INT >= 31) {
                    (caps.transportInfo as? WifiInfo)?.let { w ->
                        if (w.rssi in -127..-1) o.put("rssi", w.rssi)
                        if (w.linkSpeed > 0) o.put("mbps", w.linkSpeed)
                        if (w.frequency > 0) o.put("mhz", w.frequency)
                    }
                }
            }
            caps.hasTransport(NetworkCapabilities.TRANSPORT_CELLULAR) -> {
                o.put("kind", "cell")
                if (Build.VERSION.SDK_INT >= 29) {
                    getSystemService(TelephonyManager::class.java)?.signalStrength?.let { ss ->
                        o.put("bars", ss.level)
                        val all = ss.cellSignalStrengths
                        // 5G next to 4G (NSA): the 5G one.
                        (all.firstOrNull { it is CellSignalStrengthNr } ?: all.firstOrNull())?.let { c ->
                            if (c.dbm in -150..-1) o.put("rssi", c.dbm)
                            o.put(
                                "cell",
                                when (c) {
                                    is CellSignalStrengthNr -> "5g"
                                    is CellSignalStrengthLte -> "lte"
                                    is CellSignalStrengthWcdma, is CellSignalStrengthTdscdma -> "3g"
                                    is CellSignalStrengthGsm -> "2g"
                                    else -> "other"
                                },
                            )
                        }
                    }
                }
            }
            caps.hasTransport(NetworkCapabilities.TRANSPORT_ETHERNET) -> o.put("kind", "eth")
            else -> o.put("kind", "other")
        }
        o.toString()
    }.getOrDefault("")

    // --- quick settings tile ---

    private fun updateTile() {
        runCatching { TileService.requestListeningState(this, ComponentName(this, QuickTile::class.java)) }
    }

    // --- network changes ---

    private fun watchNetwork() {
        unwatchNetwork()
        val cm = getSystemService(ConnectivityManager::class.java) ?: return
        var first = true
        var current: Network? = null
        var lost = false
        var kind = ""
        val cb = object : ConnectivityManager.NetworkCallback() {
            override fun onAvailable(network: Network) {
                // New routes bind to it (set before the engine hears of it).
                val caps = runCatching { cm.getNetworkCapabilities(network) }.getOrNull()
                if (caps != null && kindOf(caps) != null) underlying = network
                when {
                    first -> {}
                    network == current && lost -> {
                        log("сеть вернулась, проверяем маршруты")
                        mobile.Mobile.networkBack()
                    }
                    network != current -> {
                        log("сеть сменилась, переносим маршруты")
                        mobile.Mobile.networkChanged()
                    }
                }
                first = false
                lost = false
                current = network
            }

            override fun onLost(network: Network) {
                if (network != current) return
                lost = true
                if (underlying == network) underlying = null
                log("сеть пропала, маршруты ждут её")
                mobile.Mobile.networkLost()
            }

            override fun onCapabilitiesChanged(network: Network, caps: NetworkCapabilities) {
                if (kindOf(caps) != null && network == current) underlying = network
                val k = kindOf(caps) ?: networkKind()
                if (k == kind) return
                kind = k
                // Rules by network: a new mode; when the apps Android lets
                // into the tunnel change, reconnect.
                val replan = runCatching { mobile.Mobile.setNetwork(k, "") }.getOrDefault(false)
                if (replan && mobile.Mobile.running()) {
                    log("правила для сети «${netNames[k] ?: k}» меняют список приложений в VPN — переподключаем")
                    restart(this@TunnelService)
                }
            }
        }
        runCatching { cm.registerDefaultNetworkCallback(cb) }.onSuccess { networkCallback = cb }
    }

    /** The kind of a network: "wifi", "mobile", "wired"; null for a VPN or unknown. */
    private fun kindOf(caps: NetworkCapabilities): String? = when {
        caps.hasTransport(NetworkCapabilities.TRANSPORT_VPN) -> null
        caps.hasTransport(NetworkCapabilities.TRANSPORT_WIFI) -> "wifi"
        caps.hasTransport(NetworkCapabilities.TRANSPORT_CELLULAR) -> "mobile"
        caps.hasTransport(NetworkCapabilities.TRANSPORT_ETHERNET) -> "wired"
        else -> null
    }

    /** The kind of the physical network the phone uses now ("" when unknown). */
    @Suppress("DEPRECATION")
    private fun networkKind(): String {
        val cm = getSystemService(ConnectivityManager::class.java) ?: return ""
        cm.activeNetwork?.let { n -> cm.getNetworkCapabilities(n)?.let { kindOf(it) }?.let { return it } }
        // The app is inside the VPN (only it was let in): the network under it.
        for (n in cm.allNetworks) {
            val c = cm.getNetworkCapabilities(n) ?: continue
            if (c.hasCapability(NetworkCapabilities.NET_CAPABILITY_INTERNET)) kindOf(c)?.let { return it }
        }
        return ""
    }

    private fun unwatchNetwork() {
        underlying = null
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
        val mark = PendingIntent.getService(
            this, 3, Intent(this, TunnelService::class.java).setAction(ACTION_MARK), PendingIntent.FLAG_IMMUTABLE,
        )
        return noteBuilder(CHANNEL)
            .setSmallIcon(R.drawable.ic_stat_vpn)
            .setContentTitle(store.current?.name ?: getString(R.string.app_name))
            .setContentText(text)
            .setContentIntent(open)
            .setOngoing(true)
            .addAction(Notification.Action.Builder(null as Icon?, "Отключить", stop).build())
            .addAction(Notification.Action.Builder(null as Icon?, "Что-то не так", mark).build())
            .build()
    }

    private fun notify(id: Int, n: Notification) {
        runCatching { getSystemService(NotificationManager::class.java).notify(id, n) }
    }

    private fun startForegroundCompat(n: Notification) {
        noteText = ""
        if (Build.VERSION.SDK_INT >= 34) {
            startForeground(NOTE_ID, n, ServiceInfo.FOREGROUND_SERVICE_TYPE_SPECIAL_USE)
        } else {
            startForeground(NOTE_ID, n)
        }
    }
}
