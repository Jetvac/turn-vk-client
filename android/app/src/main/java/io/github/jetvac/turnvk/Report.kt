package io.github.jetvac.turnvk

import android.Manifest
import android.content.Context
import android.content.pm.PackageManager
import android.net.ConnectivityManager
import android.net.NetworkCapabilities
import android.os.Build
import android.os.PowerManager

/**
 * The diagnostic report for developers (blocking: it runs network checks
 * for a few seconds). The engine adds its state, the checks and the
 * formatting; secrets are taken out there.
 */
fun buildReport(ctx: Context): String {
    val store = Store(ctx)
    val running = TunnelState.status.value.active

    val system = mutableListOf(
        "android: ${Build.VERSION.RELEASE} (SDK ${Build.VERSION.SDK_INT})",
        "device: ${Build.MANUFACTURER} ${Build.MODEL}",
    )
    runCatching {
        val cm = ctx.getSystemService(ConnectivityManager::class.java)
        val nets = cm.allNetworks.mapNotNull { n -> cm.getNetworkCapabilities(n)?.let { n to it } }
        for ((n, c) in nets) {
            val kinds = buildList {
                if (c.hasTransport(NetworkCapabilities.TRANSPORT_WIFI)) add("Wi-Fi")
                if (c.hasTransport(NetworkCapabilities.TRANSPORT_CELLULAR)) add("mobile")
                if (c.hasTransport(NetworkCapabilities.TRANSPORT_ETHERNET)) add("ethernet")
                if (c.hasTransport(NetworkCapabilities.TRANSPORT_VPN)) add("VPN")
            }.ifEmpty { listOf("other") }.joinToString("+")
            val ok = c.hasCapability(NetworkCapabilities.NET_CAPABILITY_VALIDATED)
            val lp = cm.getLinkProperties(n)
            val dns = lp?.dnsServers?.joinToString(" ") { it.hostAddress.orEmpty() }.orEmpty()
            system += "network ${lp?.interfaceName ?: "?"}: $kinds, internet ${if (ok) "checked" else "not checked"}, " +
                "down ${c.linkDownstreamBandwidthKbps} kbit/s, DNS ${dns.ifEmpty { "-" }}"
            if (c.hasTransport(NetworkCapabilities.TRANSPORT_VPN) && !running) {
                system += "another VPN is on (TurnVK is not connected)"
            }
        }
    }
    system += "battery optimisation off: " +
        (ctx.getSystemService(PowerManager::class.java)?.isIgnoringBatteryOptimizations(ctx.packageName) == true)
    if (Build.VERSION.SDK_INT >= 33) {
        system += "notifications allowed: " +
            (ctx.checkSelfPermission(Manifest.permission.POST_NOTIFICATIONS) == PackageManager.PERMISSION_GRANTED)
    }

    val settings = listOf(
        "routes: ${store.sessions}, disguise: ${store.obfs}, auto captcha: ${store.captchaAuto}, connect at boot: ${store.bootConnect}",
        "split tunneling: ${describeSplit(SplitRules.parse(store.split))}, saved servers: ${store.profiles.size}",
    )
    return mobile.Mobile.report(
        "TurnVK Android ${BuildConfig.VERSION_NAME}",
        system.joinToString("\n"),
        settings.joinToString("\n"),
        store.current?.link.orEmpty(),
        TunnelState.error.value.orEmpty(),
        TunnelState.log.value.joinToString("\n"),
    )
}
