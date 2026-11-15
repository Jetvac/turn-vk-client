package io.github.jetvac.turnvk

import android.annotation.SuppressLint
import android.app.PendingIntent
import android.content.BroadcastReceiver
import android.content.Context
import android.content.Intent
import android.net.VpnService
import android.os.Build
import android.service.quicksettings.Tile
import android.service.quicksettings.TileService

/** Quick settings tile: connect or disconnect without opening the app. */
class QuickTile : TileService() {

    override fun onStartListening() {
        val tile = qsTile ?: return
        val s = TunnelState.status.value
        val store = Store(this)
        tile.state = if (s.active) Tile.STATE_ACTIVE else Tile.STATE_INACTIVE
        tile.label = getString(R.string.app_name)
        if (Build.VERSION.SDK_INT >= 29) {
            tile.subtitle = when (s.state) {
                "connected" -> store.current?.name ?: "Подключено"
                "connecting" -> "Подключение…"
                "captcha" -> "Проверка VK"
                else -> "Отключено"
            }
        }
        tile.updateTile()
    }

    override fun onClick() {
        if (TunnelState.status.value.active) {
            TunnelService.disconnect(this)
            return
        }
        // First start (no VPN permission yet, or no server): open the app.
        if (VpnService.prepare(this) != null || Store(this).current == null) {
            openApp()
            return
        }
        TunnelService.connect(this)
    }

    @SuppressLint("StartActivityAndCollapseDeprecated")
    private fun openApp() {
        val i = Intent(this, MainActivity::class.java).addFlags(Intent.FLAG_ACTIVITY_NEW_TASK)
        if (Build.VERSION.SDK_INT >= 34) {
            startActivityAndCollapse(PendingIntent.getActivity(this, 0, i, PendingIntent.FLAG_IMMUTABLE))
        } else {
            @Suppress("DEPRECATION")
            startActivityAndCollapse(i)
        }
    }
}

/** Connects after the phone starts, if the user turned that on. */
class BootReceiver : BroadcastReceiver() {
    override fun onReceive(ctx: Context, intent: Intent) {
        if (intent.action != Intent.ACTION_BOOT_COMPLETED) return
        val store = Store(ctx)
        if (!store.bootConnect || store.current == null) return
        // Without the VPN permission the system would show a dialog: skip.
        if (VpnService.prepare(ctx) != null) return
        TunnelService.connect(ctx)
    }
}
