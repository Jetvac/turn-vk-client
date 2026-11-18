package io.github.jetvac.turnvk

import android.annotation.SuppressLint
import android.app.PendingIntent
import android.content.Intent
import android.os.Build
import android.service.quicksettings.Tile
import android.service.quicksettings.TileService

/**
 * Quick settings tile for split tunneling: on (the mode set in the app) or
 * off (everything through the VPN). When the apps Android lets into the
 * tunnel change, the connection is restarted.
 */
class SplitTile : TileService() {

    override fun onStartListening() = refresh()

    override fun onClick() {
        val store = Store(this)
        val r = SplitRules.parse(store.split)
        // Nothing set up yet: the app's tab, to choose a mode.
        if (!r.on && r.apps.isEmpty() && r.domains.isEmpty() && r.lists.isEmpty() && r.default != "direct") {
            openApp()
            return
        }
        val applied = TunnelState.plan.value
        val now = applyRules(store, r.copy(on = !r.on))
        TunnelState.log("раздельное туннелирование " + (if (now.on) "включено" else "выключено") + " (плитка)")
        val plan = runCatching { mobile.Mobile.appPlan() }.getOrDefault("")
        if (mobile.Mobile.running() && applied != null && plan.isNotEmpty() && plan != applied) TunnelService.restart(this)
        refresh()
    }

    private fun refresh() {
        val tile = qsTile ?: return
        val r = SplitRules.parse(Store(this).split)
        tile.state = if (r.on) Tile.STATE_ACTIVE else Tile.STATE_INACTIVE
        tile.label = getString(R.string.split_tile)
        if (Build.VERSION.SDK_INT >= 29) {
            tile.subtitle = if (r.on) (modeTitles[r.mode()] ?: "Включено") else "Всё через VPN"
        }
        tile.updateTile()
    }

    @SuppressLint("StartActivityAndCollapseDeprecated")
    private fun openApp() {
        val i = Intent(this, MainActivity::class.java).addFlags(Intent.FLAG_ACTIVITY_NEW_TASK)
        if (Build.VERSION.SDK_INT >= 34) {
            startActivityAndCollapse(PendingIntent.getActivity(this, 3, i, PendingIntent.FLAG_IMMUTABLE or PendingIntent.FLAG_UPDATE_CURRENT))
        } else {
            @Suppress("DEPRECATION")
            startActivityAndCollapse(i)
        }
    }
}
