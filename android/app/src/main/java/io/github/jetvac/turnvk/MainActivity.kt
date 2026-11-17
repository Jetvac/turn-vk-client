package io.github.jetvac.turnvk

import android.Manifest
import android.content.Intent
import android.content.pm.PackageManager
import android.net.Uri
import android.net.VpnService
import android.os.Build
import android.os.Bundle
import androidx.activity.ComponentActivity
import androidx.activity.compose.setContent
import androidx.activity.enableEdgeToEdge
import androidx.activity.result.contract.ActivityResultContracts
import androidx.compose.runtime.mutableStateOf

class MainActivity : ComponentActivity() {

    private val store by lazy { Store(this) }

    /** A wdtt:// link opened from outside, waiting to be saved as a profile. */
    private val imported = mutableStateOf<String?>(null)

    private var pending: (() -> Unit)? = null

    private val vpnPermission = registerForActivityResult(ActivityResultContracts.StartActivityForResult()) { r ->
        if (r.resultCode == RESULT_OK) pending?.invoke() else TunnelState.setError("Разрешение на VPN не выдано")
        pending = null
    }

    private val notifPermission = registerForActivityResult(ActivityResultContracts.RequestPermission()) { }

    override fun onCreate(savedInstanceState: Bundle?) {
        super.onCreate(savedInstanceState)
        enableEdgeToEdge()
        // Only a fresh start: after a rotation, or when Android reopens the
        // app from Recents with the intent that first opened it, the link
        // was already handled.
        if (savedInstanceState == null && intent.flags and Intent.FLAG_ACTIVITY_LAUNCHED_FROM_HISTORY == 0) {
            handleLink(intent)
        }
        if (Build.VERSION.SDK_INT >= 33 &&
            checkSelfPermission(Manifest.permission.POST_NOTIFICATIONS) != PackageManager.PERMISSION_GRANTED
        ) {
            notifPermission.launch(Manifest.permission.POST_NOTIFICATIONS)
        }
        setContent {
            TurnVKTheme {
                App(store = store, imported = imported, connect = ::connect)
            }
        }
    }

    override fun onNewIntent(intent: Intent) {
        super.onNewIntent(intent)
        handleLink(intent)
    }

    /**
     * A wdtt:// link opened from outside: select the saved server with it,
     * or offer to save it. The link is then taken off the intent, so that
     * the app does not ask again each time it is opened.
     */
    private fun handleLink(intent: Intent?) {
        val raw = intent?.dataString ?: return
        if (!raw.startsWith("wdtt://", ignoreCase = true)) return
        // Messengers and browsers may percent-encode parts of the link.
        val link = Uri.decode(raw).trim()
        intent.data = null
        setIntent(intent)
        val existing = store.profiles.firstOrNull { Uri.decode(it.link).trim() == link }
        if (existing != null) {
            store.currentId = existing.id
        } else {
            imported.value = link
        }
    }

    /** Connects to the selected profile, asking for the VPN permission first. */
    private fun connect() {
        val start = { TunnelService.connect(this) }
        val ask = VpnService.prepare(this)
        if (ask != null) {
            pending = start
            vpnPermission.launch(ask)
        } else {
            start()
        }
    }
}
