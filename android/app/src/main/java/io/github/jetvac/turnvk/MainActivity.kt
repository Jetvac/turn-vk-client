package io.github.jetvac.turnvk

import android.Manifest
import android.content.Intent
import android.content.pm.PackageManager
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
        handleLink(intent)
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

    /** A wdtt:// link opened from outside: offer to save it. */
    private fun handleLink(intent: Intent?) {
        val data = intent?.dataString ?: return
        if (data.startsWith("wdtt://", ignoreCase = true)) imported.value = data
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
