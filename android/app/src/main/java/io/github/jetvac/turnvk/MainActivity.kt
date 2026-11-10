package io.github.jetvac.turnvk

import android.Manifest
import android.content.ClipboardManager
import android.content.Context
import android.content.Intent
import android.content.pm.PackageManager
import android.net.VpnService
import android.os.Build
import android.os.Bundle
import androidx.activity.ComponentActivity
import androidx.activity.compose.setContent
import androidx.activity.enableEdgeToEdge
import androidx.activity.result.contract.ActivityResultContracts
import androidx.compose.foundation.isSystemInDarkTheme
import androidx.compose.foundation.layout.Arrangement
import androidx.compose.foundation.layout.Column
import androidx.compose.foundation.layout.Row
import androidx.compose.foundation.layout.fillMaxSize
import androidx.compose.foundation.layout.fillMaxWidth
import androidx.compose.foundation.layout.height
import androidx.compose.foundation.layout.padding
import androidx.compose.foundation.layout.safeDrawingPadding
import androidx.compose.foundation.lazy.LazyColumn
import androidx.compose.foundation.lazy.items
import androidx.compose.foundation.lazy.rememberLazyListState
import androidx.compose.foundation.text.KeyboardOptions
import androidx.compose.material3.Button
import androidx.compose.material3.Card
import androidx.compose.material3.ExperimentalMaterial3Api
import androidx.compose.material3.MaterialTheme
import androidx.compose.material3.OutlinedButton
import androidx.compose.material3.OutlinedTextField
import androidx.compose.material3.SegmentedButton
import androidx.compose.material3.SegmentedButtonDefaults
import androidx.compose.material3.SingleChoiceSegmentedButtonRow
import androidx.compose.material3.Slider
import androidx.compose.material3.Switch
import androidx.compose.material3.Surface
import androidx.compose.material3.Text
import androidx.compose.material3.darkColorScheme
import androidx.compose.material3.lightColorScheme
import androidx.compose.runtime.Composable
import androidx.compose.runtime.LaunchedEffect
import androidx.compose.runtime.collectAsState
import androidx.compose.runtime.getValue
import androidx.compose.runtime.mutableFloatStateOf
import androidx.compose.runtime.mutableStateOf
import androidx.compose.runtime.remember
import androidx.compose.runtime.setValue
import androidx.compose.ui.Modifier
import androidx.compose.ui.text.font.FontFamily
import androidx.compose.ui.text.input.KeyboardType
import androidx.compose.ui.text.input.PasswordVisualTransformation
import androidx.compose.ui.unit.dp
import androidx.compose.ui.unit.sp

class MainActivity : ComponentActivity() {

    private val prefs by lazy { getSharedPreferences("settings", Context.MODE_PRIVATE) }
    private var pending: (() -> Unit)? = null

    private val vpnPermission = registerForActivityResult(ActivityResultContracts.StartActivityForResult()) { r ->
        if (r.resultCode == RESULT_OK) pending?.invoke() else TunnelState.setError("Разрешение на VPN не выдано")
        pending = null
    }

    private val notifPermission = registerForActivityResult(ActivityResultContracts.RequestPermission()) { }

    override fun onCreate(savedInstanceState: Bundle?) {
        super.onCreate(savedInstanceState)
        captchaMode = prefs.getBoolean("captcha_mode", false)
        enableEdgeToEdge()
        handleLink(intent)
        if (Build.VERSION.SDK_INT >= 33 &&
            checkSelfPermission(Manifest.permission.POST_NOTIFICATIONS) != PackageManager.PERMISSION_GRANTED
        ) {
            notifPermission.launch(Manifest.permission.POST_NOTIFICATIONS)
        }
        setContent {
            val dark = isSystemInDarkTheme()
            MaterialTheme(colorScheme = if (dark) darkColorScheme() else lightColorScheme()) {
                Surface(Modifier.fillMaxSize()) { Screen() }
            }
        }
    }

    override fun onNewIntent(intent: Intent) {
        super.onNewIntent(intent)
        handleLink(intent)
    }

    /** A wdtt:// link opened from outside fills in the link field. */
    private fun handleLink(intent: Intent?) {
        val data = intent?.dataString ?: return
        if (data.startsWith("wdtt://", ignoreCase = true)) {
            prefs.edit().putString("link", data).apply()
            linkOverride.value = data
        }
    }

    private val linkOverride = mutableStateOf<String?>(null)
    private var captchaMode: Boolean = false

    private fun connect(link: String, sessions: Int, obfs: String) {
        prefs.edit().putString("link", link).putInt("sessions", sessions).putString("obfs", obfs).putBoolean("captcha_mode", captchaMode).apply()
        mobile.SetCaptchaMode(if captchaMode { "auto" } else { "manual" })
        val start = { TunnelService.connect(this, link, sessions, obfs) }
        val ask = VpnService.prepare(this)
        if (ask != null) {
            pending = start
            vpnPermission.launch(ask)
        } else {
            start()
        }
    }

    @OptIn(ExperimentalMaterial3Api::class)
    @Composable
    private fun Screen() {
        val status by TunnelState.status.collectAsState()
        val error by TunnelState.error.collectAsState()
        val log by TunnelState.log.collectAsState()
        val captcha by TunnelState.captcha.collectAsState()
        val override by linkOverride

        var link by remember { mutableStateOf(prefs.getString("link", "") ?: "") }
        var sessions by remember { mutableFloatStateOf(prefs.getInt("sessions", 16).toFloat()) }
        var obfs by remember { mutableStateOf(prefs.getString("obfs", "audio") ?: "audio") }
        LaunchedEffect(override) { override?.let { link = it } }

        // Open the captcha page as soon as VK asks for one.
        LaunchedEffect(captcha) {
            captcha?.let {
                startActivity(Intent(this@MainActivity, CaptchaActivity::class.java).putExtra(CaptchaActivity.EXTRA_URL, it))
            }
        }

        val active = status.state in setOf("connecting", "connected", "captcha")
        val linkError = remember(link) { if (link.isBlank()) "" else mobile.Mobile.validateLink(link) }

        Column(
            Modifier.fillMaxSize().safeDrawingPadding().padding(16.dp),
            verticalArrangement = Arrangement.spacedBy(12.dp),
        ) {
            Text("TurnVK", style = MaterialTheme.typography.headlineSmall)

            OutlinedTextField(
                value = link,
                onValueChange = { link = it.trim() },
                label = { Text("Ссылка wdtt://") },
                singleLine = true,
                enabled = !active,
                visualTransformation = PasswordVisualTransformation(),
                keyboardOptions = KeyboardOptions(keyboardType=KeyboardType.Password),
                isError = linkError.isNotEmpty(),
                supportingText = { if (linkError.isNotEmpty()) Text(linkError) },
                modifier = Modifier.fillMaxWidth(),
            )
            Row(horizontalArrangement = Arrangement.spacedBy(8.dp)) {
                OutlinedButton(enabled = !active, onClick = {
                    val cm = getSystemService(ClipboardManager::class.java)
                    cm.primaryClip?.getItemAt(0)?.coerceToText(this@MainActivity)?.toString()?.trim()?.let { link = it }
                }) { Text("Вставить") }
            }
            Row(horizontalArrangement = Arrangement.spacedBy(8.dp)) {
                Text("Автокапча", style = MaterialTheme.typography.bodySmall)
                Switch(checked = captchaMode, onCheckedChange = { captchaMode = it })
            }

            Text("Сессий: ${sessions.toInt()}")
            Slider(
                value = sessions,
                onValueChange = { sessions = it },
                valueRange = 4f..48f,
                steps = 10,
                enabled = !active,
            )
            SingleChoiceSegmentedButtonRow(Modifier.fillMaxWidth()) {
                listOf("audio" to "Аудио", "video" to "Видео").forEachIndexed { i, (v, label) ->
                    SegmentedButton(
                        selected = obfs == v,
                        onClick = { obfs = v },
                        enabled = !active,
                        shape = SegmentedButtonDefaults.itemShape(i, 2),
                    ) { Text(label) }
                }
            }

            Button(
                modifier = Modifier.fillMaxWidth().height(52.dp),
                enabled = active || (link.isNotBlank() && linkError.isEmpty()),
                onClick = {
                    if (active) TunnelService.disconnect(this@MainActivity)
                    else connect(link, sessions.toInt(), obfs)
                },
            ) { Text(if (active) "Отключить" else "Подключить") }

            Card(Modifier.fillMaxWidth()) {
                Column(Modifier.padding(12.dp), verticalArrangement = Arrangement.spacedBy(4.dp)) {
                    Text(stateText(status.state), style = MaterialTheme.typography.titleMedium)
                    if (active) {
                        Text("Сессий: ${status.sessions} из ${status.target}")
                        if (status.address.isNotEmpty()) Text("Адрес: ${status.address}")
                        Text("Принято ${bytes(status.rxBytes)} · отправлено ${bytes(status.txBytes)}")
                    }
                    val err = error ?: status.lastError.takeIf { it.isNotEmpty() && status.state != "connected" }
                    if (!err.isNullOrEmpty()) Text(err, color = MaterialTheme.colorScheme.error)
                }
            }

            val listState = rememberLazyListState()
            LaunchedEffect(log.size) { if (log.isNotEmpty()) listState.scrollToItem(log.size - 1) }
            LazyColumn(Modifier.fillMaxWidth().weight(1f), state = listState) {
                items(log) { Text(it, fontFamily = FontFamily.Monospace, fontSize = 11.sp) }
            }
        }
    }

    private fun stateText(s: String) = when (s) {
        "connected" -> "Подключено"
        "connecting" -> "Подключение…"
        "captcha" -> "Ждём проверку VK"
        "failed" -> "Ошибка"
        else -> "Отключено"
    }

    private fun bytes(n: Long): String = when {
        n >= 1L shl 30 -> "%.2f ГБ".format(n / (1L shl 30).toDouble())
        n >= 1L shl 20 -> "%.1f МБ".format(n / (1L shl 20).toDouble())
        else -> "${n shr 10} КБ"
    }
}
