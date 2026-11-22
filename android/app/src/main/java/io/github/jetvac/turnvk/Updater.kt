package io.github.jetvac.turnvk

import android.content.ActivityNotFoundException
import android.content.Context
import android.content.Intent
import android.net.Uri
import android.os.Build
import android.provider.Settings
import androidx.core.content.FileProvider
import kotlinx.coroutines.Dispatchers
import kotlinx.coroutines.flow.MutableStateFlow
import kotlinx.coroutines.flow.StateFlow
import kotlinx.coroutines.flow.asStateFlow
import kotlinx.coroutines.withContext
import org.json.JSONObject
import java.io.File

/**
 * Finds a newer TurnVK release on GitHub and installs it: the APK is
 * downloaded and checked by the engine (SHA256SUMS.txt), then Android's
 * installer asks the user to confirm.
 */
object Updater {
    /** A newer version ("0.4.0") and its release as JSON, or null. */
    data class Available(val version: String, val json: String)

    sealed interface State {
        data object Idle : State
        data object Checking : State
        data object Latest : State
        data object Downloading : State
        data class Failed(val message: String) : State
    }

    private val _available = MutableStateFlow<Available?>(null)
    val available: StateFlow<Available?> = _available.asStateFlow()

    private val _state = MutableStateFlow<State>(State.Idle)
    val state: StateFlow<State> = _state.asStateFlow()

    private var lastCheck = 0L

    /** Asks GitHub; quietly at most every few hours unless [manual]. */
    suspend fun check(manual: Boolean = false) {
        val now = System.currentTimeMillis()
        if (!manual && now - lastCheck < 3 * 3600_000L) return
        lastCheck = now
        if (manual) _state.value = State.Checking
        val r = withContext(Dispatchers.IO) { runCatching { mobile.Mobile.checkUpdate(BuildConfig.VERSION_NAME) } }
        r.onSuccess { json ->
            _available.value = if (json.isNullOrEmpty()) null else Available(JSONObject(json).optString("version"), json)
            if (manual) _state.value = if (json.isNullOrEmpty()) State.Latest else State.Idle
        }.onFailure {
            if (manual) _state.value = State.Failed("не удалось проверить: ${it.message}")
        }
    }

    /** How often the tunnel service asks GitHub in the background. */
    private const val BACKGROUND_EVERY = 12 * 3600_000L

    /**
     * From the tunnel service, on a worker thread: asks GitHub at most every
     * [BACKGROUND_EVERY] (kept across restarts; a failed try is repeated at
     * the next call) and returns the newer version, if any. A phone whose
     * owner never opens the app otherwise never hears of one: the stats
     * showed phones two versions behind, with bugs long fixed.
     */
    fun checkInBackground(ctx: Context): Available? {
        val store = Store(ctx)
        val now = System.currentTimeMillis()
        if (now - store.updateCheckedAt < BACKGROUND_EVERY) return _available.value
        val json = runCatching { mobile.Mobile.checkUpdate(BuildConfig.VERSION_NAME) }.getOrNull() ?: return null
        store.updateCheckedAt = now
        lastCheck = now
        val a = if (json.isEmpty()) null else Available(JSONObject(json).optString("version"), json)
        _available.value = a
        return a
    }

    /** Downloads the new version and opens the installer. */
    suspend fun install(ctx: Context) {
        val a = _available.value ?: return
        if (Build.VERSION.SDK_INT >= 26 && !ctx.packageManager.canRequestPackageInstalls()) {
            // Android asks once to let TurnVK install apps.
            _state.value = State.Failed("Разрешите TurnVK устанавливать приложения и нажмите «Обновить» ещё раз.")
            runCatching {
                ctx.startActivity(
                    Intent(Settings.ACTION_MANAGE_UNKNOWN_APP_SOURCES, Uri.parse("package:${ctx.packageName}"))
                        .addFlags(Intent.FLAG_ACTIVITY_NEW_TASK)
                )
            }
            return
        }
        _state.value = State.Downloading
        val dir = File(ctx.cacheDir, "updates").apply { mkdirs() }
        dir.listFiles()?.forEach { it.delete() }
        val apk = File(dir, "TurnVK-${a.version}.apk")
        val r = withContext(Dispatchers.IO) { runCatching { mobile.Mobile.downloadUpdate(a.json, apk.absolutePath) } }
        r.onFailure {
            _state.value = State.Failed("обновление не скачалось: ${it.message}")
            return
        }
        _state.value = State.Idle
        val uri = FileProvider.getUriForFile(ctx, "${ctx.packageName}.files", apk)
        val install = Intent(Intent.ACTION_VIEW)
            .setDataAndType(uri, "application/vnd.android.package-archive")
            .addFlags(Intent.FLAG_GRANT_READ_URI_PERMISSION or Intent.FLAG_ACTIVITY_NEW_TASK)
        try {
            ctx.startActivity(install)
        } catch (e: ActivityNotFoundException) {
            _state.value = State.Failed("нет программы установки: ${e.message}")
        }
    }
}
