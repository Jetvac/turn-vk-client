package io.github.jetvac.turnvk

import kotlinx.coroutines.flow.MutableStateFlow
import kotlinx.coroutines.flow.StateFlow
import kotlinx.coroutines.flow.asStateFlow
import org.json.JSONObject

/** Engine status as the UI shows it. */
data class Status(
    val state: String = "stopped",
    val sessions: Int = 0,
    val target: Int = 0,
    val address: String = "",
    val rxBytes: Long = 0,
    val txBytes: Long = 0,
    val reconnects: Long = 0,
    val lastError: String = "",
) {
    companion object {
        fun parse(json: String): Status = runCatching {
            val o = JSONObject(json)
            Status(
                state = o.optString("state", "stopped"),
                sessions = o.optInt("sessions"),
                target = o.optInt("target"),
                address = o.optString("address"),
                rxBytes = o.optLong("rx_bytes"),
                txBytes = o.optLong("tx_bytes"),
                reconnects = o.optLong("reconnects"),
                lastError = o.optString("last_error"),
            )
        }.getOrDefault(Status())
    }
}

/** Shared state between the service and the UI (same process). */
object TunnelState {
    private val _status = MutableStateFlow(Status())
    val status: StateFlow<Status> = _status.asStateFlow()

    /** The captcha page VK asked the user to solve, while one is pending. */
    private val _captcha = MutableStateFlow<String?>(null)
    val captcha: StateFlow<String?> = _captcha.asStateFlow()

    /** Why the last connection attempt ended, for the UI. */
    private val _error = MutableStateFlow<String?>(null)
    val error: StateFlow<String?> = _error.asStateFlow()

    private val _log = MutableStateFlow<List<String>>(emptyList())
    val log: StateFlow<List<String>> = _log.asStateFlow()

    fun setStatus(s: Status) { _status.value = s }
    fun setCaptcha(url: String?) { _captcha.value = url }
    fun setError(e: String?) { _error.value = e }

    fun log(line: String) {
        val t = java.text.SimpleDateFormat("HH:mm:ss", java.util.Locale.ROOT).format(java.util.Date())
        val next = _log.value + "$t $line"
        _log.value = if (next.size > 300) next.takeLast(300) else next
    }
}
