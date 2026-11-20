package io.github.jetvac.turnvk

import kotlinx.coroutines.flow.MutableStateFlow
import kotlinx.coroutines.flow.StateFlow
import kotlinx.coroutines.flow.asStateFlow
import org.json.JSONObject

/** One route through VK TURN. */
data class PathInfo(
    val id: Int,
    val server: String,
    val rttMs: Int,
    val fresh: Boolean,
    val rx: Long,
    val tx: Long,
)

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
    /** VK is waiting for the user to pass its check. */
    val captcha: Boolean = false,
    /** Unix seconds of the last state change. */
    val since: Long = 0,
    /** "direct" (TurnVK server) or "dtls" (standard server). */
    val protocol: String = "",
    val rttMs: Int = 0,
    val paths: List<PathInfo> = emptyList(),
    /** The tunnel is idle: a few routes, pinging together (saves battery). */
    val quiet: Boolean = false,
) {
    val active: Boolean get() = state in setOf("connecting", "connected", "captcha")

    companion object {
        fun parse(json: String): Status = runCatching {
            val o = JSONObject(json)
            val pa = o.optJSONArray("paths")
            val paths = if (pa == null) emptyList() else (0 until pa.length()).map {
                val p = pa.getJSONObject(it)
                PathInfo(
                    id = p.optInt("id"),
                    server = p.optString("server"),
                    rttMs = p.optInt("rtt_ms"),
                    fresh = p.optBoolean("fresh"),
                    rx = p.optLong("rx"),
                    tx = p.optLong("tx"),
                )
            }
            Status(
                state = o.optString("state", "stopped"),
                sessions = o.optInt("sessions"),
                target = o.optInt("target"),
                address = o.optString("address"),
                rxBytes = o.optLong("rx_bytes"),
                txBytes = o.optLong("tx_bytes"),
                reconnects = o.optLong("reconnects"),
                lastError = o.optString("last_error"),
                captcha = o.optBoolean("captcha"),
                since = o.optLong("since"),
                protocol = o.optString("protocol"),
                rttMs = o.optInt("rtt_ms"),
                paths = paths.sortedBy { it.id },
                quiet = o.optBoolean("quiet"),
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

    /**
     * Which apps Android lets into the VPN (mobile.AppPlan) as set when the
     * VPN interface was created; null while not connected.
     */
    private val _plan = MutableStateFlow<String?>(null)
    val plan: StateFlow<String?> = _plan.asStateFlow()

    fun setPlan(p: String?) { _plan.value = p }

    /** The power mode the running tunnel started with; null while stopped. */
    private val _power = MutableStateFlow<String?>(null)
    val power: StateFlow<String?> = _power.asStateFlow()

    fun setPower(p: String?) { _power.value = p }

    fun setStatus(s: Status) { _status.value = s }
    fun setCaptcha(url: String?) { _captcha.value = url }
    fun setError(e: String?) { _error.value = e }

    fun log(line: String) {
        val t = java.text.SimpleDateFormat("HH:mm:ss", java.util.Locale.ROOT).format(java.util.Date())
        val next = _log.value + "$t $line"
        _log.value = if (next.size > 500) next.takeLast(500) else next
    }

    fun clearLog() { _log.value = emptyList() }
}
