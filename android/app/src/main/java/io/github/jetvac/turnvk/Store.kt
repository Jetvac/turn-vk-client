package io.github.jetvac.turnvk

import android.content.Context
import android.content.SharedPreferences
import org.json.JSONArray
import org.json.JSONObject
import java.util.UUID

/** A saved server: a wdtt:// link under a name the user chose. */
data class Profile(val id: String, val name: String, val link: String) {
    /** The server's host, for display ("" if the link has another form). */
    val host: String
        get() = link.removePrefix("wdtt://").substringBefore(':').substringBefore('?')
}

/**
 * The app's settings and saved servers (SharedPreferences). The service,
 * the quick settings tile and the boot receiver read the same values, so
 * a connection started from any of them uses what the user set up.
 */
class Store(ctx: Context) {
    private val p: SharedPreferences = ctx.applicationContext.getSharedPreferences("settings", Context.MODE_PRIVATE)

    init {
        migrate()
    }

    /** Before profiles there was one "link" setting: keep it as the first profile. */
    private fun migrate() {
        if (p.contains("profiles")) return
        val old = p.getString("link", "").orEmpty()
        val list = if (old.isNotBlank()) listOf(Profile(newId(), "Мой сервер", old)) else emptyList()
        p.edit().putString("profiles", encode(list)).putString("current", list.firstOrNull()?.id).apply()
    }

    var profiles: List<Profile>
        get() = decode(p.getString("profiles", "[]").orEmpty())
        set(v) {
            p.edit().putString("profiles", encode(v)).apply()
        }

    var currentId: String?
        get() = p.getString("current", null)
        set(v) {
            p.edit().putString("current", v).apply()
        }

    /** The selected profile, or the first one. */
    val current: Profile?
        get() {
            val all = profiles
            return all.firstOrNull { it.id == currentId } ?: all.firstOrNull()
        }

    /** Adds a profile, or replaces the one with the same id; selects it. */
    fun save(profile: Profile) {
        val all = profiles.toMutableList()
        val i = all.indexOfFirst { it.id == profile.id }
        if (i >= 0) all[i] = profile else all.add(profile)
        profiles = all
        currentId = profile.id
    }

    fun delete(id: String) {
        profiles = profiles.filter { it.id != id }
        if (currentId == id) currentId = profiles.firstOrNull()?.id
    }

    var sessions: Int
        get() = p.getInt("sessions", 32)
        set(v) {
            p.edit().putInt("sessions", v).apply()
        }

    /** RTP disguise: "audio" or "video". */
    var obfs: String
        get() = p.getString("obfs", "audio") ?: "audio"
        set(v) {
            p.edit().putString("obfs", v).apply()
        }

    /**
     * Power mode: "saver", "balanced" (the default) or "always" (never
     * idles). See Power.kt.
     */
    var power: String
        get() = p.getString("power", Power.BALANCED) ?: Power.BALANCED
        set(v) {
            p.edit().putString("power", v).apply()
        }

    var captchaAuto: Boolean
        get() = p.getBoolean("captcha_mode", false)
        set(v) {
            p.edit().putBoolean("captcha_mode", v).apply()
        }

    /** Connect when the phone starts. */
    var bootConnect: Boolean
        get() = p.getBoolean("boot_connect", false)
        set(v) {
            p.edit().putBoolean("boot_connect", v).apply()
        }

    /** Download the split tunneling lists on Wi-Fi only (on by default). */
    var listsWifiOnly: Boolean
        get() = p.getBoolean("lists_wifi_only", true)
        set(v) {
            p.edit().putBoolean("lists_wifi_only", v).apply()
        }

    /** Send the server statistics of the connection (on by default). */
    var serverStats: Boolean
        get() = p.getBoolean("server_stats", true)
        set(v) {
            p.edit().putBoolean("server_stats", v).apply()
        }

    /** When the tunnel service last heard from GitHub about updates (ms). */
    var updateCheckedAt: Long
        get() = p.getLong("update_checked_at", 0L)
        set(v) {
            p.edit().putLong("update_checked_at", v).apply()
        }

    /** The newest version a notification announced. */
    var updateNotified: String
        get() = p.getString("update_notified", "") ?: ""
        set(v) {
            p.edit().putString("update_notified", v).apply()
        }

    /**
     * Split tunneling rules (JSON, as the engine keeps them; see
     * SplitRules). The apps an older version let around the tunnel become
     * rules sending them direct.
     */
    var split: String
        get() {
            p.getString("split", null)?.let { return it }
            val old = p.getStringSet("excluded_apps", emptySet()).orEmpty()
            if (old.isEmpty()) return ""
            val r = SplitRules(on = true, apps = old.sorted().map { AppRoute(it, "direct") }).toJson()
            p.edit().putString("split", r).remove("excluded_apps").apply()
            return r
        }
        set(v) {
            p.edit().putString("split", v).apply()
        }

    companion object {
        fun newId(): String = UUID.randomUUID().toString()

        private fun encode(list: List<Profile>): String {
            val a = JSONArray()
            list.forEach { a.put(JSONObject().put("id", it.id).put("name", it.name).put("link", it.link)) }
            return a.toString()
        }

        private fun decode(s: String): List<Profile> = runCatching {
            val a = JSONArray(s)
            (0 until a.length()).map {
                val o = a.getJSONObject(it)
                Profile(o.getString("id"), o.optString("name"), o.optString("link"))
            }
        }.getOrDefault(emptyList())
    }
}
