package io.github.jetvac.turnvk

import android.content.Context
import androidx.compose.foundation.Image
import androidx.compose.foundation.background
import androidx.compose.foundation.clickable
import androidx.compose.foundation.layout.Arrangement
import androidx.compose.foundation.layout.Box
import androidx.compose.foundation.layout.Column
import androidx.compose.foundation.layout.ExperimentalLayoutApi
import androidx.compose.foundation.layout.FlowRow
import androidx.compose.foundation.layout.PaddingValues
import androidx.compose.foundation.layout.Row
import androidx.compose.foundation.layout.Spacer
import androidx.compose.foundation.layout.fillMaxSize
import androidx.compose.foundation.layout.fillMaxWidth
import androidx.compose.foundation.layout.height
import androidx.compose.foundation.layout.padding
import androidx.compose.foundation.layout.size
import androidx.compose.foundation.layout.width
import androidx.compose.foundation.lazy.LazyColumn
import androidx.compose.foundation.lazy.items
import androidx.compose.foundation.rememberScrollState
import androidx.compose.foundation.shape.RoundedCornerShape
import androidx.compose.foundation.text.KeyboardActions
import androidx.compose.foundation.text.KeyboardOptions
import androidx.compose.foundation.verticalScroll
import androidx.compose.material.icons.Icons
import androidx.compose.material.icons.automirrored.filled.ArrowBack
import androidx.compose.material.icons.filled.Add
import androidx.compose.material.icons.filled.Delete
import androidx.compose.material.icons.filled.Search
import androidx.compose.material3.Button
import androidx.compose.material3.CircularProgressIndicator
import androidx.compose.material3.DropdownMenu
import androidx.compose.material3.DropdownMenuItem
import androidx.compose.material3.ExperimentalMaterial3Api
import androidx.compose.material3.FilterChip
import androidx.compose.material3.HorizontalDivider
import androidx.compose.material3.Icon
import androidx.compose.material3.IconButton
import androidx.compose.material3.ListItem
import androidx.compose.material3.ListItemDefaults
import androidx.compose.material3.MaterialTheme
import androidx.compose.material3.OutlinedButton
import androidx.compose.material3.OutlinedTextField
import androidx.compose.material3.RadioButton
import androidx.compose.material3.Scaffold
import androidx.compose.material3.SegmentedButton
import androidx.compose.material3.SegmentedButtonDefaults
import androidx.compose.material3.SingleChoiceSegmentedButtonRow
import androidx.compose.material3.Switch
import androidx.compose.material3.Text
import androidx.compose.material3.TextButton
import androidx.compose.material3.TopAppBar
import androidx.compose.runtime.Composable
import androidx.compose.runtime.LaunchedEffect
import androidx.compose.runtime.collectAsState
import androidx.compose.runtime.getValue
import androidx.compose.runtime.mutableStateOf
import androidx.compose.runtime.remember
import androidx.compose.runtime.rememberCoroutineScope
import androidx.compose.runtime.setValue
import androidx.compose.ui.Alignment
import androidx.compose.ui.Modifier
import androidx.compose.ui.graphics.Color
import androidx.compose.ui.graphics.ImageBitmap
import androidx.compose.ui.graphics.asImageBitmap
import androidx.compose.ui.platform.LocalContext
import androidx.compose.ui.text.font.FontWeight
import androidx.compose.ui.text.input.ImeAction
import androidx.compose.ui.text.style.TextOverflow
import androidx.compose.ui.unit.dp
import androidx.compose.ui.unit.sp
import androidx.core.graphics.drawable.toBitmap
import kotlinx.coroutines.Dispatchers
import kotlinx.coroutines.delay
import kotlinx.coroutines.launch
import kotlinx.coroutines.withContext
import org.json.JSONArray
import org.json.JSONObject
import java.text.SimpleDateFormat
import java.util.Locale

// ---------------------------------------------------------------- rules
//
// The same rules as on Windows (core/split.Rules), with package names in
// place of program paths. The engine cleans them up and applies them.

data class AppRoute(val path: String, val route: String, val off: Boolean = false)
data class SiteRoute(val domain: String, val route: String, val off: Boolean = false)
data class ListRoute(val list: String, val route: String, val off: Boolean = false)

/** A mode for a network: "wifi", "mobile" or "wired" (core/split.NetRule). */
data class NetRoute(val network: String, val mode: String, val off: Boolean = false)

data class SplitRules(
    val on: Boolean = false,
    val default: String = "vpn",
    val lan: Boolean = true,
    val apps: List<AppRoute> = emptyList(),
    val domains: List<SiteRoute> = emptyList(),
    val lists: List<ListRoute> = emptyList(),
    /** A site sent direct that does not open is not tried through the VPN. */
    val noRetry: Boolean = false,
    /** Only the apps sent through the VPN enter it; the others stay out. */
    val appsOnly: Boolean = false,
    /** "Own rules" chosen: not read back as a ready-made mode. */
    val custom: Boolean = false,
    /** Modes by network. */
    val networks: List<NetRoute> = emptyList(),
    /** Game apps stay out of the VPN, whatever the mode. */
    val games: Boolean = false,
) {
    /** The route a new rule gets: the opposite of the others'. */
    val other: String get() = if (default == "direct") "vpn" else "direct"

    fun toJson(): String {
        val o = JSONObject().put("on", on).put("default", default).put("lan", lan).put("noRetry", noRetry)
        o.put("apps", JSONArray().apply { apps.forEach { put(JSONObject().put("path", it.path).put("route", it.route).put("off", it.off)) } })
        o.put("domains", JSONArray().apply { domains.forEach { put(JSONObject().put("domain", it.domain).put("route", it.route).put("off", it.off)) } })
        o.put("lists", JSONArray().apply { lists.forEach { put(JSONObject().put("list", it.list).put("route", it.route).put("off", it.off)) } })
        o.put("appsOnly", appsOnly)
        if (custom) o.put("custom", true)
        if (games) o.put("games", true)
        o.put("networks", JSONArray().apply { networks.forEach { put(JSONObject().put("network", it.network).put("mode", it.mode).put("off", it.off)) } })
        return o.toString()
    }

    companion object {
        fun parse(s: String): SplitRules = runCatching {
            if (s.isBlank()) return SplitRules()
            val o = JSONObject(s)
            fun <T> arr(name: String, f: (JSONObject) -> T): List<T> {
                val a = o.optJSONArray(name) ?: return emptyList()
                return (0 until a.length()).map { f(a.getJSONObject(it)) }
            }
            SplitRules(
                on = o.optBoolean("on"),
                default = o.optString("default", "vpn").ifEmpty { "vpn" },
                lan = o.optBoolean("lan", true),
                apps = arr("apps") { AppRoute(it.optString("path"), it.optString("route", "direct"), it.optBoolean("off")) },
                domains = arr("domains") { SiteRoute(it.optString("domain"), it.optString("route", "direct"), it.optBoolean("off")) },
                lists = arr("lists") { ListRoute(it.optString("list"), it.optString("route", "direct"), it.optBoolean("off")) },
                noRetry = o.optBoolean("noRetry"),
                appsOnly = o.optBoolean("appsOnly"),
                custom = o.optBoolean("custom"),
                networks = arr("networks") { NetRoute(it.optString("network"), it.optString("mode", "vpn"), it.optBoolean("off")) },
                games = o.optBoolean("games"),
            )
        }.getOrDefault(SplitRules())
    }
}

/** Gives the rules to the engine and saves them as it cleaned them up. */
fun applyRules(store: Store, r: SplitRules): SplitRules {
    val js = runCatching { mobile.Mobile.setSplit(r.toJson()) }.getOrElse { r.toJson() }
    store.split = js
    return SplitRules.parse(js)
}

/** The mode the rules are in: "vpn", "blocked", "russia" or "custom". */
fun SplitRules.mode(): String = runCatching { mobile.Mobile.modeOf(toJson()) }.getOrDefault("custom")

/** The rules put into a mode (the engine adds the lists it needs). */
fun SplitRules.withMode(mode: String): SplitRules =
    runCatching { SplitRules.parse(mobile.Mobile.applyMode(toJson(), mode)) }.getOrDefault(this)

internal val modeTitles = mapOf(
    "vpn" to "Всё через VPN",
    "blocked" to "Только заблокированное через VPN",
    "russia" to "Российское напрямую",
    "apps" to "Только выбранные приложения через VPN",
    "custom" to "Свои правила",
)

private val modeTexts = mapOf(
    "vpn" to "Раздельное туннелирование выключено",
    "blocked" to "Сайты и адреса, заблокированные в России, — через VPN, остальное напрямую. Российские сайты и игры работают с обычной скоростью",
    "russia" to "Российские сайты и адреса (.ru, .su, .рф) — напрямую, остальное через VPN",
    "apps" to "Через VPN идут только приложения с правилом «Через VPN» (ниже); остальные Android не пускает в туннель совсем — меньше расход батареи. Правила для сайтов действуют внутри выбранных приложений",
    "custom" to "Приложения, сайты и списки ниже — как вы настроите",
)

/** What applies now: the mode for the network the phone is on. */
internal data class Effective(val mode: String, val network: String, val networkName: String, val here: String) {
    companion object {
        fun now(): Effective = runCatching {
            val o = JSONObject(mobile.Mobile.effective())
            Effective(o.optString("mode"), o.optString("network"), o.optString("networkName"), o.optString("here"))
        }.getOrDefault(Effective("", "", "", ""))
    }
}

internal val netNames = mapOf("wifi" to "Wi-Fi", "mobile" to "Мобильная сеть", "wired" to "Кабель (Ethernet)")

/** Notes on the rules (core/split.CheckRules), by "kind|key". */
private fun ruleNotes(r: SplitRules): Map<String, List<Pair<String, Boolean>>> = runCatching {
    val a = JSONArray(mobile.Mobile.checkRules(r.toJson()))
    (0 until a.length()).map { a.getJSONObject(it) }
        .groupBy({ it.optString("kind") + "|" + it.optString("key") }, { it.optString("text") to it.optBoolean("warn") })
}.getOrDefault(emptyMap())

private fun plural(n: Int, one: String, few: String, many: String): String {
    val a = n % 10
    val b = n % 100
    return "$n " + when {
        a == 1 && b != 11 -> one
        a in 2..4 && (b < 12 || b > 14) -> few
        else -> many
    }
}

/** One line about the rules for the home screen. */
fun splitSummary(r: SplitRules): String {
    val mode = r.mode()
    if (!r.on) return modeTitles.getValue("vpn")
    var t = if (mode == "custom") "Своё: остальное " + routeName(r.default) else modeTitles[mode] ?: ""
    val eff = Effective.now()
    if (eff.network.isNotEmpty()) t = (modeTitles[eff.mode] ?: t) + " (" + eff.networkName + ")"
    val parts = buildList {
        r.apps.count { !it.off }.takeIf { it > 0 }?.let { add(plural(it, "приложение", "приложения", "приложений")) }
        r.domains.count { !it.off }.takeIf { it > 0 }?.let { add(plural(it, "сайт", "сайта", "сайтов")) }
        r.lists.count { !it.off }.takeIf { it > 0 }?.let { add(plural(it, "список", "списка", "списков")) }
    }
    if (parts.isNotEmpty()) t += " · " + parts.joinToString(", ")
    return t
}

/** Adds (or changes) the rule for an app. */
fun SplitRules.withApp(pkg: String, route: String): SplitRules {
    val rest = apps.filter { it.path != pkg }
    return copy(on = true, apps = rest + AppRoute(pkg, route))
}

/** The rules for the report: counts, no app or site names. */
fun describeSplit(r: SplitRules): String {
    if (!r.on) return "off"
    fun <T> n(l: List<T>, route: (T) -> String, off: (T) -> Boolean, want: String) = l.count { !off(it) && route(it) == want }
    return "on, others ${r.default}, LAN direct ${r.lan}, apps direct/VPN " +
        "${n(r.apps, { it.route }, { it.off }, "direct")}/${n(r.apps, { it.route }, { it.off }, "vpn")}, sites " +
        "${n(r.domains, { it.route }, { it.off }, "direct")}/${n(r.domains, { it.route }, { it.off }, "vpn")}, lists " +
        r.lists.filter { !it.off }.joinToString(" ") { it.list + "=" + it.route }
}

internal fun routeName(r: String) = if (r == "direct") "напрямую" else "через VPN"

// ---------------------------------------------------------------- lists

private val listTitles = mapOf(
    "geoip:ru-blocked" to "Адреса, заблокированные в России",
    "geoip:ru-blocked-community" to "Адреса, заблокированные в России (сообщество)",
    "geoip:re-filter" to "Адреса re:filter",
    "geoip:ru-whitelist" to "Белый список мобильного интернета",
    "geoip:private" to "Локальные адреса",
    "geosite:ru-blocked" to "Сайты, заблокированные в России",
    "geosite:ru-blocked-all" to "Все известные заблокированные сайты (большой список)",
    "geosite:ru-available-only-inside" to "Сайты, работающие только из России",
    "geosite:category-ru" to "Российские сайты",
    "geosite:category-gov-ru" to "Госсайты России",
    "geosite:category-ads-all" to "Реклама",
    "geoip:telegram" to "Telegram (адреса)",
    "geosite:telegram" to "Telegram",
    "geosite:youtube" to "YouTube",
    "geosite:discord" to "Discord",
    "geosite:openai" to "ChatGPT (OpenAI)",
    "geosite:google" to "Google",
    "geoip:google" to "Google (адреса)",
    "geosite:meta" to "Instagram, Facebook, WhatsApp",
    "geoip:facebook" to "Facebook (адреса)",
    "geosite:twitter" to "X (Twitter)",
    "geoip:twitter" to "X (Twitter, адреса)",
    "geoip:cloudflare" to "Cloudflare (адреса)",
    "geosite:netflix" to "Netflix",
    "geosite:steam" to "Steam",
    "geosite:twitch" to "Twitch",
    "geosite:spotify" to "Spotify",
)

private val ru = Locale("ru")

private fun countryName(code: String): String {
    if (!Regex("[a-z]{2}").matches(code)) return ""
    val n = Locale("", code.uppercase()).getDisplayCountry(ru)
    return if (n.isBlank() || n.equals(code, true)) "" else n
}

private fun listTitle(n: String): String {
    listTitles[n]?.let { return it }
    val kind = n.substringBefore(':')
    val code = n.substringAfter(':')
    if (kind == "geoip") countryName(code).let { if (it.isNotEmpty()) return it }
    return if (kind == "geoip") "Адреса $code" else "Сайты $code"
}

private val presets = listOf(
    "Россия напрямую" to listOf("geoip:ru" to "direct"),
    "Заблокированное в России — через VPN" to listOf("geosite:ru-blocked" to "vpn", "geoip:ru-blocked" to "vpn"),
    "Работает только из России — напрямую" to listOf("geosite:ru-available-only-inside" to "direct"),
)
private val services = listOf(
    "YouTube" to listOf("geosite:youtube"),
    "Discord" to listOf("geosite:discord"),
    "Telegram" to listOf("geosite:telegram", "geoip:telegram"),
    "ChatGPT" to listOf("geosite:openai"),
    "Google" to listOf("geosite:google"),
    "Instagram, Facebook" to listOf("geosite:meta"),
    "X (Twitter)" to listOf("geosite:twitter"),
)

private fun SplitRules.withLists(items: List<Pair<String, String>>): SplitRules {
    val names = items.map { it.first }.toSet()
    return copy(on = true, lists = lists.filter { it.list !in names } + items.map { ListRoute(it.first, it.second) })
}

private data class ListsInfo(
    val files: List<Triple<String, Long, String>> = emptyList(),
    val busy: Boolean = false,
    val error: String = "",
    val missing: Set<String> = emptySet(),
    val sizes: Map<String, Int> = emptyMap(),
    val big: Int = Int.MAX_VALUE,
    val approx: Map<String, Int> = emptyMap(),
    val waiting: Boolean = false,
) {
    companion object {
        fun parse(s: String): ListsInfo = runCatching {
            val o = JSONObject(s)
            val fa = o.optJSONArray("files") ?: JSONArray()
            val ma = o.optJSONArray("missing") ?: JSONArray()
            ListsInfo(
                files = (0 until fa.length()).map { val f = fa.getJSONObject(it); Triple(f.optString("name"), f.optLong("size"), f.optString("updated")) },
                busy = o.optBoolean("busy"),
                error = o.optString("error"),
                missing = (0 until ma.length()).map { ma.getString(it) }.toSet(),
                sizes = o.optJSONObject("sizes")?.let { m -> m.keys().asSequence().associateWith { m.optInt(it) } }.orEmpty(),
                big = o.optInt("big", Int.MAX_VALUE),
                approx = o.optJSONObject("approx")?.let { m -> m.keys().asSequence().associateWith { m.optInt(it) } }.orEmpty(),
                waiting = o.optBoolean("waiting"),
            )
        }.getOrDefault(ListsInfo())
    }
}

private fun fmtUpdated(iso: String): String = runCatching {
    // "2026-11-17T12:12:00.123456+03:00": the part Java 7's parser reads.
    val d = SimpleDateFormat("yyyy-MM-dd'T'HH:mm:ss", Locale.US).parse(iso.take(19))!!
    SimpleDateFormat("d MMM HH:mm", ru).format(d)
}.getOrDefault("")

// ---------------------------------------------------------------- apps

internal class AppLabels(private val ctx: Context) {
    private val cache = HashMap<String, Pair<String, ImageBitmap?>>()
    fun get(pkg: String): Pair<String, ImageBitmap?> = cache.getOrPut(pkg) {
        val pm = ctx.packageManager
        runCatching {
            val ai = pm.getApplicationInfo(pkg, 0)
            pm.getApplicationLabel(ai).toString() to runCatching { pm.getApplicationIcon(ai).toBitmap(72, 72).asImageBitmap() }.getOrNull()
        }.getOrDefault(pkg to null)
    }
}

// ---------------------------------------------------------------- the tab

@OptIn(ExperimentalLayoutApi::class)
@Composable
internal fun RoutesTab(store: Store, rules: SplitRules, update: (SplitRules) -> Unit, active: Boolean, onAddApp: () -> Unit) {
    val ctx = LocalContext.current
    val scope = rememberCoroutineScope()
    val labels = remember { AppLabels(ctx) }
    val applied by TunnelState.plan.collectAsState()
    var info by remember { mutableStateOf(ListsInfo()) }
    var conns by remember { mutableStateOf<List<JSONObject>>(emptyList()) }
    var fails by remember { mutableStateOf<List<JSONObject>>(emptyList()) }
    var recent by remember { mutableStateOf(false) }
    var filter by remember { mutableStateOf("all") }
    var eff by remember { mutableStateOf(Effective.now()) }
    val notes = remember(rules) { ruleNotes(rules) }
    // The lists' state, and the connections while connected.
    val onScreen = rememberOnScreen()
    LaunchedEffect(active, rules, recent, onScreen) {
        if (!onScreen) return@LaunchedEffect
        while (true) {
            info = ListsInfo.parse(withContext(Dispatchers.IO) { runCatching { mobile.Mobile.listsInfo() }.getOrDefault("") })
            eff = Effective.now()
            conns = if (active) withContext(Dispatchers.IO) {
                runCatching { JSONArray(if (recent) mobile.Mobile.history() else mobile.Mobile.conns()) }.getOrDefault(JSONArray()).let { a -> (0 until a.length()).map { a.getJSONObject(it) } }
            } else emptyList()
            fails = if (active) withContext(Dispatchers.IO) {
                runCatching { JSONArray(mobile.Mobile.failures()) }.getOrDefault(JSONArray()).let { a -> (0 until a.length()).map { a.getJSONObject(it) } }
            } else emptyList()
            delay(2000)
        }
    }
    val planNow = remember(rules) { runCatching { mobile.Mobile.appPlan() }.getOrDefault("") }

    Column(
        Modifier.fillMaxSize().verticalScroll(rememberScrollState()).padding(horizontal = 16.dp, vertical = 6.dp),
        verticalArrangement = Arrangement.spacedBy(12.dp),
    ) {
        Panel {
            Column {
                SectionTitle("Режим", Modifier.padding(bottom = 2.dp))
                val mode = remember(rules) { rules.mode() }
                modeTitles.forEach { (id, title) ->
                    Row(
                        Modifier.fillMaxWidth().clickable { update(rules.withMode(id)) }.padding(vertical = 6.dp),
                        verticalAlignment = Alignment.CenterVertically,
                    ) {
                        RadioButton(selected = mode == id, onClick = { update(rules.withMode(id)) })
                        Spacer(Modifier.width(6.dp))
                        Column(Modifier.weight(1f)) {
                            Text(title, fontWeight = FontWeight.SemiBold)
                            Text(modeTexts[id] ?: "", fontSize = 12.5.sp, color = pal.muted, lineHeight = 17.sp)
                        }
                    }
                }
                Text(
                    "Режим добавляет нужные списки и не трогает ваши правила для приложений и сайтов. Путь выбирается для каждого нового соединения.",
                    fontSize = 12.5.sp, color = pal.muted, lineHeight = 17.sp, modifier = Modifier.padding(top = 4.dp),
                )
            }
        }

        Panel {
            SwitchRow(
                title = "Игры напрямую",
                text = "Приложения-игры идут мимо VPN при любом режиме: у большинства игр нет блокировок, а напрямую пинг самый низкий. " +
                    "Android узнаёт игры по их категории в магазине; другую игру можно добавить ниже правилом «напрямую». Меняется при подключении",
                checked = rules.games,
                onChange = { update(rules.copy(games = it)) },
            )
        }

        NetworksPanel(rules, update, active, eff)

        if (active && applied != null && planNow.isNotEmpty() && planNow != applied) {
            Banner(
                "Нужно переподключиться",
                "Какие приложения Android пускает в VPN, меняется только при подключении.",
                action = "Переподключить",
            ) { TunnelService.restart(ctx) }
        }

        ExplainPanel(rules, labels)

        if (fails.isNotEmpty()) FailuresPanel(fails, rules, update) {
            scope.launch {
                withContext(Dispatchers.IO) { runCatching { mobile.Mobile.forgetFailures() } }
                fails = emptyList()
            }
        }

        Panel {
            Column {
                Text("Остальные приложения", fontWeight = FontWeight.SemiBold)
                Text("Куда идут приложения, для которых нет правила", fontSize = 12.5.sp, color = pal.muted)
                Spacer(Modifier.height(8.dp))
                RouteSeg(rules.default, Modifier.fillMaxWidth()) { update(rules.copy(default = it)) }
                HorizontalDivider(color = pal.line, modifier = Modifier.padding(top = 10.dp, bottom = 2.dp))
                SwitchRow(
                    title = "Локальная сеть напрямую",
                    text = "Роутер, принтеры и другие устройства дома (192.168.x.x, 10.x.x.x)",
                    checked = rules.lan,
                    onChange = { update(rules.copy(lan = it)) },
                )
                HorizontalDivider(color = pal.line, modifier = Modifier.padding(vertical = 2.dp))
                SwitchRow(
                    title = "Не открылся напрямую — через VPN",
                    text = "Если сайт, который идёт напрямую, не отвечает или обрывает соединение (так обычно выглядит блокировка), TurnVK откроет его через VPN и предложит правило",
                    checked = !rules.noRetry,
                    onChange = { update(rules.copy(noRetry = !it)) },
                )
            }
        }

        // ---- apps
        Panel {
            Column {
                SectionTitle("Приложения", Modifier.padding(bottom = 8.dp))
                if (rules.apps.isEmpty()) {
                    Text("Правил пока нет. Добавьте приложение — или выберите его в списке соединений ниже.", fontSize = 12.5.sp, color = pal.muted)
                }
                rules.apps.forEachIndexed { i, a ->
                    val (label, icon) = labels.get(a.path)
                    RuleRow(
                        title = label, sub = a.path, icon = icon, route = a.route, off = a.off,
                        onRoute = { r -> update(rules.copy(apps = rules.apps.toMutableList().also { it[i] = a.copy(route = r) })) },
                        onOff = { v -> update(rules.copy(apps = rules.apps.toMutableList().also { it[i] = a.copy(off = !v) })) },
                        onDelete = { update(rules.copy(apps = rules.apps.filterIndexed { j, _ -> j != i })) },
                        first = i == 0,
                        notes = if (a.off) emptyList() else notes["app|${a.path}"].orEmpty(),
                    )
                }
                Spacer(Modifier.height(8.dp))
                OutlinedButton(onClick = onAddApp) {
                    Icon(Icons.Filled.Add, null, Modifier.size(18.dp))
                    Spacer(Modifier.width(6.dp))
                    Text("Приложение")
                }
                Spacer(Modifier.height(8.dp))
                Text(
                    "Приложения VK всегда идут в обход VPN, чтобы звонки работали.",
                    fontSize = 12.5.sp, color = pal.muted, lineHeight = 17.sp,
                )
            }
        }

        // ---- sites
        Panel {
            Column {
                SectionTitle("Сайты", Modifier.padding(bottom = 8.dp))
                var text by remember { mutableStateOf("") }
                var err by remember { mutableStateOf("") }
                val add = { s: String, route: String? ->
                    scope.launch {
                        val r = withContext(Dispatchers.IO) { runCatching { mobile.Mobile.normDomain(s) } }
                        r.onSuccess { d ->
                            err = ""
                            text = ""
                            update(rules.copy(on = true, domains = rules.domains.filter { it.domain != d } + SiteRoute(d, route ?: rules.other)))
                        }.onFailure { err = it.message ?: it.toString() }
                    }
                    Unit
                }
                Row(verticalAlignment = Alignment.CenterVertically) {
                    OutlinedTextField(
                        value = text, onValueChange = { text = it; err = "" },
                        placeholder = { Text("example.com или .su") },
                        singleLine = true, shape = RoundedCornerShape(12.dp),
                        keyboardOptions = KeyboardOptions(imeAction = ImeAction.Done),
                        keyboardActions = KeyboardActions(onDone = { if (text.isNotBlank()) add(text, null) }),
                        modifier = Modifier.weight(1f),
                    )
                    Spacer(Modifier.width(8.dp))
                    Button(onClick = { if (text.isNotBlank()) add(text, null) }) { Text("Добавить") }
                }
                if (err.isNotEmpty()) Text(err, color = pal.err, fontSize = 12.5.sp, modifier = Modifier.padding(top = 4.dp))
                FlowRow(horizontalArrangement = Arrangement.spacedBy(6.dp), verticalArrangement = Arrangement.Center, modifier = Modifier.padding(vertical = 6.dp)) {
                    Text("Быстро:", fontSize = 12.5.sp, color = pal.muted, modifier = Modifier.align(Alignment.CenterVertically))
                    listOf("ru", "su", "рф").forEach { d -> Chip(".$d") { add(d, "direct") } }
                }
                rules.domains.forEachIndexed { i, d ->
                    RuleRow(
                        title = if (d.domain.contains('.')) d.domain else "все сайты .${d.domain}", sub = null, icon = null,
                        route = d.route, off = d.off,
                        onRoute = { r -> update(rules.copy(domains = rules.domains.toMutableList().also { it[i] = d.copy(route = r) })) },
                        onOff = { v -> update(rules.copy(domains = rules.domains.toMutableList().also { it[i] = d.copy(off = !v) })) },
                        onDelete = { update(rules.copy(domains = rules.domains.filterIndexed { j, _ -> j != i })) },
                        first = i == 0,
                        notes = if (d.off) emptyList() else notes["domain|${d.domain}"].orEmpty(),
                    )
                }
                Spacer(Modifier.height(6.dp))
                Text(
                    "Правило для сайта действует на все его поддомены, в любом приложении, и сильнее правил для приложений. Если приложение узнаёт адрес сайта само (свой DNS, «Частный DNS» Android), TurnVK читает имя сайта из начала соединения.",
                    fontSize = 12.5.sp, color = pal.muted, lineHeight = 17.sp,
                )
            }
        }

        // ---- lists
        Panel {
            Column {
                SectionTitle("Страны и списки сайтов", Modifier.padding(bottom = 8.dp))
                FlowRow(horizontalArrangement = Arrangement.spacedBy(6.dp)) {
                    presets.forEach { (label, items) -> Chip(label) { update(rules.withLists(items)) } }
                }
                FlowRow(horizontalArrangement = Arrangement.spacedBy(6.dp), modifier = Modifier.padding(top = 2.dp)) {
                    Text("Сервисы:", fontSize = 12.5.sp, color = pal.muted, modifier = Modifier.align(Alignment.CenterVertically))
                    services.forEach { (label, names) -> Chip(label) { update(rules.withLists(names.map { it to rules.other })) } }
                }
                var text by remember { mutableStateOf("") }
                var err by remember { mutableStateOf("") }
                val add = {
                    scope.launch {
                        val r = withContext(Dispatchers.IO) { runCatching { resolveList(text) } }
                        r.onSuccess { n ->
                            err = ""
                            text = ""
                            update(rules.withLists(listOf(n to rules.other)))
                        }.onFailure { err = it.message ?: it.toString() }
                    }
                    Unit
                }
                Spacer(Modifier.height(6.dp))
                Row(verticalAlignment = Alignment.CenterVertically) {
                    OutlinedTextField(
                        value = text, onValueChange = { text = it; err = "" },
                        placeholder = { Text("Страна или список") },
                        singleLine = true, shape = RoundedCornerShape(12.dp),
                        keyboardOptions = KeyboardOptions(imeAction = ImeAction.Done),
                        keyboardActions = KeyboardActions(onDone = { if (text.isNotBlank()) add() }),
                        modifier = Modifier.weight(1f),
                    )
                    Spacer(Modifier.width(8.dp))
                    Button(onClick = { if (text.isNotBlank()) add() }) { Text("Добавить") }
                }
                if (err.isNotEmpty()) Text(err, color = pal.err, fontSize = 12.5.sp, modifier = Modifier.padding(top = 4.dp))
                Spacer(Modifier.height(6.dp))
                val has = info.files.map { it.first }.toSet()
                rules.lists.forEachIndexed { i, l ->
                    val missing = !l.off && l.list in info.missing
                    val ip = l.list.startsWith("geoip:")
                    val file = if (ip) "geoip.dat" else "geosite.dat"
                    val n = info.sizes[l.list] ?: 0
                    val big = n > info.big
                    val sub = l.list + when {
                        missing && file in has -> " — такого списка нет"
                        missing -> " — скачается после подключения (файл около ${info.approx[if (ip) "geoip" else "geosite"] ?: "?"} МБ)"
                        n > 0 -> " · " + String.format(ru, "%,d", n) + (if (ip) " диапазонов" else " сайтов") +
                            if (big) " — большой список: больше памяти и дольше загрузка" else ""
                        else -> ""
                    }
                    RuleRow(
                        title = listTitle(l.list),
                        sub = sub,
                        subWarn = missing || big, icon = null, route = l.route, off = l.off,
                        notes = if (l.off) emptyList() else notes["list|${l.list}"].orEmpty(),
                        onRoute = { r -> update(rules.copy(lists = rules.lists.toMutableList().also { it[i] = l.copy(route = r) })) },
                        onOff = { v -> update(rules.copy(lists = rules.lists.toMutableList().also { it[i] = l.copy(off = !v) })) },
                        onDelete = { update(rules.copy(lists = rules.lists.filterIndexed { j, _ -> j != i })) },
                        first = i == 0,
                    )
                }
                if (rules.lists.isNotEmpty()) {
                    Row(verticalAlignment = Alignment.CenterVertically, modifier = Modifier.padding(top = 6.dp)) {
                        val st = when {
                            info.busy -> "Скачиваю списки…"
                            info.waiting -> "Списки скачаются при подключении к Wi-Fi (или нажмите «Обновить»)."
                            info.files.isNotEmpty() -> "Обновлены: " + info.files.joinToString(", ") { (n, size, upd) ->
                                (if (n == "geoip.dat") "страны " else "сайты ") + fmtUpdated(upd) + " (" + String.format(ru, "%.1f", size / 1048576.0) + " МБ)"
                            }
                            else -> "Списки скачаются после подключения."
                        } + if (info.error.isNotEmpty() && !info.busy) " Ошибка: ${info.error}" else ""
                        Text(st, fontSize = 12.5.sp, color = if (info.error.isNotEmpty() && !info.busy) pal.err else pal.muted, modifier = Modifier.weight(1f), lineHeight = 17.sp)
                        TextButton(enabled = !info.busy, onClick = {
                            scope.launch {
                                withContext(Dispatchers.IO) { runCatching { mobile.Mobile.updateLists() } }
                                    .onFailure { err = it.message ?: it.toString() }
                            }
                        }) { Text("Обновить") }
                    }
                }
                if (rules.lists.isNotEmpty() || rules.networks.isNotEmpty()) {
                    var wifiOnly by remember { mutableStateOf(store.listsWifiOnly) }
                    SwitchRow(
                        title = "Скачивать списки только по Wi-Fi",
                        text = "Файл сайтов — около ${info.approx["geosite"] ?: 90} МБ. В мобильной сети списки ждут Wi-Fi; кнопка «Обновить» скачивает сразу",
                        checked = wifiOnly,
                        onChange = {
                            wifiOnly = it
                            store.listsWifiOnly = it
                            runCatching { mobile.Mobile.setListsWiFiOnly(it) }
                        },
                    )
                }
                Spacer(Modifier.height(6.dp))
                Text(
                    "Списки сайтов работают как правила для сайтов. Страны и адреса сервисов — для приложений без своего правила. Если адрес или сайт есть в нескольких списках, побеждает VPN. Списки (runetfreedom) обновляются после подключения, не чаще раза в 3 дня, кнопкой «Обновить» — сразу.",
                    fontSize = 12.5.sp, color = pal.muted, lineHeight = 17.sp,
                )
            }
        }

        // ---- connections
        if (active) {
            Panel {
                Column {
                    SectionTitle("Соединения", Modifier.padding(bottom = 4.dp))
                    FlowRow(horizontalArrangement = Arrangement.spacedBy(6.dp)) {
                        FilterChip(selected = !recent, onClick = { recent = false; conns = emptyList() }, label = { Text("Сейчас", fontSize = 13.sp) })
                        FilterChip(selected = recent, onClick = { recent = true; conns = emptyList() }, label = { Text("Закрытые за час", fontSize = 13.sp) })
                        if (recent) TextButton(onClick = {
                            scope.launch { withContext(Dispatchers.IO) { runCatching { mobile.Mobile.forgetHistory() } }; conns = emptyList() }
                        }) { Text("Очистить") }
                    }
                    FlowRow(horizontalArrangement = Arrangement.spacedBy(6.dp)) {
                        listOf("all" to "Все", "direct" to "Напрямую", "vpn" to "Через VPN", "retried" to "Не открылись напрямую").forEach { (id, label) ->
                            FilterChip(selected = filter == id, onClick = { filter = id }, label = { Text(label, fontSize = 13.sp) })
                        }
                    }
                    val shown = conns.filter { c ->
                        when (filter) {
                            "all" -> true
                            "retried" -> c.optBoolean("retried")
                            else -> c.optString("route") == filter
                        }
                    }
                    // Connections without an app's package: Android's own
                    // (DNS from the system resolver, system services), by UID.
                    val groups = shown.groupBy { c -> c.optString("path").ifEmpty { c.optLong("pid").let { if (it > 0) "uid:$it" else "" } } }.entries
                        .sortedByDescending { e -> e.value.maxOf { it.optLong("last") } }
                    if (groups.isEmpty()) {
                        Text(
                            when {
                                filter != "all" -> "Ничего не найдено."
                                recent -> "Закрытых соединений пока нет."
                                else -> "Соединений пока нет: список заполняется, пока открыта эта вкладка."
                            },
                            fontSize = 12.5.sp, color = pal.muted,
                        )
                    }
                    groups.take(40).forEachIndexed { gi, (pkg, list) ->
                        if (gi > 0) HorizontalDivider(color = pal.line)
                        ConnGroup(pkg, list, labels, rules, update)
                    }
                }
            }
        }
        Note("Правила действуют сразу для новых соединений; открытые соединения сохраняют свой путь, пока приложение их не переоткроет.")
        Spacer(Modifier.height(8.dp))
    }
}

/** Modes by network: Wi-Fi, mobile data, Ethernet. */
@OptIn(ExperimentalLayoutApi::class)
@Composable
private fun NetworksPanel(rules: SplitRules, update: (SplitRules) -> Unit, active: Boolean, eff: Effective) {
    Panel {
        Column {
            SectionTitle("Режим по сети", Modifier.padding(bottom = 2.dp))
            val now = when {
                !active -> "Сеть видна, пока VPN подключён."
                eff.here.isEmpty() -> "Сейчас: сеть не определена."
                eff.network.isNotEmpty() -> "Сейчас: ${eff.here} — режим «${modeTitles[eff.mode] ?: eff.mode}»"
                else -> "Сейчас: ${eff.here} — без правила для этой сети"
            } + if (!rules.on && rules.networks.isNotEmpty()) ". Раздельное туннелирование выключено — правила по сети не действуют." else ""
            Text(now, fontSize = 12.5.sp, color = pal.muted, lineHeight = 17.sp)
            rules.networks.forEachIndexed { i, n ->
                HorizontalDivider(color = pal.line, modifier = Modifier.padding(vertical = 6.dp))
                Row(verticalAlignment = Alignment.CenterVertically) {
                    Column(Modifier.weight(1f)) {
                        Text(
                            (netNames[n.network] ?: n.network.removePrefix("wifi:")) + if (active && eff.network == n.network) " · сейчас" else "",
                            fontWeight = FontWeight.SemiBold, color = if (n.off) pal.muted else MaterialTheme.colorScheme.onSurface,
                        )
                        ModePicker(n.mode) { m -> update(rules.copy(networks = rules.networks.toMutableList().also { it[i] = n.copy(mode = m) })) }
                    }
                    Switch(checked = !n.off, onCheckedChange = { v -> update(rules.copy(networks = rules.networks.toMutableList().also { it[i] = n.copy(off = !v) })) })
                    IconButton(onClick = { update(rules.copy(networks = rules.networks.filterIndexed { j, _ -> j != i })) }) {
                        Icon(Icons.Filled.Delete, "Удалить", tint = pal.muted)
                    }
                }
            }
            val free = netNames.keys.filter { k -> rules.networks.none { it.network == k } }
            if (free.isNotEmpty()) {
                FlowRow(horizontalArrangement = Arrangement.spacedBy(6.dp), modifier = Modifier.padding(top = 8.dp)) {
                    free.forEach { k ->
                        Chip("+ " + netNames.getValue(k)) {
                            update(rules.copy(on = true, networks = rules.networks + NetRoute(k, if (k == "wifi") "vpn" else "blocked")))
                        }
                    }
                }
            }
            Text(
                "Например: в мобильной сети — «Только заблокированное через VPN», в чужом Wi-Fi — «Всё через VPN». В сети с правилом её режим действует поверх ваших правил. Если от этого меняется, какие приложения Android пускает в VPN, TurnVK переподключится сам.",
                fontSize = 12.5.sp, color = pal.muted, lineHeight = 17.sp, modifier = Modifier.padding(top = 6.dp),
            )
        }
    }
}

@Composable
private fun ModePicker(mode: String, onPick: (String) -> Unit) {
    var open by remember { mutableStateOf(false) }
    Box {
        TextButton(onClick = { open = true }, contentPadding = PaddingValues(horizontal = 0.dp, vertical = 0.dp), modifier = Modifier.height(32.dp)) {
            Text((if (mode == "custom") "Свои правила (как настроено)" else modeTitles[mode] ?: mode) + " ▾", fontSize = 13.sp, maxLines = 1, overflow = TextOverflow.Ellipsis)
        }
        DropdownMenu(expanded = open, onDismissRequest = { open = false }) {
            modeTitles.forEach { (id, title) ->
                DropdownMenuItem(
                    text = { Text(if (id == "custom") "Свои правила (как настроено)" else title) },
                    onClick = { open = false; onPick(id) },
                )
            }
        }
    }
}

/** "Where would this site go?": the rules' answer, with the reason. */
@OptIn(ExperimentalLayoutApi::class)
@Composable
private fun ExplainPanel(rules: SplitRules, labels: AppLabels) {
    val scope = rememberCoroutineScope()
    var text by remember { mutableStateOf("") }
    var app by remember { mutableStateOf("") }
    var res by remember { mutableStateOf<JSONObject?>(null) }
    var err by remember { mutableStateOf("") }
    val go = {
        val t = text
        val a = app
        if (t.isNotBlank()) scope.launch {
            withContext(Dispatchers.IO) { runCatching { JSONObject(mobile.Mobile.explain(t, a)) } }
                .onSuccess { res = it; err = "" }
                .onFailure { res = null; err = it.message ?: it.toString() }
        }
        Unit
    }
    LaunchedEffect(app, rules) { if (res != null) go() }
    Panel {
        Column {
            SectionTitle("Куда пойдёт сайт?", Modifier.padding(bottom = 8.dp))
            Row(verticalAlignment = Alignment.CenterVertically) {
                OutlinedTextField(
                    value = text, onValueChange = { text = it; err = "" },
                    placeholder = { Text("Сайт или адрес") },
                    singleLine = true, shape = RoundedCornerShape(12.dp),
                    keyboardOptions = KeyboardOptions(imeAction = ImeAction.Done),
                    keyboardActions = KeyboardActions(onDone = { go() }),
                    modifier = Modifier.weight(1f),
                )
                Spacer(Modifier.width(8.dp))
                Button(onClick = go) { Text("Проверить") }
            }
            val apps = rules.apps.map { it.path }.distinct()
            if (apps.isNotEmpty()) {
                FlowRow(horizontalArrangement = Arrangement.spacedBy(6.dp), modifier = Modifier.padding(top = 6.dp)) {
                    FilterChip(selected = app.isEmpty(), onClick = { app = "" }, label = { Text("Любое приложение", fontSize = 13.sp) })
                    apps.forEach { p ->
                        FilterChip(selected = app == p, onClick = { app = p }, label = { Text(labels.get(p).first, fontSize = 13.sp, maxLines = 1) })
                    }
                }
            }
            if (err.isNotEmpty()) Text(err, color = pal.err, fontSize = 12.5.sp, modifier = Modifier.padding(top = 4.dp))
            res?.let { e ->
                val host = e.optString("host")
                val addr = e.optString("addr")
                Spacer(Modifier.height(8.dp))
                Row(verticalAlignment = Alignment.CenterVertically) {
                    Text(
                        host.ifEmpty { addr } + if (host.isNotEmpty() && addr.isNotEmpty()) " ($addr)" else "",
                        fontWeight = FontWeight.SemiBold, modifier = Modifier.weight(1f, fill = false),
                        maxLines = 1, overflow = TextOverflow.Ellipsis,
                    )
                    Spacer(Modifier.width(8.dp))
                    val direct = e.optString("route") == "direct"
                    Text(
                        if (direct) "напрямую" else "через VPN",
                        fontSize = 12.sp, fontWeight = FontWeight.SemiBold,
                        color = if (direct) pal.ok else pal.accent,
                        modifier = Modifier.background(if (direct) pal.okSoft else pal.accentSoft, RoundedCornerShape(99.dp)).padding(horizontal = 8.dp, vertical = 2.dp),
                    )
                }
                Text("Почему: " + e.optString("why"), fontSize = 13.sp, color = pal.muted, lineHeight = 18.sp, modifier = Modifier.padding(top = 2.dp))
                e.optString("note").takeIf { it.isNotEmpty() }?.let {
                    Text(it, fontSize = 12.5.sp, color = pal.muted, lineHeight = 17.sp, modifier = Modifier.padding(top = 4.dp))
                }
            }
        }
    }
}

/** Sites that did not open direct and were opened through the VPN, with a rule to add. */
@Composable
private fun FailuresPanel(fails: List<JSONObject>, rules: SplitRules, update: (SplitRules) -> Unit, onClear: () -> Unit) {
    Panel {
        Column {
            SectionTitle("Не открылись напрямую", Modifier.padding(bottom = 4.dp))
            Text(
                "Эти сайты не ответили напрямую — TurnVK открыл их через VPN. Добавьте правило, чтобы они сразу шли через VPN.",
                fontSize = 12.5.sp, color = pal.muted, lineHeight = 17.sp, modifier = Modifier.padding(bottom = 6.dp),
            )
            fails.forEachIndexed { i, f ->
                if (i > 0) HorizontalDivider(color = pal.line, modifier = Modifier.padding(vertical = 4.dp))
                val ok = f.optBoolean("ok")
                val rule = f.optString("rule")
                val count = f.optInt("count")
                Text(f.optString("host").ifEmpty { f.optString("addr") }, fontWeight = FontWeight.SemiBold, maxLines = 1, overflow = TextOverflow.Ellipsis)
                Text(
                    f.optString("why") + (if (ok) ", открыт через VPN" else ", через VPN тоже не открылся") +
                        (if (count > 1) " · " + plural(count, "раз", "раза", "раз") else ""),
                    fontSize = 12.sp, color = pal.muted,
                )
                if (ok && rule.isNotEmpty()) {
                    OutlinedButton(
                        onClick = { update(rules.copy(on = true, domains = rules.domains.filter { it.domain != rule } + SiteRoute(rule, "vpn"))) },
                        contentPadding = PaddingValues(horizontal = 10.dp, vertical = 0.dp),
                        modifier = Modifier.padding(top = 4.dp).height(34.dp),
                    ) { Text("$rule — через VPN", fontSize = 13.sp, maxLines = 1) }
                }
            }
            TextButton(onClick = onClear, modifier = Modifier.padding(top = 4.dp)) { Text("Очистить список") }
        }
    }
}

/** What the user typed into the lists field: "geoip:de", a country's name or code, a list's title or a category. */
private fun resolveList(text: String): String {
    val t = text.trim()
    val low = t.lowercase().replace('ё', 'е')
    if (t.contains(':')) return mobile.Mobile.normList(t)
    listTitles.entries.firstOrNull { it.value.lowercase().replace('ё', 'е') == low }?.let { return it.key }
    val codes = runCatching { mobile.Mobile.listNames("geoip") }.getOrDefault("").split("\n").filter { it.length == 2 }
    val all = codes.ifEmpty { Locale.getISOCountries().map { it.lowercase() } }
    all.firstOrNull { countryName(it).lowercase().replace('ё', 'е') == low }?.let { return "geoip:$it" }
    if (Regex("[a-z]{2}").matches(low)) return "geoip:$low"
    if (Regex("[a-z0-9._@!-]+").matches(low)) return mobile.Mobile.normList("geosite:$low")
    throw Exception("Не нашёл такую страну или список")
}

@Composable
private fun RouteSeg(route: String, modifier: Modifier = Modifier, onChange: (String) -> Unit) {
    SingleChoiceSegmentedButtonRow(modifier) {
        listOf("vpn" to "Через VPN", "direct" to "Напрямую").forEachIndexed { i, (v, label) ->
            SegmentedButton(
                selected = route == v,
                onClick = { onChange(v) },
                shape = SegmentedButtonDefaults.itemShape(i, 2),
                icon = {},
            ) { Text(label, fontSize = 13.sp, maxLines = 1) }
        }
    }
}

@Composable
private fun Chip(label: String, onClick: () -> Unit) {
    OutlinedButton(onClick = onClick, contentPadding = PaddingValues(horizontal = 10.dp, vertical = 0.dp), modifier = Modifier.height(34.dp)) {
        Text(label, fontSize = 13.sp, maxLines = 1)
    }
}

@Composable
private fun RuleRow(
    title: String,
    sub: String?,
    icon: ImageBitmap?,
    route: String,
    off: Boolean,
    onRoute: (String) -> Unit,
    onOff: (Boolean) -> Unit,
    onDelete: () -> Unit,
    first: Boolean,
    subWarn: Boolean = false,
    notes: List<Pair<String, Boolean>> = emptyList(),
) {
    if (!first) HorizontalDivider(color = pal.line, modifier = Modifier.padding(vertical = 6.dp))
    Column(Modifier.fillMaxWidth().padding(vertical = 2.dp)) {
        Row(verticalAlignment = Alignment.CenterVertically) {
            if (icon != null) {
                Image(icon, null, Modifier.size(32.dp))
                Spacer(Modifier.width(10.dp))
            }
            Column(Modifier.weight(1f)) {
                Text(title, fontWeight = FontWeight.SemiBold, maxLines = 1, overflow = TextOverflow.Ellipsis,
                    color = if (off) pal.muted else MaterialTheme.colorScheme.onSurface)
                if (sub != null) Text(sub, fontSize = 12.sp, color = if (subWarn) pal.warn else pal.muted, maxLines = 2, overflow = TextOverflow.Ellipsis)
            }
            Switch(checked = !off, onCheckedChange = onOff)
            IconButton(onClick = onDelete) { Icon(Icons.Filled.Delete, "Удалить", tint = pal.muted) }
        }
        RouteSeg(route, Modifier.padding(top = 4.dp).width(240.dp), onRoute)
        notes.forEach { (text, warn) ->
            Text(text, fontSize = 12.sp, color = if (warn) pal.warn else pal.muted, lineHeight = 16.sp, modifier = Modifier.padding(top = 4.dp))
        }
    }
}

@Composable
private fun ConnGroup(pkg: String, list: List<JSONObject>, labels: AppLabels, rules: SplitRules, update: (SplitRules) -> Unit) {
    var open by remember(pkg) { mutableStateOf(false) }
    val dns = list.all { it.optString("dst").substringAfterLast(':') in setOf("53", "853") }
    val uid = pkg.removePrefix("uid:").toLongOrNull()
    val (label, icon) = when {
        dns && (pkg.isEmpty() || pkg.startsWith("uid:")) -> "Запросы DNS (Android)" to null
        pkg.startsWith("uid:") && uid != null && uid < 10000 -> "Система Android (UID $uid)" to null
        pkg.startsWith("uid:") -> "Приложение без пакета (UID $uid)" to null
        pkg.isEmpty() -> "Не определено" to null
        else -> labels.get(pkg)
    }
    val direct = list.count { it.optString("route") == "direct" }
    val total = list.sumOf { it.optInt("n", 1).coerceAtLeast(1) }
    Column(Modifier.fillMaxWidth().clickable { open = !open }.padding(vertical = 8.dp)) {
        Row(verticalAlignment = Alignment.CenterVertically) {
            if (icon != null) Image(icon, null, Modifier.size(28.dp)) else Spacer(Modifier.size(28.dp))
            Spacer(Modifier.width(10.dp))
            Column(Modifier.weight(1f)) {
                Text(label, fontWeight = FontWeight.SemiBold, maxLines = 1, overflow = TextOverflow.Ellipsis)
                Text(
                    "соединений: $total" + when (direct) {
                        0 -> ", все через VPN"
                        list.size -> ", все напрямую"
                        else -> ", напрямую $direct"
                    },
                    fontSize = 12.sp, color = pal.muted,
                )
            }
        }
        if (open) {
            list.sortedByDescending { it.optLong("last") }.take(30).forEach { c ->
                val host = c.optString("host")
                val dst = c.optString("dst")
                val n = c.optInt("n")
                Text(
                    (if (host.isNotEmpty()) "$host (${dst.substringAfterLast(':')})" else dst) +
                        " · ${c.optString("proto")} · ${routeName(c.optString("route"))} — ${c.optString("why")}" +
                        if (n > 1) " · ×$n" else "",
                    fontSize = 12.sp, color = pal.muted, lineHeight = 16.sp,
                    modifier = Modifier.padding(start = 38.dp, top = 4.dp),
                )
                // A rule for this site alone (its main domain), the other way.
                val site = c.optString("site")
                if (site.isNotEmpty()) {
                    val other = if (c.optString("route") == "direct") "vpn" else "direct"
                    TextButton(
                        onClick = { update(rules.copy(on = true, domains = rules.domains.filter { it.domain != site } + SiteRoute(site, other))) },
                        contentPadding = PaddingValues(horizontal = 8.dp, vertical = 0.dp),
                        modifier = Modifier.padding(start = 30.dp).height(30.dp),
                    ) { Text("$site — ${routeName(other)}", fontSize = 12.5.sp, maxLines = 1, overflow = TextOverflow.Ellipsis) }
                }
            }
            if (pkg.isNotEmpty() && !pkg.startsWith("uid:")) {
                Row(Modifier.padding(start = 38.dp, top = 6.dp), horizontalArrangement = Arrangement.spacedBy(8.dp)) {
                    OutlinedButton(onClick = { update(rules.withApp(pkg, "direct")) }) { Text("Напрямую") }
                    OutlinedButton(onClick = { update(rules.withApp(pkg, "vpn")) }) { Text("Через VPN") }
                }
            }
        }
    }
}

// ---------------------------------------------------------------- app picker

@OptIn(ExperimentalMaterial3Api::class)
@Composable
internal fun AppsScreen(rules: SplitRules, onPick: (String) -> Unit, onBack: () -> Unit) {
    val ctx = LocalContext.current
    var apps by remember { mutableStateOf<List<AppEntry>?>(null) }
    var query by remember { mutableStateOf("") }
    LaunchedEffect(Unit) { apps = withContext(Dispatchers.IO) { loadApps(ctx) } }
    val ruled = remember(rules) { rules.apps.associate { it.path to it } }

    Scaffold(
        containerColor = MaterialTheme.colorScheme.background,
        topBar = {
            TopAppBar(
                title = { Text("Выберите приложение", fontWeight = FontWeight.SemiBold) },
                navigationIcon = { IconButton(onClick = onBack) { Icon(Icons.AutoMirrored.Filled.ArrowBack, "Назад") } },
            )
        },
    ) { pad ->
        Column(Modifier.fillMaxSize().padding(pad)) {
            Note(
                "Приложение пойдёт ${routeName(rules.other)}; путь можно сменить в списке правил.",
                Modifier.padding(horizontal = 12.dp),
            )
            OutlinedTextField(
                value = query,
                onValueChange = { query = it },
                leadingIcon = { Icon(Icons.Filled.Search, null) },
                placeholder = { Text("Поиск") },
                singleLine = true,
                shape = RoundedCornerShape(12.dp),
                modifier = Modifier.fillMaxWidth().padding(16.dp),
            )
            val list = apps
            if (list == null) {
                Box(Modifier.fillMaxSize(), contentAlignment = Alignment.Center) { CircularProgressIndicator() }
            } else {
                val shown = list.filter { query.isBlank() || it.label.contains(query, true) || it.pkg.contains(query, true) }
                    .sortedBy { it.label.lowercase() }
                LazyColumn(Modifier.fillMaxSize()) {
                    items(shown, key = { it.pkg }) { a ->
                        val forced = a.pkg in TunnelService.BYPASS
                        val rule = ruled[a.pkg]
                        ListItem(
                            headlineContent = { Text(a.label) },
                            supportingContent = {
                                Text(
                                    when {
                                        forced -> "всегда в обход VPN"
                                        rule != null -> "уже есть правило: ${routeName(rule.route)}"
                                        else -> a.pkg
                                    },
                                    maxLines = 1, overflow = TextOverflow.Ellipsis,
                                )
                            },
                            leadingContent = {
                                if (a.icon != null) Image(a.icon, null, Modifier.size(36.dp)) else Spacer(Modifier.size(36.dp))
                            },
                            colors = ListItemDefaults.colors(containerColor = Color.Transparent),
                            modifier = Modifier.clickable(enabled = !forced) { onPick(a.pkg) },
                        )
                    }
                }
            }
        }
    }
}
