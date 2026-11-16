@file:OptIn(ExperimentalMaterial3Api::class, ExperimentalLayoutApi::class)

package io.github.jetvac.turnvk

import android.app.StatusBarManager
import android.content.ClipData
import android.content.ClipboardManager
import android.content.ComponentName
import android.content.Context
import android.content.Intent
import android.content.pm.PackageManager
import android.net.Uri
import android.os.Build
import android.os.PowerManager
import android.os.SystemClock
import android.provider.Settings
import androidx.activity.compose.BackHandler
import androidx.compose.animation.core.LinearEasing
import androidx.compose.animation.core.animateFloat
import androidx.compose.animation.core.infiniteRepeatable
import androidx.compose.animation.core.rememberInfiniteTransition
import androidx.compose.animation.core.tween
import androidx.compose.foundation.Canvas
import androidx.compose.foundation.Image
import androidx.compose.foundation.background
import androidx.compose.foundation.border
import androidx.compose.foundation.clickable
import androidx.compose.foundation.isSystemInDarkTheme
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
import androidx.compose.foundation.layout.statusBarsPadding
import androidx.compose.foundation.layout.width
import androidx.compose.foundation.lazy.LazyColumn
import androidx.compose.foundation.lazy.items
import androidx.compose.foundation.lazy.rememberLazyListState
import androidx.compose.foundation.rememberScrollState
import androidx.compose.foundation.shape.CircleShape
import androidx.compose.foundation.shape.RoundedCornerShape
import androidx.compose.foundation.text.KeyboardOptions
import androidx.compose.foundation.text.selection.SelectionContainer
import androidx.compose.foundation.verticalScroll
import androidx.compose.material.icons.Icons
import androidx.compose.material.icons.automirrored.filled.ArrowBack
import androidx.compose.material.icons.automirrored.filled.KeyboardArrowRight
import androidx.compose.material.icons.automirrored.filled.List
import androidx.compose.material.icons.filled.Add
import androidx.compose.material.icons.filled.Delete
import androidx.compose.material.icons.filled.Edit
import androidx.compose.material.icons.filled.Info
import androidx.compose.material.icons.filled.Search
import androidx.compose.material.icons.filled.Settings
import androidx.compose.material.icons.filled.Share
import androidx.compose.material.icons.filled.Warning
import androidx.compose.material3.AlertDialog
import androidx.compose.material3.Button
import androidx.compose.material3.ButtonDefaults
import androidx.compose.material3.Checkbox
import androidx.compose.material3.CircularProgressIndicator
import androidx.compose.material3.ExperimentalMaterial3Api
import androidx.compose.material3.HorizontalDivider
import androidx.compose.material3.Icon
import androidx.compose.material3.IconButton
import androidx.compose.material3.ListItem
import androidx.compose.material3.ListItemDefaults
import androidx.compose.material3.MaterialTheme
import androidx.compose.material3.NavigationBar
import androidx.compose.material3.NavigationBarItem
import androidx.compose.material3.NavigationBarItemDefaults
import androidx.compose.material3.OutlinedButton
import androidx.compose.material3.OutlinedTextField
import androidx.compose.material3.Scaffold
import androidx.compose.material3.SegmentedButton
import androidx.compose.material3.SegmentedButtonDefaults
import androidx.compose.material3.SingleChoiceSegmentedButtonRow
import androidx.compose.material3.Slider
import androidx.compose.material3.Surface
import androidx.compose.material3.Switch
import androidx.compose.material3.Text
import androidx.compose.material3.TextButton
import androidx.compose.material3.TopAppBar
import androidx.compose.material3.darkColorScheme
import androidx.compose.material3.lightColorScheme
import androidx.compose.runtime.Composable
import androidx.compose.runtime.CompositionLocalProvider
import androidx.compose.runtime.LaunchedEffect
import androidx.compose.runtime.MutableState
import androidx.compose.runtime.collectAsState
import androidx.compose.runtime.getValue
import androidx.compose.runtime.mutableFloatStateOf
import androidx.compose.runtime.mutableIntStateOf
import androidx.compose.runtime.mutableLongStateOf
import androidx.compose.runtime.mutableStateListOf
import androidx.compose.runtime.mutableStateOf
import androidx.compose.runtime.remember
import androidx.compose.runtime.setValue
import androidx.compose.runtime.staticCompositionLocalOf
import androidx.compose.ui.Alignment
import androidx.compose.ui.Modifier
import androidx.compose.ui.draw.clip
import androidx.compose.ui.draw.rotate
import androidx.compose.ui.draw.shadow
import androidx.compose.ui.geometry.Offset
import androidx.compose.ui.graphics.Brush
import androidx.compose.ui.graphics.Color
import androidx.compose.ui.graphics.Path
import androidx.compose.ui.graphics.StrokeCap
import androidx.compose.ui.graphics.StrokeJoin
import androidx.compose.ui.graphics.asImageBitmap
import androidx.compose.ui.graphics.drawscope.Stroke
import androidx.compose.ui.platform.LocalContext
import androidx.compose.ui.res.painterResource
import androidx.compose.ui.text.font.FontFamily
import androidx.compose.ui.text.font.FontWeight
import androidx.compose.ui.text.input.KeyboardType
import androidx.compose.ui.text.input.PasswordVisualTransformation
import androidx.compose.ui.text.input.VisualTransformation
import androidx.compose.ui.text.style.TextAlign
import androidx.compose.ui.text.style.TextOverflow
import androidx.compose.ui.unit.Dp
import androidx.compose.ui.unit.dp
import androidx.compose.ui.unit.sp
import androidx.core.graphics.drawable.toBitmap
import androidx.lifecycle.compose.LifecycleResumeEffect
import kotlinx.coroutines.Dispatchers
import kotlinx.coroutines.delay
import kotlinx.coroutines.withContext

// ---------------------------------------------------------------- theme
//
// The same look as the Windows app: a blue brand colour, white cards on a
// pale background (dark: deep blue-grey), green for a working connection.

/** Colours Material's scheme has no slot for. */
private data class Palette(
    val card: Color,
    val card2: Color,
    val line: Color,
    val muted: Color,
    val faint: Color,
    val accent: Color,
    val accentSoft: Color,
    val ok: Color,
    val okSoft: Color,
    val warn: Color,
    val warnSoft: Color,
    val err: Color,
    val errSoft: Color,
    val down: Color,
    val up: Color,
)

private val LightPalette = Palette(
    card = Color(0xFFFFFFFF), card2 = Color(0xFFF2F4F9), line = Color(0xFFE4E7F0),
    muted = Color(0xFF697089), faint = Color(0xFFA3A9BB),
    accent = Color(0xFF2E5BFF), accentSoft = Color(0xFFE8EEFF),
    ok = Color(0xFF18A058), okSoft = Color(0xFFE3F6EC),
    warn = Color(0xFFD88A0C), warnSoft = Color(0xFFFDF2DF),
    err = Color(0xFFD93A3A), errSoft = Color(0xFFFDE8E8),
    down = Color(0xFF2E5BFF), up = Color(0xFF18A058),
)

private val DarkPalette = Palette(
    card = Color(0xFF181C25), card2 = Color(0xFF1E232E), line = Color(0xFF272C38),
    muted = Color(0xFF9AA1B5), faint = Color(0xFF5D6478),
    accent = Color(0xFF5B82FF), accentSoft = Color(0xFF1F2A4D),
    ok = Color(0xFF34C77B), okSoft = Color(0xFF15301F),
    warn = Color(0xFFF0A83A), warnSoft = Color(0xFF33270F),
    err = Color(0xFFF26B6B), errSoft = Color(0xFF3A1A1A),
    down = Color(0xFF6C8FFF), up = Color(0xFF34C77B),
)

private val LocalPalette = staticCompositionLocalOf { LightPalette }

@Composable
fun TurnVKTheme(content: @Composable () -> Unit) {
    val dark = isSystemInDarkTheme()
    val p = if (dark) DarkPalette else LightPalette
    val scheme = if (dark) {
        darkColorScheme(
            primary = p.accent, onPrimary = Color.White, primaryContainer = p.accentSoft, onPrimaryContainer = p.accent,
            secondaryContainer = p.accentSoft, onSecondaryContainer = p.accent,
            background = Color(0xFF0F1218), onBackground = Color(0xFFE9ECF3),
            surface = Color(0xFF0F1218), onSurface = Color(0xFFE9ECF3), onSurfaceVariant = p.muted,
            surfaceContainer = p.card, surfaceContainerHigh = p.card2, surfaceContainerHighest = p.card2, surfaceContainerLow = p.card,
            outline = p.faint, outlineVariant = p.line,
            error = p.err, errorContainer = p.errSoft, onErrorContainer = p.err,
            tertiaryContainer = p.warnSoft, onTertiaryContainer = Color(0xFFE9ECF3),
        )
    } else {
        lightColorScheme(
            primary = p.accent, onPrimary = Color.White, primaryContainer = p.accentSoft, onPrimaryContainer = p.accent,
            secondaryContainer = p.accentSoft, onSecondaryContainer = p.accent,
            background = Color(0xFFF3F5FA), onBackground = Color(0xFF141824),
            surface = Color(0xFFF3F5FA), onSurface = Color(0xFF141824), onSurfaceVariant = p.muted,
            surfaceContainer = p.card, surfaceContainerHigh = p.card2, surfaceContainerHighest = p.card2, surfaceContainerLow = p.card,
            outline = p.faint, outlineVariant = p.line,
            error = p.err, errorContainer = p.errSoft, onErrorContainer = p.err,
            tertiaryContainer = p.warnSoft, onTertiaryContainer = Color(0xFF141824),
        )
    }
    CompositionLocalProvider(LocalPalette provides p) {
        MaterialTheme(colorScheme = scheme) {
            Surface(Modifier.fillMaxSize(), color = MaterialTheme.colorScheme.background) { content() }
        }
    }
}

private val pal: Palette @Composable get() = LocalPalette.current

// ---------------------------------------------------------------- app

private enum class Tab(val label: String) { Home("Главная"), Servers("Серверы"), Settings("Настройки"), Logs("Журнал") }

/** Live numbers polled from the engine once a second while connected. */
private data class Live(val status: Status = Status(), val rxRate: Long = 0, val txRate: Long = 0)

@Composable
fun App(store: Store, imported: MutableState<String?>, connect: () -> Unit) {
    var tab by remember { mutableStateOf(Tab.Home) }
    var apps by remember { mutableStateOf(false) }
    // Bumped when the store changes, so that screens re-read it.
    var revision by remember { mutableIntStateOf(0) }
    val refresh: () -> Unit = { revision++ }
    val ctx = LocalContext.current

    BackHandler(enabled = apps || tab != Tab.Home) {
        if (apps) apps = false else tab = Tab.Home
    }

    val status by TunnelState.status.collectAsState()
    val captcha by TunnelState.captcha.collectAsState()

    // Speed and route numbers, kept here so that switching tabs keeps the graph.
    var live by remember { mutableStateOf(Live()) }
    val history = remember { mutableStateListOf<Pair<Long, Long>>() }
    var now by remember { mutableLongStateOf(System.currentTimeMillis()) }
    LaunchedEffect(status.active) {
        history.clear()
        if (!status.active) {
            live = Live()
            return@LaunchedEffect
        }
        var prev: Status? = null
        var prevT = 0L
        while (true) {
            val js = mobile.Mobile.status()
            if (js.isNotEmpty()) {
                val s = Status.parse(js)
                val t = SystemClock.elapsedRealtime()
                val p = prev
                live = if (p != null && t > prevT) {
                    val dt = (t - prevT) / 1000.0
                    val l = Live(s, ((s.rxBytes - p.rxBytes) / dt).toLong().coerceAtLeast(0), ((s.txBytes - p.txBytes) / dt).toLong().coerceAtLeast(0))
                    history.add(l.rxRate to l.txRate)
                    if (history.size > 60) history.removeAt(0)
                    l
                } else {
                    Live(s)
                }
                prev = s
                prevT = t
            }
            now = System.currentTimeMillis()
            delay(1000)
        }
    }

    // Open the captcha page as soon as VK asks for one.
    LaunchedEffect(captcha) {
        if (captcha != null) ctx.startActivity(Intent(ctx, CaptchaActivity::class.java))
    }

    // A wdtt:// link opened from outside.
    imported.value?.let { link ->
        val existing = store.profiles.firstOrNull { it.link == link }
        if (existing != null) {
            store.currentId = existing.id
            imported.value = null
            refresh()
        } else {
            ProfileDialog(
                initial = Profile(Store.newId(), defaultName(link), link),
                isNew = true,
                onSave = { store.save(it); imported.value = null; refresh() },
                onDelete = null,
                onDismiss = { imported.value = null },
            )
        }
    }

    if (apps) {
        AppsScreen(store, refresh, onBack = { apps = false })
        return
    }

    // What the screens show: the engine's live numbers while connected,
    // with the state the service reports.
    val s = if (live.status.state.isNotEmpty() && status.active) {
        live.status.copy(state = status.state, captcha = status.captcha || live.status.captcha)
    } else {
        status
    }

    Scaffold(
        containerColor = MaterialTheme.colorScheme.background,
        topBar = { Header(s, captcha != null) },
        bottomBar = {
            NavigationBar(containerColor = pal.card, tonalElevation = 0.dp) {
                Tab.entries.forEach { t ->
                    NavigationBarItem(
                        selected = tab == t,
                        onClick = { tab = t },
                        icon = {
                            when (t) {
                                Tab.Home -> Icon(painterResource(R.drawable.ic_shield_outline), null, Modifier.size(22.dp))
                                Tab.Servers -> Icon(painterResource(R.drawable.ic_server), null, Modifier.size(22.dp))
                                Tab.Settings -> Icon(Icons.Filled.Settings, null)
                                Tab.Logs -> Icon(Icons.AutoMirrored.Filled.List, null)
                            }
                        },
                        label = { Text(t.label, fontSize = 12.sp) },
                        colors = NavigationBarItemDefaults.colors(
                            indicatorColor = pal.accentSoft,
                            selectedIconColor = pal.accent,
                            selectedTextColor = MaterialTheme.colorScheme.onSurface,
                            unselectedIconColor = pal.muted,
                            unselectedTextColor = pal.muted,
                        ),
                    )
                }
            }
        },
    ) { pad ->
        Box(Modifier.fillMaxSize().padding(pad)) {
            when (tab) {
                Tab.Home -> HomeTab(store, revision, s, live, history, now, connect, onServers = { tab = Tab.Servers })
                Tab.Servers -> ServersTab(store, revision, refresh, s.active)
                Tab.Settings -> SettingsTab(store, revision, refresh, s.active, onApps = { apps = true })
                Tab.Logs -> LogsTab()
            }
        }
    }
}

private fun defaultName(link: String): String {
    val host = Profile("", "", link).host
    return if (host.isNotEmpty()) "Сервер $host" else "Мой сервер"
}

// ---------------------------------------------------------------- shared pieces

@Composable
private fun Logo(size: Dp, radius: Dp) {
    Box(
        Modifier.size(size).clip(RoundedCornerShape(radius))
            .background(Brush.verticalGradient(listOf(Color(0xFF4A78FF), Color(0xFF2444E0)))),
        contentAlignment = Alignment.Center,
    ) {
        Image(painterResource(R.drawable.ic_logo), null, Modifier.size(size * 0.6f))
    }
}

@Composable
private fun Header(s: Status, captcha: Boolean) {
    val (kind, text) = when {
        s.state == "connected" -> "ok" to "Защищено"
        captcha || s.state == "captcha" -> "warn" to "Проверка"
        s.state == "connecting" -> "warn" to "Подключение"
        s.state == "failed" -> "err" to "Ошибка"
        else -> "" to "Отключено"
    }
    val (bg, fg) = when (kind) {
        "ok" -> pal.okSoft to pal.ok
        "warn" -> pal.warnSoft to pal.warn
        "err" -> pal.errSoft to pal.err
        else -> pal.card2 to pal.muted
    }
    Row(
        Modifier.fillMaxWidth().statusBarsPadding().padding(start = 18.dp, end = 18.dp, top = 12.dp, bottom = 8.dp),
        verticalAlignment = Alignment.CenterVertically,
    ) {
        Logo(32.dp, 9.dp)
        Spacer(Modifier.width(10.dp))
        Text("TurnVK", fontSize = 19.sp, fontWeight = FontWeight.SemiBold, modifier = Modifier.weight(1f))
        Row(
            Modifier.clip(CircleShape).background(bg).padding(horizontal = 10.dp, vertical = 4.dp),
            verticalAlignment = Alignment.CenterVertically,
        ) {
            Box(Modifier.size(7.dp).clip(CircleShape).background(fg))
            Spacer(Modifier.width(6.dp))
            Text(text, color = fg, fontSize = 12.sp, fontWeight = FontWeight.SemiBold)
        }
    }
}

/** A white rounded card, as on the Windows app. */
@Composable
private fun Panel(modifier: Modifier = Modifier, padding: Dp = 16.dp, content: @Composable () -> Unit) {
    Surface(modifier.fillMaxWidth(), shape = RoundedCornerShape(16.dp), color = pal.card, shadowElevation = 1.dp) {
        Box(Modifier.padding(padding)) { content() }
    }
}

@Composable
private fun SectionTitle(text: String, modifier: Modifier = Modifier) {
    Text(
        text.uppercase(),
        fontSize = 12.sp,
        fontWeight = FontWeight.SemiBold,
        letterSpacing = 0.4.sp,
        color = pal.muted,
        modifier = modifier,
    )
}

@Composable
private fun Note(text: String, modifier: Modifier = Modifier) {
    Row(modifier.padding(horizontal = 4.dp), verticalAlignment = Alignment.Top) {
        Icon(Icons.Filled.Info, null, Modifier.size(16.dp).padding(top = 1.dp), tint = pal.muted)
        Spacer(Modifier.width(8.dp))
        Text(text, fontSize = 12.5.sp, color = pal.muted, lineHeight = 17.sp)
    }
}

@Composable
private fun Banner(title: String, text: String, action: String? = null, error: Boolean = false, onAction: () -> Unit = {}) {
    Row(
        Modifier.fillMaxWidth().clip(RoundedCornerShape(14.dp)).background(if (error) pal.errSoft else pal.warnSoft).padding(14.dp),
        verticalAlignment = Alignment.CenterVertically,
    ) {
        Icon(Icons.Filled.Warning, null, tint = if (error) pal.err else pal.warn)
        Spacer(Modifier.width(12.dp))
        Column(Modifier.weight(1f)) {
            Text(title, fontWeight = FontWeight.SemiBold, fontSize = 14.sp, color = MaterialTheme.colorScheme.onSurface)
            Text(text, fontSize = 13.sp, color = MaterialTheme.colorScheme.onSurface, lineHeight = 17.sp)
        }
        if (action != null) {
            Spacer(Modifier.width(8.dp))
            Button(onClick = onAction) { Text(action) }
        }
    }
}

// ---------------------------------------------------------------- home

@Composable
private fun HomeTab(
    store: Store,
    revision: Int,
    s: Status,
    live: Live,
    history: List<Pair<Long, Long>>,
    now: Long,
    connect: () -> Unit,
    onServers: () -> Unit,
) {
    val ctx = LocalContext.current
    val error by TunnelState.error.collectAsState()
    val captcha by TunnelState.captcha.collectAsState()
    val profiles = remember(revision) { store.profiles }
    val current = remember(revision) { store.current }
    var creating by remember { mutableStateOf(false) }

    Column(
        Modifier.fillMaxSize().verticalScroll(rememberScrollState()).padding(horizontal = 16.dp, vertical = 6.dp),
        verticalArrangement = Arrangement.spacedBy(12.dp),
    ) {
        val err = error ?: s.lastError.takeIf { it.isNotEmpty() && s.state == "failed" }
        Hero(
            s = s,
            now = now,
            hasServer = current != null,
            error = if (!s.active && !err.isNullOrEmpty()) humanError(err) else null,
            onClick = {
                when {
                    s.active -> TunnelService.disconnect(ctx)
                    current == null -> creating = true
                    else -> connect()
                }
            },
        )

        if (captcha != null || s.captcha) {
            Banner(
                title = "Нужна проверка VK",
                text = if (s.state == "connected") "VPN работает. Пройдите проверку, чтобы он и дальше переподключался без перебоев." else "Подключение ждёт, пока вы подтвердите, что вы не робот.",
                action = if (captcha != null) "Пройти" else null,
                onAction = { ctx.startActivity(Intent(ctx, CaptchaActivity::class.java)) },
            )
        }

        ServerRow(current, profiles.size, onClick = { if (current == null) creating = true else onServers() })

        if (s.active) Stats(s, live, history)

        Note("Весь трафик идёт через серверы звонков VK и шифруется WireGuard.")
        Spacer(Modifier.height(8.dp))
    }

    if (creating) {
        ProfileDialog(
            initial = Profile(Store.newId(), "", ""),
            isNew = true,
            onSave = { store.save(it); creating = false; TunnelState.setError(null) },
            onDelete = null,
            onDismiss = { creating = false },
        )
    }
}

@Composable
private fun Hero(s: Status, now: Long, hasServer: Boolean, error: String?, onClick: () -> Unit) {
    val connected = s.state == "connected"
    val busy = s.state == "connecting" || s.state == "captcha"
    val glow = when {
        connected -> pal.ok.copy(alpha = 0.22f)
        busy -> pal.accent.copy(alpha = 0.18f)
        else -> Color.Transparent
    }
    Surface(Modifier.fillMaxWidth(), shape = RoundedCornerShape(16.dp), color = pal.card, shadowElevation = 1.dp) {
        Box {
            Box(
                Modifier.matchParentSize()
                    .background(Brush.radialGradient(listOf(glow, Color.Transparent), center = Offset.Unspecified, radius = 560f)),
            )
            Column(
                Modifier.fillMaxWidth().padding(start = 16.dp, end = 16.dp, top = 26.dp, bottom = 22.dp),
                horizontalAlignment = Alignment.CenterHorizontally,
            ) {
                PowerButton(connected, busy, s.state == "failed" || error != null, onClick)
                Spacer(Modifier.height(18.dp))
                val title = when {
                    connected -> "Подключено"
                    s.state == "captcha" || (busy && s.captcha) -> "Нужна проверка VK"
                    busy -> "Подключение…"
                    error != null -> "Не удалось подключиться"
                    else -> "Отключено"
                }
                val sub = when {
                    connected -> {
                        val sec = if (s.since > 0) (now / 1000 - s.since).coerceAtLeast(0) else 0
                        if (sec >= 3600) "%d:%02d:%02d".format(sec / 3600, sec / 60 % 60, sec % 60) else "%02d:%02d".format(sec / 60, sec % 60)
                    }
                    s.state == "captcha" || (busy && s.captcha) -> "Подтвердите, что вы не робот"
                    busy -> if (s.target > 0) "маршрутов ${s.sessions} из ${s.target}" else ""
                    error != null -> "Нажмите, чтобы попробовать снова"
                    !hasServer -> "Сначала добавьте сервер"
                    else -> "Нажмите, чтобы подключиться"
                }
                Text(title, fontSize = 21.sp, fontWeight = FontWeight.SemiBold)
                Text(sub, fontSize = 14.sp, color = pal.muted)
                if (error != null) {
                    Spacer(Modifier.height(12.dp))
                    Text(
                        error,
                        fontSize = 13.sp,
                        color = pal.err,
                        modifier = Modifier.fillMaxWidth().clip(RoundedCornerShape(10.dp)).background(pal.errSoft).padding(horizontal = 12.dp, vertical = 10.dp),
                    )
                }
            }
        }
    }
}

@Composable
private fun PowerButton(connected: Boolean, busy: Boolean, failed: Boolean, onClick: () -> Unit) {
    val p = pal
    val spin = rememberInfiniteTransition(label = "spin")
    val angle by spin.animateFloat(0f, 360f, infiniteRepeatable(tween(1000, easing = LinearEasing)), label = "angle")
    Box(Modifier.size(156.dp), contentAlignment = Alignment.Center) {
        Canvas(Modifier.fillMaxSize().rotate(if (busy) angle else 0f)) {
            val w = 3.dp.toPx()
            when {
                busy -> {
                    drawArc(p.accent.copy(alpha = 0.18f), 0f, 360f, false, style = Stroke(w))
                    drawArc(p.accent, -90f, 100f, false, style = Stroke(w, cap = StrokeCap.Round))
                }
                connected -> drawArc(p.ok.copy(alpha = 0.28f), 0f, 360f, false, style = Stroke(w))
            }
        }
        val shape = CircleShape
        var m = Modifier.size(130.dp)
        m = if (connected) m.shadow(14.dp, shape, ambientColor = p.ok, spotColor = p.ok) else m
        m = m.clip(shape)
        m = when {
            connected -> m.background(Brush.linearGradient(listOf(Color(0xFF3FD38A), Color(0xFF14965A))))
            busy -> m.background(p.accentSoft)
            else -> m.background(p.card2).border(1.dp, p.line, shape)
        }
        Box(m.clickable(onClick = onClick), contentAlignment = Alignment.Center) {
            Icon(
                painterResource(R.drawable.ic_power),
                if (connected || busy) "Отключить" else "Подключить",
                Modifier.size(52.dp),
                tint = when {
                    connected -> Color.White
                    busy -> p.accent
                    failed -> p.err
                    else -> p.faint
                },
            )
        }
    }
}

@Composable
private fun ServerRow(p: Profile?, count: Int, onClick: () -> Unit) {
    Surface(onClick = onClick, modifier = Modifier.fillMaxWidth(), shape = RoundedCornerShape(14.dp), color = pal.card, shadowElevation = 1.dp) {
        Row(Modifier.padding(horizontal = 14.dp, vertical = 12.dp), verticalAlignment = Alignment.CenterVertically) {
            Box(Modifier.size(40.dp).clip(RoundedCornerShape(11.dp)).background(pal.accentSoft), contentAlignment = Alignment.Center) {
                Icon(painterResource(R.drawable.ic_server), null, Modifier.size(20.dp), tint = pal.accent)
            }
            Spacer(Modifier.width(12.dp))
            Column(Modifier.weight(1f)) {
                Text(p?.name ?: "Добавьте сервер", fontWeight = FontWeight.SemiBold, maxLines = 1, overflow = TextOverflow.Ellipsis)
                Text(
                    if (p == null) "Ссылка wdtt:// из панели сервера" else "Сервер ${p.host}" + if (count > 1) " · ещё ${count - 1}" else "",
                    fontSize = 12.5.sp, color = pal.muted, maxLines = 1, overflow = TextOverflow.Ellipsis,
                )
            }
            Icon(if (p == null) Icons.Filled.Add else Icons.AutoMirrored.Filled.KeyboardArrowRight, null, tint = pal.faint)
        }
    }
}

@Composable
private fun Stats(s: Status, live: Live, history: List<Pair<Long, Long>>) {
    Panel {
        Column {
            Row {
                Speed("Загрузка", pal.down, live.rxRate, Modifier.weight(1f))
                Speed("Отдача", pal.up, live.txRate, Modifier.weight(1f))
            }
            Chart(history, Modifier.fillMaxWidth().height(70.dp).padding(vertical = 8.dp))
            Column(verticalArrangement = Arrangement.spacedBy(8.dp)) {
                Row(horizontalArrangement = Arrangement.spacedBy(8.dp)) {
                    MiniTile("Маршруты через VK", "${s.sessions} из ${s.target}", Modifier.weight(1f))
                    MiniTile("Пинг", if (s.rttMs > 0) "${s.rttMs} мс" else "—", Modifier.weight(1f))
                }
                Row(horizontalArrangement = Arrangement.spacedBy(8.dp)) {
                    MiniTile("Трафик", "↓ ${bytes(s.rxBytes)}  ↑ ${bytes(s.txBytes)}", Modifier.weight(1f))
                    MiniTile("Адрес в VPN", s.address.substringBefore('/').ifEmpty { "определяется…" }, Modifier.weight(1f))
                }
            }
            if (s.paths.isNotEmpty()) {
                Spacer(Modifier.height(12.dp))
                FlowRow(horizontalArrangement = Arrangement.spacedBy(4.dp), verticalArrangement = Arrangement.spacedBy(4.dp)) {
                    s.paths.forEach { p ->
                        Box(Modifier.size(11.dp).clip(RoundedCornerShape(3.dp)).background(if (p.fresh) pal.ok else pal.line))
                    }
                }
            }
            Spacer(Modifier.height(10.dp))
            val proto = when (s.protocol) {
                "direct" -> "Протокол: прямой (сервер TurnVK)"
                "dtls" -> "Протокол: DTLS (стандартный сервер WDTT)"
                else -> ""
            }
            val extra = if (s.reconnects > 0) " · замен маршрутов: ${s.reconnects}" else ""
            if (proto.isNotEmpty() || extra.isNotEmpty()) Text(proto + extra, fontSize = 12.5.sp, color = pal.muted)
        }
    }
}

@Composable
private fun Speed(label: String, color: Color, bps: Long, modifier: Modifier) {
    Column(modifier) {
        Row(verticalAlignment = Alignment.CenterVertically) {
            Box(Modifier.size(8.dp).clip(RoundedCornerShape(2.dp)).background(color))
            Spacer(Modifier.width(6.dp))
            Text(label, fontSize = 12.sp, color = pal.muted)
        }
        Row(verticalAlignment = Alignment.Bottom) {
            Text(mbit(bps), fontSize = 24.sp, fontWeight = FontWeight.SemiBold)
            Spacer(Modifier.width(4.dp))
            Text("Мбит/с", fontSize = 13.sp, color = pal.muted, modifier = Modifier.padding(bottom = 3.dp))
        }
    }
}

@Composable
private fun Chart(history: List<Pair<Long, Long>>, modifier: Modifier) {
    val p = pal
    Canvas(modifier) {
        val w = size.width
        val h = size.height
        for (i in 1..2) {
            val y = h * i / 3
            drawLine(p.line, Offset(0f, y), Offset(w, y), 1f)
        }
        if (history.size < 2) return@Canvas
        val max = maxOf(100_000L, history.maxOf { maxOf(it.first, it.second) }) * 1.15f
        val step = w / 59f
        val x0 = w - (history.size - 1) * step
        listOf(p.down to { e: Pair<Long, Long> -> e.first }, p.up to { e: Pair<Long, Long> -> e.second }).forEach { (color, pick) ->
            val line = Path()
            history.forEachIndexed { i, e ->
                val x = x0 + i * step
                val y = h - 2f - pick(e) / max * (h - 6f)
                if (i == 0) line.moveTo(x, y) else line.lineTo(x, y)
            }
            val fill = Path().apply {
                addPath(line)
                lineTo(w, h)
                lineTo(x0, h)
                close()
            }
            drawPath(fill, Brush.verticalGradient(listOf(color.copy(alpha = 0.2f), Color.Transparent)))
            drawPath(line, color, style = Stroke(2.dp.toPx(), cap = StrokeCap.Round, join = StrokeJoin.Round))
        }
    }
}

@Composable
private fun MiniTile(label: String, value: String, modifier: Modifier) {
    Column(modifier.clip(RoundedCornerShape(11.dp)).background(pal.card2).padding(horizontal = 11.dp, vertical = 9.dp)) {
        Text(label, fontSize = 11.5.sp, color = pal.muted, maxLines = 1)
        Text(value, fontWeight = FontWeight.SemiBold, fontSize = 14.sp, maxLines = 1, overflow = TextOverflow.Ellipsis)
    }
}

// ---------------------------------------------------------------- servers

@Composable
private fun ServersTab(store: Store, revision: Int, refresh: () -> Unit, active: Boolean) {
    val ctx = LocalContext.current
    val profiles = remember(revision) { store.profiles }
    val current = remember(revision) { store.current }
    var editing by remember { mutableStateOf<Profile?>(null) }
    var creating by remember { mutableStateOf(false) }

    Column(
        Modifier.fillMaxSize().verticalScroll(rememberScrollState()).padding(horizontal = 16.dp, vertical = 6.dp),
        verticalArrangement = Arrangement.spacedBy(12.dp),
    ) {
        Panel {
            Column {
                SectionTitle("Серверы", Modifier.padding(bottom = 6.dp))
                if (profiles.isEmpty()) {
                    Column(Modifier.fillMaxWidth().padding(vertical = 18.dp), horizontalAlignment = Alignment.CenterHorizontally) {
                        Box(Modifier.size(56.dp).clip(RoundedCornerShape(16.dp)).background(pal.accentSoft), contentAlignment = Alignment.Center) {
                            Icon(painterResource(R.drawable.ic_server), null, Modifier.size(28.dp), tint = pal.accent)
                        }
                        Spacer(Modifier.height(12.dp))
                        Text("Пока нет серверов", fontWeight = FontWeight.SemiBold)
                        Text("Вставьте ссылку wdtt:// из панели вашего сервера.", fontSize = 12.5.sp, color = pal.muted, textAlign = TextAlign.Center)
                    }
                }
                profiles.forEachIndexed { i, p ->
                    if (i > 0) HorizontalDivider(color = pal.line)
                    val selected = p.id == current?.id
                    Row(
                        Modifier.fillMaxWidth().clickable {
                            if (active && !selected) {
                                android.widget.Toast.makeText(ctx, "Сначала отключитесь", android.widget.Toast.LENGTH_SHORT).show()
                            } else {
                                store.currentId = p.id
                                refresh()
                            }
                        }.padding(vertical = 12.dp),
                        verticalAlignment = Alignment.CenterVertically,
                    ) {
                        Box(
                            Modifier.size(20.dp).clip(CircleShape).border(2.dp, if (selected) pal.accent else pal.faint, CircleShape),
                            contentAlignment = Alignment.Center,
                        ) {
                            if (selected) Box(Modifier.size(9.dp).clip(CircleShape).background(pal.accent))
                        }
                        Spacer(Modifier.width(12.dp))
                        Column(Modifier.weight(1f)) {
                            Text(p.name, fontWeight = FontWeight.SemiBold, maxLines = 1, overflow = TextOverflow.Ellipsis)
                            Text("Сервер ${p.host}", fontSize = 12.5.sp, color = pal.muted, maxLines = 1, overflow = TextOverflow.Ellipsis)
                        }
                        IconButton(onClick = { editing = p }) { Icon(Icons.Filled.Edit, "Изменить", tint = pal.muted) }
                    }
                }
            }
        }
        Button(
            onClick = { creating = true },
            modifier = Modifier.fillMaxWidth().height(48.dp),
            shape = RoundedCornerShape(12.dp),
            colors = ButtonDefaults.buttonColors(containerColor = pal.accent),
        ) {
            Icon(Icons.Filled.Add, null)
            Spacer(Modifier.width(6.dp))
            Text("Добавить сервер", fontWeight = FontWeight.SemiBold)
        }
        Note("Ссылку на сервер даёт панель WDTT Router: «Подключения» → ссылка для TurnVK.")
    }

    if (creating) {
        ProfileDialog(
            initial = Profile(Store.newId(), "", ""),
            isNew = true,
            onSave = { store.save(it); refresh(); creating = false },
            onDelete = null,
            onDismiss = { creating = false },
        )
    }
    editing?.let { p ->
        ProfileDialog(
            initial = p,
            isNew = false,
            onSave = { store.save(it); refresh(); editing = null },
            onDelete = { store.delete(p.id); refresh(); editing = null },
            onDismiss = { editing = null },
        )
    }
}

// ---------------------------------------------------------------- profile editor

@Composable
private fun ProfileDialog(
    initial: Profile,
    isNew: Boolean,
    onSave: (Profile) -> Unit,
    onDelete: (() -> Unit)?,
    onDismiss: () -> Unit,
) {
    val ctx = LocalContext.current
    var name by remember { mutableStateOf(initial.name) }
    var link by remember { mutableStateOf(initial.link) }
    var show by remember { mutableStateOf(false) }
    var confirmDelete by remember { mutableStateOf(false) }
    val linkError = remember(link) { if (link.isBlank()) "" else mobile.Mobile.validateLink(link) }
    val ok = link.isNotBlank() && linkError.isEmpty()

    AlertDialog(
        onDismissRequest = onDismiss,
        containerColor = pal.card,
        shape = RoundedCornerShape(20.dp),
        title = { Text(if (isNew) "Новый сервер" else "Изменить сервер", fontWeight = FontWeight.SemiBold) },
        text = {
            Column(verticalArrangement = Arrangement.spacedBy(8.dp)) {
                OutlinedTextField(
                    value = name,
                    onValueChange = { name = it },
                    label = { Text("Название") },
                    placeholder = { Text("Мой сервер") },
                    singleLine = true,
                    shape = RoundedCornerShape(10.dp),
                    modifier = Modifier.fillMaxWidth(),
                )
                OutlinedTextField(
                    value = link,
                    onValueChange = { link = it.trim() },
                    label = { Text("Ссылка wdtt://") },
                    singleLine = true,
                    shape = RoundedCornerShape(10.dp),
                    visualTransformation = if (show) VisualTransformation.None else PasswordVisualTransformation(),
                    keyboardOptions = KeyboardOptions(keyboardType = KeyboardType.Password),
                    isError = linkError.isNotEmpty(),
                    supportingText = { if (linkError.isNotEmpty()) Text(linkError) },
                    modifier = Modifier.fillMaxWidth(),
                )
                Row(horizontalArrangement = Arrangement.spacedBy(8.dp)) {
                    OutlinedButton(onClick = {
                        val cm = ctx.getSystemService(ClipboardManager::class.java)
                        cm.primaryClip?.getItemAt(0)?.coerceToText(ctx)?.toString()?.trim()?.let {
                            link = it
                            if (name.isBlank()) name = defaultName(it)
                        }
                    }) { Text("Вставить") }
                    TextButton(onClick = { show = !show }) { Text(if (show) "Скрыть" else "Показать") }
                }
                if (!isNew) {
                    Row {
                        TextButton(onClick = {
                            val send = Intent(Intent.ACTION_SEND).setType("text/plain").putExtra(Intent.EXTRA_TEXT, initial.link)
                            ctx.startActivity(Intent.createChooser(send, "Поделиться ссылкой"))
                        }) {
                            Icon(Icons.Filled.Share, null)
                            Spacer(Modifier.width(6.dp))
                            Text("Поделиться")
                        }
                        if (onDelete != null) {
                            TextButton(onClick = { confirmDelete = true }) {
                                Icon(Icons.Filled.Delete, null, tint = MaterialTheme.colorScheme.error)
                                Spacer(Modifier.width(6.dp))
                                Text("Удалить", color = MaterialTheme.colorScheme.error)
                            }
                        }
                    }
                }
                Text(
                    "В ссылке пароль подключения: делитесь ею только с теми, кому доверяете.",
                    fontSize = 12.5.sp,
                    color = pal.muted,
                )
            }
        },
        confirmButton = {
            TextButton(enabled = ok, onClick = {
                // A name the app made up follows the link to a new server.
                val auto = name.isBlank() || (name == initial.name && initial.link.isNotEmpty() && name == defaultName(initial.link))
                onSave(initial.copy(name = if (auto) defaultName(link) else name, link = link))
            }) { Text("Сохранить") }
        },
        dismissButton = { TextButton(onClick = onDismiss) { Text("Отмена") } },
    )
    if (confirmDelete && onDelete != null) {
        AlertDialog(
            onDismissRequest = { confirmDelete = false },
            containerColor = pal.card,
            title = { Text("Удалить «${initial.name}»?") },
            text = { Text("Ссылка удалится с телефона. Если она понадобится снова, её придётся вставить заново.") },
            confirmButton = { TextButton(onClick = { confirmDelete = false; onDelete() }) { Text("Удалить", color = MaterialTheme.colorScheme.error) } },
            dismissButton = { TextButton(onClick = { confirmDelete = false }) { Text("Отмена") } },
        )
    }
}

// ---------------------------------------------------------------- settings

@Composable
private fun SettingsTab(store: Store, revision: Int, refresh: () -> Unit, active: Boolean, onApps: () -> Unit) {
    val ctx = LocalContext.current
    var sessions by remember(revision) { mutableFloatStateOf(store.sessions.toFloat().coerceIn(8f, 64f)) }
    var obfs by remember(revision) { mutableStateOf(store.obfs) }
    var captchaAuto by remember(revision) { mutableStateOf(store.captchaAuto) }
    var boot by remember(revision) { mutableStateOf(store.bootConnect) }
    val excluded = remember(revision) { store.excludedApps.size }
    // Re-checked whenever the screen is shown again (after the system pages).
    var resumes by remember { mutableIntStateOf(0) }
    LifecycleResumeEffect(Unit) {
        resumes++
        onPauseOrDispose { }
    }
    val batteryOk = remember(resumes) {
        ctx.getSystemService(PowerManager::class.java)?.isIgnoringBatteryOptimizations(ctx.packageName) == true
    }
    val notesOk = remember(resumes) {
        ctx.getSystemService(android.app.NotificationManager::class.java)?.areNotificationsEnabled() == true
    }

    Column(
        Modifier.fillMaxSize().verticalScroll(rememberScrollState()).padding(horizontal = 16.dp, vertical = 6.dp),
        verticalArrangement = Arrangement.spacedBy(12.dp),
    ) {
        if (active) Note("Изменения применятся при следующем подключении.")

        Panel {
            Column {
                SectionTitle("Подключение", Modifier.padding(bottom = 10.dp))
                Text("Маршрутов через VK", fontWeight = FontWeight.SemiBold)
                Text(
                    "VK пропускает по каждому маршруту около 1,5 Мбит/с: больше маршрутов — выше скорость и устойчивость. 16 маршрутов — около 25 Мбит/с, 32 — около 45. Больше 16 маршрутов VK даёт одному гостю звонка, поэтому дальше нужен второй гость, а с ним иногда ещё одна проверка VK в сутки.",
                    fontSize = 12.5.sp, color = pal.muted, lineHeight = 17.sp,
                )
                Row(verticalAlignment = Alignment.CenterVertically) {
                    Slider(
                        value = sessions,
                        onValueChange = { sessions = it },
                        onValueChangeFinished = { store.sessions = sessions.toInt(); refresh() },
                        valueRange = 8f..64f,
                        steps = 6,
                        modifier = Modifier.weight(1f),
                    )
                    Text("${sessions.toInt()}", fontWeight = FontWeight.SemiBold, modifier = Modifier.width(36.dp), textAlign = TextAlign.End)
                }
                HorizontalDivider(color = pal.line, modifier = Modifier.padding(vertical = 10.dp))
                Text("Маскировка трафика", fontWeight = FontWeight.SemiBold)
                Text("Под какой звонок VK оформлены пакеты.", fontSize = 12.5.sp, color = pal.muted)
                Spacer(Modifier.height(8.dp))
                SingleChoiceSegmentedButtonRow(Modifier.fillMaxWidth()) {
                    listOf("audio" to "Аудиозвонок", "video" to "Видеозвонок").forEachIndexed { i, (v, label) ->
                        SegmentedButton(
                            selected = obfs == v,
                            onClick = { obfs = v; store.obfs = v; refresh() },
                            shape = SegmentedButtonDefaults.itemShape(i, 2),
                        ) { Text(label) }
                    }
                }
                HorizontalDivider(color = pal.line, modifier = Modifier.padding(top = 10.dp))
                SwitchRow(
                    title = "Автокапча",
                    text = "Пытаться пройти проверку VK без вас",
                    checked = captchaAuto,
                    onChange = { captchaAuto = it; store.captchaAuto = it; refresh() },
                )
            }
        }

        Panel(padding = 0.dp) {
            Column {
                SectionTitle("Приложения", Modifier.padding(start = 16.dp, top = 16.dp))
                ClickRow(
                    title = "Приложения в обход VPN",
                    text = (if (excluded > 0) "Выбрано: $excluded. " else "") + "Приложения VK всегда идут в обход, чтобы звонки работали.",
                    onClick = onApps,
                )
            }
        }

        Panel(padding = 0.dp) {
            Column {
                SectionTitle("Запуск и работа в фоне", Modifier.padding(start = 16.dp, top = 16.dp))
                SwitchRow(
                    title = "Подключаться при включении телефона",
                    text = "К выбранному серверу, если VPN уже разрешён",
                    checked = boot,
                    onChange = { boot = it; store.bootConnect = it; refresh() },
                    inset = true,
                )
                ClickRow(
                    title = "Постоянный VPN",
                    text = "В системных настройках включите «Постоянная VPN» и «Блокировать подключения без VPN»: Android сам будет поднимать TurnVK, и трафик не пойдёт мимо туннеля.",
                    onClick = { runCatching { ctx.startActivity(Intent(Settings.ACTION_VPN_SETTINGS)) } },
                )
                ClickRow(
                    title = "Экономия заряда",
                    text = if (batteryOk) "Отключена для TurnVK: система не прервёт VPN в фоне" else "Включена: система может усыплять VPN. Нажмите, чтобы разрешить работу в фоне.",
                    warn = !batteryOk,
                    onClick = {
                        if (!batteryOk) {
                            runCatching {
                                ctx.startActivity(Intent(Settings.ACTION_REQUEST_IGNORE_BATTERY_OPTIMIZATIONS, Uri.parse("package:" + ctx.packageName)))
                            }
                        }
                    },
                )
                ClickRow(
                    title = "Уведомления",
                    text = if (notesOk) "Включены: о проверке VK вы узнаете сразу" else "Выключены: о проверке VK вы не узнаете, пока не откроете приложение",
                    warn = !notesOk,
                    onClick = {
                        val i = if (Build.VERSION.SDK_INT >= 26) {
                            Intent(Settings.ACTION_APP_NOTIFICATION_SETTINGS).putExtra(Settings.EXTRA_APP_PACKAGE, ctx.packageName)
                        } else {
                            Intent(Settings.ACTION_APPLICATION_DETAILS_SETTINGS, Uri.parse("package:" + ctx.packageName))
                        }
                        runCatching { ctx.startActivity(i) }
                    },
                )
                ClickRow(
                    title = "Плитка в шторке",
                    text = if (Build.VERSION.SDK_INT >= 33) {
                        "Нажмите, чтобы добавить плитку TurnVK в быстрые настройки: VPN включается, не открывая приложение."
                    } else {
                        "Добавьте плитку TurnVK в быстрые настройки (карандаш в шторке): VPN включается, не открывая приложение."
                    },
                    onClick = { if (Build.VERSION.SDK_INT >= 33) requestTile(ctx) },
                )
            }
        }

        Panel {
            Row(verticalAlignment = Alignment.CenterVertically) {
                Logo(46.dp, 13.dp)
                Spacer(Modifier.width(12.dp))
                Column {
                    Row {
                        Text("TurnVK ", fontWeight = FontWeight.SemiBold)
                        Text(BuildConfig.VERSION_NAME, color = pal.muted)
                    }
                    Text(
                        "Трафик идёт только через серверы звонков VK (TURN) и шифруется WireGuard внутри маскировки под RTP.",
                        fontSize = 12.5.sp, color = pal.muted, lineHeight = 17.sp,
                    )
                }
            }
        }
        Spacer(Modifier.height(8.dp))
    }
}

/** A setting with a switch; [inset] adds the side padding of a list row. */
@Composable
private fun SwitchRow(title: String, text: String, checked: Boolean, onChange: (Boolean) -> Unit, inset: Boolean = false) {
    Row(
        Modifier.fillMaxWidth().clickable { onChange(!checked) }
            .padding(horizontal = if (inset) 16.dp else 0.dp, vertical = 10.dp),
        verticalAlignment = Alignment.CenterVertically,
    ) {
        Column(Modifier.weight(1f)) {
            Text(title, fontWeight = FontWeight.SemiBold)
            Text(text, color = pal.muted, fontSize = 12.5.sp, lineHeight = 17.sp)
        }
        Spacer(Modifier.width(12.dp))
        Switch(checked = checked, onCheckedChange = onChange)
    }
}

@Composable
private fun ClickRow(title: String, text: String, warn: Boolean = false, onClick: () -> Unit) {
    ListItem(
        headlineContent = { Text(title, fontWeight = FontWeight.SemiBold) },
        supportingContent = { Text(text, color = if (warn) pal.err else pal.muted, fontSize = 12.5.sp, lineHeight = 17.sp) },
        trailingContent = { Icon(Icons.AutoMirrored.Filled.KeyboardArrowRight, null, tint = pal.faint) },
        colors = ListItemDefaults.colors(containerColor = Color.Transparent),
        modifier = Modifier.clickable(onClick = onClick),
    )
}

// ---------------------------------------------------------------- logs

@Composable
private fun LogsTab() {
    val ctx = LocalContext.current
    val log by TunnelState.log.collectAsState()
    val listState = rememberLazyListState()
    LaunchedEffect(log.size) { if (log.isNotEmpty()) listState.scrollToItem(log.size - 1) }
    var collecting by remember { mutableStateOf(false) }
    var report by remember { mutableStateOf<String?>(null) }
    LaunchedEffect(collecting) {
        if (collecting) {
            report = withContext(Dispatchers.IO) { buildReport(ctx) }
            collecting = false
        }
    }
    report?.let { text ->
        AlertDialog(
            onDismissRequest = { report = null },
            title = { Text("Отчёт для разработчика") },
            text = {
                Column {
                    Text("Отправьте его разработчику. Ключи и ссылка на сервер скрыты.", color = pal.muted, fontSize = 13.sp)
                    Surface(Modifier.fillMaxWidth().height(260.dp).padding(top = 10.dp), shape = RoundedCornerShape(10.dp), color = pal.card2) {
                        SelectionContainer {
                            Text(text, Modifier.verticalScroll(rememberScrollState()).padding(10.dp), fontFamily = FontFamily.Monospace, fontSize = 10.sp, lineHeight = 14.sp)
                        }
                    }
                }
            },
            confirmButton = {
                TextButton(onClick = {
                    val send = Intent(Intent.ACTION_SEND).setType("text/plain").putExtra(Intent.EXTRA_TEXT, text)
                    ctx.startActivity(Intent.createChooser(send, "Отчёт TurnVK"))
                }) { Text("Поделиться") }
            },
            dismissButton = {
                TextButton(onClick = {
                    ctx.getSystemService(ClipboardManager::class.java).setPrimaryClip(ClipData.newPlainText("TurnVK", text))
                    report = null
                }) { Text("Копировать") }
            },
        )
    }
    Column(Modifier.fillMaxSize().padding(horizontal = 16.dp, vertical = 6.dp)) {
        Panel(Modifier.padding(bottom = 12.dp)) {
            Column {
                Text("Что-то не работает?", fontWeight = FontWeight.SemiBold)
                Text(
                    "Соберите отчёт и отправьте его разработчику: журнал, состояние подключения и проверка сети. Ключи и ссылка на сервер скрыты.",
                    color = pal.muted, fontSize = 13.sp, modifier = Modifier.padding(top = 4.dp, bottom = 10.dp),
                )
                Button(
                    onClick = { collecting = true },
                    enabled = !collecting,
                    modifier = Modifier.fillMaxWidth(),
                    shape = RoundedCornerShape(10.dp),
                ) { Text(if (collecting) "Проверяем сеть…" else "Собрать отчёт", fontWeight = FontWeight.SemiBold) }
            }
        }
        Row(horizontalArrangement = Arrangement.spacedBy(8.dp), modifier = Modifier.padding(bottom = 12.dp)) {
            LogButton("Копировать") {
                ctx.getSystemService(ClipboardManager::class.java)
                    .setPrimaryClip(ClipData.newPlainText("TurnVK", log.joinToString("\n")))
            }
            LogButton("Поделиться") {
                val send = Intent(Intent.ACTION_SEND).setType("text/plain").putExtra(Intent.EXTRA_TEXT, log.joinToString("\n"))
                ctx.startActivity(Intent.createChooser(send, "Журнал TurnVK"))
            }
            LogButton("Очистить") { TunnelState.clearLog() }
        }
        Surface(Modifier.fillMaxWidth().weight(1f).padding(bottom = 12.dp), shape = RoundedCornerShape(16.dp), color = pal.card, shadowElevation = 1.dp) {
            if (log.isEmpty()) {
                Box(Modifier.fillMaxSize(), contentAlignment = Alignment.Center) {
                    Text("Пока пусто", color = pal.muted)
                }
            } else {
                SelectionContainer {
                    LazyColumn(Modifier.fillMaxSize(), state = listState, contentPadding = PaddingValues(12.dp)) {
                        items(log) { Text(it, fontFamily = FontFamily.Monospace, fontSize = 11.sp, lineHeight = 16.sp) }
                    }
                }
            }
        }
    }
}

@Composable
private fun LogButton(text: String, onClick: () -> Unit) {
    Button(
        onClick = onClick,
        shape = RoundedCornerShape(10.dp),
        colors = ButtonDefaults.buttonColors(containerColor = pal.card, contentColor = MaterialTheme.colorScheme.onSurface),
        contentPadding = PaddingValues(horizontal = 14.dp, vertical = 8.dp),
    ) { Text(text, fontWeight = FontWeight.SemiBold, fontSize = 13.sp) }
}

// ---------------------------------------------------------------- apps

private class AppEntry(val pkg: String, val label: String, val icon: androidx.compose.ui.graphics.ImageBitmap?)

@Composable
private fun AppsScreen(store: Store, refresh: () -> Unit, onBack: () -> Unit) {
    val ctx = LocalContext.current
    var apps by remember { mutableStateOf<List<AppEntry>?>(null) }
    var selected by remember { mutableStateOf(store.excludedApps) }
    var query by remember { mutableStateOf("") }
    LaunchedEffect(Unit) { apps = withContext(Dispatchers.IO) { loadApps(ctx) } }
    val save = { set: Set<String> ->
        selected = set
        store.excludedApps = set
        refresh()
    }

    Scaffold(
        containerColor = MaterialTheme.colorScheme.background,
        topBar = {
            TopAppBar(
                title = { Text("В обход VPN", fontWeight = FontWeight.SemiBold) },
                navigationIcon = { IconButton(onClick = onBack) { Icon(Icons.AutoMirrored.Filled.ArrowBack, "Назад") } },
                actions = { if (selected.isNotEmpty()) TextButton(onClick = { save(emptySet()) }) { Text("Сбросить") } },
            )
        },
    ) { pad ->
        Column(Modifier.fillMaxSize().padding(pad)) {
            Note(
                "Отмеченные приложения ходят в интернет напрямую, без VPN: например, банки или сервисы, которым нужен ваш обычный адрес.",
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
                    .sortedWith(compareByDescending<AppEntry> { it.pkg in selected }.thenBy { it.label.lowercase() })
                LazyColumn(Modifier.fillMaxSize()) {
                    items(shown, key = { it.pkg }) { a ->
                        val forced = a.pkg in TunnelService.BYPASS
                        val on = forced || a.pkg in selected
                        ListItem(
                            headlineContent = { Text(a.label) },
                            supportingContent = { Text(if (forced) "всегда в обход" else a.pkg, maxLines = 1, overflow = TextOverflow.Ellipsis) },
                            leadingContent = {
                                if (a.icon != null) Image(a.icon, null, Modifier.size(36.dp)) else Spacer(Modifier.size(36.dp))
                            },
                            trailingContent = {
                                Checkbox(checked = on, enabled = !forced, onCheckedChange = { c -> save(if (c) selected + a.pkg else selected - a.pkg) })
                            },
                            colors = ListItemDefaults.colors(containerColor = Color.Transparent),
                            modifier = Modifier.clickable(enabled = !forced) { save(if (on) selected - a.pkg else selected + a.pkg) },
                        )
                    }
                }
            }
        }
    }
}

private fun loadApps(ctx: Context): List<AppEntry> {
    val pm = ctx.packageManager
    val launcher = Intent(Intent.ACTION_MAIN).addCategory(Intent.CATEGORY_LAUNCHER)
    val infos = if (Build.VERSION.SDK_INT >= 33) {
        pm.queryIntentActivities(launcher, PackageManager.ResolveInfoFlags.of(0))
    } else {
        @Suppress("DEPRECATION")
        pm.queryIntentActivities(launcher, 0)
    }
    return infos.map { it.activityInfo.applicationInfo }
        .distinctBy { it.packageName }
        .filter { it.packageName != ctx.packageName }
        .map { ai ->
            val icon = runCatching { pm.getApplicationIcon(ai).toBitmap(96, 96).asImageBitmap() }.getOrNull()
            AppEntry(ai.packageName, pm.getApplicationLabel(ai).toString(), icon)
        }
}

@androidx.annotation.RequiresApi(33)
private fun requestTile(ctx: Context) {
    runCatching {
        ctx.getSystemService(StatusBarManager::class.java).requestAddTileService(
            ComponentName(ctx, QuickTile::class.java),
            ctx.getString(R.string.app_name),
            android.graphics.drawable.Icon.createWithResource(ctx, R.drawable.ic_stat_vpn),
            ctx.mainExecutor,
        ) { }
    }
}

// ---------------------------------------------------------------- formatting

private fun bytes(n: Long): String = when {
    n >= 1L shl 30 -> "%.2f ГБ".format(n / (1L shl 30).toDouble())
    n >= 1L shl 20 -> "%.1f МБ".format(n / (1L shl 20).toDouble())
    n >= 1L shl 10 -> "${n shr 10} КБ"
    else -> "$n Б"
}

/** Bytes per second as megabits per second, the way speed tests show it. */
private fun mbit(bps: Long): String {
    val m = bps * 8 / 1e6
    return when {
        m >= 100 -> "%.0f".format(m)
        m >= 10 -> "%.1f".format(m)
        else -> "%.2f".format(m)
    }
}

/** Engine errors are English; the common ones get a plain explanation. */
private fun humanError(e: String): String {
    val l = e.lowercase()
    return when {
        "dtls handshake timed out" in l -> "Сервер не ответил. Проверьте, что сервер включён в панели, а ссылка актуальна (после переустановки сервера нужна новая)."
        "server's key does not match" in l -> "Ключ сервера не совпал со ссылкой: сервер переустановлен или это не ваш сервер. Возьмите новую ссылку в панели."
        "rejected the connection password" in l -> "Сервер не принял пароль из ссылки. Возьмите новую ссылку в панели."
        "expired" in l && "password" in l -> "Срок действия пароля истёк."
        "disabled" in l && "password" in l -> "Пароль отключён в панели."
        "bound to another device" in l -> "Этот пароль привязан к другому устройству."
        "newer connection" in l -> "Это устройство подключилось заново в другом месте."
        "vk call is unavailable" in l || "no usable vk call" in l -> "Звонок VK в ссылке больше не работает. Обновите ссылку в панели."
        "captcha" in l -> "VK попросил проверку, но она не была пройдена."
        else -> e
    }
}
