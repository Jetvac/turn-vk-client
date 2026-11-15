@file:OptIn(ExperimentalMaterial3Api::class)

package io.github.jetvac.turnvk

import android.app.StatusBarManager
import android.content.ClipData
import android.content.ComponentName
import android.content.ClipboardManager
import android.content.Context
import android.content.Intent
import android.content.pm.PackageManager
import android.net.Uri
import android.os.Build
import android.os.PowerManager
import android.os.SystemClock
import android.provider.Settings
import androidx.activity.compose.BackHandler
import androidx.compose.animation.animateColorAsState
import androidx.compose.animation.animateContentSize
import androidx.compose.foundation.Image
import androidx.compose.foundation.background
import androidx.compose.foundation.clickable
import androidx.compose.foundation.isSystemInDarkTheme
import androidx.compose.foundation.layout.Arrangement
import androidx.compose.foundation.layout.Box
import androidx.compose.foundation.layout.Column
import androidx.compose.foundation.layout.PaddingValues
import androidx.compose.foundation.layout.Row
import androidx.compose.foundation.layout.Spacer
import androidx.compose.foundation.layout.fillMaxSize
import androidx.compose.foundation.layout.fillMaxWidth
import androidx.compose.foundation.layout.height
import androidx.compose.foundation.layout.navigationBarsPadding
import androidx.compose.foundation.layout.padding
import androidx.compose.foundation.layout.size
import androidx.compose.foundation.layout.width
import androidx.compose.foundation.lazy.LazyColumn
import androidx.compose.foundation.lazy.items
import androidx.compose.foundation.lazy.rememberLazyListState
import androidx.compose.foundation.rememberScrollState
import androidx.compose.foundation.shape.CircleShape
import androidx.compose.foundation.text.KeyboardOptions
import androidx.compose.foundation.verticalScroll
import androidx.compose.material.icons.Icons
import androidx.compose.material.icons.automirrored.filled.ArrowBack
import androidx.compose.material.icons.automirrored.filled.List
import androidx.compose.material.icons.filled.Add
import androidx.compose.material.icons.filled.Delete
import androidx.compose.material.icons.filled.Edit
import androidx.compose.material.icons.filled.KeyboardArrowDown
import androidx.compose.material.icons.filled.KeyboardArrowUp
import androidx.compose.material.icons.filled.Search
import androidx.compose.material.icons.filled.Settings
import androidx.compose.material.icons.filled.Share
import androidx.compose.material.icons.filled.Warning
import androidx.compose.material3.AlertDialog
import androidx.compose.material3.Button
import androidx.compose.material3.Card
import androidx.compose.material3.CardDefaults
import androidx.compose.material3.Checkbox
import androidx.compose.material3.CircularProgressIndicator
import androidx.compose.material3.ExperimentalMaterial3Api
import androidx.compose.material3.HorizontalDivider
import androidx.compose.material3.Icon
import androidx.compose.material3.IconButton
import androidx.compose.material3.ListItem
import androidx.compose.material3.MaterialTheme
import androidx.compose.material3.ModalBottomSheet
import androidx.compose.material3.OutlinedButton
import androidx.compose.material3.OutlinedTextField
import androidx.compose.material3.RadioButton
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
import androidx.compose.material3.dynamicDarkColorScheme
import androidx.compose.material3.dynamicLightColorScheme
import androidx.compose.material3.lightColorScheme
import androidx.compose.runtime.Composable
import androidx.compose.runtime.LaunchedEffect
import androidx.compose.runtime.MutableState
import androidx.compose.runtime.collectAsState
import androidx.compose.runtime.getValue
import androidx.compose.runtime.mutableFloatStateOf
import androidx.compose.runtime.mutableIntStateOf
import androidx.compose.runtime.mutableLongStateOf
import androidx.compose.runtime.mutableStateOf
import androidx.compose.runtime.remember
import androidx.compose.runtime.setValue
import androidx.compose.ui.Alignment
import androidx.compose.ui.Modifier
import androidx.compose.ui.draw.clip
import androidx.compose.ui.graphics.Color
import androidx.compose.ui.graphics.asImageBitmap
import androidx.compose.ui.platform.LocalContext
import androidx.compose.ui.text.font.FontFamily
import androidx.compose.ui.text.font.FontWeight
import androidx.compose.ui.text.input.KeyboardType
import androidx.compose.ui.text.input.PasswordVisualTransformation
import androidx.compose.ui.text.input.VisualTransformation
import androidx.compose.ui.text.style.TextAlign
import androidx.compose.ui.text.style.TextOverflow
import androidx.compose.ui.unit.dp
import androidx.compose.ui.unit.sp
import androidx.core.graphics.drawable.toBitmap
import androidx.lifecycle.compose.LifecycleResumeEffect
import kotlinx.coroutines.Dispatchers
import kotlinx.coroutines.delay
import kotlinx.coroutines.withContext

// ---------------------------------------------------------------- theme

private val Green = Color(0xFF2E9D5B)

@Composable
fun TurnVKTheme(content: @Composable () -> Unit) {
    val dark = isSystemInDarkTheme()
    val ctx = LocalContext.current
    val scheme = when {
        Build.VERSION.SDK_INT >= 31 -> if (dark) dynamicDarkColorScheme(ctx) else dynamicLightColorScheme(ctx)
        dark -> darkColorScheme()
        else -> lightColorScheme()
    }
    MaterialTheme(colorScheme = scheme) {
        Surface(Modifier.fillMaxSize(), color = MaterialTheme.colorScheme.background) { content() }
    }
}

// ---------------------------------------------------------------- app

private enum class Page { Home, Settings, Logs, Apps }

/** Live numbers polled from the engine once a second while connected. */
private data class Live(val status: Status = Status(), val rxRate: Long = 0, val txRate: Long = 0)

@Composable
fun App(store: Store, imported: MutableState<String?>, connect: () -> Unit) {
    var page by remember { mutableStateOf(Page.Home) }
    // Bumped when the store changes, so that screens re-read it.
    var revision by remember { mutableIntStateOf(0) }
    val refresh: () -> Unit = { revision++ }

    BackHandler(enabled = page != Page.Home) {
        page = if (page == Page.Apps) Page.Settings else Page.Home
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

    when (page) {
        Page.Home -> HomeScreen(store, revision, refresh, connect, onSettings = { page = Page.Settings }, onLogs = { page = Page.Logs })
        Page.Settings -> SettingsScreen(store, revision, refresh, onBack = { page = Page.Home }, onApps = { page = Page.Apps })
        Page.Logs -> LogsScreen(onBack = { page = Page.Home })
        Page.Apps -> AppsScreen(store, refresh, onBack = { page = Page.Settings })
    }
}

private fun defaultName(link: String): String {
    val host = Profile("", "", link).host
    return if (host.isNotEmpty()) "Сервер $host" else "Мой сервер"
}

// ---------------------------------------------------------------- home

@Composable
private fun HomeScreen(
    store: Store,
    revision: Int,
    refresh: () -> Unit,
    connect: () -> Unit,
    onSettings: () -> Unit,
    onLogs: () -> Unit,
) {
    val ctx = LocalContext.current
    val status by TunnelState.status.collectAsState()
    val error by TunnelState.error.collectAsState()
    val captcha by TunnelState.captcha.collectAsState()
    val profiles = remember(revision) { store.profiles }
    val current = remember(revision) { store.current }

    var live by remember { mutableStateOf(Live()) }
    var now by remember { mutableLongStateOf(System.currentTimeMillis()) }
    LaunchedEffect(status.active) {
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
                    Live(s, ((s.rxBytes - p.rxBytes) / dt).toLong().coerceAtLeast(0), ((s.txBytes - p.txBytes) / dt).toLong().coerceAtLeast(0))
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

    var pickProfile by remember { mutableStateOf(false) }
    var editing by remember { mutableStateOf<Profile?>(null) }
    var creating by remember { mutableStateOf(false) }

    Scaffold(
        topBar = {
            TopAppBar(
                title = { Text("TurnVK", fontWeight = FontWeight.SemiBold) },
                actions = {
                    IconButton(onClick = onLogs) { Icon(Icons.AutoMirrored.Filled.List, "Журнал") }
                    IconButton(onClick = onSettings) { Icon(Icons.Filled.Settings, "Настройки") }
                },
            )
        },
    ) { pad ->
        Column(
            Modifier.fillMaxSize().padding(pad).verticalScroll(rememberScrollState()).padding(horizontal = 16.dp),
            verticalArrangement = Arrangement.spacedBy(12.dp),
            horizontalAlignment = Alignment.CenterHorizontally,
        ) {
            ProfileCard(current, enabled = !status.active, onClick = {
                if (profiles.isEmpty()) creating = true else pickProfile = true
            })

            Spacer(Modifier.height(8.dp))
            val s = if (live.status.state.isNotEmpty() && status.active) live.status.copy(state = status.state, captcha = status.captcha || live.status.captcha) else status
            ConnectButton(
                state = s.state,
                enabled = s.active || current != null,
                onClick = {
                    if (s.active) TunnelService.disconnect(ctx) else if (current == null) creating = true else connect()
                },
            )
            StateLine(s, now)
            Spacer(Modifier.height(4.dp))

            if (captcha != null || s.captcha) {
                Banner(
                    title = "Нужна проверка VK",
                    text = if (s.state == "connected") "VPN работает. Пройдите проверку, чтобы он и дальше переподключался без перебоев." else "Подключение ждёт, пока вы подтвердите, что вы не робот.",
                    action = if (captcha != null) "Пройти" else null,
                    onAction = { ctx.startActivity(Intent(ctx, CaptchaActivity::class.java)) },
                )
            }
            val err = error ?: status.lastError.takeIf { it.isNotEmpty() && status.state == "failed" }
            if (!err.isNullOrEmpty() && !s.active) {
                Banner(title = "Не удалось подключиться", text = humanError(err), error = true)
            }

            if (s.active) {
                Row(horizontalArrangement = Arrangement.spacedBy(12.dp)) {
                    Tile("Загрузка", rate(live.rxRate), Modifier.weight(1f))
                    Tile("Отдача", rate(live.txRate), Modifier.weight(1f))
                }
                Row(horizontalArrangement = Arrangement.spacedBy(12.dp)) {
                    Tile("Пинг", if (s.rttMs > 0) "${s.rttMs} мс" else "—", Modifier.weight(1f), hint = "до сервера через VK")
                    Tile("Маршруты", "${s.sessions} из ${s.target}", Modifier.weight(1f), hint = "через VK TURN")
                }
                Details(s)
                if (s.paths.isNotEmpty()) Routes(s.paths)
            } else if (current != null) {
                Text(
                    "Весь трафик идёт через серверы звонков VK и шифруется WireGuard.",
                    style = MaterialTheme.typography.bodySmall,
                    color = MaterialTheme.colorScheme.onSurfaceVariant,
                    textAlign = TextAlign.Center,
                    modifier = Modifier.padding(horizontal = 24.dp),
                )
            }
            Spacer(Modifier.height(24.dp))
        }
    }

    if (pickProfile) {
        ModalBottomSheet(onDismissRequest = { pickProfile = false }) {
            Column(Modifier.navigationBarsPadding().padding(bottom = 16.dp)) {
                Text("Серверы", style = MaterialTheme.typography.titleMedium, modifier = Modifier.padding(horizontal = 24.dp, vertical = 8.dp))
                profiles.forEach { p ->
                    ListItem(
                        headlineContent = { Text(p.name) },
                        supportingContent = { Text(p.host, maxLines = 1, overflow = TextOverflow.Ellipsis) },
                        leadingContent = {
                            RadioButton(selected = p.id == current?.id, onClick = { store.currentId = p.id; refresh(); pickProfile = false })
                        },
                        trailingContent = {
                            IconButton(onClick = { editing = p; pickProfile = false }) { Icon(Icons.Filled.Edit, "Изменить") }
                        },
                        modifier = Modifier.clickable { store.currentId = p.id; refresh(); pickProfile = false },
                    )
                }
                TextButton(onClick = { creating = true; pickProfile = false }, modifier = Modifier.padding(horizontal = 16.dp)) {
                    Icon(Icons.Filled.Add, null)
                    Spacer(Modifier.width(8.dp))
                    Text("Добавить сервер")
                }
            }
        }
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

@Composable
private fun ProfileCard(p: Profile?, enabled: Boolean, onClick: () -> Unit) {
    Card(
        onClick = onClick,
        enabled = enabled,
        modifier = Modifier.fillMaxWidth(),
        colors = CardDefaults.cardColors(
            containerColor = MaterialTheme.colorScheme.surfaceContainerHigh,
            disabledContainerColor = MaterialTheme.colorScheme.surfaceContainerHigh,
            disabledContentColor = MaterialTheme.colorScheme.onSurface,
        ),
    ) {
        Row(Modifier.padding(16.dp), verticalAlignment = Alignment.CenterVertically) {
            Column(Modifier.weight(1f)) {
                Text("Сервер", style = MaterialTheme.typography.labelMedium, color = MaterialTheme.colorScheme.onSurfaceVariant)
                Text(p?.name ?: "Добавьте ссылку wdtt://", style = MaterialTheme.typography.titleMedium)
                if (p != null && p.host.isNotEmpty()) {
                    Text(p.host, style = MaterialTheme.typography.bodySmall, color = MaterialTheme.colorScheme.onSurfaceVariant)
                }
            }
            if (enabled) Icon(if (p == null) Icons.Filled.Add else Icons.Filled.KeyboardArrowDown, null)
        }
    }
}

@Composable
private fun ConnectButton(state: String, enabled: Boolean, onClick: () -> Unit) {
    val scheme = MaterialTheme.colorScheme
    val busy = state == "connecting" || state == "captcha"
    val bg by animateColorAsState(
        when (state) {
            "connected" -> Green
            "connecting", "captcha" -> scheme.tertiaryContainer
            else -> scheme.primary
        },
        label = "bg",
    )
    val fg = when (state) {
        "connected" -> Color.White
        "connecting", "captcha" -> scheme.onTertiaryContainer
        else -> scheme.onPrimary
    }
    Box(Modifier.size(196.dp), contentAlignment = Alignment.Center) {
        if (busy) CircularProgressIndicator(Modifier.size(196.dp), strokeWidth = 4.dp)
        Surface(
            onClick = onClick,
            enabled = enabled,
            shape = CircleShape,
            color = bg,
            contentColor = fg,
            shadowElevation = 6.dp,
            modifier = Modifier.size(172.dp),
        ) {
            Box(contentAlignment = Alignment.Center) {
                Text(
                    when (state) {
                        "connected" -> "Отключить"
                        "connecting" -> "Отмена"
                        "captcha" -> "Отмена"
                        else -> "Подключить"
                    },
                    style = MaterialTheme.typography.titleLarge,
                    fontWeight = FontWeight.SemiBold,
                )
            }
        }
    }
}

@Composable
private fun StateLine(s: Status, now: Long) {
    val text = when (s.state) {
        "connected" -> {
            val sec = if (s.since > 0) (now / 1000 - s.since).coerceAtLeast(0) else 0
            "Подключено · " + "%d:%02d:%02d".format(sec / 3600, sec / 60 % 60, sec % 60)
        }
        "connecting" -> if (s.target > 0) "Подключение… маршрутов ${s.sessions} из ${s.target}" else "Подключение…"
        "captcha" -> "Ждём проверку VK"
        "failed" -> "Ошибка"
        else -> "Отключено"
    }
    Text(
        text,
        style = MaterialTheme.typography.titleMedium,
        color = if (s.state == "connected") Green else MaterialTheme.colorScheme.onSurface,
    )
}

@Composable
private fun Banner(title: String, text: String, action: String? = null, error: Boolean = false, onAction: () -> Unit = {}) {
    val scheme = MaterialTheme.colorScheme
    Card(
        Modifier.fillMaxWidth(),
        colors = CardDefaults.cardColors(
            containerColor = if (error) scheme.errorContainer else scheme.tertiaryContainer,
            contentColor = if (error) scheme.onErrorContainer else scheme.onTertiaryContainer,
        ),
    ) {
        Row(Modifier.padding(16.dp), verticalAlignment = Alignment.CenterVertically) {
            Icon(Icons.Filled.Warning, null)
            Spacer(Modifier.width(12.dp))
            Column(Modifier.weight(1f)) {
                Text(title, style = MaterialTheme.typography.titleSmall)
                Text(text, style = MaterialTheme.typography.bodySmall)
            }
            if (action != null) {
                Spacer(Modifier.width(8.dp))
                Button(onClick = onAction) { Text(action) }
            }
        }
    }
}

@Composable
private fun Tile(label: String, value: String, modifier: Modifier, hint: String? = null) {
    Card(modifier, colors = CardDefaults.cardColors(containerColor = MaterialTheme.colorScheme.surfaceContainer)) {
        Column(Modifier.padding(14.dp)) {
            Text(label, style = MaterialTheme.typography.labelMedium, color = MaterialTheme.colorScheme.onSurfaceVariant)
            Text(value, style = MaterialTheme.typography.headlineSmall, fontWeight = FontWeight.Medium, maxLines = 1)
            if (hint != null) Text(hint, style = MaterialTheme.typography.labelSmall, color = MaterialTheme.colorScheme.onSurfaceVariant)
        }
    }
}

@Composable
private fun Details(s: Status) {
    Card(Modifier.fillMaxWidth(), colors = CardDefaults.cardColors(containerColor = MaterialTheme.colorScheme.surfaceContainer)) {
        Column(Modifier.padding(14.dp), verticalArrangement = Arrangement.spacedBy(6.dp)) {
            DetailRow("Протокол", when (s.protocol) {
                "direct" -> "прямой (сервер TurnVK)"
                "dtls" -> "DTLS (стандартный сервер)"
                else -> "определяется…"
            })
            if (s.address.isNotEmpty()) DetailRow("Адрес в VPN", s.address.substringBefore('/'))
            DetailRow("Трафик", "↓ ${bytes(s.rxBytes)} · ↑ ${bytes(s.txBytes)}")
            if (s.reconnects > 0) DetailRow("Замен маршрутов", s.reconnects.toString())
        }
    }
}

@Composable
private fun DetailRow(k: String, v: String) {
    Row {
        Text(k, style = MaterialTheme.typography.bodyMedium, color = MaterialTheme.colorScheme.onSurfaceVariant, modifier = Modifier.weight(1f))
        Text(v, style = MaterialTheme.typography.bodyMedium)
    }
}

@Composable
private fun Routes(paths: List<PathInfo>) {
    var open by remember { mutableStateOf(false) }
    Card(Modifier.fillMaxWidth().animateContentSize(), colors = CardDefaults.cardColors(containerColor = MaterialTheme.colorScheme.surfaceContainer)) {
        Row(
            Modifier.fillMaxWidth().clickable { open = !open }.padding(14.dp),
            verticalAlignment = Alignment.CenterVertically,
        ) {
            val alive = paths.count { it.fresh }
            Text("Маршруты через VK: $alive в работе", style = MaterialTheme.typography.titleSmall, modifier = Modifier.weight(1f))
            Icon(if (open) Icons.Filled.KeyboardArrowUp else Icons.Filled.KeyboardArrowDown, null)
        }
        if (open) {
            HorizontalDivider()
            Column(Modifier.padding(horizontal = 14.dp, vertical = 8.dp), verticalArrangement = Arrangement.spacedBy(6.dp)) {
                paths.forEach { p ->
                    Row(verticalAlignment = Alignment.CenterVertically) {
                        Box(
                            Modifier.size(8.dp).clip(CircleShape)
                                .background(if (p.fresh) Green else MaterialTheme.colorScheme.error),
                        )
                        Spacer(Modifier.width(10.dp))
                        Text("№${p.id + 1}", style = MaterialTheme.typography.bodySmall, modifier = Modifier.width(40.dp))
                        Text(p.server.substringBefore(':'), style = MaterialTheme.typography.bodySmall, fontFamily = FontFamily.Monospace, modifier = Modifier.weight(1f))
                        Text("↓${bytes(p.rx)}", style = MaterialTheme.typography.bodySmall, modifier = Modifier.width(72.dp), textAlign = TextAlign.End)
                        Text(if (p.rttMs > 0) "${p.rttMs} мс" else "—", style = MaterialTheme.typography.bodySmall, modifier = Modifier.width(56.dp), textAlign = TextAlign.End)
                    }
                }
            }
        }
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
        title = { Text(if (isNew) "Новый сервер" else "Сервер") },
        text = {
            Column(verticalArrangement = Arrangement.spacedBy(8.dp)) {
                OutlinedTextField(
                    value = name,
                    onValueChange = { name = it },
                    label = { Text("Название") },
                    singleLine = true,
                    modifier = Modifier.fillMaxWidth(),
                )
                OutlinedTextField(
                    value = link,
                    onValueChange = { link = it.trim() },
                    label = { Text("Ссылка wdtt://") },
                    singleLine = true,
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
                    Text(
                        "В ссылке пароль подключения: делитесь ею только с теми, кому доверяете.",
                        style = MaterialTheme.typography.bodySmall,
                        color = MaterialTheme.colorScheme.onSurfaceVariant,
                    )
                }
            }
        },
        confirmButton = {
            TextButton(enabled = ok, onClick = {
                onSave(initial.copy(name = name.ifBlank { defaultName(link) }, link = link))
            }) { Text("Сохранить") }
        },
        dismissButton = { TextButton(onClick = onDismiss) { Text("Отмена") } },
    )
    if (confirmDelete && onDelete != null) {
        AlertDialog(
            onDismissRequest = { confirmDelete = false },
            title = { Text("Удалить «${initial.name}»?") },
            text = { Text("Ссылка удалится с телефона. Если она понадобится снова, её придётся вставить заново.") },
            confirmButton = { TextButton(onClick = { confirmDelete = false; onDelete() }) { Text("Удалить") } },
            dismissButton = { TextButton(onClick = { confirmDelete = false }) { Text("Отмена") } },
        )
    }
}

// ---------------------------------------------------------------- settings

@Composable
private fun SettingsScreen(store: Store, revision: Int, refresh: () -> Unit, onBack: () -> Unit, onApps: () -> Unit) {
    val ctx = LocalContext.current
    val status by TunnelState.status.collectAsState()
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

    Scaffold(
        topBar = {
            TopAppBar(
                title = { Text("Настройки") },
                navigationIcon = { IconButton(onClick = onBack) { Icon(Icons.AutoMirrored.Filled.ArrowBack, "Назад") } },
            )
        },
    ) { pad ->
        Column(Modifier.fillMaxSize().padding(pad).verticalScroll(rememberScrollState())) {
            if (status.active) {
                Text(
                    "Изменения применятся при следующем подключении.",
                    style = MaterialTheme.typography.bodySmall,
                    color = MaterialTheme.colorScheme.onSurfaceVariant,
                    modifier = Modifier.padding(horizontal = 16.dp, vertical = 4.dp),
                )
            }
            Section("Подключение")
            Column(Modifier.padding(horizontal = 16.dp)) {
                Text("Маршрутов через VK: ${sessions.toInt()}", style = MaterialTheme.typography.bodyLarge)
                Slider(
                    value = sessions,
                    onValueChange = { sessions = it },
                    onValueChangeFinished = { store.sessions = sessions.toInt(); refresh() },
                    valueRange = 8f..64f,
                    steps = 6,
                )
                Text(
                    "VK пропускает по каждому маршруту около 1,5 Мбит/с: больше маршрутов — выше скорость и устойчивость. 16 маршрутов — около 25 Мбит/с, 32 — около 45. Больше 16 маршрутов VK даёт одному гостю звонка, поэтому дальше нужен второй гость, а с ним иногда ещё одна проверка VK в сутки.",
                    style = MaterialTheme.typography.bodySmall,
                    color = MaterialTheme.colorScheme.onSurfaceVariant,
                )
                Spacer(Modifier.height(16.dp))
                Text("Маскировка трафика", style = MaterialTheme.typography.bodyLarge)
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
            }
            SwitchRow(
                title = "Автокапча",
                text = "Пытаться пройти проверку VK без вас",
                checked = captchaAuto,
                onChange = { captchaAuto = it; store.captchaAuto = it; refresh() },
            )

            Section("Приложения")
            ClickRow(
                title = "Приложения в обход VPN",
                text = (if (excluded > 0) "Выбрано: $excluded. " else "") + "Приложения VK всегда идут в обход, чтобы звонки работали.",
                onClick = onApps,
            )

            Section("Запуск и работа в фоне")
            SwitchRow(
                title = "Подключаться при включении телефона",
                text = "К выбранному серверу, если VPN уже разрешён",
                checked = boot,
                onChange = { boot = it; store.bootConnect = it; refresh() },
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

            Section("О приложении")
            Text(
                "TurnVK ${BuildConfig.VERSION_NAME}. Трафик идёт только через серверы звонков VK (TURN) и шифруется WireGuard внутри маскировки под RTP.",
                style = MaterialTheme.typography.bodySmall,
                color = MaterialTheme.colorScheme.onSurfaceVariant,
                modifier = Modifier.padding(16.dp),
            )
            Spacer(Modifier.navigationBarsPadding())
        }
    }
}

@Composable
private fun Section(title: String) {
    Text(
        title,
        style = MaterialTheme.typography.labelLarge,
        color = MaterialTheme.colorScheme.primary,
        modifier = Modifier.padding(start = 16.dp, end = 16.dp, top = 24.dp, bottom = 8.dp),
    )
}

@Composable
private fun SwitchRow(title: String, text: String, checked: Boolean, onChange: (Boolean) -> Unit) {
    ListItem(
        headlineContent = { Text(title) },
        supportingContent = { Text(text) },
        trailingContent = { Switch(checked = checked, onCheckedChange = onChange) },
        modifier = Modifier.clickable { onChange(!checked) },
    )
}

@Composable
private fun ClickRow(title: String, text: String, warn: Boolean = false, onClick: () -> Unit) {
    ListItem(
        headlineContent = { Text(title) },
        supportingContent = { Text(text, color = if (warn) MaterialTheme.colorScheme.error else MaterialTheme.colorScheme.onSurfaceVariant) },
        modifier = Modifier.clickable(onClick = onClick),
    )
}

// ---------------------------------------------------------------- logs

@Composable
private fun LogsScreen(onBack: () -> Unit) {
    val ctx = LocalContext.current
    val log by TunnelState.log.collectAsState()
    val listState = rememberLazyListState()
    LaunchedEffect(log.size) { if (log.isNotEmpty()) listState.scrollToItem(log.size - 1) }
    Scaffold(
        topBar = {
            TopAppBar(
                title = { Text("Журнал") },
                navigationIcon = { IconButton(onClick = onBack) { Icon(Icons.AutoMirrored.Filled.ArrowBack, "Назад") } },
                actions = {
                    TextButton(onClick = {
                        ctx.getSystemService(ClipboardManager::class.java)
                            .setPrimaryClip(ClipData.newPlainText("TurnVK", log.joinToString("\n")))
                    }) { Text("Копировать") }
                    IconButton(onClick = {
                        val send = Intent(Intent.ACTION_SEND).setType("text/plain").putExtra(Intent.EXTRA_TEXT, log.joinToString("\n"))
                        ctx.startActivity(Intent.createChooser(send, "Журнал TurnVK"))
                    }) { Icon(Icons.Filled.Share, "Поделиться") }
                    IconButton(onClick = { TunnelState.clearLog() }) { Icon(Icons.Filled.Delete, "Очистить") }
                },
            )
        },
    ) { pad ->
        if (log.isEmpty()) {
            Box(Modifier.fillMaxSize().padding(pad), contentAlignment = Alignment.Center) {
                Text("Пока пусто", color = MaterialTheme.colorScheme.onSurfaceVariant)
            }
        } else {
            LazyColumn(
                Modifier.fillMaxSize().padding(pad),
                state = listState,
                contentPadding = PaddingValues(horizontal = 12.dp, vertical = 8.dp),
            ) {
                items(log) { Text(it, fontFamily = FontFamily.Monospace, fontSize = 11.sp, lineHeight = 15.sp) }
            }
        }
    }
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
        topBar = {
            TopAppBar(
                title = { Text("В обход VPN") },
                navigationIcon = { IconButton(onClick = onBack) { Icon(Icons.AutoMirrored.Filled.ArrowBack, "Назад") } },
                actions = { if (selected.isNotEmpty()) TextButton(onClick = { save(emptySet()) }) { Text("Сбросить") } },
            )
        },
    ) { pad ->
        Column(Modifier.fillMaxSize().padding(pad)) {
            Text(
                "Отмеченные приложения ходят в интернет напрямую, без VPN: например, банки или сервисы, которым нужен ваш обычный адрес.",
                style = MaterialTheme.typography.bodySmall,
                color = MaterialTheme.colorScheme.onSurfaceVariant,
                modifier = Modifier.padding(horizontal = 16.dp),
            )
            OutlinedTextField(
                value = query,
                onValueChange = { query = it },
                leadingIcon = { Icon(Icons.Filled.Search, null) },
                placeholder = { Text("Поиск") },
                singleLine = true,
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

/** Bytes per second as bits per second, the way speed tests show it. */
private fun rate(bps: Long): String {
    val bits = bps * 8.0
    return when {
        bits >= 1e6 -> "%.1f Мбит/с".format(bits / 1e6)
        bits >= 1e3 -> "%.0f Кбит/с".format(bits / 1e3)
        else -> "0 Кбит/с"
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
        "vpn" in l && "разрешение" in l -> e
        else -> e
    }
}
