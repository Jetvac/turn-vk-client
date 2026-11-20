@file:OptIn(ExperimentalMaterial3Api::class)

package io.github.jetvac.turnvk

import androidx.compose.foundation.background
import androidx.compose.foundation.layout.Column
import androidx.compose.foundation.layout.Row
import androidx.compose.foundation.layout.Spacer
import androidx.compose.foundation.layout.fillMaxWidth
import androidx.compose.foundation.layout.height
import androidx.compose.foundation.layout.padding
import androidx.compose.foundation.layout.size
import androidx.compose.foundation.layout.width
import androidx.compose.foundation.shape.RoundedCornerShape
import androidx.compose.material.icons.Icons
import androidx.compose.material.icons.automirrored.filled.KeyboardArrowRight
import androidx.compose.material3.ExperimentalMaterial3Api
import androidx.compose.material3.Icon
import androidx.compose.material3.SegmentedButton
import androidx.compose.material3.SegmentedButtonDefaults
import androidx.compose.material3.SingleChoiceSegmentedButtonRow
import androidx.compose.material3.Surface
import androidx.compose.material3.Text
import androidx.compose.runtime.Composable
import androidx.compose.ui.Alignment
import androidx.compose.ui.Modifier
import androidx.compose.ui.draw.clip
import androidx.compose.ui.res.painterResource
import androidx.compose.ui.text.font.FontWeight
import androidx.compose.ui.text.style.TextOverflow
import androidx.compose.ui.unit.dp
import androidx.compose.ui.unit.sp

/**
 * Power modes (engine.Power*). Balanced and the saver let an idle tunnel
 * doze on a few routes that ping together every 25 s; "always" never
 * dozes and keeps Wi-Fi out of power saving while connected.
 */
object Power {
    const val SAVER = "saver"
    const val BALANCED = "balanced"
    const val ALWAYS = "always"

    val all = listOf(SAVER, BALANCED, ALWAYS)

    fun label(mode: String): String = when (mode) {
        SAVER -> "Экономия"
        ALWAYS -> "Всегда на связи"
        else -> "Баланс"
    }

    /** What the mode does, for the settings. */
    fun describe(mode: String): String = when (mode) {
        SAVER -> "Через 30 секунд без трафика остаются 2 маршрута, они проверяют связь раз в 25 секунд, а телефон и радио спят. Wi-Fi всегда в режиме энергосбережения. Заряд держится дольше всего, но пинг в играх может прыгать, а после простоя первые 1–2 секунды уходят на возврат маршрутов."
        ALWAYS -> "Туннель не засыпает: все маршруты всё время наготове, Wi-Fi без энергосбережения, пока VPN включён. Нет задержки после простоя, но заряд уходит заметно быстрее, особенно ночью и с выключенным экраном."
        else -> "Через 1,5 минуты без трафика остаются 4 маршрута, они проверяют связь раз в 25 секунд, и телефон может спать. Как только появляется трафик, все маршруты возвращаются за 1–2 секунды. Пока трафик идёт, Wi-Fi работает без энергосбережения, чтобы пинг был ровным."
    }

    /** One line for the main screen. */
    fun short(mode: String): String = when (mode) {
        SAVER -> "Засыпает через 30 с без трафика, 2 маршрута"
        ALWAYS -> "Не засыпает: быстрее отклик, выше расход"
        else -> "Засыпает через 1,5 мин без трафика, 4 маршрута"
    }
}

/** The settings' choice of power mode. */
@Composable
internal fun PowerPanel(mode: String, batteryOk: Boolean, onChange: (String) -> Unit) {
    Panel {
        Column {
            SectionTitle("Энергосбережение", Modifier.padding(bottom = 10.dp))
            Text(
                "Когда трафика нет, TurnVK может «задремать»: оставить несколько маршрутов и реже будить телефон. Это сильно экономит заряд, но первый трафик после простоя ждёт возврата маршрутов.",
                fontSize = 12.5.sp, color = pal.muted, lineHeight = 17.sp,
            )
            Spacer(Modifier.height(10.dp))
            SingleChoiceSegmentedButtonRow(Modifier.fillMaxWidth()) {
                Power.all.forEachIndexed { i, m ->
                    SegmentedButton(
                        selected = mode == m,
                        onClick = { onChange(m) },
                        shape = SegmentedButtonDefaults.itemShape(i, Power.all.size),
                        icon = {},
                    ) {
                        Text(if (m == Power.ALWAYS) "Всегда" else Power.label(m), maxLines = 1, fontSize = 13.sp)
                    }
                }
            }
            Spacer(Modifier.height(10.dp))
            Text(Power.label(mode), fontWeight = FontWeight.SemiBold)
            Text(Power.describe(mode), fontSize = 12.5.sp, color = pal.muted, lineHeight = 17.sp)
            if (mode == Power.ALWAYS && !batteryOk) {
                Spacer(Modifier.height(8.dp))
                Text(
                    "Android всё ещё может усыплять TurnVK: разрешите работу в фоне в пункте «Экономия заряда» ниже.",
                    fontSize = 12.5.sp, color = pal.warn, lineHeight = 17.sp,
                )
            }
        }
    }
}

/**
 * The main screen's line about the power mode: what it does now (the
 * tunnel dozing or not) and that it is set in the settings.
 */
@Composable
internal fun PowerRow(mode: String, running: String?, s: Status, onClick: () -> Unit) {
    val dozing = s.state == "connected" && s.quiet
    val title = if (dozing) "Простой · экономия заряда" else "Энергосбережение: ${Power.label(mode)}"
    val text = when {
        running != null && running != mode -> "Режим «${Power.label(mode)}» включится после переподключения"
        dozing -> "Трафика нет: работает маршрутов: ${s.sessions}, телефон спит. Трафик вернёт все маршруты за 1–2 с. Не засыпать — в настройках."
        else -> Power.short(mode)
    }
    Surface(onClick = onClick, modifier = Modifier.fillMaxWidth(), shape = RoundedCornerShape(14.dp), color = pal.card, shadowElevation = 1.dp) {
        Row(Modifier.padding(horizontal = 14.dp, vertical = 12.dp), verticalAlignment = Alignment.CenterVertically) {
            Box40(if (dozing) pal.okSoft else pal.accentSoft) {
                Icon(painterResource(R.drawable.ic_battery), null, Modifier.size(20.dp), tint = if (dozing) pal.ok else pal.accent)
            }
            Spacer(Modifier.width(12.dp))
            Column(Modifier.weight(1f)) {
                Text(title, fontWeight = FontWeight.SemiBold, maxLines = 1, overflow = TextOverflow.Ellipsis)
                Text(text, fontSize = 12.5.sp, color = pal.muted, lineHeight = 16.sp, maxLines = 3, overflow = TextOverflow.Ellipsis)
            }
            Icon(Icons.AutoMirrored.Filled.KeyboardArrowRight, null, tint = pal.faint)
        }
    }
}

@Composable
private fun Box40(bg: androidx.compose.ui.graphics.Color, content: @Composable () -> Unit) {
    androidx.compose.foundation.layout.Box(
        Modifier.size(40.dp).clip(RoundedCornerShape(11.dp)).background(bg),
        contentAlignment = Alignment.Center,
    ) { content() }
}
