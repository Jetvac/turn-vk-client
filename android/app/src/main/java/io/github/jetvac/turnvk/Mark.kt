package io.github.jetvac.turnvk

import android.content.Context
import android.os.Handler
import android.os.Looper
import android.widget.Toast
import androidx.compose.foundation.layout.Arrangement
import androidx.compose.foundation.layout.Column
import androidx.compose.foundation.layout.fillMaxWidth
import androidx.compose.foundation.shape.RoundedCornerShape
import androidx.compose.material3.AlertDialog
import androidx.compose.material3.OutlinedButton
import androidx.compose.material3.OutlinedTextField
import androidx.compose.material3.Text
import androidx.compose.material3.TextButton
import androidx.compose.runtime.Composable
import androidx.compose.runtime.getValue
import androidx.compose.runtime.mutableStateOf
import androidx.compose.runtime.remember
import androidx.compose.runtime.setValue
import androidx.compose.ui.Modifier
import androidx.compose.ui.platform.LocalContext
import androidx.compose.ui.text.font.FontWeight
import androidx.compose.ui.unit.dp
import androidx.compose.ui.unit.sp

/**
 * "Something is wrong right now": the user marks the moment, and the
 * engine sends it with the connection's state in the next statistics
 * report, so the developer sees exactly when it happened.
 */
object Marker {
    /** Marks the moment (note: what is wrong, may be empty); off the main thread. */
    fun mark(ctx: Context, note: String) {
        val app = ctx.applicationContext
        val stats = Store(app).serverStats
        Thread {
            val line = runCatching { mobile.Mobile.mark(note) }.getOrNull() ?: return@Thread
            TunnelState.log(line)
            Handler(Looper.getMainLooper()).post {
                Toast.makeText(
                    app,
                    if (stats) "Отмечено: разработчик увидит этот момент" else "Отмечено в журнале (статистика выключена)",
                    Toast.LENGTH_SHORT,
                ).show()
            }
        }.start()
    }
}

@Composable
internal fun MarkButton() {
    val ctx = LocalContext.current
    var open by remember { mutableStateOf(false) }
    var note by remember { mutableStateOf("") }
    OutlinedButton(onClick = { note = ""; open = true }, modifier = Modifier.fillMaxWidth(), shape = RoundedCornerShape(12.dp)) {
        Text("Сейчас что-то не так")
    }
    if (open) {
        AlertDialog(
            onDismissRequest = { open = false },
            containerColor = pal.card,
            shape = RoundedCornerShape(20.dp),
            title = { Text("Что-то не так?", fontWeight = FontWeight.SemiBold) },
            text = {
                Column(verticalArrangement = Arrangement.spacedBy(8.dp)) {
                    Text(
                        "TurnVK отметит этот момент: время и состояние подключения уйдут разработчику со статистикой, " +
                            "и будет видно, что происходило именно тогда. Отмечайте сразу, как заметили. " +
                            "То же есть в уведомлении TurnVK.",
                        fontSize = 13.5.sp,
                        color = pal.muted,
                    )
                    OutlinedTextField(
                        value = note,
                        onValueChange = { note = it.take(200) },
                        label = { Text("Что не работает (необязательно)") },
                        placeholder = { Text("Например: Telegram не грузит") },
                        singleLine = true,
                        shape = RoundedCornerShape(10.dp),
                        modifier = Modifier.fillMaxWidth(),
                    )
                }
            },
            confirmButton = { TextButton(onClick = { open = false; Marker.mark(ctx, note) }) { Text("Отметить") } },
            dismissButton = { TextButton(onClick = { open = false }) { Text("Отмена") } },
        )
    }
}
