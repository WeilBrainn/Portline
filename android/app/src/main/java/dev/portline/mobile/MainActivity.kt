package dev.portline.mobile

import android.Manifest
import android.app.Activity
import android.content.Intent
import android.content.pm.PackageManager
import android.graphics.Color
import android.graphics.Typeface
import android.graphics.drawable.GradientDrawable
import android.net.Uri
import android.net.VpnService
import android.os.Build
import android.os.Bundle
import android.os.Handler
import android.os.Looper
import android.provider.Settings
import android.view.Gravity
import android.view.View
import android.view.ViewGroup
import android.widget.Button
import android.widget.EditText
import android.widget.LinearLayout
import android.widget.ScrollView
import android.widget.TextView
import org.json.JSONObject
import java.net.HttpURLConnection
import java.net.URL

class MainActivity : Activity() {
    companion object {
        private const val APP_VERSION = "1.4.0"
        private const val REQ_VPN = 1
        private const val REQ_IMPORT = 2
        private const val REQ_NOTIFY = 3
    }

    private lateinit var statusDot: View
    private lateinit var statusTitle: TextView
    private lateinit var statusSub: TextView
    private lateinit var endpointLabel: TextView
    private lateinit var heroCard: LinearLayout
    private lateinit var metricLatency: TextView
    private lateinit var metricSent: TextView
    private lateinit var metricRecv: TextView
    private lateinit var metricUptime: TextView
    private lateinit var primaryBtn: Button
    private lateinit var leakCheckBtn: Button
    private lateinit var profileSummary: TextView
    private lateinit var pasteBox: LinearLayout
    private lateinit var input: EditText
    private lateinit var updateBtn: TextView

    private var pendingProfile = ""
    private val uiHandler = Handler(Looper.getMainLooper())
    private val pollRunnable = object : Runnable {
        override fun run() {
            renderSnapshot(PortlineVpnService.snapshot())
            uiHandler.postDelayed(this, 650)
        }
    }

    private fun dp(n: Int): Int = (resources.displayMetrics.density * n).toInt()

    private fun roundedBox(fill: Int, stroke: Int, radiusDp: Int = 14, strokeDp: Int = 1): GradientDrawable {
        return GradientDrawable().apply {
            setColor(fill)
            cornerRadius = dp(radiusDp).toFloat()
            if (stroke != Color.TRANSPARENT) {
                setStroke(dp(strokeDp), stroke)
            }
        }
    }

    override fun onCreate(savedInstanceState: Bundle?) {
        super.onCreate(savedInstanceState)

        val bg = 0xff080d18.toInt()
        val cardBg = 0xff0f172a.toInt()
        val cardBorder = 0xff1e293b.toInt()
        val textPrimary = 0xfff8fafc.toInt()
        val textMuted = 0xff94a3b8.toInt()
        val textSubtle = 0xff64748b.toInt()
        val accent = 0xff38bdf8.toInt()

        window.statusBarColor = bg
        window.navigationBarColor = bg

        val root = LinearLayout(this).apply {
            orientation = LinearLayout.VERTICAL
            setPadding(dp(20), dp(22), dp(20), dp(22))
            setBackgroundColor(bg)
        }

        // Top header
        val header = LinearLayout(this).apply {
            orientation = LinearLayout.HORIZONTAL
            gravity = Gravity.CENTER_VERTICAL
            setPadding(0, 0, 0, dp(18))
        }
        val brandCol = LinearLayout(this).apply {
            orientation = LinearLayout.VERTICAL
            layoutParams = LinearLayout.LayoutParams(0, ViewGroup.LayoutParams.WRAP_CONTENT, 1f)
        }
        brandCol.addView(TextView(this).apply {
            text = "PORTLINE"
            textSize = 19f
            typeface = Typeface.DEFAULT_BOLD
            setTextColor(textPrimary)
            letterSpacing = 0.06f
        })
        brandCol.addView(TextView(this).apply {
            text = "v$APP_VERSION · Full-Tunnel VPN"
            textSize = 11f
            typeface = Typeface.MONOSPACE
            setTextColor(accent)
        })
        header.addView(brandCol)

        updateBtn = TextView(this).apply {
            text = "Обновления"
            textSize = 12f
            typeface = Typeface.DEFAULT_BOLD
            setTextColor(0xffbae6fd.toInt())
            background = roundedBox(0xff13253d.toInt(), 0xff284b73.toInt(), 99)
            setPadding(dp(12), dp(7), dp(12), dp(7))
            setOnClickListener { checkUpdates() }
        }
        header.addView(updateBtn)
        root.addView(header)

        // Hero Connection Card
        heroCard = LinearLayout(this).apply {
            orientation = LinearLayout.VERTICAL
            background = roundedBox(cardBg, cardBorder, 18)
            setPadding(dp(18), dp(18), dp(18), dp(18))
        }

        val statusRow = LinearLayout(this).apply {
            orientation = LinearLayout.HORIZONTAL
            gravity = Gravity.CENTER_VERTICAL
        }
        statusDot = View(this).apply {
            background = roundedBox(textSubtle, Color.TRANSPARENT, 99)
        }
        statusRow.addView(statusDot, LinearLayout.LayoutParams(dp(10), dp(10)).apply {
            rightMargin = dp(10)
        })
        statusTitle = TextView(this).apply {
            text = "VPN отключён"
            textSize = 20f
            typeface = Typeface.DEFAULT_BOLD
            setTextColor(textPrimary)
        }
        statusRow.addView(statusTitle)
        heroCard.addView(statusRow)

        statusSub = TextView(this).apply {
            text = "Весь IPv4-трафик и DNS через защищённый туннель"
            textSize = 13f
            setTextColor(textMuted)
            setPadding(0, dp(6), 0, dp(4))
        }
        heroCard.addView(statusSub)

        endpointLabel = TextView(this).apply {
            text = "Сервер не выбран"
            textSize = 12f
            typeface = Typeface.MONOSPACE
            setTextColor(accent)
            setPadding(0, 0, 0, dp(12))
        }
        heroCard.addView(endpointLabel)

        // Shield pills
        val pillsRow = LinearLayout(this).apply {
            orientation = LinearLayout.HORIZONTAL
            setPadding(0, 0, 0, dp(14))
        }
        for (pillText in listOf("0.0.0.0/0 → VPS", "DNS 1.1.1.1", "IPv6 Blocked")) {
            val pill = TextView(this).apply {
                text = pillText
                textSize = 10f
                typeface = Typeface.MONOSPACE
                setTextColor(0xffcbd5e1.toInt())
                background = roundedBox(0xff172338.toInt(), 0xff29384f.toInt(), 99)
                setPadding(dp(9), dp(4), dp(9), dp(4))
            }
            pillsRow.addView(pill, LinearLayout.LayoutParams(ViewGroup.LayoutParams.WRAP_CONTENT, ViewGroup.LayoutParams.WRAP_CONTENT).apply {
                rightMargin = dp(6)
            })
        }
        heroCard.addView(pillsRow)

        // Telemetry grid (4 columns)
        val telemetryRow = LinearLayout(this).apply {
            orientation = LinearLayout.HORIZONTAL
            setPadding(0, 0, 0, dp(16))
        }
        fun metricCell(label: String): Pair<LinearLayout, TextView> {
            val cell = LinearLayout(this).apply {
                orientation = LinearLayout.VERTICAL
                background = roundedBox(0xff0b1222.toInt(), 0xff1e293b.toInt(), 11)
                setPadding(dp(8), dp(9), dp(8), dp(9))
            }
            cell.addView(TextView(this).apply {
                text = label
                textSize = 10f
                setTextColor(textSubtle)
            })
            val valView = TextView(this).apply {
                text = "—"
                textSize = 13f
                typeface = Typeface.MONOSPACE
                setTextColor(textPrimary)
                setPadding(0, dp(2), 0, 0)
            }
            cell.addView(valView)
            return cell to valView
        }
        val (c1, v1) = metricCell("Пинг"); metricLatency = v1
        val (c2, v2) = metricCell("Отпр."); metricSent = v2
        val (c3, v3) = metricCell("Получ."); metricRecv = v3
        val (c4, v4) = metricCell("Время"); metricUptime = v4
        listOf(c1, c2, c3, c4).forEachIndexed { idx, cell ->
            telemetryRow.addView(cell, LinearLayout.LayoutParams(0, ViewGroup.LayoutParams.WRAP_CONTENT, 1f).apply {
                if (idx < 3) rightMargin = dp(6)
            })
        }
        heroCard.addView(telemetryRow)

        primaryBtn = Button(this).apply {
            text = "Подключить VPN"
            isAllCaps = false
            textSize = 15f
            typeface = Typeface.DEFAULT_BOLD
            setTextColor(0xff061523.toInt())
            background = roundedBox(accent, Color.TRANSPARENT, 12)
            stateListAnimator = null
            setOnClickListener { onPrimaryAction() }
        }
        heroCard.addView(primaryBtn, LinearLayout.LayoutParams(ViewGroup.LayoutParams.MATCH_PARENT, dp(48)))

        leakCheckBtn = Button(this).apply {
            text = "Проверить IP / DNS ↗"
            isAllCaps = false
            textSize = 13f
            setTextColor(0xffbae6fd.toInt())
            background = roundedBox(0xff13253d.toInt(), 0xff284b73.toInt(), 10)
            stateListAnimator = null
            visibility = View.GONE
            setOnClickListener {
                startActivity(Intent(Intent.ACTION_VIEW, Uri.parse("https://browserleaks.com/ip")))
            }
        }
        heroCard.addView(leakCheckBtn, LinearLayout.LayoutParams(ViewGroup.LayoutParams.MATCH_PARENT, dp(42)).apply {
            topMargin = dp(10)
        })

        root.addView(heroCard, LinearLayout.LayoutParams(ViewGroup.LayoutParams.MATCH_PARENT, ViewGroup.LayoutParams.WRAP_CONTENT).apply {
            bottomMargin = dp(16)
        })

        // Profile Card
        val profileCard = LinearLayout(this).apply {
            orientation = LinearLayout.VERTICAL
            background = roundedBox(cardBg, cardBorder, 16)
            setPadding(dp(16), dp(16), dp(16), dp(16))
        }
        profileCard.addView(TextView(this).apply {
            text = "ПРОФИЛЬ ПОДКЛЮЧЕНИЯ"
            textSize = 10f
            typeface = Typeface.MONOSPACE
            setTextColor(accent)
        })
        profileSummary = TextView(this).apply {
            text = "Профиль ещё не загружен"
            textSize = 13f
            setTextColor(textPrimary)
            setPadding(0, dp(6), 0, dp(12))
        }
        profileCard.addView(profileSummary)

        val profileActions = LinearLayout(this).apply {
            orientation = LinearLayout.HORIZONTAL
        }
        val importBtn = Button(this).apply {
            text = "Импорт файла"
            isAllCaps = false
            textSize = 13f
            setTextColor(textPrimary)
            background = roundedBox(0xff172338.toInt(), 0xff334155.toInt(), 10)
            stateListAnimator = null
            setOnClickListener {
                startActivityForResult(Intent(Intent.ACTION_OPEN_DOCUMENT).apply {
                    addCategory(Intent.CATEGORY_OPENABLE)
                    type = "*/*"
                }, REQ_IMPORT)
            }
        }
        val togglePasteBtn = Button(this).apply {
            text = "Вставить Base64"
            isAllCaps = false
            textSize = 13f
            setTextColor(textPrimary)
            background = roundedBox(0xff172338.toInt(), 0xff334155.toInt(), 10)
            stateListAnimator = null
            setOnClickListener {
                pasteBox.visibility = if (pasteBox.visibility == View.VISIBLE) View.GONE else View.VISIBLE
            }
        }
        profileActions.addView(importBtn, LinearLayout.LayoutParams(0, dp(42), 1f).apply { rightMargin = dp(8) })
        profileActions.addView(togglePasteBtn, LinearLayout.LayoutParams(0, dp(42), 1f))
        profileCard.addView(profileActions)

        pasteBox = LinearLayout(this).apply {
            orientation = LinearLayout.VERTICAL
            visibility = View.GONE
            setPadding(0, dp(12), 0, 0)
        }
        input = EditText(this).apply {
            hint = "Вставь строку профиля Portline (Base64)"
            setHintTextColor(textSubtle)
            setTextColor(textPrimary)
            textSize = 12f
            typeface = Typeface.MONOSPACE
            minLines = 3
            maxLines = 5
            background = roundedBox(0xff080d18.toInt(), 0xff334155.toInt(), 10)
            setPadding(dp(12), dp(10), dp(12), dp(10))
        }
        pasteBox.addView(input, LinearLayout.LayoutParams(ViewGroup.LayoutParams.MATCH_PARENT, dp(96)))
        val saveBtn = Button(this).apply {
            text = "Сохранить в Android Keystore"
            isAllCaps = false
            textSize = 13f
            setTextColor(0xff061523.toInt())
            background = roundedBox(accent, Color.TRANSPARENT, 10)
            stateListAnimator = null
            setOnClickListener {
                try {
                    val raw = input.text.toString().trim()
                    val parsed = PortlineProfile.decode(raw)
                    ProfileVault.save(this@MainActivity, raw)
                    input.setText("")
                    pasteBox.visibility = View.GONE
                    refreshSavedProfile()
                    statusSub.text = "Профиль ${parsed.host}:${parsed.port} сохранён в Keystore"
                } catch (e: Exception) {
                    statusSub.text = "Ошибка профиля: ${e.message}"
                }
            }
        }
        pasteBox.addView(saveBtn, LinearLayout.LayoutParams(ViewGroup.LayoutParams.MATCH_PARENT, dp(42)).apply {
            topMargin = dp(8)
        })
        profileCard.addView(pasteBox)

        root.addView(profileCard, LinearLayout.LayoutParams(ViewGroup.LayoutParams.MATCH_PARENT, ViewGroup.LayoutParams.WRAP_CONTENT).apply {
            bottomMargin = dp(16)
        })

        // Android System VPN Tip Card
        val tipCard = LinearLayout(this).apply {
            orientation = LinearLayout.VERTICAL
            background = roundedBox(0xff0c1525.toInt(), 0xff1e293b.toInt(), 14)
            setPadding(dp(16), dp(14), dp(16), dp(14))
        }
        tipCard.addView(TextView(this).apply {
            text = "ЗАЩИТА ОТ УТЕЧЕК"
            textSize = 10f
            typeface = Typeface.MONOSPACE
            setTextColor(0xfffbbf24.toInt())
        })
        tipCard.addView(TextView(this).apply {
            text = "Для полной блокировки трафика при обрыве включи в настройках Android: Постоянный VPN (Always-on) и Блокировать без VPN."
            textSize = 12f
            setTextColor(textMuted)
            setPadding(0, dp(5), 0, dp(10))
        })
        tipCard.addView(Button(this).apply {
            text = "Открыть настройки VPN Android"
            isAllCaps = false
            textSize = 12f
            setTextColor(textPrimary)
            background = roundedBox(0xff172338.toInt(), 0xff334155.toInt(), 9)
            stateListAnimator = null
            setOnClickListener {
                try {
                    startActivity(Intent(Settings.ACTION_VPN_SETTINGS))
                } catch (_: Exception) {
                }
            }
        }, LinearLayout.LayoutParams(ViewGroup.LayoutParams.MATCH_PARENT, dp(38)))
        root.addView(tipCard, LinearLayout.LayoutParams(ViewGroup.LayoutParams.MATCH_PARENT, ViewGroup.LayoutParams.WRAP_CONTENT).apply {
            bottomMargin = dp(18)
        })

        // Footer credit
        root.addView(TextView(this).apply {
            text = "developed by WeilBrain"
            textSize = 11f
            typeface = Typeface.MONOSPACE
            setTextColor(textSubtle)
            gravity = Gravity.CENTER
            setPadding(0, dp(4), 0, dp(8))
        })

        val scroll = ScrollView(this).apply {
            isFillViewport = true
            setBackgroundColor(bg)
            addView(root)
        }
        setContentView(scroll)

        if (Build.VERSION.SDK_INT >= 33 && checkSelfPermission(Manifest.permission.POST_NOTIFICATIONS) != PackageManager.PERMISSION_GRANTED) {
            requestPermissions(arrayOf(Manifest.permission.POST_NOTIFICATIONS), REQ_NOTIFY)
        }

        refreshSavedProfile()
        renderSnapshot(PortlineVpnService.snapshot())
    }

    override fun onResume() {
        super.onResume()
        uiHandler.post(pollRunnable)
    }

    override fun onPause() {
        super.onPause()
        uiHandler.removeCallbacks(pollRunnable)
    }

    private fun refreshSavedProfile() {
        try {
            val raw = ProfileVault.load(this)
            if (raw != null) {
                val p = PortlineProfile.decode(raw)
                profileSummary.text = "Сохранён сервер: ${p.host}:${p.port}"
                if (PortlineVpnService.snapshot().state == "idle") {
                    endpointLabel.text = "${p.host}:${p.port} · готов к подключению"
                }
            } else {
                profileSummary.text = "Профиль ещё не загружен"
            }
        } catch (_: Exception) {
            profileSummary.text = "Сохранённый профиль недоступен"
        }
    }

    private fun onPrimaryAction() {
        val snap = PortlineVpnService.snapshot()
        if (snap.state == "connected" || snap.state == "connecting") {
            startService(Intent(this, PortlineVpnService::class.java).apply { action = PortlineVpnService.DISCONNECT })
            return
        }
        try {
            val typed = input.text.toString().trim()
            val raw = typed.ifBlank { ProfileVault.load(this) ?: error("Сначала импортируй или вставь профиль") }
            PortlineProfile.decode(raw)
            pendingProfile = raw
            val prepare = VpnService.prepare(this)
            if (prepare != null) startActivityForResult(prepare, REQ_VPN) else startVpnService()
        } catch (e: Exception) {
            statusSub.text = "Ошибка: ${e.message}"
        }
    }

    private fun startVpnService() {
        val intent = Intent(this, PortlineVpnService::class.java).apply {
            action = PortlineVpnService.CONNECT
            putExtra(PortlineVpnService.PROFILE, pendingProfile)
        }
        if (Build.VERSION.SDK_INT >= 26) startForegroundService(intent) else startService(intent)
        renderSnapshot(PortlineVpnService.snapshot())
    }

    private fun formatPackets(n: Long): String {
        return when {
            n >= 1_000_000 -> String.format("%.2fM", n / 1_000_000.0)
            n >= 10_000 -> String.format("%.1fK", n / 1_000.0)
            else -> n.toString()
        }
    }

    private fun formatUptime(connectedAtMs: Long): String {
        if (connectedAtMs <= 0L) return "00:00:00"
        val sec = ((System.currentTimeMillis() - connectedAtMs) / 1000L).coerceAtLeast(0L)
        val h = sec / 3600
        val m = (sec % 3600) / 60
        val s = sec % 60
        return String.format("%02d:%02d:%02d", h, m, s)
    }

    private fun renderSnapshot(snap: TunnelSnapshot) {
        when (snap.state) {
            "connected" -> {
                heroCard.background = roundedBox(0xff082621.toInt(), 0xff10b981.toInt(), 18)
                statusDot.background = roundedBox(0xff34d399.toInt(), Color.TRANSPARENT, 99)
                statusTitle.text = "VPN подключён"
                primaryBtn.text = "Отключить VPN"
                primaryBtn.setTextColor(0xfffda4af.toInt())
                primaryBtn.background = roundedBox(0xff3b1822.toInt(), 0xfff43f5e.toInt(), 12)
                leakCheckBtn.visibility = View.VISIBLE
            }
            "connecting" -> {
                heroCard.background = roundedBox(0xff0c1e34.toInt(), 0xff38bdf8.toInt(), 18)
                statusDot.background = roundedBox(0xff38bdf8.toInt(), Color.TRANSPARENT, 99)
                statusTitle.text = snap.phase
                primaryBtn.text = "Отменить"
                primaryBtn.setTextColor(0xfff8fafc.toInt())
                primaryBtn.background = roundedBox(0xff1e293b.toInt(), 0xff475569.toInt(), 12)
                leakCheckBtn.visibility = View.GONE
            }
            "disconnecting" -> {
                heroCard.background = roundedBox(0xff0f172a.toInt(), 0xfff59e0b.toInt(), 18)
                statusDot.background = roundedBox(0xfffbbf24.toInt(), Color.TRANSPARENT, 99)
                statusTitle.text = "Отключение…"
                primaryBtn.text = "Отключение…"
                leakCheckBtn.visibility = View.GONE
            }
            "error" -> {
                heroCard.background = roundedBox(0xff261219.toInt(), 0xfff43f5e.toInt(), 18)
                statusDot.background = roundedBox(0xfffb7185.toInt(), Color.TRANSPARENT, 99)
                statusTitle.text = snap.phase
                primaryBtn.text = "Подключить VPN"
                primaryBtn.setTextColor(0xff061523.toInt())
                primaryBtn.background = roundedBox(0xff38bdf8.toInt(), Color.TRANSPARENT, 12)
                leakCheckBtn.visibility = View.GONE
            }
            else -> {
                heroCard.background = roundedBox(0xff0f172a.toInt(), 0xff1e293b.toInt(), 18)
                statusDot.background = roundedBox(0xff64748b.toInt(), Color.TRANSPARENT, 99)
                statusTitle.text = "VPN отключён"
                primaryBtn.text = "Подключить VPN"
                primaryBtn.setTextColor(0xff061523.toInt())
                primaryBtn.background = roundedBox(0xff38bdf8.toInt(), Color.TRANSPARENT, 12)
                leakCheckBtn.visibility = View.GONE
            }
        }
        statusSub.text = snap.message
        if (snap.endpoint.isNotBlank()) {
            endpointLabel.text = if (snap.clientIp.isNotBlank()) "${snap.endpoint} · ${snap.clientIp}" else snap.endpoint
        }
        metricLatency.text = if (snap.state == "connected" && snap.latencyMs > 0) "${snap.latencyMs} мс" else "—"
        metricSent.text = if (snap.state == "connected") formatPackets(snap.sentPackets) else "0"
        metricRecv.text = if (snap.state == "connected") formatPackets(snap.receivedPackets) else "0"
        metricUptime.text = if (snap.state == "connected") formatUptime(snap.connectedAtMs) else "00:00:00"
    }

    private fun checkUpdates() {
        updateBtn.text = "Проверка…"
        Thread {
            try {
                val conn = (URL("https://api.github.com/repos/WeilBrainn/Portline/releases/latest").openConnection() as HttpURLConnection).apply {
                    connectTimeout = 6000
                    readTimeout = 6000
                    setRequestProperty("Accept", "application/vnd.github+json")
                    setRequestProperty("User-Agent", "Portline-Android/$APP_VERSION")
                }
                val code = conn.responseCode
                if (code == 200) {
                    val body = conn.inputStream.bufferedReader().use { it.readText() }
                    val json = JSONObject(body)
                    val tag = json.optString("tag_name", "").removePrefix("v")
                    val url = json.optString("html_url", "https://github.com/WeilBrainn/Portline/releases")
                    val newer = isNewer(APP_VERSION, tag)
                    runOnUiThread {
                        if (newer) {
                            updateBtn.text = "v$tag ↗"
                            statusSub.text = "Доступно обновление v$tag — нажми на кнопку справа для скачивания"
                            updateBtn.setOnClickListener {
                                startActivity(Intent(Intent.ACTION_VIEW, Uri.parse(url)))
                            }
                        } else {
                            updateBtn.text = "Актуально"
                        }
                    }
                } else {
                    runOnUiThread { updateBtn.text = "Обновления" }
                }
            } catch (_: Exception) {
                runOnUiThread { updateBtn.text = "Обновления" }
            }
        }.start()
    }

    private fun isNewer(current: String, latest: String): Boolean {
        if (latest.isBlank()) return false
        val c = current.substringBefore('-').split('.').map { it.toIntOrNull() ?: 0 }
        val l = latest.substringBefore('-').split('.').map { it.toIntOrNull() ?: 0 }
        for (i in 0 until 3) {
            val cv = c.getOrElse(i) { 0 }
            val lv = l.getOrElse(i) { 0 }
            if (lv != cv) return lv > cv
        }
        return current.contains('-') && !latest.contains('-')
    }

    @Deprecated("Deprecated in Android API")
    override fun onActivityResult(requestCode: Int, resultCode: Int, data: Intent?) {
        super.onActivityResult(requestCode, resultCode, data)
        if (requestCode == REQ_IMPORT && resultCode == RESULT_OK) {
            val uri = data?.data ?: return
            try {
                val raw = contentResolver.openInputStream(uri)?.use { stream ->
                    val buf = ByteArray(8193)
                    var count = 0
                    while (count < buf.size) {
                        val n = stream.read(buf, count, buf.size - count)
                        if (n < 0) break
                        count += n
                    }
                    require(count in 1..8192) { "Неверный размер профиля" }
                    String(buf, 0, count, Charsets.UTF_8).trim()
                } ?: error("Файл недоступен")
                PortlineProfile.decode(raw)
                ProfileVault.save(this, raw)
                input.setText("")
                pasteBox.visibility = View.GONE
                refreshSavedProfile()
                statusSub.text = "VPN-профиль импортирован и готов к подключению"
            } catch (_: Exception) {
                statusSub.text = "Ошибка импорта профиля"
            }
        }
        if (requestCode == REQ_VPN) {
            if (resultCode == RESULT_OK) startVpnService()
            else statusSub.text = "Разрешение Android на VPN не предоставлено"
        }
    }
}
